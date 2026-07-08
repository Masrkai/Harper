use crate::host::table::DiscoveredHost;
use crate::scanner::config::{ScanConfig, is_wireless_iface};
use crate::utils::net::get_interface;
use crate::network::{
    IpRange, NetworkError,
    packet::{ArpReply, ArpRequest},
};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, watch};
// use tokio::time::interval;


/// Returns true if an ARP reply from the active scan should be recorded.
/// Filters out replies that are outside our target range or not addressed to us.
pub(crate) fn should_record_scan_reply(
    reply_sender_ip: Ipv4Addr,
    reply_target_ip: Ipv4Addr,
    range: &IpRange,
    local_ip: Ipv4Addr,
) -> bool {
    range.contains(reply_sender_ip) && reply_target_ip == local_ip
}

/// Returns true if a passively-sniffed ARP frame should be ignored.
/// Ignores our own frames, frames from the local MAC, broadcasts, and zero MACs.
pub(crate) fn should_ignore_passive_frame(
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    local_ip: Ipv4Addr,
    local_mac: MacAddr,
) -> bool {
    sender_ip == local_ip
        || sender_mac == local_mac
        || sender_mac == MacAddr::broadcast()
        || sender_mac == MacAddr::zero()
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub struct ArpScanner {
    interface: NetworkInterface,
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    receiver: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    pub config: ScanConfig,
}

impl ArpScanner {
// ... (imports)

    pub async fn new(interface_name: &str) -> Result<Self, NetworkError> {
        let interface = get_interface(interface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(interface_name.to_string()))?;

        let local_mac = interface.mac.ok_or_else(|| {
            NetworkError::InterfaceNotFound(format!("{} has no MAC", interface_name))
        })?;

        let local_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or_else(|| {
                NetworkError::InterfaceNotFound(format!("{} has no IPv4", interface_name))
            })?;

        let config = ScanConfig::for_interface(interface_name);

        let (sender, receiver) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetworkError::PermissionDenied(
                    "Non-ethernet interface".to_string(),
                ));
            }
            Err(e) => return Err(NetworkError::PermissionDenied(e.to_string())),
        };

        Ok(Self {
            interface,
            local_mac,
            local_ip,
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            config,
        })
    }

    /// Sends a small UDP probe to every IP in `range` before the ARP sweep.
    ///
    /// The datagrams will almost certainly be dropped (nothing listens on port 9),
    /// but receiving *any* unicast frame can pull a sleeping 802.11 client's radio
    /// out of its deepest power-save state in time for the first ARP request.
    pub async fn pre_wake(&self, range: IpRange) {
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            eprintln!("[!] pre_wake: could not bind UDP socket — skipping");
            return;
        };

        let payload = b"\x00"; // single byte is enough
        let mut sent = 0u32;

        for ip in range.iter().filter(|&ip| ip != self.local_ip) {
            let dest = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 9);
            // Best-effort; ignore errors (ICMP unreachable responses are fine).
            let _ = sock.send_to(payload, dest).await;
            sent += 1;
        }

        println!("[*] pre_wake: {sent} UDP probes sent — waiting 150 ms for radios to wake…");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    pub async fn scan(&self, range: IpRange) -> Result<Vec<DiscoveredHost>, NetworkError> {
        self.scan_with_config(range, self.config.clone()).await
    }

    pub async fn scan_with_config(
        &self,
        range: IpRange,
        config: ScanConfig,
    ) -> Result<Vec<DiscoveredHost>, NetworkError> {
        let is_wireless = is_wireless_iface(self.interface_name());

        println!(
            "[*] Scan config: {} | {} pass(es) | send interval {}ms | idle cutoff {}ms",
            if is_wireless { "wireless" } else { "ethernet" },
            config.passes,
            config.send_interval_ms,
            config.idle_cutoff_ms,
        );

        let results: Arc<Mutex<HashMap<Ipv4Addr, DiscoveredHost>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // watch channel: receiver publishes the Instant it last saw a *new* host.
        // The main task reads this to decide when to stop waiting.
        let (new_host_tx, new_host_rx) = watch::channel(Instant::now());

        let local_ip = self.local_ip;
        let local_mac = self.local_mac;

        // ── Receiver — runs entirely on a blocking OS thread ─────────────────
        //
        // pnet's DataLinkReceiver::next() is synchronous/blocking and offers no
        // async or timeout variant. Calling it inside tokio::spawn() blocks the
        // worker thread for the full duration of the scan, preventing other tasks
        // from running on that thread. Moving it to spawn_blocking gives it a
        // dedicated thread from the blocking pool and keeps the async scheduler
        // healthy.

        let receiver_arc = Arc::clone(&self.receiver);
        let results_for_recv = Arc::clone(&results);
        let hard_timeout = Duration::from_secs(config.hard_timeout_secs);

        // ── Stop flag ────────────────────────────────────────────────────────────
        // spawn_blocking ignores .abort() — this flag is the only reliable way
        // to stop the blocking receiver thread from the async side.
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_recv = Arc::clone(&stop_flag);

        let receiver_handle = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + hard_timeout;
            let mut guard = receiver_arc.blocking_lock();

            loop {
                // Check stop flag FIRST so we exit promptly after signal.
                if stop_flag_recv.load(Ordering::Relaxed) {
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }

                match guard.next() {
                    Ok(data) => {
                        if let Some(reply) = ArpReply::from_bytes(data) {
                            if should_record_scan_reply(
                                reply.sender_ip,
                                reply.target_ip,
                                &range,
                                local_ip,
                            ) {
                                let host = DiscoveredHost {
                                    ip: reply.sender_ip,
                                    mac: reply.sender_mac,
                                    hostname: None,
                                    vendor: None,
                                    last_seen: Instant::now(),
                                };

                                let mut res = results_for_recv.blocking_lock();
                                let is_new = !res.contains_key(&reply.sender_ip);
                                res.insert(reply.sender_ip, host);
                                let _ = new_host_tx.send(Instant::now()); // always reset idle timer
                                if is_new {
                                    println!(
                                        "[+] Discovered {} (total: {})",
                                        reply.sender_ip,
                                        res.len()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Receive error: {e}");
                        break;
                    }
                }
            }
        });

        if config.pre_wake {
            self.pre_wake(range).await;
        }

        // ── Sender — multi-pass ──────────────────────────────────────────────
        //
        // Each pass sweeps the full range. The inter-pass delay is the key
        // knob for wireless: it lets 802.11 power-save clients (which may have
        // slept through pass 1) wake up before pass 2 arrives.
        let sender_arc = Arc::clone(&self.sender);
        let passes = config.passes;
        // let send_interval = Duration::from_millis(config.send_interval_ms);
        let inter_pass_delay = Duration::from_millis(config.inter_pass_delay_ms);

        let sender_handle = tokio::spawn(async move {
            for pass in 0..passes {
                // Sleep between passes only — no print here anymore
                if pass > 0 {
                    tokio::time::sleep(inter_pass_delay).await;
                }

                // Pre-build all packets — zero allocation in the hot path
                let packets: Vec<[u8; 42]> = range
                    .iter()
                    .filter(|&ip| ip != local_ip)
                    .map(|ip| ArpRequest::new(ip, local_ip, local_mac).to_bytes())
                    .collect();

                // Single, accurate print — fires right before the actual send
                println!(
                    "[*] ARP scan pass {}/{}{}",
                    pass + 1,
                    passes,
                    if pass > 0 {
                        format!(" (after {}ms delay)", inter_pass_delay.as_millis())
                    } else {
                        String::new()
                    }
                );

                let send_interval_us = config.send_interval_ms * 1_000; // ms → µs
                let sender_arc_clone = Arc::clone(&sender_arc);

                tokio::task::spawn_blocking(move || {
            let mut sender = sender_arc_clone.blocking_lock();

            for bytes in &packets {
                // Backpressure: on TX buffer saturation back off and retry once.
                // Without this, send_to() silently drops packets and returns None/Err.
                let mut retries = 0u8;
                loop {
                    match sender.send_to(bytes, None) {
                        Some(Err(ref e))
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.raw_os_error() == Some(105) // ENOBUFS on Linux
                        =>  {
                            retries += 1;
                            if retries >= 3 {
                                eprintln!("[!] TX buffer saturated, dropping packet (gave up after {retries} retries)");
                                break;
                            }
                            // Exponential back-off: 10 ms, 20 ms, 40 ms
                            std::thread::sleep(std::time::Duration::from_millis(10 * (1 << retries)));
                        }
                        _ => break, // sent OK (or unrecoverable error — don't spin)
                    }
                }

                // Paced sending: honouring send_interval_ms prevents both TX buffer
                // saturation and AP queue overflow on wireless networks.
                if send_interval_us > 0 {
                    std::thread::sleep(std::time::Duration::from_micros(send_interval_us));
                }
            }
        })
        .await
        .unwrap();
            }
            println!("[*] All {passes} ARP pass(es) complete");
        });

        // ── Wait for sender to finish ────────────────────────────────────────
        let _ = sender_handle.await;
        let send_finished_at = Instant::now();

        // ── Adaptive collection window ───────────────────────────────────────
        //
        // We poll every 100 ms and apply two independent exit conditions:
        //
        //   1. Minimum window (post_send_min_ms) — always honoured so that
        //      far-away wireless clients that replied during the last pass still
        //      have time for their packets to arrive.
        //
        //   2. Idle cutoff (idle_cutoff_ms) — exit early once *both* conditions
        //      are met: the minimum window has passed AND no new host has been
        //      seen for idle_cutoff_ms. This avoids sitting out the full minimum
        //      on a quiet, fast, wired network.
        //
        //   3. Hard timeout — absolute ceiling.
        let post_send_min = Duration::from_millis(config.post_send_min_ms);
        let idle_cutoff = Duration::from_millis(config.idle_cutoff_ms);
        let hard_deadline = send_finished_at + Duration::from_secs(config.hard_timeout_secs);

        println!(
            "[*] Collecting replies (min {}ms, idle cutoff {}ms)…",
            config.post_send_min_ms, config.idle_cutoff_ms
        );

        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let now = Instant::now();

            if now >= hard_deadline {
                println!("[!] Hard timeout reached");
                break;
            }

            let elapsed_since_send = now.duration_since(send_finished_at);
            let last_new_host = *new_host_rx.borrow();
            let idle_for = now.duration_since(last_new_host);

            if elapsed_since_send >= post_send_min && idle_for >= idle_cutoff {
                println!(
                    "[*] Network quiet for {}ms — scan complete",
                    idle_for.as_millis()
                );
                break;
            }
        }

        // ── Signal the receiver to stop, then WAIT for it ────────────────────────
        // Setting the flag before awaiting ensures the thread exits its current
        // loop iteration and doesn't print any more discoveries after this point.
        stop_flag.store(true, Ordering::Relaxed);
        let _ = receiver_handle.await; // now guaranteed to finish promptly

        // Snapshot results only after the thread is truly done.
        let final_results = {
            let res = results.lock().await;
            res.values().cloned().collect::<Vec<_>>()
        };

        println!(
            "[+] Scan finished — {} host(s) discovered",
            final_results.len()
        );
        Ok(final_results)
    }

    /// Passively captures ARP traffic for `duration` without sending anything.
    ///
    /// Catches devices that never reply to active probes but do emit spontaneous
    /// ARP frames: gratuitous ARP on IP acquisition, ARP requests to the gateway,
    /// DHCP-renewal side-effects, etc.
    ///
    /// Run this *before* `scan()` and merge the results into the HostTable so the
    /// active sweep only needs to fill in whatever the passive phase missed.
    pub async fn passive_sniff(
        &self,
        duration: Duration,
    ) -> Result<Vec<DiscoveredHost>, NetworkError> {
        use pnet::packet::Packet;
        use pnet::packet::arp::ArpPacket;
        use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

        let results: Arc<Mutex<HashMap<Ipv4Addr, DiscoveredHost>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_recv = Arc::clone(&stop_flag);
        let receiver_arc = Arc::clone(&self.receiver);
        let results_recv = Arc::clone(&results);
        let local_ip = self.local_ip;
        let local_mac = self.local_mac;
        let deadline = Instant::now() + duration;

        println!("[*] Passive ARP sniff for {} ms…", duration.as_millis());

        let handle = tokio::task::spawn_blocking(move || {
            let mut guard = receiver_arc.blocking_lock();

            loop {
                if stop_flag_recv.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }

                match guard.next() {
                    Ok(data) => {
                        let Some(eth) = EthernetPacket::new(data) else {
                            continue;
                        };
                        if eth.get_ethertype() != EtherTypes::Arp {
                            continue;
                        }
                        let Some(arp) = ArpPacket::new(eth.payload()) else {
                            continue;
                        };

                        let sender_ip = arp.get_sender_proto_addr();
                        let sender_mac = arp.get_sender_hw_addr();

                        // Ignore our own frames, broadcast, and zero MACs.
                        if should_ignore_passive_frame(sender_ip, sender_mac, local_ip, local_mac) {
                            continue;
                        }

                        let mut res = results_recv.blocking_lock();
                        if !res.contains_key(&sender_ip) {
                            println!("[+] Passive: {sender_ip} ({sender_mac})");
                            res.insert(
                                sender_ip,
                                DiscoveredHost {
                                    ip: sender_ip,
                                    mac: sender_mac,
                                    hostname: None,
                                    vendor: None,
                                    last_seen: Instant::now(),
                                },
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Passive sniff rx error: {e}");
                        break;
                    }
                }
            }
        });

        // Sleep for the requested duration, then signal and drain the thread.
        tokio::time::sleep(duration).await;
        stop_flag.store(true, Ordering::Relaxed);
        let _ = handle.await;

        let final_hosts: Vec<DiscoveredHost> = results.lock().await.values().cloned().collect();
        println!(
            "[+] Passive phase done — {} host(s) spotted",
            final_hosts.len()
        );
        Ok(final_hosts)
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    pub fn interface_name(&self) -> &str {
        &self.interface.name
    }

    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    pub fn get_sender(&self) -> Arc<Mutex<Box<dyn DataLinkSender>>> {
        Arc::clone(&self.sender)
    }

    pub fn get_receiver(&self) -> Arc<Mutex<Box<dyn DataLinkReceiver>>> {
        Arc::clone(&self.receiver)
    }

    /// Sends targeted ARP requests for a specific list of IPs and collects replies.
    /// Used when the user bypasses the full subnet scan via CLI args.
    /// No validation — if a host doesn't reply, it's added with a zero MAC.
    pub async fn resolve_hosts(
        &self,
        ips: &[Ipv4Addr],
    ) -> Result<Vec<DiscoveredHost>, NetworkError> {
        use std::collections::HashSet;

        let targets: Vec<Ipv4Addr> = ips
            .iter()
            .copied()
            .filter(|&ip| ip != self.local_ip)
            .collect();

        if targets.is_empty() {
            return Ok(vec![]);
        }

        let results: Arc<Mutex<HashMap<Ipv4Addr, DiscoveredHost>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let remaining: Arc<Mutex<HashSet<Ipv4Addr>>> =
            Arc::new(Mutex::new(targets.iter().copied().collect()));

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_recv = Arc::clone(&stop_flag);
        let receiver_arc = Arc::clone(&self.receiver);
        let results_recv = Arc::clone(&results);
        let remaining_recv = Arc::clone(&remaining);
        let local_ip = self.local_ip;

        // Receiver thread — stops once all targets replied or timeout fires.
        let handle = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut guard = receiver_arc.blocking_lock();

            loop {
                if stop_flag_recv.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                if remaining_recv.blocking_lock().is_empty() {
                    break; // all targets answered
                }

                match guard.next() {
                    Ok(data) => {
                        let Some(reply) = ArpReply::from_bytes(data) else {
                            continue;
                        };
                        let mut rem = remaining_recv.blocking_lock();
                        if rem.remove(&reply.sender_ip) {
                            println!("[+] Resolved {} → {}", reply.sender_ip, reply.sender_mac);
                            results_recv.blocking_lock().insert(
                                reply.sender_ip,
                                DiscoveredHost {
                                    ip: reply.sender_ip,
                                    mac: reply.sender_mac,
                                    hostname: None,
                                    vendor: None,
                                    last_seen: Instant::now(),
                                },
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] resolve_hosts rx error: {e}");
                        break;
                    }
                }
            }
        });

        // Send 3 targeted ARP requests per IP with a short inter-pass gap.
        for pass in 0..3u8 {
            if pass > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let packets: Vec<[u8; 42]> = targets
                .iter()
                .map(|&ip| ArpRequest::new(ip, self.local_ip, self.local_mac).to_bytes())
                .collect();

            let sender_arc = Arc::clone(&self.sender);
            tokio::task::spawn_blocking(move || {
                let mut sender = sender_arc.blocking_lock();
                for bytes in &packets {
                    let _ = sender.send_to(bytes, None);
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
            .await
            .unwrap();

            // Early exit if all targets already replied.
            if remaining.lock().await.is_empty() {
                break;
            }
        }

        // Give the receiver a trailing window then stop it.
        tokio::time::sleep(Duration::from_millis(800)).await;
        stop_flag.store(true, Ordering::Relaxed);
        let _ = handle.await;

        // For IPs that never replied, insert a stub with zero MAC.
        // The caller said no validation — we trust the user.
        let mut res = results.lock().await;
        for &ip in &targets {
            res.entry(ip).or_insert_with(|| {
                eprintln!("[!] No ARP reply from {ip} — using zero MAC (unvalidated)");
                DiscoveredHost {
                    ip,
                    mac: MacAddr::zero(),
                    hostname: None,
                    vendor: None,
                    last_seen: Instant::now(),
                }
            });
        }

        Ok(res.values().cloned().collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/network/scanner.rs
//
// Paste this #[cfg(test)] block at the bottom of src/network/scanner.rs
//
// ArpScanner::new() opens a raw socket and requires root + a real interface,
// so every test that touches the scanner itself is #[ignore].
//
// What we CAN test without any of that:
//   • ScanConfig  — field values, which variant is chosen per interface name
//   • is_wireless_iface() — the name-matching heuristic (make it pub(crate))
//
// To run the ignored (live) tests:
//   sudo cargo test -- --ignored
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── is_wireless_iface() ───────────────────────────────────────────────────
    //
    // The function is currently private.  Change its signature to:
    //   pub(crate) fn is_wireless_iface(name: &str) -> bool
    // That makes it visible to this module without leaking it to callers.

    #[test]
    fn test_wlan_prefix_is_wireless() {
        assert!(is_wireless_iface("wlan0"));
        assert!(is_wireless_iface("wlan1"));
    }

    #[test]
    fn test_wlp_prefix_is_wireless() {
        assert!(is_wireless_iface("wlp3s0"));
        assert!(is_wireless_iface("wlp59s0"));
    }

    #[test]
    fn test_wlo_prefix_is_wireless() {
        assert!(is_wireless_iface("wlo1"));
    }

    #[test]
    fn test_generic_wl_prefix_is_wireless() {
        assert!(is_wireless_iface("wl0"));
    }

    #[test]
    fn test_eth_is_not_wireless() {
        assert!(!is_wireless_iface("eth0"));
        assert!(!is_wireless_iface("eth1"));
    }

    #[test]
    fn test_enp_is_not_wireless() {
        assert!(!is_wireless_iface("enp0s3"));
        assert!(!is_wireless_iface("enp3s0f1"));
    }

    #[test]
    fn test_lo_is_not_wireless() {
        assert!(!is_wireless_iface("lo"));
    }

    #[test]
    fn test_docker_is_not_wireless() {
        assert!(!is_wireless_iface("docker0"));
        assert!(!is_wireless_iface("br-abc123"));
    }

    #[test]
    fn test_empty_string_is_not_wireless() {
        assert!(!is_wireless_iface(""));
    }

    // ── ScanConfig::for_interface() ───────────────────────────────────────────

    #[test]
    fn test_for_interface_wlan_returns_wireless_config() {
        let cfg = ScanConfig::for_interface("wlan0");
        // Wireless has more passes than ethernet.
        assert!(
            cfg.passes >= 5,
            "wireless config should have ≥ 5 passes, got {}",
            cfg.passes
        );
    }

    #[test]
    fn test_for_interface_eth_returns_ethernet_config() {
        let cfg = ScanConfig::for_interface("eth0");
        // Ethernet config should have fewer passes than wireless.
        let wlan_cfg = ScanConfig::for_interface("wlan0");
        assert!(
            cfg.passes < wlan_cfg.passes,
            "ethernet should have fewer passes than wireless"
        );
    }

    #[test]
    fn test_for_interface_enp_returns_ethernet_config() {
        // enp* (PCI-Express NIC naming) should use ethernet config.
        let cfg = ScanConfig::for_interface("enp3s0");
        let wlan_cfg = ScanConfig::for_interface("wlan0");
        assert!(cfg.passes < wlan_cfg.passes);
    }

    // ── ScanConfig field sanity ───────────────────────────────────────────────

    #[test]
    fn test_ethernet_config_fields_are_nonzero() {
        let cfg = ScanConfig::ethernet();
        assert!(cfg.send_interval_ms > 0);
        assert!(cfg.passes > 0);
        assert!(cfg.inter_pass_delay_ms > 0);
        assert!(cfg.post_send_min_ms > 0);
        assert!(cfg.idle_cutoff_ms > 0);
        assert!(cfg.hard_timeout_secs > 0);
    }

    #[test]
    fn test_wireless_config_fields_are_nonzero() {
        let cfg = ScanConfig::wireless();
        assert!(cfg.send_interval_ms > 0);
        assert!(cfg.passes > 0);
        assert!(cfg.inter_pass_delay_ms > 0);
        assert!(cfg.post_send_min_ms > 0);
        assert!(cfg.idle_cutoff_ms > 0);
        assert!(cfg.hard_timeout_secs > 0);
    }

    /// Wireless must always have a longer inter-pass delay than ethernet,
    /// because it needs to wait for 802.11 power-save clients to wake up.
    #[test]
    fn test_wireless_inter_pass_delay_gt_ethernet() {
        let eth = ScanConfig::ethernet();
        let wlan = ScanConfig::wireless();
        assert!(
            wlan.inter_pass_delay_ms > eth.inter_pass_delay_ms,
            "wireless inter_pass_delay ({} ms) should exceed ethernet ({} ms)",
            wlan.inter_pass_delay_ms,
            eth.inter_pass_delay_ms
        );
    }

    /// pre_wake must be enabled on wireless (sleeping radios need the nudge).
    #[test]
    fn test_wireless_pre_wake_is_enabled() {
        assert!(ScanConfig::wireless().pre_wake);
    }

    /// Hard timeout must be long enough for a realistic scan to finish.
    /// If someone accidentally sets it to 1 second the whole scan breaks.
    #[test]
    fn test_hard_timeout_is_at_least_30_seconds() {
        assert!(ScanConfig::ethernet().hard_timeout_secs >= 30);
        assert!(ScanConfig::wireless().hard_timeout_secs >= 30);
    }

    // ── ArpScanner::new() — live, root required ───────────────────────────────

    /// Verifying that ArpScanner::new() succeeds on a real interface.
    /// Requires root and a live interface named "lo" (always present on Linux).
    #[tokio::test]
    #[ignore]
    async fn test_scanner_new_loopback() {
        // lo doesn't have an IPv4 address in the pnet sense on all distros,
        // so this may legitimately fail with InterfaceNotFound.  We only check
        // it doesn't panic.
        let _ = ArpScanner::new("lo").await;
    }

    /// Constructing a scanner for a nonexistent interface must return Err.
    #[tokio::test]
    #[ignore]
    async fn test_scanner_new_nonexistent_interface_returns_err() {
        let result = ArpScanner::new("does_not_exist_harper").await;
        assert!(
            result.is_err(),
            "ArpScanner::new on a nonexistent interface must return Err"
        );
    }
}
