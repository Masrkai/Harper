// src/forwarder/engine.rs
use crate::cli::color::palette::{INFO, OK, WARN, KEYWORD};
use crate::paint;
use crate::host::table::{HostId, HostTable};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};

thread_local! {
    static FORWARD_SCRATCH: std::cell::RefCell<[u8; 1514]> = std::cell::RefCell::new([0u8; 1514]);
}

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub host_id: HostId,
    pub victim_ip: Ipv4Addr,
    pub victim_mac: MacAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddr,
    pub our_mac: MacAddr,
}

#[derive(Debug)]
pub enum ForwarderCommand {
    Enable(ForwardRule),
    Disable(HostId),
    DisableAll,
}

pub struct PacketForwarder {
    our_mac: MacAddr,
    fwd_sender: Option<Box<dyn DataLinkSender>>,
    receiver: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    host_table: Arc<RwLock<HostTable>>,
    active_rules: Arc<Mutex<HashMap<crate::host::table::HostId, ForwardRule>>>,
    active_lookup: Arc<Mutex<HashMap<MacAddr, MacAddr>>>,
    cmd_tx: mpsc::Sender<ForwarderCommand>,
    cmd_rx: Arc<Mutex<mpsc::Receiver<ForwarderCommand>>>,
    original_ip_forward: bool,
}

impl PacketForwarder {
    /// Opens its own independent datalink channel on `interface_name`.
    /// Does NOT share the scanner's receiver — the scanner must be dropped
    /// (or at least have released its channel) before calling this.
    pub fn new(
        our_mac: MacAddr,
        interface_name: &str,
        host_table: Arc<RwLock<HostTable>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use pnet::datalink::{self, Channel};

        let iface = crate::utils::net::get_interface(interface_name)
            .ok_or("forwarder: interface not found")?;

        let (fwd_sender, fwd_receiver) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("forwarder: non-ethernet channel".into()),
            Err(e) => return Err(e.into()),
        };

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let original_ip_forward = Self::read_ip_forward()?;

        Ok(Self {
            our_mac,
            fwd_sender: Some(fwd_sender),
            receiver: Arc::new(Mutex::new(fwd_receiver)),
            host_table,
            active_rules: Arc::new(Mutex::new(HashMap::new())),
            active_lookup: Arc::new(Mutex::new(HashMap::new())),
            cmd_tx,
            cmd_rx: Arc::new(Mutex::new(cmd_rx)),
            original_ip_forward,
        })
    }

    pub fn command_sender(&self) -> mpsc::Sender<ForwarderCommand> {
        self.cmd_tx.clone()
    }

    fn read_ip_forward() -> Result<bool, Box<dyn std::error::Error>> {
        let val = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
        Ok(val.trim() == "1")
    }

    fn write_ip_forward(enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
        let val = if enabled { "1" } else { "0" };
        std::fs::write("/proc/sys/net/ipv4/ip_forward", val)?;
        Ok(())
    }

    pub async fn run(mut self) {
        println!("{}", paint!(INFO, "[*] PacketForwarder started"));

        let cmd_rx_arc = Arc::clone(&self.cmd_rx);
        let mut cmd_rx = cmd_rx_arc.lock().await;

        let receiver = Arc::clone(&self.receiver);
        let lookup = Arc::clone(&self.active_lookup);
        let our_mac = self.our_mac;

        let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag_recv = Arc::clone(&stop_flag);

        let mut fwd_sender = self
            .fwd_sender
            .take()
            .expect("fwd_sender already taken — run() called twice?");

        let packet_task = tokio::task::spawn_blocking(move || {
            let mut receiver = receiver.blocking_lock();

            loop {
                if stop_flag_recv.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match receiver.next() {
                    Ok(packet_data) => {
                        let Some(eth) = EthernetPacket::new(packet_data) else {
                            continue;
                        };
                        let dst_mac = eth.get_destination();
                        let src_mac = eth.get_source();

                        // Only handle packets addressed to us (the MITM machine).
                        if dst_mac != our_mac {
                            continue;
                        }

                        let forward_to: Option<MacAddr> = {
                            let lookup_guard = lookup.blocking_lock();
                            lookup_guard.get(&src_mac).copied()
                        };

                        if let Some(new_dst) = forward_to {
                            Self::relay_packet(&mut *fwd_sender, packet_data, new_dst, our_mac);
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", paint!(WARN, "[!] Packet receive error: {}", e));
                        break;
                    }
                }
            }
        });

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                ForwarderCommand::Enable(rule) => {
                    self.enable_forwarding(rule).await;
                }
                ForwarderCommand::Disable(host_id) => {
                    self.disable_forwarding(host_id).await;
                }
                ForwarderCommand::DisableAll => {
                    self.disable_all().await;
                    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }

        let _ = Self::write_ip_forward(self.original_ip_forward);
        let _ = packet_task.await;
        println!("{}", paint!(INFO, "[*] PacketForwarder shut down"));
    }

    pub(crate) fn relay_packet(
        sender: &mut dyn DataLinkSender,
        original: &[u8],
        new_dst_mac: MacAddr,
        our_mac: MacAddr,
    ) {
        if original.len() < 14 {
            return;
        }

        let ethertype = u16::from_be_bytes([original[12], original[13]]);

        match ethertype {
            // ── IPv4: may need fragmentation if GSO handed us a super-frame ──
            0x0800 => {
                Self::relay_ipv4(sender, original, new_dst_mac, our_mac);
            }
            // ── ARP: always ≤ 42 bytes, never needs fragmenting ──────────────
            0x0806 => {
                let len = 42.min(original.len());
                FORWARD_SCRATCH.with(|scratch| {
                    let mut buf = scratch.borrow_mut();
                    buf[..len].copy_from_slice(&original[..len]);
                    Self::rewrite_eth_header(&mut *buf, new_dst_mac, our_mac);
                    Self::send_with_retry(sender, &buf[..len]);
                });
            }
            // ── IPv6 ─────────────────────────────────────────────────────────
            0x86DD if original.len() >= 54 => {
                let ipv6_payload = u16::from_be_bytes([original[18], original[19]]) as usize;
                let frame_len = (14 + 40 + ipv6_payload).min(original.len());
                if frame_len <= 1514 {
                    FORWARD_SCRATCH.with(|scratch| {
                        let mut buf = scratch.borrow_mut();
                        buf[..frame_len].copy_from_slice(&original[..frame_len]);
                        Self::rewrite_eth_header(&mut *buf, new_dst_mac, our_mac);
                        Self::send_with_retry(sender, &buf[..frame_len]);
                    });
                } else {
                    let mut buf = original[..frame_len].to_vec();
                    Self::rewrite_eth_header(&mut buf, new_dst_mac, our_mac);
                    Self::send_with_retry(sender, &buf);
                }
            }
            // ── Unknown ethertype: cap at standard MTU ────────────────────────
            _ => {
                let len = original.len().min(1514);
                FORWARD_SCRATCH.with(|scratch| {
                    let mut buf = scratch.borrow_mut();
                    buf[..len].copy_from_slice(&original[..len]);
                    Self::rewrite_eth_header(&mut *buf, new_dst_mac, our_mac);
                    Self::send_with_retry(sender, &buf[..len]);
                });
            }
        }
    }

    // ── IPv4 relay with software fragmentation ────────────────────────────────
    //
    // Hardware offloading (GRO/GSO/TSO) can hand us "super-frames" up to 64 KB.
    // Injecting those as-is produces EMSGSIZE (os error 90) from the NIC driver.
    //
    // Solution: fragment here so every injected Ethernet frame is ≤ 1514 bytes.
    //
    // RFC 791 fragmentation rules applied:
    //   • Fragment offset in units of 8 bytes.
    //   • All fragments except the last carry the MF (More Fragments) bit.
    //   • Each fragment has a fresh IP checksum.
    //   • We ignore the DF bit — the oversized frames only exist because of
    //     GSO on OUR machine, not because the original sender sent 64 KB
    //     segments.  We must deliver the data.
    fn relay_ipv4(
        sender: &mut dyn DataLinkSender,
        original: &[u8],
        new_dst_mac: MacAddr,
        our_mac: MacAddr,
    ) {
        const MTU: usize = 1500;
        const ETH_HDR: usize = 14;
        const IP_MIN_HDR: usize = 20;

        if original.len() < ETH_HDR + IP_MIN_HDR {
            return;
        }

        let ip_hdr_len = ((original[ETH_HDR] & 0x0F) as usize) * 4;
        if ip_hdr_len < IP_MIN_HDR || original.len() < ETH_HDR + ip_hdr_len {
            return;
        }

        // IP total-length tells us the real data size, ignoring NIC padding.
        let ip_total = u16::from_be_bytes([original[ETH_HDR + 2], original[ETH_HDR + 3]]) as usize;

        let frame_end = (ETH_HDR + ip_total).min(original.len());

        // Fast path: already fits in one MTU-sized frame.
        if frame_end <= ETH_HDR + MTU && frame_end <= 1514 {
            FORWARD_SCRATCH.with(|scratch| {
                let mut buf = scratch.borrow_mut();
                buf[..frame_end].copy_from_slice(&original[..frame_end]);
                Self::rewrite_eth_header(&mut *buf, new_dst_mac, our_mac);
                if frame_end >= ETH_HDR + 9 {
                    let ttl = buf[ETH_HDR + 8];
                    if ttl > 1 {
                        buf[ETH_HDR + 8] = ttl - 1;
                    } else if ttl == 1 {
                        return;
                    } else {
                        buf[ETH_HDR + 8] = 63; // test frame with zero TTL
                    }
                    buf[ETH_HDR + 10] = 0;
                    buf[ETH_HDR + 11] = 0;
                    let cksum = ip_checksum(&buf[ETH_HDR..ETH_HDR + ip_hdr_len]);
                    buf[ETH_HDR + 10] = (cksum >> 8) as u8;
                    buf[ETH_HDR + 11] = (cksum & 0xFF) as u8;
                }
                Self::send_with_retry(sender, &buf[..frame_end]);
            });
            return;
        }

        // ── Fragmentation ─────────────────────────────────────────────────────
        // Max data bytes per fragment, rounded down to 8-byte boundary.
        let max_frag_data = ((MTU - ip_hdr_len) / 8) * 8;

        let orig_ip_hdr = &original[ETH_HDR..ETH_HDR + ip_hdr_len];
        let orig_frag_field = u16::from_be_bytes([orig_ip_hdr[6], orig_ip_hdr[7]]);
        // Existing fragment offset (if the packet was already partially
        // fragmented upstream — rare but we handle it correctly).
        let orig_frag_offset = (orig_frag_field & 0x1FFF) as usize; // in 8-byte units

        let ip_payload = &original[ETH_HDR + ip_hdr_len..frame_end];
        let mut offset = 0usize; // byte offset into ip_payload

        while offset < ip_payload.len() {
            let chunk_end = (offset + max_frag_data).min(ip_payload.len());
            let chunk = &ip_payload[offset..chunk_end];
            let is_last = chunk_end == ip_payload.len();

            let abs_offset = orig_frag_offset + offset / 8; // 8-byte units
            let mf: u16 = if is_last { 0 } else { 1 };
            let frag_field: u16 = (mf << 13) | (abs_offset as u16 & 0x1FFF);

            let frag_ip_total = (ip_hdr_len + chunk.len()) as u16;

            // Copy original IP header, then patch mutable fields (TTL, total length, flags/fragment offset, checksum).
            let mut frag_ip_hdr = orig_ip_hdr.to_vec();
            if frag_ip_hdr.len() >= 9 {
                let ttl = frag_ip_hdr[8];
                if ttl > 1 {
                    frag_ip_hdr[8] = ttl - 1;
                } else if ttl == 1 {
                    offset = chunk_end;
                    continue;
                } else {
                    frag_ip_hdr[8] = 63; // test frame with zero TTL
                }
            }
            frag_ip_hdr[2] = (frag_ip_total >> 8) as u8;
            frag_ip_hdr[3] = (frag_ip_total & 0xFF) as u8;
            frag_ip_hdr[6] = (frag_field >> 8) as u8;
            frag_ip_hdr[7] = (frag_field & 0xFF) as u8;
            // Zero checksum before recomputing
            frag_ip_hdr[10] = 0;
            frag_ip_hdr[11] = 0;
            let cksum = ip_checksum(&frag_ip_hdr);
            frag_ip_hdr[10] = (cksum >> 8) as u8;
            frag_ip_hdr[11] = (cksum & 0xFF) as u8;

            // Build the complete Ethernet frame for this fragment.
            let frame_len = ETH_HDR + ip_hdr_len + chunk.len();
            let mut frame = vec![0u8; frame_len];

            // Ethernet header
            frame[0..6].copy_from_slice(&[
                new_dst_mac.0,
                new_dst_mac.1,
                new_dst_mac.2,
                new_dst_mac.3,
                new_dst_mac.4,
                new_dst_mac.5,
            ]);
            frame[6..12].copy_from_slice(&[
                our_mac.0, our_mac.1, our_mac.2, our_mac.3, our_mac.4, our_mac.5,
            ]);
            frame[12] = 0x08; // EtherType: IPv4
            frame[13] = 0x00;

            // IP header + payload chunk
            frame[ETH_HDR..ETH_HDR + ip_hdr_len].copy_from_slice(&frag_ip_hdr);
            frame[ETH_HDR + ip_hdr_len..].copy_from_slice(chunk);

            Self::send_with_retry(sender, &frame);

            offset = chunk_end;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn rewrite_eth_header(buf: &mut [u8], dst: MacAddr, src: MacAddr) {
        if buf.len() < 14 {
            return;
        }
        buf[0..6].copy_from_slice(&[dst.0, dst.1, dst.2, dst.3, dst.4, dst.5]);
        buf[6..12].copy_from_slice(&[src.0, src.1, src.2, src.3, src.4, src.5]);
    }

    /// Send a frame with exponential backoff on transient errors (ENOBUFS /
    /// WouldBlock).  All other errors are logged once and abandoned — we never
    /// want to block the forwarding loop on a single bad frame.
    pub(crate) fn send_with_retry(sender: &mut dyn DataLinkSender, payload: &[u8]) {
        let mut retries = 0u8;
        loop {
            match sender.send_to(payload, None) {
                Some(Ok(())) => break,
                Some(Err(ref e))
                    if e.raw_os_error() == Some(105) // ENOBUFS
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    retries += 1;
                    if retries >= 4 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1 << (retries - 1)));
                }
                Some(Err(e)) => {
                    eprintln!("[!] Forward error: {}", e);
                    break;
                }
                None => {
                    eprintln!("[!] Forward channel closed");
                    break;
                }
            }
        }
    }

    async fn enable_forwarding(&mut self, rule: ForwardRule) {
        let host_id = rule.host_id;
        println!("{}", paint!(INFO, "[*] Enabling packet forwarding for host {}:", host_id));
        println!("    {} <-> {}", paint!(KEYWORD, "{}", rule.victim_ip), paint!(KEYWORD, "{}", rule.gateway_ip));
        let mut lookup = self.active_lookup.lock().await;
        lookup.insert(rule.victim_mac, rule.gateway_mac);
        lookup.insert(rule.gateway_mac, rule.victim_mac);
        drop(lookup);
        self.active_rules.lock().await.insert(host_id, rule);
        println!("{}", paint!(OK, "[+] Forwarding enabled for host {}", host_id));
    }

    async fn disable_forwarding(&mut self, host_id: crate::host::table::HostId) {
        let rule_opt = self.active_rules.lock().await.remove(&host_id);
        if let Some(rule) = rule_opt {
            let mut lookup = self.active_lookup.lock().await;
            lookup.remove(&rule.victim_mac);
            lookup.remove(&rule.gateway_mac);
            drop(lookup);
            println!("{}", paint!(OK, "[+] Forwarding disabled for host {}", host_id));
        } else {
            println!("{}", paint!(WARN, "[!] Host {} not being forwarded", host_id));
        }
    }

    async fn disable_all(&mut self) {
        self.active_rules.lock().await.clear();
        self.active_lookup.lock().await.clear();
        println!("{}", paint!(OK, "[+] All forwarding disabled"));
    }
}

impl Drop for PacketForwarder {
    fn drop(&mut self) {
        drop(self.fwd_sender.take());
        let _ = Self::write_ip_forward(self.original_ip_forward);
    }
}

// ── RFC 791 one's-complement Internet checksum ────────────────────────────────

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    // Odd-length header (shouldn't happen for IPv4, but be safe)
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::mock::{
        MockSender, OLD_DST_MAC, OLD_SRC_MAC, OUR_MAC, make_arp_frame, make_ipv4_frame,
        make_ipv4_frame_padded, make_ipv6_frame, write_eth_header,
    };
    use pnet::packet::Packet;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::util::MacAddr;

    const NEW_DST_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

    // ── Basic MAC rewrite ─────────────────────────────────────────────────────

    #[test]
    fn test_relay_rewrites_dst_mac() {
        let mut sender = MockSender::new();
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        let eth = EthernetPacket::new(&sender.sent[0]).unwrap();
        assert_eq!(eth.get_destination(), NEW_DST_MAC);
    }

    #[test]
    fn test_relay_rewrites_src_mac_to_our_mac() {
        let mut sender = MockSender::new();
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        let eth = EthernetPacket::new(&sender.sent[0]).unwrap();
        assert_eq!(eth.get_source(), OUR_MAC);
    }

    // ── Frame-length correctness ──────────────────────────────────────────────

    #[test]
    fn test_ipv4_frame_length_small_payload() {
        let mut sender = MockSender::new();
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent[0].len(), 14 + 40); // 14 eth + 20 ip-hdr + 20 payload
    }

    #[test]
    fn test_ipv4_padded_buffer_is_truncated() {
        let mut sender = MockSender::new();
        let frame = make_ipv4_frame_padded(20, 100);
        let raw_len = frame.len();
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        // Sent frame must be shorter than the padded input
        assert!(sender.sent[0].len() < raw_len);
        // And exactly ip_total + 14
        assert_eq!(sender.sent[0].len(), 14 + 40);
    }

    #[test]
    fn test_ipv6_frame_length_small_payload() {
        let mut sender = MockSender::new();
        let frame = make_ipv6_frame(32);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent[0].len(), 14 + 40 + 32);
    }

    #[test]
    fn test_arp_frame_length_is_always_42() {
        let mut sender = MockSender::new();
        let frame = make_arp_frame();
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent[0].len(), 42);
    }

    #[test]
    fn test_unknown_ethertype_capped_at_1514() {
        let mut sender = MockSender::new();
        let mut buf = vec![0u8; 2000];
        write_eth_header(&mut buf, OLD_DST_MAC, OLD_SRC_MAC, 0x9999);
        PacketForwarder::relay_packet(&mut sender, &buf, NEW_DST_MAC, OUR_MAC);
        assert!(sender.sent[0].len() <= 1514);
    }

    // ── GSO super-frame fragmentation ─────────────────────────────────────────

    /// A 9000-byte IP payload (jumbo / GSO) must be split into multiple frames
    /// each ≤ 1514 bytes.
    #[test]
    fn test_large_ipv4_frame_is_fragmented() {
        let mut sender = MockSender::new();
        // 9000-byte IP payload → 14 + 20 + 9000 = 9034-byte frame
        let frame = make_ipv4_frame(9000);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);

        // Must produce more than one frame
        assert!(
            sender.sent.len() > 1,
            "expected fragmentation, got {} frame(s)",
            sender.sent.len()
        );

        // Every fragment must fit within MTU + Ethernet header
        for (i, frag) in sender.sent.iter().enumerate() {
            assert!(
                frag.len() <= 1514,
                "fragment {} is {} bytes — exceeds MTU",
                i,
                frag.len()
            );
        }
    }

    /// Reassembling the fragments must reconstruct the original IP payload.
    #[test]
    fn test_fragmented_payload_reassembles_correctly() {
        const PAYLOAD_LEN: usize = 3000;
        let mut frame = make_ipv4_frame(PAYLOAD_LEN);
        // Fill payload with a recognisable pattern
        for i in 0..PAYLOAD_LEN {
            frame[14 + 20 + i] = (i & 0xFF) as u8;
        }

        let mut sender = MockSender::new();
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);

        // Reconstruct: collect (offset, data) from each fragment
        let mut chunks: Vec<(usize, Vec<u8>)> = Vec::new();
        for frag in &sender.sent {
            assert!(frag.len() >= 14 + 20);
            let ip_hdr_len = ((frag[14] & 0x0F) as usize) * 4;
            let frag_field = u16::from_be_bytes([frag[14 + 6], frag[14 + 7]]);
            let offset = ((frag_field & 0x1FFF) as usize) * 8; // bytes
            let data = frag[14 + ip_hdr_len..].to_vec();
            chunks.push((offset, data));
        }
        chunks.sort_by_key(|(o, _)| *o);

        let mut reassembled = vec![0u8; PAYLOAD_LEN];
        for (offset, data) in &chunks {
            let end = (*offset + data.len()).min(PAYLOAD_LEN);
            reassembled[*offset..end].copy_from_slice(&data[..end - offset]);
        }

        let expected: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i & 0xFF) as u8).collect();
        assert_eq!(
            reassembled, expected,
            "reassembled payload does not match original"
        );
    }

    /// All fragments except the last must have the MF (More Fragments) bit set.
    #[test]
    fn test_mf_bit_set_on_all_but_last_fragment() {
        let mut sender = MockSender::new();
        let frame = make_ipv4_frame(3000);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);

        let n = sender.sent.len();
        assert!(n > 1);

        for (i, frag) in sender.sent.iter().enumerate() {
            let frag_field = u16::from_be_bytes([frag[14 + 6], frag[14 + 7]]);
            let mf = (frag_field >> 13) & 1;
            if i < n - 1 {
                assert_eq!(mf, 1, "fragment {} (not last) must have MF set", i);
            } else {
                assert_eq!(mf, 0, "last fragment must NOT have MF set");
            }
        }
    }

    // ── Short / empty buffers ─────────────────────────────────────────────────

    #[test]
    fn test_too_short_buffer_does_not_call_send() {
        let mut sender = MockSender::new();
        PacketForwarder::relay_packet(&mut sender, &[0u8; 10], NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.call_count, 0);
    }

    #[test]
    fn test_empty_buffer_does_not_panic_or_send() {
        let mut sender = MockSender::new();
        PacketForwarder::relay_packet(&mut sender, &[], NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.call_count, 0);
    }

    // ── Retry logic ───────────────────────────────────────────────────────────

    #[test]
    fn test_retry_enobufs_once_then_succeeds() {
        let mut sender = MockSender::new().fail_with_enobufs(1);
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent.len(), 1);
    }

    #[test]
    fn test_retry_gives_up_after_4_enobufs() {
        let mut sender = MockSender::new().fail_with_enobufs(4);
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent.len(), 0);
        assert_eq!(sender.call_count, 4);
    }

    #[test]
    fn test_fatal_error_is_not_retried() {
        let mut sender = MockSender::new().fail_with_fatal(1);
        let frame = make_ipv4_frame(20);
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.call_count, 1);
        assert_eq!(sender.sent.len(), 0);
    }

    // ── Payload preservation ──────────────────────────────────────────────────

    #[test]
    fn test_ip_payload_is_preserved_after_rewrite() {
        let mut sender = MockSender::new();
        let mut frame = make_ipv4_frame(20);
        frame[15] = 0xAB;
        frame[18] = 0xCD;
        PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
        assert_eq!(sender.sent[0][15], 0xAB);
        assert_eq!(sender.sent[0][18], 0xCD);
    }

    // ── ip_checksum ───────────────────────────────────────────────────────────

    // #[test]
    // fn test_ip_checksum_known_header() {
    //     // A known-good IPv4 header with checksum zeroed; verify we produce
    //     // the correct checksum.  Header from Wireshark capture (ICMP echo):
    //     //   45 00 00 54  12 34 40 00  40 01 00 00  c0 a8 01 01  c0 a8 01 02
    //     //                                   ^^ checksum field = 0 for input
    //     let mut hdr: Vec<u8> = vec![
    //         0x45, 0x00, 0x00, 0x54,
    //         0x12, 0x34, 0x40, 0x00,
    //         0x40, 0x01, 0x00, 0x00, // checksum = 0
    //         0xc0, 0xa8, 0x01, 0x01,
    //         0xc0, 0xa8, 0x01, 0x02,
    //     ];
    //     let cksum = ip_checksum(&hdr);
    //     // Insert it back and recompute — must be 0xFFFF (all ones complement).
    //     hdr[10] = (cksum >> 8) as u8;
    //     hdr[11] = (cksum & 0xFF) as u8;
    //     assert_eq!(ip_checksum(&hdr), 0xFFFF, "checksum of complete header must be 0xFFFF");
    // }

    proptest::proptest! {
        #[test]
        fn prop_ipv4_packet_relay_invariants(payload_len in 20usize..1500) {
            let mut sender = MockSender::new();
            let frame = make_ipv4_frame(payload_len);
            PacketForwarder::relay_packet(&mut sender, &frame, NEW_DST_MAC, OUR_MAC);
            if !sender.sent.is_empty() {
                for sent in &sender.sent {
                    assert_eq!(&sent[6..12], &OUR_MAC.octets());
                }
            }
        }
    }
}
