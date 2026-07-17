// src/forwarder/mock.rs
//
// Shared, root-free test helpers for the forwarder packet path. `MockSender`
// implements pnet's `DataLinkSender` so it can be fed to `send_with_retry`
// (the production retry/backoff logic) without a real network device. Frame
// builders produce valid Ethernet+IP/ARP buffers for exercising the path.

#![cfg(test)]

use pnet::datalink::{DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::io;

/// A `DataLinkSender` that records sends and can be programmed to fail with
/// specific transient or fatal errors, so retry/backoff behaviour is observable.
pub struct MockSender {
    pub sent: Vec<Vec<u8>>,
    pub inject_errors: std::collections::VecDeque<io::Error>,
    pub call_count: usize,
}

impl MockSender {
    pub fn new() -> Self {
        Self {
            sent: Vec::new(),
            inject_errors: std::collections::VecDeque::new(),
            call_count: 0,
        }
    }

    pub fn fail_with_enobufs(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.inject_errors.push_back(io::Error::from_raw_os_error(105));
        }
        self
    }

    pub fn fail_with_would_block(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.inject_errors
                .push_back(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self
    }

    pub fn fail_with_fatal(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.inject_errors
                .push_back(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self
    }
}

impl DataLinkSender for MockSender {
    fn send_to(
        &mut self,
        packet: &[u8],
        _dst: Option<NetworkInterface>,
    ) -> Option<io::Result<()>> {
        self.call_count += 1;
        if let Some(err) = self.inject_errors.pop_front() {
            return Some(Err(err));
        }
        self.sent.push(packet.to_vec());
        Some(Ok(()))
    }

    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        unimplemented!()
    }
}

pub const OUR_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
pub const OLD_DST_MAC: MacAddr = MacAddr(0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02);
pub const OLD_SRC_MAC: MacAddr = MacAddr(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);

pub fn write_eth_header(buf: &mut [u8], dst: MacAddr, src: MacAddr, ethertype: u16) {
    buf[0..6].copy_from_slice(&[dst.0, dst.1, dst.2, dst.3, dst.4, dst.5]);
    buf[6..12].copy_from_slice(&[src.0, src.1, src.2, src.3, src.4, src.5]);
    buf[12] = (ethertype >> 8) as u8;
    buf[13] = (ethertype & 0xFF) as u8;
}

/// IPv4 frame whose IP total-length matches payload+20; buffer is exactly that.
pub fn make_ipv4_frame(ip_payload_len: usize) -> Vec<u8> {
    let ip_total = 20 + ip_payload_len;
    let frame_len = 14 + ip_total;
    let mut buf = vec![0u8; frame_len];
    write_eth_header(&mut buf, OLD_DST_MAC, OLD_SRC_MAC, 0x0800);
    buf[14] = 0x45;
    buf[16] = (ip_total >> 8) as u8;
    buf[17] = (ip_total & 0xFF) as u8;
    buf
}

/// GSO super-frame: IP total-length says `ip_payload_len` but buffer has extra padding.
pub fn make_ipv4_frame_padded(ip_payload_len: usize, extra_pad: usize) -> Vec<u8> {
    let ip_total = 20 + ip_payload_len;
    let mut buf = vec![0u8; 14 + ip_total + extra_pad];
    write_eth_header(&mut buf, OLD_DST_MAC, OLD_SRC_MAC, 0x0800);
    buf[14] = 0x45;
    buf[16] = (ip_total >> 8) as u8;
    buf[17] = (ip_total & 0xFF) as u8;
    buf
}

pub fn make_ipv6_frame(ipv6_payload_len: usize) -> Vec<u8> {
    let real_frame_len = 14 + 40 + ipv6_payload_len;
    let mut buf = vec![0u8; real_frame_len + 100];
    write_eth_header(&mut buf, OLD_DST_MAC, OLD_SRC_MAC, 0x86DD);
    buf[18] = (ipv6_payload_len >> 8) as u8;
    buf[19] = (ipv6_payload_len & 0xFF) as u8;
    buf
}

pub fn make_arp_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 200];
    write_eth_header(&mut buf, OLD_DST_MAC, OLD_SRC_MAC, 0x0806);
    buf
}
