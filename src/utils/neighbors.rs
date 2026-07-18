// src/utils/neighbors.rs
//
// Reads the kernel neighbour table from /proc/net/arp and returns the hosts
// currently known to the OS on a given interface. In gateway mode the kernel
// already forwards traffic for every client, so its ARP cache is the
// authoritative, zero-cost source of client IP+MAC pairs — no active scan
// (broadcast storm) is needed to discover them.

use crate::host::table::DiscoveredHost;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Instant;

/// Returns the clients the kernel currently knows about on `interface_name`,
/// parsed from `/proc/net/arp`. Our own IP is excluded.
///
/// Returns an empty vec if the file cannot be read or contains no matching
/// rows — callers should fall back to an active scan in that case.
pub fn discover_via_cache(interface_name: &str, our_ip: Ipv4Addr) -> Vec<DiscoveredHost> {
    let content = match std::fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_arp_table(&content, interface_name, our_ip)
}

/// Parses `/proc/net/arp` content, keeping rows for `interface_name` whose IP
/// differs from `our_ip`. Each row:
/// `IP_address HW_type Flags HW_address Mask Device`
pub(crate) fn parse_arp_table(
    content: &str,
    interface_name: &str,
    our_ip: Ipv4Addr,
) -> Vec<DiscoveredHost> {
    let mut hosts = Vec::new();

    for line in content.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (ip_s, _hw_type, _flags, mac_s, _mask, iface) = match (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) {
            (Some(a), Some(b), Some(d), Some(c), Some(f), Some(e)) => (a, b, d, c, f, e),
            _ => continue,
        };

        if iface != interface_name {
            continue;
        }

        let Ok(ip) = ip_s.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip == our_ip {
            continue;
        }

        let Some(mac) = parse_mac(mac_s) else {
            continue;
        };

        hosts.push(DiscoveredHost {
            ip,
            mac,
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        });
    }

    hosts
}

/// Parses a colon-separated MAC ("00:11:22:33:44:55") into `MacAddr`.
fn parse_mac(s: &str) -> Option<MacAddr> {
    let mut octets = [0u8; 6];
    let mut i = 0;
    for part in s.split(':') {
        if i >= 6 {
            return None;
        }
        octets[i] = u8::from_str_radix(part, 16).ok()?;
        i += 1;
    }
    if i != 6 {
        return None;
    }
    Some(MacAddr::new(
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    ))
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "IP address\tHW type\tFlags\tHW address\tMask\tDevice";

    fn make_table(rows: &[(&str, &str)]) -> String {
        let mut out = format!("{HEADER}\n");
        for (ip, mac) in rows {
            // HW type 0x1, Flags 0x0, Mask 0x0
            out.push_str(&format!("{ip}\t0x1\t0x0\t{mac}\t0x0\teth0\n"));
        }
        out
    }

    #[test]
    fn test_parses_clients_on_interface() {
        let table = make_table(&[
            ("192.168.1.10", "AA:BB:CC:DD:EE:01"),
            ("192.168.1.11", "AA:BB:CC:DD:EE:02"),
        ]);
        let hosts = parse_arp_table(&table, "eth0", Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(
            hosts[0].mac,
            MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01)
        );
    }

    #[test]
    fn test_excludes_our_ip() {
        let table = make_table(&[
            ("192.168.1.1", "AA:BB:CC:DD:EE:00"), // our IP → excluded
            ("192.168.1.10", "AA:BB:CC:DD:EE:01"),
        ]);
        let hosts = parse_arp_table(&table, "eth0", Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn test_filters_by_interface() {
        let other = "10.0.0.5\t0x1\t0x0\tBB:BB:BB:BB:BB:BB\t0x0\twlan0\n";
        let table = format!(
            "{HEADER}\n{other}{}",
            make_table(&[("192.168.1.10", "AA:BB:CC:DD:EE:01",)])
        );
        let hosts = parse_arp_table(&table, "eth0", Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn test_empty_and_malformed_rows() {
        assert!(parse_arp_table("", "eth0", Ipv4Addr::new(0, 0, 0, 0)).is_empty());
        assert!(
            parse_arp_table(&format!("{HEADER}\n"), "eth0", Ipv4Addr::new(0, 0, 0, 0)).is_empty()
        );
        // bad MAC → row skipped
        let bad = format!("{HEADER}\n192.168.1.10\t0x1\t0x0\tNOTMAC\t0x0\teth0\n");
        assert!(parse_arp_table(&bad, "eth0", Ipv4Addr::new(192, 168, 1, 1)).is_empty());
    }
}
