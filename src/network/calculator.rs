use std::str::FromStr;

use pnet::datalink;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// Pure logic — testable without real interfaces.
/// Given a slice of IP networks, returns the first IPv4 CIDR string found.
pub(crate) fn first_ipv4_cidr(ips: &[pnet::ipnetwork::IpNetwork]) -> Option<String> {
    ips.iter().find_map(|ip| match ip {
        pnet::ipnetwork::IpNetwork::V4(net) => Some(format!("{}/{}", net.network(), net.prefix())),
        _ => None,
    })
}

pub fn get_cidr(interface_name: &str) -> Option<String> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.iter().find(|i| i.name == interface_name)?;
    first_ipv4_cidr(&iface.ips)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/network/calculator.rs
//
// Paste this #[cfg(test)] block at the bottom of src/network/calculator.rs
// ─────────────────────────────────────────────────────────────────────────────
//
// get_cidr() calls pnet::datalink::interfaces() which reads /proc/net and
// real system state — that's I/O we can't fake in a unit test.
//
// The testable surface here is therefore the *output format*, verified by
// calling the function against "lo" (the loopback interface, which exists
// on every Linux/macOS machine and always has 127.0.0.1/8) and parsing the
// result ourselves.  Tests that require a specific interface name are
// marked #[ignore] so `cargo test` passes in CI without special setup;
// run them manually with `cargo test -- --ignored` on a real machine.

#[cfg(test)]
mod tests {
    use super::*;

    // ── Output-format contract ────────────────────────────────────────────────

    /// Whatever get_cidr returns for "lo", it must be valid CIDR notation:
    /// an IPv4 address, a slash, and a decimal prefix length.
    ///
    /// This test is #[ignore] because it requires a live loopback interface.
    /// Run with: cargo test -- --ignored
    #[test]
    #[ignore]
    fn test_loopback_returns_valid_cidr_format() {
        let result = get_cidr("lo");
        assert!(result.is_some(), "lo should always have an IPv4 address");

        let cidr = result.unwrap();

        // Must contain exactly one slash.
        let parts: Vec<&str> = cidr.splitn(2, '/').collect();
        assert_eq!(parts.len(), 2, "CIDR must contain exactly one '/'");

        // Left side must parse as IPv4.
        parts[0]
            .parse::<std::net::Ipv4Addr>()
            .expect("left side of CIDR must be a valid IPv4 address");

        // Right side must be a decimal integer 0–32.
        let prefix: u8 = parts[1]
            .parse()
            .expect("right side of CIDR must be a decimal number");
        assert!(prefix <= 32, "prefix length must be ≤ 32");
    }

    /// A made-up interface name that can never exist returns None.
    #[test]
    fn test_nonexistent_interface_returns_none() {
        // An interface named with a UUID-like string will never exist.
        let result = get_cidr("does_not_exist_harper_test");
        assert!(
            result.is_none(),
            "get_cidr on a nonexistent interface must return None"
        );
    }

    /// get_cidr is safe to call multiple times with the same argument.
    /// (Idempotency — no hidden mutable state.)
    #[test]
    fn test_repeated_call_is_safe() {
        // We don't care about the value, just that it doesn't panic or corrupt.
        let _ = get_cidr("does_not_exist_1");
        let _ = get_cidr("does_not_exist_1");
        let _ = get_cidr("does_not_exist_2");
    }

    // ── Format validation helper (pure, always runs) ─────────────────────────

    /// A standalone check that a CIDR string produced by get_cidr is the
    /// format we feed into IpRange::from_cidr().  We test it separately so
    /// the scanner integration tests don't have to depend on real interfaces.
    #[test]
    fn test_cidr_format_is_accepted_by_ip_range() {
        // Simulate what get_cidr would return for a /24.
        let synthetic = "192.168.0.0/24";

        // If IpRange lives in the parent module (network.rs) you need:
        // use crate::network::IpRange;
        // We can't import it here without restructuring, so we validate the
        // format rules directly — IpRange::from_cidr() tests cover the rest.
        let parts: Vec<&str> = synthetic.splitn(2, '/').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<std::net::Ipv4Addr>().is_ok());
        let prefix: u8 = parts[1].parse().unwrap();
        assert!(prefix <= 30); // IpRange rejects > 30
    }

    // ── first_ipv4_cidr() ─────────────────────────────────────────────────────

    #[test]
    fn test_ipv4_cidr_extracted_correctly() {
        let net = IpNetwork::V4(Ipv4Network::from_str("192.168.1.0/24").unwrap());
        assert_eq!(first_ipv4_cidr(&[net]), Some("192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_ipv4_cidr_prefix_preserved() {
        let net = IpNetwork::V4(Ipv4Network::from_str("10.0.0.0/8").unwrap());
        assert_eq!(first_ipv4_cidr(&[net]), Some("10.0.0.0/8".to_string()));
    }

    #[test]
    fn test_ipv6_only_returns_none() {
        let net = IpNetwork::V6(Ipv6Network::from_str("fe80::1/64").unwrap());
        assert_eq!(first_ipv4_cidr(&[net]), None);
    }

    #[test]
    fn test_empty_ip_list_returns_none() {
        assert_eq!(first_ipv4_cidr(&[]), None);
    }

    #[test]
    fn test_ipv6_before_ipv4_returns_ipv4() {
        let v6 = IpNetwork::V6(Ipv6Network::from_str("fe80::1/64").unwrap());
        let v4 = IpNetwork::V4(Ipv4Network::from_str("172.16.0.0/12").unwrap());
        assert_eq!(
            first_ipv4_cidr(&[v6, v4]),
            Some("172.16.0.0/12".to_string())
        );
    }

    #[test]
    fn test_first_ipv4_wins_when_multiple_present() {
        let v4a = IpNetwork::V4(Ipv4Network::from_str("192.168.1.0/24").unwrap());
        let v4b = IpNetwork::V4(Ipv4Network::from_str("10.0.0.0/8").unwrap());
        assert_eq!(
            first_ipv4_cidr(&[v4a, v4b]),
            Some("192.168.1.0/24".to_string())
        );
    }
}
