// src/utils/ip_range.rs
//
// Shared IP address expansion logic used by both MITM mode (main.rs)
// and gateway mode (gateway_mode.rs).  Previously duplicated verbatim
// in both files as `expand_target` / `expand_one`.

use crate::network::IpRange;
use std::net::Ipv4Addr;

/// Expands a single string token into one or more IPv4 addresses.
///
/// Accepted formats:
///   "192.168.1.5"      — single IP
///   "192.168.1.0/24"   — CIDR range (host addresses only, network/broadcast excluded)
///   "192.168.1.1-5"    — last-octet range (inclusive)
///
/// Returns `Err` with a human-readable message on any parse failure.
pub fn expand_one(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    // CIDR: contains a '/'
    if s.contains('/') {
        let range = IpRange::from_cidr(s).map_err(|e| format!("invalid CIDR '{s}': {e}"))?;
        return Ok(range.iter().collect());
    }

    // Last-octet range: "a.b.c.lo-hi"
    if let Some((prefix, range_part)) = s.rsplit_once('.') {
        if let Some((lo_s, hi_s)) = range_part.split_once('-') {
            let octs = format!("{prefix}.0")
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("invalid prefix '{prefix}'"))?
                .octets();
            let lo: u8 = lo_s
                .parse()
                .map_err(|_| format!("bad range start in '{s}'"))?;
            let hi: u8 = hi_s
                .parse()
                .map_err(|_| format!("bad range end in '{s}'"))?;
            if lo > hi {
                return Err(format!("range start > end in '{s}'"));
            }
            return Ok((lo..=hi)
                .map(|n| Ipv4Addr::new(octs[0], octs[1], octs[2], n))
                .collect());
        }
    }

    // Single IP
    s.parse::<Ipv4Addr>()
        .map(|ip| vec![ip])
        .map_err(|_| format!("cannot parse '{s}' as IP, CIDR, or range"))
}

/// Expands a slice of raw target strings, deduplicates, and sorts the result.
/// Calls `process::exit(1)` on the first parse error, logging via `logger`.
///
/// This is a convenience wrapper used by both modes' startup paths.
pub fn expand_targets(raw_targets: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for raw in raw_targets {
        let expanded = expand_one(raw).map_err(|e| format!("target '{raw}': {e}"))?;
        ips.extend(expanded);
    }
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Table-driven tests: (input, expected_len, first_ip, last_ip)
    // Groups all "happy path" cases for expand_one in one place.
    #[test]
    fn test_expand_one_valid_inputs() {
        let cases: &[(&str, usize, &str, &str)] = &[
            // Single IP
            ("192.168.1.5", 1, "192.168.1.5", "192.168.1.5"),
            ("10.0.0.1", 1, "10.0.0.1", "10.0.0.1"),
            // CIDR /30 → 2 host addresses
            ("10.0.0.0/30", 2, "10.0.0.1", "10.0.0.2"),
            // CIDR /29 → 6 host addresses
            ("10.0.0.0/29", 6, "10.0.0.1", "10.0.0.6"),
            // Last-octet range
            ("10.0.0.1-3", 3, "10.0.0.1", "10.0.0.3"),
            ("10.0.0.5-5", 1, "10.0.0.5", "10.0.0.5"),
        ];

        for &(input, expected_len, first, last) in cases {
            let result = expand_one(input).unwrap_or_else(|e| panic!("'{input}' failed: {e}"));
            assert_eq!(result.len(), expected_len, "len mismatch for '{input}'");
            assert_eq!(
                result.first().unwrap().to_string(),
                first,
                "first IP mismatch for '{input}'"
            );
            assert_eq!(
                result.last().unwrap().to_string(),
                last,
                "last IP mismatch for '{input}'"
            );
        }
    }

    // All error cases in one table: (input, reason)
    #[test]
    fn test_expand_one_invalid_inputs() {
        let cases = [
            ("not_an_ip", "garbage string"),
            ("10.0.0.5-3", "reversed range"),
            ("999.0.0.1", "invalid octet"),
            ("10.0.0.0/31", "prefix too large for IpRange"),
            ("", "empty string"),
        ];

        for (input, reason) in cases {
            assert!(
                expand_one(input).is_err(),
                "'{input}' should fail ({reason}) but returned Ok"
            );
        }
    }

    #[test]
    fn test_expand_targets_deduplicates_and_sorts() {
        let raw = vec![
            "10.0.0.3".to_string(),
            "10.0.0.1".to_string(),
            "10.0.0.1".to_string(), // duplicate
        ];
        let result = expand_targets(&raw).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(result[1], "10.0.0.3".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_expand_targets_empty_input() {
        assert_eq!(expand_targets(&[]).unwrap(), Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn test_expand_targets_returns_err_on_bad_input() {
        let raw = vec!["not_valid".to_string()];
        assert!(expand_targets(&raw).is_err());
    }
}
