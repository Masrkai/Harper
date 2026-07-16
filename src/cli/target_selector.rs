// src/cli/target_selector.rs
//
// Prompts the user to pick one or more hosts from the HostTable after a scan.
// Accepted input formats:
//   "3"       — single host
//   "1-5"     — inclusive range
//   "1,3,5"   — comma-separated list
//   "all"     — every host in the table
//
// After target selection the user is optionally asked for a per-host
// bandwidth limit (in kbps).  Entering nothing / 0 means unlimited.
//
// The gateway is automatically excluded regardless of input.

use crate::cli::color::palette;
use crate::host::table::{HostId, HostTable};
use crate::paint;
use std::io::{self, Write};
use std::net::Ipv4Addr;

// ─────────────────────────────────────────────────────────────────────────────

pub struct SelectionResult {
    pub host_ids: Vec<HostId>,
    pub bandwidth_kbps: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────

pub struct TargetSelector;

impl TargetSelector {
    pub fn select(table: &HostTable, gateway_ip: Ipv4Addr) -> Option<SelectionResult> {
        let gateway_id = table.get_by_ip(gateway_ip).map(|e| e.id);

        let mut available: Vec<HostId> = table
            .iter()
            .filter(|e| Some(e.id) != gateway_id)
            .map(|e| e.id)
            .collect();
        available.sort_unstable();

        if available.is_empty() {
            eprintln!("No targets available — only the gateway was discovered.");
            return None;
        }

        println!("\n{}", "=".repeat(62));
        println!("{:^62}", "ARP Spoof — Target Selection");
        println!("{}", "=".repeat(62));

        println!(
            "{:<5} {:<16} {:<18} {:<12} {:<24}",
            "ID", "IP", "MAC", "Status", "Vendor"
        );
        println!("{}", "-".repeat(62));

        let mut entries: Vec<_> = table.iter().filter(|e| Some(e.id) != gateway_id).collect();
        entries.sort_by_key(|e| e.id);

        for entry in &entries {
            let vendor = entry.host.vendor.as_deref().unwrap_or("Unknown");
            println!(
                "{:<5} {:<16} {:<18} {:<12} {}",
                format!("[{}]", entry.id),
                entry.host.ip,
                entry.host.mac,
                format!("{:?}", entry.state),
                if vendor.len() > 22 {
                    format!("{:.21}…", vendor)
                } else {
                    vendor.to_string()
                },
            );
        }

        println!("{}", "-".repeat(62));

        if let Some(gw_id) = gateway_id {
            if let Some(gw) = table.get_by_id(gw_id) {
                println!(
                    "{}",
                    paint!(
                        &palette::WARN,
                        "  Gateway [{}] {} is excluded from selection.",
                        gw_id,
                        gw.host.ip
                    )
                );
            }
        }

        println!(
            "\n{}",
            paint!(&palette::DIM, r#"  Formats:  "3"   "1-5"   "1,3,5"   "all""#)
        );

        print!(
            "\n{}",
            paint!(
                &palette::PROMPT,
                "Select target(s) [1-{}] or 'q' to quit: ",
                available.iter().copied().max().unwrap_or(0)
            )
        );
        io::stdout().flush().unwrap();

        let raw = read_line()?;
        if raw.eq_ignore_ascii_case("q") || raw.eq_ignore_ascii_case("quit") {
            return None;
        }

        let host_ids = Self::parse_selection(&raw, &available)?;

        if host_ids.is_empty() {
            eprintln!("No valid hosts matched your input.");
            return None;
        }

        println!(
            "\n{}",
            paint!(&palette::OK, "  {} host(s) selected:", host_ids.len())
        );
        for id in &host_ids {
            if let Some(entry) = table.get_by_id(*id) {
                println!("    [{}] {}  {}", id, entry.host.ip, entry.host.mac);
            }
        }

        let bandwidth_kbps = Self::prompt_bandwidth();

        Some(SelectionResult {
            host_ids,
            bandwidth_kbps,
        })
    }

    pub(crate) fn parse_selection(raw: &str, available: &[HostId]) -> Option<Vec<HostId>> {
        let max_id = available.iter().copied().max().unwrap_or(0);

        if raw.eq_ignore_ascii_case("all") {
            return Some(available.to_vec());
        }

        let mut ids: Vec<HostId> = Vec::new();

        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            if let Some((lo, hi)) = token.split_once('-') {
                let lo: HostId = match lo.trim().parse::<usize>() {
                    Ok(v) if v >= 1 => v,
                    _ => {
                        eprintln!("Invalid range start in '{}'.", token);
                        return None;
                    }
                };
                let hi: HostId = match hi.trim().parse::<usize>() {
                    Ok(v) if v <= max_id => v,
                    _ => {
                        eprintln!("Invalid range end in '{}' (max is {}).", token, max_id);
                        return None;
                    }
                };

                if lo > hi {
                    eprintln!("Invalid range {}-{}: start must be ≤ end.", lo, hi);
                    return None;
                }

                for id in lo..=hi {
                    if available.contains(&id) {
                        ids.push(id);
                    }
                }
            } else {
                let id: HostId = match token.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("'{}' is not a valid number.", token);
                        return None;
                    }
                };

                if !available.contains(&id) {
                    eprintln!(
                        "ID {} is not selectable (does not exist or is the gateway).",
                        id
                    );
                    return None;
                }

                ids.push(id);
            }
        }

        ids.sort_unstable();
        ids.dedup();

        if ids.is_empty() {
            return None;
        }

        Some(ids)
    }

    pub(crate) fn parse_bandwidth(raw: &str) -> Option<u64> {
        if raw.is_empty() || raw == "0" {
            return None;
        }
        match raw.parse::<u64>() {
            Ok(kbps) if kbps > 0 => Some(kbps),
            _ => None,
        }
    }

    fn prompt_bandwidth() -> Option<u64> {
        print!(
            "\n{}",
            paint!(
                &palette::PROMPT,
                "Bandwidth cap in kbps per host (leave blank = unlimited): "
            )
        );
        io::stdout().flush().unwrap();
        let raw = read_line()?;
        let result = Self::parse_bandwidth(&raw);
        match result {
            Some(kbps) => println!(
                "{}",
                paint!(&palette::OK, "  Bandwidth limit: {} kbps per host", kbps)
            ),
            None => println!("{}", paint!(&palette::DIM, "  No bandwidth limit.")),
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────

fn read_line() -> Option<String> {
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buf.trim().to_owned()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn avail_1_to_5() -> Vec<HostId> { vec![1, 2, 3, 4, 5] }
    fn avail_sparse()  -> Vec<HostId> { vec![1, 3, 5] }
    fn avail_single()  -> Vec<HostId> { vec![1] }

    // ── "all" keyword ─────────────────────────────────────────────────────────
    #[test]
    fn test_all_keyword() {
        // Case-insensitive; returns exactly the available slice
        for variant in ["all", "ALL", "All", "aLl"] {
            assert_eq!(
                TargetSelector::parse_selection(variant, &avail_1_to_5()),
                Some(vec![1, 2, 3, 4, 5]),
                "'{variant}' should be treated as 'all'"
            );
        }
        // Sparse set: returns only available IDs, not a filled range
        assert_eq!(
            TargetSelector::parse_selection("all", &avail_sparse()),
            Some(vec![1, 3, 5])
        );
        // Empty available: returns Some([])
        assert_eq!(
            TargetSelector::parse_selection("all", &[]),
            Some(vec![])
        );
    }

    // ── Single IDs ────────────────────────────────────────────────────────────
    #[test]
    fn test_single_valid_ids() {
        let cases = [
            ("1", &avail_1_to_5() as &[HostId], vec![1]),
            ("5", &avail_1_to_5(),               vec![5]),
            ("3", &avail_1_to_5(),               vec![3]),
            ("1", &avail_single(),               vec![1]),
        ];
        for (input, avail, expected) in cases {
            assert_eq!(TargetSelector::parse_selection(input, avail), Some(expected));
        }
    }

    // ── Ranges ────────────────────────────────────────────────────────────────
    #[test]
    fn test_ranges() {
        let cases: &[(&str, &[HostId], Vec<HostId>)] = &[
            ("1-5", &[1,2,3,4,5], vec![1,2,3,4,5]),  // full
            ("1-3", &[1,2,3,4,5], vec![1,2,3]),       // partial low
            ("3-5", &[1,2,3,4,5], vec![3,4,5]),       // partial high
            ("3-3", &[1,2,3,4,5], vec![3]),            // unit range
            ("1-5", &[1,3,5],     vec![1,3,5]),        // skips unavailable IDs
        ];
        for &(input, avail, ref expected) in cases {
            assert_eq!(
                TargetSelector::parse_selection(input, avail),
                Some(expected.clone()),
                "range '{input}'"
            );
        }
    }

    // ── Comma-separated lists ─────────────────────────────────────────────────
    #[test]
    fn test_comma_lists() {
        let a = avail_1_to_5();
        let cases: &[(&str, Vec<HostId>)] = &[
            ("1,3",   vec![1, 3]),
            ("1,3,5", vec![1, 3, 5]),
            ("1, 3, 5", vec![1, 3, 5]),   // spaces around commas
            ("1,1,2", vec![1, 2]),         // deduplication
            ("5,1,3", vec![1, 3, 5]),      // output is sorted
        ];
        for &(input, ref expected) in cases {
            assert_eq!(
                TargetSelector::parse_selection(input, &a),
                Some(expected.clone()),
                "list '{input}'"
            );
        }
    }

    // ── Mixed range + single ──────────────────────────────────────────────────
    #[test]
    fn test_mixed_inputs() {
        let a = avail_1_to_5();
        let cases: &[(&str, Vec<HostId>)] = &[
            ("1-3,5",   vec![1,2,3,5]),
            ("1,3-5",   vec![1,3,4,5]),
            ("1-3,2",   vec![1,2,3]),     // overlap deduplication
        ];
        for &(input, ref expected) in cases {
            assert_eq!(
                TargetSelector::parse_selection(input, &a),
                Some(expected.clone()),
                "mixed '{input}'"
            );
        }
    }

    // ── Invalid / error inputs ────────────────────────────────────────────────
    #[test]
    fn test_invalid_inputs_return_none() {
        let a5 = avail_1_to_5();
        let cases: &[(&str, &[HostId], &str)] = &[
            ("5-1",  &a5, "reversed range"),
            ("3-2",  &a5, "adjacent reversed"),
            ("6",    &a5, "ID not in available set"),
            ("0",    &a5, "zero ID"),
            ("1-99", &a5, "range end above max"),
            ("",     &a5, "empty string"),
            ("abc",  &a5, "non-numeric word"),
            ("1.5",  &a5, "float"),
            ("-1",   &a5, "negative number"),
        ];
        for &(input, avail, reason) in cases {
            assert!(
                TargetSelector::parse_selection(input, avail).is_none(),
                "'{input}' ({reason}) should return None"
            );
        }
    }

    // ── Edge cases ────────────────────────────────────────────────────────────
    #[test]
    fn test_trailing_comma_skips_empty_token() {
        // "1," — empty token from trailing comma is silently skipped
        assert_eq!(
            TargetSelector::parse_selection("1,", &avail_1_to_5()),
            Some(vec![1])
        );
    }

    #[test]
    fn test_comma_only_does_not_panic() {
        let _ = TargetSelector::parse_selection(",", &avail_1_to_5());
    }

    // ── parse_bandwidth ───────────────────────────────────────────────────────
    #[test]
    fn test_parse_bandwidth() {
        // Valid → Some
        let valid: &[(&str, u64)] = &[
            ("1",       1),
            ("512",     512),
            ("1000",    1_000),
            ("1000000", 1_000_000),
        ];
        for &(input, expected) in valid {
            assert_eq!(TargetSelector::parse_bandwidth(input), Some(expected), "input '{input}'");
        }

        // Invalid → None
        let invalid = ["", "0", "abc", "1.5", "-100"];
        for input in invalid {
            assert!(
                TargetSelector::parse_bandwidth(input).is_none(),
                "'{input}' should return None"
            );
        }
    }
}