// src/utils/gateway.rs
use std::net::Ipv4Addr;

pub fn get_gateway(interface_name: &str) -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&content, interface_name)
}

pub(crate) fn parse_route_table(content: &str, interface_name: &str) -> Option<Ipv4Addr> {
    for line in content.lines().skip(1) {
        let mut fields = line.split_whitespace();

        let (iface, destination, gateway_hex, flags_hex) =
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => continue,
            };

        if iface != interface_name {
            continue;
        }
        if destination != "00000000" {
            continue;
        }

        let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
        if flags & 0x0002 == 0 {
            continue;
        }

        let gw_u32 = match u32::from_str_radix(gateway_hex, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let b = gw_u32.to_le_bytes();
        return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";

    fn make_table(rows: &[(&str, &str, &str, &str)]) -> String {
        let mut out = format!("{}\n", HEADER);
        for (iface, dst, gw, flags) in rows {
            out.push_str(&format!(
                "{iface}\t{dst}\t{gw}\t{flags}\t0\t0\t100\t00000000\t0\t0\t0\n"
            ));
        }
        out
    }

    // ── Happy path: various gateway IPs ──────────────────────────────────────
    // All "known good" parse cases in one table.
    #[test]
    fn test_parse_known_gateways() {
        // (iface, gateway_hex_le, expected_ip)
        // Little-endian: 0x0101A8C0 → bytes [C0,A8,01,01] → 192.168.1.1
        let cases: &[(&str, &str, &str, Ipv4Addr)] = &[
            ("eth0", "0101A8C0", "0003", Ipv4Addr::new(192, 168, 1, 1)),
            ("wlan0", "0100000A", "0003", Ipv4Addr::new(10, 0, 0, 1)),
            ("enp3s0", "010010AC", "0003", Ipv4Addr::new(172, 16, 0, 1)),
            ("eth0", "FE01A8C0", "0003", Ipv4Addr::new(192, 168, 1, 254)),
            ("eth0", "0204A8C0", "0003", Ipv4Addr::new(192, 168, 4, 2)),
            ("eth0", "01020A0A", "0003", Ipv4Addr::new(10, 10, 2, 1)),
        ];
        for &(iface, gw_hex, flags, expected) in cases {
            let table = make_table(&[(iface, "00000000", gw_hex, flags)]);
            assert_eq!(
                parse_route_table(&table, iface),
                Some(expected),
                "gateway hex '{gw_hex}' on '{iface}'"
            );
        }
    }

    // ── Multi-interface: correct interface is selected ────────────────────────
    #[test]
    fn test_correct_interface_is_selected() {
        let table = make_table(&[
            ("eth0", "00000000", "0101A8C0", "0003"),
            ("wlan0", "00000000", "0100000A", "0003"),
        ]);
        assert_eq!(
            parse_route_table(&table, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_route_table(&table, "wlan0"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    // First matching row wins when duplicates exist
    #[test]
    fn test_first_default_route_wins() {
        let table = make_table(&[
            ("eth0", "00000000", "0101A8C0", "0003"), // 192.168.1.1 ← first
            ("eth0", "00000000", "FE01A8C0", "0003"), // 192.168.1.254
        ]);
        assert_eq!(
            parse_route_table(&table, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    // Non-default rows are skipped even when the interface matches
    #[test]
    fn test_non_default_route_is_skipped() {
        let table = make_table(&[
            ("eth0", "0001A8C0", "0101A8C0", "0001"), // subnet route, not default
            ("eth0", "00000000", "FE01A8C0", "0003"), // default → 192.168.1.254
        ]);
        assert_eq!(
            parse_route_table(&table, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 254))
        );
    }

    // ── RTF_GATEWAY flag combinations ─────────────────────────────────────────
    #[test]
    fn test_gateway_flag_combinations() {
        // 0x0002 must be set; other bits don't matter
        let accepted = ["0003", "0007"]; // RTF_UP|RTF_GATEWAY, + RTF_HOST
        let rejected = ["0001", "0000"]; // RTF_UP only, nothing

        for flags in accepted {
            let table = make_table(&[("eth0", "00000000", "0101A8C0", flags)]);
            assert!(
                parse_route_table(&table, "eth0").is_some(),
                "flags {flags} should be accepted"
            );
        }
        for flags in rejected {
            let table = make_table(&[("eth0", "00000000", "0101A8C0", flags)]);
            assert!(
                parse_route_table(&table, "eth0").is_none(),
                "flags {flags} should be rejected"
            );
        }
    }

    // ── Returns None cases ────────────────────────────────────────────────────
    #[test]
    fn test_returns_none_cases() {
        let valid_table = make_table(&[("eth0", "00000000", "0101A8C0", "0003")]);

        // (table_content, interface, reason)
        let cases: &[(&str, &str, &str)] = &[
            (&valid_table, "wlan0", "unknown interface"),
            (&format!("{}\n", HEADER), "eth0", "header only"),
            ("", "eth0", "empty string"),
        ];
        for &(content, iface, reason) in cases {
            assert!(
                parse_route_table(content, iface).is_none(),
                "should return None for: {reason}"
            );
        }
    }

    // ── Malformed rows are skipped without panic ──────────────────────────────
    #[test]
    fn test_malformed_rows_are_skipped() {
        // Bad hex in gateway field → row skipped, next valid row still works
        let bad_hex = format!(
            "{}\neth0\t00000000\tZZZZZZZZ\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            HEADER
        );
        assert_eq!(
            parse_route_table(&bad_hex, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );

        // Row with too few columns → skipped, next valid row wins
        let short_row = format!(
            "{}\neth0\tBAD\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            HEADER
        );
        assert_eq!(
            parse_route_table(&short_row, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    #[ignore]
    fn test_get_gateway_does_not_panic_on_live_system() {
        let _ = get_gateway("eth0");
        let _ = get_gateway("wlan0");
        let _ = get_gateway("does_not_exist");
    }
}
