// src/utils/oui.rs
//
// Wraps the `oui-data` crate (IEEE-sourced, fully embedded — no file needed)
// to resolve the first 3 octets of a MAC address to a vendor name.
//
// Called as a batch pass after scanning completes, so it never slows the
// ARP send/receive loop.

use pnet::util::MacAddr;

/// Looks up the vendor name for a MAC address using the embedded IEEE OUI database.
/// Returns `"Unknown"` when no match is found.
pub fn lookup_vendor(mac: MacAddr) -> String {
    // oui-data expects the OUI prefix in uppercase colon-separated form: "AA:BB:CC"
    let oui = format!("{:02X}:{:02X}:{:02X}", mac.0, mac.1, mac.2);

    oui_data::lookup(&oui)
        .map(|record| record.organization().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Known vendor MACs (IEEE-registered, stable in the embedded database) ──

    /// Intel Corporation OUI: 8C:8D:28
    #[test]
    fn test_known_intel_mac_returns_intel() {
        let mac = MacAddr(0x8C, 0x8D, 0x28, 0x00, 0x00, 0x00);
        let vendor = lookup_vendor(mac);
        assert!(
            vendor.to_lowercase().contains("intel"),
            "expected Intel vendor, got: {vendor}"
        );
    }

    // ── Unknown MAC ───────────────────────────────────────────────────────────

    /// The OUI 00:00:00 is assigned to Xerox in the IEEE database.
    #[test]
    fn test_known_xerox_oui_returns_xerox() {
        let mac = MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        let vendor = lookup_vendor(mac);
        assert!(
            vendor.to_lowercase().contains("xerox"),
            "expected Xerox vendor, got: {vendor}"
        );
    }

    /// A locally-administered MAC (bit 1 of first octet set) is never in the
    /// IEEE database — must return "Unknown".
    #[test]
    fn test_locally_administered_mac_returns_unknown() {
        // 0x02 has the locally-administered bit set
        let mac = MacAddr(0x02, 0xAB, 0xCD, 0x00, 0x00, 0x00);
        assert_eq!(lookup_vendor(mac), "Unknown");
    }

    // ── OUI formatting contract ───────────────────────────────────────────────
    // The function formats the OUI as "AA:BB:CC" (uppercase, colon-separated).
    // We verify this indirectly: if the format were wrong (e.g. lowercase or
    // no colons), known OUI lookups would return "Unknown" instead of the vendor.

    /// Lookup is case-correct — the MAC bytes are formatted as uppercase hex.
    /// If formatting were lowercase, the oui-data lookup would fail.
    #[test]
    fn test_oui_formatting_produces_correct_lookup() {
        // 00:50:56 is VMware's OUI — well-known and stable
        let mac = MacAddr(0x00, 0x50, 0x56, 0x00, 0x00, 0x00);
        let vendor = lookup_vendor(mac);
        assert!(
            vendor.to_lowercase().contains("vmware"),
            "expected VMware vendor (formatting must be uppercase), got: {vendor}"
        );
    }

    /// Only the first 3 octets matter — the last 3 are ignored by the OUI lookup.
    #[test]
    fn test_last_three_octets_do_not_affect_result() {
        let mac_a = MacAddr(0x00, 0x50, 0x56, 0x00, 0x00, 0x00);
        let mac_b = MacAddr(0x00, 0x50, 0x56, 0xFF, 0xFF, 0xFF);
        assert_eq!(lookup_vendor(mac_a), lookup_vendor(mac_b));
    }

    /// lookup_vendor never returns an empty string — it's either a vendor name
    /// or the literal "Unknown".
    #[test]
    fn test_result_is_never_empty() {
        let macs = [
            MacAddr(0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00), // Apple
            MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00), // Unknown
            MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x00), // locally administered
        ];
        for mac in macs {
            let vendor = lookup_vendor(mac);
            assert!(
                !vendor.is_empty(),
                "vendor string must never be empty for {mac}"
            );
        }
    }
}
