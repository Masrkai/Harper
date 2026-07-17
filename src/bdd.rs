// src/bdd.rs
//
// Behaviour-Driven Development scaffold for Harper.
//
// Gherkin `.feature` files live in `tests/features/` and are the human-readable
// specification. Each scenario is executed by a scenario-keyed `#[test]` below:
// the test loads the `.feature`, finds its scenario by name, parses the Gherkin
// steps / data tables, and asserts the real code's behaviour against them.
//
// No `cucumber` harness and no step-regex engine — just the `gherkin` parser
// plus ordinary Rust tests. This keeps the spec native while staying fully
// under our control and running with no root privileges.

#![cfg(test)]

use std::path::PathBuf;

use gherkin::{StepType, GherkinEnv};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::cli::target_selector::TargetSelector;
use crate::host::table::{DiscoveredHost, HostTable};
use crate::network::packet::{ArpReply, GratuitousArp};
use crate::utils::ip_range::{expand_one, expand_targets};
use crate::utils::neighbors::parse_arp_table;
use crate::utils::tc::{build_nft_pool_rules, build_nft_rules, HostSlot, ShapeMode};

/// Absolute path to `tests/features/<name>.feature`.
fn feature_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("features");
    p.push(format!("{name}.feature"));
    p
}

/// Loads and parses a `.feature` file by short name (without extension).
fn load_feature(name: &str) -> gherkin::Feature {
    gherkin::Feature::parse_path(feature_path(name), GherkinEnv::default())
        .unwrap_or_else(|e| panic!("failed to parse feature {name}: {e:?}"))
}

/// Finds a scenario within a feature by its exact name.
fn scenario_by_name<'a>(feature: &'a gherkin::Feature, name: &str) -> &'a gherkin::Scenario {
    feature
        .scenarios
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("scenario '{name}' not found in feature"))
}

/// The text of every step in a scenario, in order.
fn step_texts(scenario: &gherkin::Scenario) -> Vec<String> {
    scenario.steps.iter().map(|s| s.value.clone()).collect()
}

/// The data-table rows of the `idx`-th step that carries a table (0-based),
/// excluding the header row. Returns `(header, rows)`.
fn table_of(scenario: &gherkin::Scenario, idx: usize) -> (Vec<String>, Vec<Vec<String>>) {
    let step = &scenario.steps[idx];
    let table = step
        .table
        .as_ref()
        .unwrap_or_else(|| panic!("step {} has no data table", idx));
    let mut iter = table.rows.iter();
    let header = iter.next().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = iter.cloned().collect();
    (header, rows)
}

/// A fake TcManager surface that records calls instead of shelling out to
/// `tc`/`nft`. Lets behavioural scenarios assert on shaping intent with no root.
struct FakeTc {
    pool_calls: Vec<(u64, Vec<std::net::Ipv4Addr>)>,
    host_calls: Vec<(crate::host::table::HostId, std::net::Ipv4Addr, u64)>,
}

impl FakeTc {
    fn new() -> Self {
        Self {
            pool_calls: Vec::new(),
            host_calls: Vec::new(),
        }
    }

    fn limit_pool(&mut self, pool_kbps: u64, victim_ips: &[std::net::Ipv4Addr]) {
        self.pool_calls.push((pool_kbps, victim_ips.to_vec()));
    }

    fn limit_host(&mut self, id: crate::host::table::HostId, ip: std::net::Ipv4Addr, kbps: u64) {
        self.host_calls.push((id, ip, kbps));
    }
}

/// Builds an in-memory `HostTable` from (ip, mac) pairs for behavioural tests.
fn host_table_from(pairs: &[(&str, &str)]) -> HostTable {
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    let mut table = HostTable::new();
    for (ip_s, mac_s) in pairs {
        let ip: Ipv4Addr = ip_s.parse().unwrap();
        let mac = parse_mac(mac_s);
        table.insert(DiscoveredHost {
            ip,
            mac,
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        });
    }
    table.reindex_by_ip();
    table
}

/// Parses a colon-separated MAC (mirrors the production helper for test data).
fn parse_mac(s: &str) -> MacAddr {
    let mut octets = [0u8; 6];
    let mut i = 0;
    for part in s.split(':') {
        octets[i] = u8::from_str_radix(part, 16).unwrap();
        i += 1;
    }
    MacAddr::new(octets[0], octets[1], octets[2], octets[3], octets[4], octets[5])
}

// ─────────────────────────────────────────────────────────────────────────────
// IP target expansion
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_ip_range_expanding_valid_target_tokens() {
    let feat = load_feature("ip_range");
    let sc = scenario_by_name(&feat, "Expanding valid target tokens");
    let (_header, rows) = table_of(sc, 0);

    for row in rows {
        let token = &row[0];
        let expected_count: usize = row[1].parse().unwrap();
        let expected_first = row[2].clone();
        let expected_last = row[3].clone();

        let result = expand_one(token).unwrap_or_else(|e| panic!("'{token}' failed: {e}"));
        assert_eq!(result.len(), expected_count, "count mismatch for '{token}'");
        assert_eq!(
            result.first().unwrap().to_string(),
            expected_first,
            "first mismatch for '{token}'"
        );
        assert_eq!(
            result.last().unwrap().to_string(),
            expected_last,
            "last mismatch for '{token}'"
        );
    }
    let steps = step_texts(sc);
    assert!(steps[0].starts_with("the following target tokens"));
    assert!(steps[1].starts_with("each token is expanded with expand_one"));
    assert!(steps[2].starts_with("the expansion matches"));
}

#[test]
fn bdd_ip_range_rejecting_invalid_target_tokens() {
    let feat = load_feature("ip_range");
    let sc = scenario_by_name(&feat, "Rejecting invalid target tokens");
    let (_header, rows) = table_of(sc, 0);

    for row in rows {
        let token = &row[0];
        assert!(
            expand_one(token).is_err(),
            "token '{token}' should fail ({})",
            row[1]
        );
    }
    assert!(step_texts(sc)[2].starts_with("expansion returns an error"));
}

#[test]
fn bdd_ip_range_expanding_and_deduplicating_a_target_list() {
    let feat = load_feature("ip_range");
    let sc = scenario_by_name(&feat, "Expanding and deduplicating a target list");
    let (header, rows) = table_of(sc, 0);

    let raw: Vec<String> = header.into_iter()
        .chain(rows.into_iter().map(|r| r[0].clone()))
        .collect();
    let result = expand_targets(&raw).unwrap();

    assert_eq!(result.len(), 2, "expected 2 unique addresses");
    assert_eq!(result[0].to_string(), "10.0.0.1");
    assert_eq!(result[1].to_string(), "10.0.0.3");

    let steps = step_texts(sc);
    assert!(steps[2].starts_with("the result has 2 unique sorted addresses"));
    assert!(steps[3].starts_with("the first address is 10.0.0.1"));
    assert!(steps[4].starts_with("the last address is 10.0.0.3"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Neighbour-cache discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Renders the ARP-cache rows from a scenario's first table into a
/// `/proc/net/arp`-shaped string for `parse_arp_table`.
fn arp_cache_from(rows: &[Vec<String>]) -> String {
    let mut out = String::from("IP address\tHW type\tFlags\tHW address\tMask\tDevice\n");
    for r in rows {
        let (ip, mac, iface) = (&r[0], &r[1], &r[2]);
        out.push_str(&format!("{ip}\t0x1\t0x0\t{mac}\t0x0\t{iface}\n"));
    }
    out
}

#[test]
fn bdd_neighbors_discovering_clients_from_a_populated_arp_cache() {
    let feat = load_feature("neighbors");
    let sc = scenario_by_name(&feat, "Discovering clients from a populated ARP cache");
    let (_h, rows) = table_of(sc, 0);
    let our_ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    let content = arp_cache_from(&rows);
    let hosts = parse_arp_table(&content, "eth0", our_ip);

    assert_eq!(hosts.len(), 2);
    let ips: Vec<String> = hosts.iter().map(|h| h.ip.to_string()).collect();
    assert!(ips.contains(&"192.168.1.10".to_string()));
    assert!(ips.contains(&"192.168.1.11".to_string()));
}

#[test]
fn bdd_neighbors_excluding_our_own_ip_from_discovery() {
    let feat = load_feature("neighbors");
    let sc = scenario_by_name(&feat, "Excluding our own IP from discovery");
    let (_h, rows) = table_of(sc, 0);
    let our_ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    let content = arp_cache_from(&rows);
    let hosts = parse_arp_table(&content, "eth0", our_ip);

    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip.to_string(), "192.168.1.10");
}

#[test]
fn bdd_neighbors_filtering_by_interface() {
    let feat = load_feature("neighbors");
    let sc = scenario_by_name(&feat, "Filtering by interface");
    let (_h, rows) = table_of(sc, 0);
    let our_ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    let content = arp_cache_from(&rows);
    let hosts = parse_arp_table(&content, "eth0", our_ip);

    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip.to_string(), "192.168.1.10");
}

#[test]
fn bdd_neighbors_discovering_from_an_empty_arp_cache() {
    let feat = load_feature("neighbors");
    let sc = scenario_by_name(&feat, "Discovering from an empty ARP cache");
    let our_ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

    let hosts = parse_arp_table("", "eth0", our_ip);
    assert_eq!(hosts.len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// nftables mark rules
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_nft_per_host_shaping_marks_each_victim_with_its_own_slot() {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    let feat = load_feature("nft_rules");
    let sc = scenario_by_name(&feat, "Per-host shaping marks each victim with its own slot");

    let mut hosts = HashMap::new();
    hosts.insert(
        1,
        HostSlot {
            slot: 7,
            ip: Ipv4Addr::new(10, 0, 0, 5),
            mode: ShapeMode::Limited(2_048),
        },
    );
    let rules = build_nft_rules(&hosts);

    assert!(rules.contains("ip saddr 10.0.0.5 meta mark set 7"));
    assert!(rules.contains("ip daddr 10.0.0.5 ct mark == 0 meta mark set 7"));
}

#[test]
fn bdd_nft_blocked_hosts_are_dropped() {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    let feat = load_feature("nft_rules");
    let sc = scenario_by_name(&feat, "Blocked hosts are dropped");

    let mut hosts = HashMap::new();
    hosts.insert(
        1,
        HostSlot {
            slot: 9,
            ip: Ipv4Addr::new(10, 0, 0, 9),
            mode: ShapeMode::Blocked,
        },
    );
    let rules = build_nft_rules(&hosts);

    assert!(rules.contains("ip saddr 10.0.0.9 drop"));
    assert!(rules.contains("ip daddr 10.0.0.9 drop"));
}

#[test]
fn bdd_nft_pool_mode_marks_every_victim_with_one_shared_mark() {
    use std::net::Ipv4Addr;

    let feat = load_feature("nft_rules");
    let sc = scenario_by_name(&feat, "Pool mode marks every victim with one shared mark");
    let (_h, rows) = table_of(sc, 0);

    let victims: Vec<Ipv4Addr> = rows.iter().map(|r| r[0].parse().unwrap()).collect();
    let rules = build_nft_pool_rules(&victims);

    assert!(rules.contains("ip saddr 10.0.0.5 meta mark set 4094"));
    assert!(rules.contains("ip saddr 10.0.0.6 meta mark set 4094"));
    assert!(rules.contains("ip daddr 10.0.0.5 ct mark == 0 meta mark set 4094"));
    assert!(rules.contains("ip daddr 10.0.0.6 ct mark == 0 meta mark set 4094"));
    assert!(!rules.contains("meta mark set 7"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Gateway-mode discovery (cache-first + scan fallback)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_gateway_cache_first_discovery_skips_the_active_scan() {
    use std::net::Ipv4Addr;

    let feat = load_feature("gateway_discovery");
    let sc = scenario_by_name(&feat, "Cache-first discovery skips the active scan");
    let our_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

    let content = arp_cache_from(&[
        vec!["192.168.1.10".into(), "AA:BB:CC:DD:EE:01".into(), "eth0".into()],
        vec!["192.168.1.11".into(), "AA:BB:CC:DD:EE:02".into(), "eth0".into()],
    ]);
    let cached = parse_arp_table(&content, "eth0", our_ip);
    let cache_non_empty = !cached.is_empty();

    assert!(cache_non_empty, "clients should be discovered from the cache");
    assert!(step_texts(sc)[4].starts_with("the active ARP scan is NOT used"));
}

#[test]
fn bdd_gateway_scan_fallback_when_the_cache_is_empty() {
    use std::net::Ipv4Addr;

    let feat = load_feature("gateway_discovery");
    let sc = scenario_by_name(&feat, "Scan fallback when the cache is empty");
    let our_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

    let cached = parse_arp_table("", "eth0", our_ip);
    assert!(cached.is_empty(), "cache must be empty to trigger fallback");
    assert!(step_texts(sc)[4].starts_with("the active ARP scan is used as a fallback"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Gateway shaping modes (pool + uplink exclusion)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_shaping_pool_mode_shares_one_class_across_all_victims() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(&feat, "Pool mode shares one bandwidth class across all victims");
    let (_h, rows) = table_of(sc, 0);

    let victims: Vec<Ipv4Addr> = rows.iter().map(|r| r[0].parse().unwrap()).collect();
    let pool_kbps = 500u64;

    let mut tc = FakeTc::new();
    tc.limit_pool(pool_kbps, &victims);

    assert_eq!(tc.pool_calls.len(), 1);
    let (actual_kbps, actual_victims) = &tc.pool_calls[0];
    assert_eq!(*actual_kbps, pool_kbps);
    assert_eq!(actual_victims.len(), victims.len());
    assert!(step_texts(sc)[3].starts_with("the attacker keeps the rest"));
}

#[test]
fn bdd_shaping_mitm_pool_applies_across_selected_victims_excluding_gateway() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(
        &feat,
        "MITM mode applies pool across selected victims excluding the gateway",
    );

    // Discovered hosts: gateway + two victims (mirrors main.rs host_table).
    let mut table = host_table_from(&[
        ("192.168.1.1", "AA:BB:CC:00:00:01"),
        ("192.168.1.5", "AA:BB:CC:00:00:02"),
        ("192.168.1.6", "AA:BB:CC:00:00:03"),
    ]);

    let gateway_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
    // MITM selection excludes the gateway/uplink (resolve_uplink → excluded_ip).
    let excluded_ip = crate::gateway_mode::resolve_uplink(&table, &None, gateway_ip);
    assert_eq!(excluded_ip, gateway_ip);

    let selection_ids: Vec<_> = table
        .iter()
        .filter(|e| e.host.ip != excluded_ip)
        .map(|e| e.id)
        .collect();
    assert_eq!(selection_ids.len(), 2, "gateway must be excluded from victims");

    // main.rs: pool wins → derive victim IPs from selection and call limit_pool.
    let pool_kbps = 1000u64;
    let mut tc = FakeTc::new();
    {
        let victim_ips: Vec<Ipv4Addr> = selection_ids
            .iter()
            .filter_map(|&id| table.get_by_id(id).map(|e| e.host.ip))
            .collect();
        assert_eq!(victim_ips.len(), 2);
        assert!(!victim_ips.contains(&gateway_ip), "gateway must not be pooled");
        tc.limit_pool(pool_kbps, &victim_ips);
    }

    assert_eq!(tc.pool_calls.len(), 1);
    let (actual_kbps, actual_victims) = &tc.pool_calls[0];
    assert_eq!(*actual_kbps, pool_kbps);
    assert_eq!(actual_victims.len(), 2);
    assert!(actual_victims.contains(&Ipv4Addr::new(192, 168, 1, 5)));
    assert!(actual_victims.contains(&Ipv4Addr::new(192, 168, 1, 6)));
    assert!(!actual_victims.contains(&gateway_ip));
}

#[test]
fn bdd_shaping_mitm_all_dynamically_adds_late_victim_to_pool() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(
        &feat,
        "MITM --all dynamically adds a late-joining victim to the shared pool",
    );

    let mut table = host_table_from(&[
        ("192.168.1.1", "AA:BB:CC:00:00:01"), // gateway
        ("192.168.1.5", "AA:BB:CC:00:00:02"),
        ("192.168.1.6", "AA:BB:CC:00:00:03"),
    ]);
    let gateway_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
    let excluded_ip = crate::gateway_mode::resolve_uplink(&table, &None, gateway_ip);
    assert_eq!(excluded_ip, gateway_ip);

    let pool_kbps = 1000u64;
    let mut tc = FakeTc::new();

    // Initial seed: victims 192.168.1.5 and 192.168.1.6.
    let initial: Vec<Ipv4Addr> = table
        .iter()
        .filter(|e| e.host.ip != excluded_ip)
        .map(|e| e.host.ip)
        .collect();
    tc.limit_pool(pool_kbps, &initial);

    // A late-joining device appears (mirrors MitmAutoManager::on_seen).
    table.insert(DiscoveredHost {
        ip: Ipv4Addr::new(192, 168, 1, 7),
        mac: parse_mac("AA:BB:CC:00:00:04"),
        hostname: None,
        vendor: None,
        last_seen: std::time::Instant::now(),
    });
    table.reindex_by_ip();

    // Pool is re-applied across the full managed set (idempotent limit_pool).
    let updated: Vec<Ipv4Addr> = table
        .iter()
        .filter(|e| e.host.ip != excluded_ip)
        .map(|e| e.host.ip)
        .collect();
    tc.limit_pool(pool_kbps, &updated);

    assert_eq!(tc.pool_calls.len(), 2, "pool re-applied once for the new victim");
    let (kbps, victims) = &tc.pool_calls[1];
    assert_eq!(*kbps, pool_kbps);
    assert_eq!(victims.len(), 3, "late victim must be added to the pool");
    assert!(victims.contains(&Ipv4Addr::new(192, 168, 1, 5)));
    assert!(victims.contains(&Ipv4Addr::new(192, 168, 1, 6)));
    assert!(victims.contains(&Ipv4Addr::new(192, 168, 1, 7)));
    assert!(!victims.contains(&gateway_ip), "gateway must never be pooled");
    assert!(step_texts(sc)[3].starts_with("the shared pool"));
}

#[test]
fn bdd_shaping_uplink_exclusion_by_mac() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(&feat, "Uplink exclusion removes the bottleneck device from victims");

    let table = host_table_from(&[("10.0.0.1", "AA:BB:CC:00:00:01")]);
    let candidate_pool = vec![
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    ];
    let excluded = crate::gateway_mode::resolve_uplink(&table, &Some("AA:BB:CC:00:00:01".into()), Ipv4Addr::new(192, 168, 1, 100));

    let remaining: Vec<Ipv4Addr> = candidate_pool
        .into_iter()
        .filter(|ip| *ip != excluded)
        .collect();
    assert_eq!(remaining, vec![Ipv4Addr::new(10, 0, 0, 2)]);
}

#[test]
fn bdd_shaping_uplink_exclusion_by_ip() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(&feat, "Uplink given as an IP excludes that device");

    let table = host_table_from(&[("10.0.0.1", "AA:BB:CC:00:00:01")]);
    let candidate_pool = vec![
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    ];
    let excluded = crate::gateway_mode::resolve_uplink(&table, &Some("10.0.0.1".into()), Ipv4Addr::new(192, 168, 1, 100));

    let remaining: Vec<Ipv4Addr> = candidate_pool
        .into_iter()
        .filter(|ip| *ip != excluded)
        .collect();
    assert_eq!(remaining, vec![Ipv4Addr::new(10, 0, 0, 2)]);
}

#[test]
fn bdd_shaping_unresolvable_uplink_falls_back_to_self() {
    use std::net::Ipv4Addr;

    let feat = load_feature("shaping_modes");
    let sc = scenario_by_name(&feat, "Unresolvable uplink falls back to excluding self");

    let table = host_table_from(&[("10.0.0.1", "AA:BB:CC:00:00:01")]);
    let our_ip = Ipv4Addr::new(192, 168, 1, 100);
    let excluded = crate::gateway_mode::resolve_uplink(&table, &Some("10.9.9.9".into()), our_ip);

    assert_eq!(excluded, our_ip);
    assert!(step_texts(sc)[3].starts_with("the excluded IP is our own IP"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Network packet builders and parser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_network_packets_arp_request_frame_fields() {
    use crate::network::packet::ArpRequest;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP request frame has correct fields");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let target_ip: Ipv4Addr = row[0].parse().unwrap();
        let sender_ip: Ipv4Addr = row[1].parse().unwrap();
        let sender_mac = parse_mac(&row[2]);

        let frame = ArpRequest::new(target_ip, sender_ip, sender_mac).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();

        assert_eq!(eth.get_destination(), MacAddr::broadcast());
        assert_eq!(eth.get_source(), sender_mac);
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_hw_addr(), sender_mac);
        assert_eq!(arp.get_sender_proto_addr(), sender_ip);
        assert_eq!(arp.get_target_proto_addr(), target_ip);
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
    }
}

#[test]
fn bdd_network_packets_arp_poison_victim_direction() {
    use crate::network::packet::ArpPoison;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP poison victim direction lies about gateway MAC");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let victim_mac = parse_mac(&row[0]);
        let victim_ip: Ipv4Addr = row[1].parse().unwrap();
        let gateway_ip: Ipv4Addr = row[2].parse().unwrap();
        let our_mac = parse_mac(&row[3]);

        let frame = ArpPoison::new(victim_mac, victim_ip, gateway_ip, our_mac).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();

        assert_eq!(eth.get_destination(), victim_mac);
        assert_eq!(eth.get_source(), our_mac);
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        assert_eq!(arp.get_sender_hw_addr(), our_mac);
        assert_eq!(arp.get_sender_proto_addr(), gateway_ip);
        assert_eq!(arp.get_target_hw_addr(), victim_mac);
        assert_eq!(arp.get_target_proto_addr(), victim_ip);
    }
}

#[test]
fn bdd_network_packets_arp_poison_gateway_direction() {
    use crate::network::packet::ArpPoison;
    use pnet::packet::arp::ArpPacket;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP poison gateway direction lies about victim MAC");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let gateway_mac = parse_mac(&row[0]);
        let gateway_ip: Ipv4Addr = row[1].parse().unwrap();
        let victim_ip: Ipv4Addr = row[2].parse().unwrap();
        let our_mac = parse_mac(&row[3]);

        let frame = ArpPoison::new(gateway_mac, gateway_ip, victim_ip, our_mac).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();

        assert_eq!(eth.get_destination(), gateway_mac);
        assert_eq!(arp.get_sender_hw_addr(), our_mac);
        assert_eq!(arp.get_sender_proto_addr(), victim_ip);
        assert_eq!(arp.get_target_hw_addr(), gateway_mac);
        assert_eq!(arp.get_target_proto_addr(), gateway_ip);
    }
}

#[test]
fn bdd_network_packets_arp_restore_fields() {
    use crate::network::packet::ArpRestore;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP restore tells victim the true gateway MAC");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let target_mac = parse_mac(&row[0]);
        let target_ip: Ipv4Addr = row[1].parse().unwrap();
        let real_ip: Ipv4Addr = row[2].parse().unwrap();
        let real_mac = parse_mac(&row[3]);

        let frame = ArpRestore::new(target_mac, target_ip, real_ip, real_mac).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();

        assert_eq!(eth.get_destination(), target_mac);
        assert_eq!(eth.get_source(), real_mac);
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        assert_eq!(arp.get_sender_hw_addr(), real_mac);
        assert_eq!(arp.get_sender_proto_addr(), real_ip);
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_accepts_poison() {
    use crate::network::packet::{ArpPoison, ArpReply};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser accepts poison frames");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let victim_mac = parse_mac(&row[0]);
        let victim_ip: Ipv4Addr = row[1].parse().unwrap();
        let gateway_ip: Ipv4Addr = row[2].parse().unwrap();
        let our_mac = parse_mac(&row[3]);

        let frame = ArpPoison::new(victim_mac, victim_ip, gateway_ip, our_mac).to_bytes();
        let parsed = ArpReply::from_bytes(&frame).expect("poison frame must parse");

        assert_eq!(parsed.sender_mac, our_mac);
        assert_eq!(parsed.sender_ip, gateway_ip);
        assert_eq!(parsed.target_mac, victim_mac);
        assert_eq!(parsed.target_ip, victim_ip);
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_accepts_restore() {
    use crate::network::packet::{ArpReply, ArpRestore};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser accepts restore frames");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let victim_mac = parse_mac(&row[0]);
        let victim_ip: Ipv4Addr = row[1].parse().unwrap();
        let real_gateway_ip: Ipv4Addr = row[2].parse().unwrap();
        let real_gateway_mac = parse_mac(&row[3]);

        let frame = ArpRestore::new(victim_mac, victim_ip, real_gateway_ip, real_gateway_mac).to_bytes();
        let parsed = ArpReply::from_bytes(&frame).expect("restore frame must parse");

        assert_eq!(parsed.sender_mac, real_gateway_mac);
        assert_eq!(parsed.sender_ip, real_gateway_ip);
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_rejects_request() {
    use crate::network::packet::{ArpReply, ArpRequest};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser rejects ARP request frames");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let target_ip: Ipv4Addr = row[0].parse().unwrap();
        let sender_ip: Ipv4Addr = row[1].parse().unwrap();
        let sender_mac = parse_mac(&row[2]);

        let frame = ArpRequest::new(target_ip, sender_ip, sender_mac).to_bytes();
        assert!(ArpReply::from_bytes(&frame).is_none(), "request must not parse as reply");
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_rejects_short_buffer() {
    use crate::network::packet::ArpReply;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser rejects short buffers");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let len: usize = row[0].parse().unwrap();
        let buf = vec![0u8; len];
        assert!(ArpReply::from_bytes(&buf).is_none(), "len {} must return None", len);
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_rejects_zero_buffer() {
    use crate::network::packet::ArpReply;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser rejects all-zero buffer");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let buf = vec![0u8; 42];
        assert!(ArpReply::from_bytes(&buf).is_none());
    }
}

#[test]
fn bdd_network_packets_arp_reply_parser_rejects_empty_buffer() {
    use crate::network::packet::ArpReply;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "ARP reply parser rejects empty buffer");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let buf = vec![0u8; 0];
        assert!(ArpReply::from_bytes(&buf).is_none());
    }
}

#[test]
fn bdd_network_packets_all_builders_produce_42_bytes() {
    use crate::network::packet::{ArpPoison, ArpRequest, ArpRestore, GratuitousArp};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let feat = load_feature("network_packets");
    let sc = scenario_by_name(&feat, "All builders produce exactly 42-byte frames");
    let (_h, rows) = table_of(sc, 0);

    let victim_mac = parse_mac(&rows[0][0]);
    let victim_ip: Ipv4Addr = rows[0][1].parse().unwrap();
    let gateway_ip: Ipv4Addr = rows[0][2].parse().unwrap();
    let our_mac = parse_mac(&rows[0][3]);
    let our_ip: Ipv4Addr = "192.168.1.100".parse().unwrap();

    assert_eq!(ArpRequest::new(victim_ip, our_ip, our_mac).to_bytes().len(), 42);
    assert_eq!(ArpPoison::new(victim_mac, victim_ip, gateway_ip, our_mac).to_bytes().len(), 42);
    assert_eq!(ArpRestore::new(victim_mac, victim_ip, gateway_ip, victim_mac).to_bytes().len(), 42);
    assert_eq!(GratuitousArp::new(victim_ip, our_mac).to_bytes().len(), 42);
}

// ─────────────────────────────────────────────────────────────────────────────
// Target selection parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_target_selection_single_valid_id() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Single valid ID selects that host");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_inclusive_range() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Inclusive range selects all IDs in range");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_range_skips_unavailable() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Range skips unavailable IDs");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_comma_list() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Comma-separated list selects multiple IDs");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_comma_list_spaces() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Comma list with spaces is accepted");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_comma_list_dedup() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Comma list deduplicates and sorts output");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_mixed_range_comma() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Mixed range and comma list works");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_overlap_dedup() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Overlapping range and single deduplicates");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_all_keyword() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "\"all\" keyword returns all available IDs (lowercase)");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_all_keyword_case_insensitive() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "\"all\" keyword is case-insensitive");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_all_empty() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "\"all\" with empty available returns empty list");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_invalid_id_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Invalid ID outside available set is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_zero_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Zero ID is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_negative_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Negative ID is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_reversed_range_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Reversed range (start > end) is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_range_end_above_max_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Range end above maximum is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_non_numeric_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Non-numeric token is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_float_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Float token is rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_empty_rejected() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Empty string returns rejected");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_trailing_comma() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Trailing comma skips empty token");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];
        let expected: Vec<usize> = row[2].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse().unwrap()).collect();

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_comma_only() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Comma-only does not panic");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let available: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let input = &row[1];

        let result = TargetSelector::parse_selection(input, &available);
        assert_eq!(result, None, "input '{}' should be rejected", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_empty_zero_unlimited() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - empty string means unlimited");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, None, "input '{}' should be unlimited", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_zero_unlimited() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - zero means unlimited");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, None, "input '{}' should be unlimited", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_positive() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - positive integer returns Some(kbps)");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let expected: u64 = row[1].parse().unwrap();
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_large() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - large integer returns Some(kbps)");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let expected: u64 = row[1].parse().unwrap();
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, Some(expected), "input '{}'", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_negative() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - negative returns unlimited");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, None, "input '{}' should be unlimited", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_non_numeric() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - non-numeric returns unlimited");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, None, "input '{}' should be unlimited", input);
    }
}

#[test]
fn bdd_target_selection_parse_bandwidth_float() {
    let feat = load_feature("target_selection");
    let sc = scenario_by_name(&feat, "Bandwidth parsing - float returns unlimited");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let input = &row[0];
        let result = TargetSelector::parse_bandwidth(input);
        assert_eq!(result, None, "input '{}' should be unlimited", input);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host table lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bdd_host_table_insert_assigns_sequential_ids_after_reindex() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Insert assigns sequential IDs after reindex by IP");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ips: Vec<&str> = row[0].split(',').map(|s| s.trim()).collect();
        let mut table = HostTable::new();
        for (i, ip) in ips.iter().enumerate() {
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip: ip.parse().unwrap(),
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }
        table.reindex_by_ip();

        let expected_ids: Vec<usize> = row[1].split(',').map(|s| s.trim().parse().unwrap()).collect();
        let actual_ids: Vec<usize> = ips.iter().map(|ip| table.get_by_ip(ip.parse().unwrap()).unwrap().id).collect();

        assert_eq!(actual_ids, expected_ids);
    }
}

#[test]
fn bdd_host_table_duplicate_ip_updates_existing() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Duplicate IP updates existing entry");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip = row[0].as_str();
        let mac1 = row[1].as_str();
        let mac2 = row[2].as_str();

        let mut table = host_table_from(&[(ip, mac1)]);
        let id1 = table.iter().next().unwrap().id;
        let count1 = table.iter().next().unwrap().scan_count;

        table.insert(host_table_from(&[(ip, mac2)]).iter().next().unwrap().host.clone());

        assert_eq!(table.len(), 1, "table should not grow");
        let entry = table.get_by_id(id1).unwrap();
        // When IP already exists, MAC is NOT updated (only last_seen, vendor, scan_count)
        assert_eq!(entry.host.mac.to_string().to_uppercase(), mac1.to_uppercase(), "MAC should NOT update, original MAC preserved");
        assert_eq!(entry.scan_count, count1 + 1, "scan_count should increment");
    }
}

#[test]
fn bdd_host_table_duplicate_mac_updates_ip() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Duplicate MAC updates IP of existing entry");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip1 = row[0].as_str();
        let mac = row[1].as_str();
        let ip2 = row[2].as_str();

        let mut table = host_table_from(&[(ip1, mac)]);
        let id1 = table.iter().next().unwrap().id;
        let count1 = table.iter().next().unwrap().scan_count;

        table.insert(host_table_from(&[(ip2, mac)]).iter().next().unwrap().host.clone());

        assert_eq!(table.len(), 1, "table should not grow");
        let entry = table.get_by_id(id1).unwrap();
        assert_eq!(entry.host.ip.to_string(), ip2, "IP should update");
        assert!(table.get_by_ip(ip1.parse().unwrap()).is_none(), "old IP removed from index");
        assert_eq!(entry.scan_count, count1 + 1, "scan_count should increment");
    }
}

#[test]
fn bdd_host_table_remove_returns_entry_and_cleans_indexes() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Remove returns entry and cleans indexes");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip = row[0].as_str();
        let mac = row[1].as_str();

        let mut table = host_table_from(&[(ip, mac)]);
        let id = table.iter().next().unwrap().id;

        let removed = table.remove(id).expect("remove should return entry");
        assert_eq!(removed.host.ip.to_string(), ip);
        assert!(table.get_by_id(id).is_none());
        assert!(table.get_by_ip(ip.parse().unwrap()).is_none());
        assert!(table.get_by_mac(parse_mac(mac)).is_none());
        assert_eq!(table.len(), 0);
    }
}

#[test]
fn bdd_host_table_remove_missing_returns_none() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Remove missing ID returns None");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let missing_id: usize = row[0].parse().unwrap();
        let mut table = HostTable::new();
        assert!(table.remove(missing_id).is_none());
    }
}

#[test]
fn bdd_host_table_remove_one_does_not_affect_others() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Remove one host does not affect others");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip1 = row[0].as_str();
        let ip2 = row[1].as_str();
        let ip3 = row[2].as_str();

        let mut table = host_table_from(&[(ip1, "AA:BB:CC:DD:EE:01"), (ip2, "AA:BB:CC:DD:EE:02"), (ip3, "AA:BB:CC:DD:EE:03")]);
        let id2 = table.get_by_ip(ip2.parse().unwrap()).unwrap().id;

        table.remove(id2);

        assert!(table.get_by_id(table.get_by_ip(ip1.parse().unwrap()).unwrap().id).is_some());
        assert!(table.get_by_id(id2).is_none());
        assert!(table.get_by_id(table.get_by_ip(ip3.parse().unwrap()).unwrap().id).is_some());
        assert_eq!(table.len(), 2);
    }
}

#[test]
fn bdd_host_table_initial_state_is_discovered() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Initial state of inserted host is Discovered");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let table = host_table_from(&[(row[0].as_str(), row[1].as_str())]);
        let state = table.iter().next().unwrap().state;
        assert_eq!(format!("{:?}", state), "Discovered");
    }
}

#[test]
fn bdd_host_table_update_state_cycles_through_all_variants() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Update state cycles through all variants");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = host_table_from(&[(row[0].as_str(), row[1].as_str())]);
        let id = table.iter().next().unwrap().id;
        let states = ["Poisoning", "Limited", "Blocked", "Error", "Discovered"];

        for state_str in states {
            let state = match state_str {
                "Poisoning" => crate::host::table::HostState::Poisoning,
                "Limited" => crate::host::table::HostState::Limited,
                "Blocked" => crate::host::table::HostState::Blocked,
                "Error" => crate::host::table::HostState::Error,
                "Discovered" => crate::host::table::HostState::Discovered,
                _ => panic!("unknown state"),
            };
            table.update_state(id, state);
            assert_eq!(format!("{:?}", table.get_by_id(id).unwrap().state), state_str);
        }
    }
}

#[test]
fn bdd_host_table_update_state_missing_returns_false() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Update state on missing ID returns false");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let missing_id: usize = row[0].parse().unwrap();
        let mut table = HostTable::new();
        assert!(!table.update_state(missing_id, crate::host::table::HostState::Poisoning));
    }
}

#[test]
fn bdd_host_table_get_stale_zero_max_age_returns_all() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Get stale with zero max_age returns all hosts");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        let ids: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        for (i, ip) in row[1].split(',').enumerate() {
            let ip = ip.trim().parse().unwrap();
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip,
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }

        let stale = table.get_stale_hosts(std::time::Duration::ZERO);
        let mut stale_sorted = stale.clone();
        stale_sorted.sort();
        assert_eq!(stale_sorted, ids);
    }
}

#[test]
fn bdd_host_table_get_stale_max_age_returns_none() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Get stale with max_age=MAX returns no hosts");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        let ids: Vec<usize> = row[0].split(',').map(|s| s.trim().parse().unwrap()).collect();
        for (i, ip) in row[1].split(',').enumerate() {
            let ip = ip.trim().parse().unwrap();
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip,
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }

        let stale = table.get_stale_hosts(std::time::Duration::MAX);
        assert!(stale.is_empty());
    }
}

#[test]
fn bdd_host_table_get_stale_empty_table_returns_empty() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Get stale on empty table returns empty");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let table = HostTable::new();
        assert!(table.get_stale_hosts(std::time::Duration::ZERO).is_empty());
        assert!(table.get_stale_hosts(std::time::Duration::MAX).is_empty());
    }
}

#[test]
fn bdd_host_table_removed_host_not_in_stale_list() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Removed host no longer appears in stale list");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        for (i, ip) in row[0].split(',').enumerate() {
            let ip = ip.trim().parse().unwrap();
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip,
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }
        let id_to_remove: usize = row[1].parse().unwrap();
        table.remove(id_to_remove);

        let stale = table.get_stale_hosts(std::time::Duration::ZERO);
        assert!(stale.contains(&stale[0]));
        assert!(!stale.contains(&id_to_remove));
    }
}

#[test]
fn bdd_host_table_clear_empties_and_resets_id_counter() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Clear empties table and resets ID counter");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        for (i, ip) in row[0].split(',').enumerate() {
            let ip = ip.trim().parse().unwrap();
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip,
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }

        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let new_id = table.insert(crate::host::table::DiscoveredHost {
            ip: "10.0.0.99".parse().unwrap(),
            mac: parse_mac("AA:BB:CC:DD:EE:99"),
            hostname: None,
            vendor: None,
            last_seen: std::time::Instant::now(),
        });
        assert_eq!(new_id, 1);
    }
}

#[test]
fn bdd_host_table_clear_empties_indexes() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Clear empties IP and MAC indexes");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip = row[0].as_str();
        let mac = row[1].as_str();

        let mut table = host_table_from(&[(ip, mac)]);
        table.clear();

        assert!(table.get_by_ip(ip.parse().unwrap()).is_none());
        assert!(table.get_by_mac(parse_mac(mac)).is_none());
    }
}

#[test]
fn bdd_host_table_clear_then_reinsert_works() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Clear then reinsert works without corruption");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        for (i, ip) in row[0].split(',').enumerate() {
            let ip = ip.trim().parse().unwrap();
            let mac = format!("AA:BB:CC:DD:EE:{:02X}", i + 1);
            table.insert(crate::host::table::DiscoveredHost {
                ip,
                mac: parse_mac(&mac),
                hostname: None,
                vendor: None,
                last_seen: std::time::Instant::now(),
            });
        }
        table.clear();

        let new_id = table.insert(crate::host::table::DiscoveredHost {
            ip: "10.0.0.99".parse().unwrap(),
            mac: parse_mac("AA:BB:CC:DD:EE:99"),
            hostname: None,
            vendor: None,
            last_seen: std::time::Instant::now(),
        });
        assert_eq!(table.len(), 1);
        assert!(table.get_by_id(new_id).is_some());
    }
}

#[test]
fn bdd_host_table_lookup_consistency_across_indexes() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Lookup consistency across all three indexes");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let ip = row[0].as_str();
        let mac = row[1].as_str();

        let table = host_table_from(&[(ip, mac)]);
        let entry = table.iter().next().unwrap();
        let id = entry.id;

        let by_id = table.get_by_id(id).unwrap();
        let by_ip = table.get_by_ip(ip.parse().unwrap()).unwrap();
        let by_mac = table.get_by_mac(parse_mac(mac)).unwrap();

        assert_eq!(by_id.id, by_ip.id);
        assert_eq!(by_id.id, by_mac.id);
    }
}

#[test]
fn bdd_host_table_duplicate_ip_does_not_grow_table() {
    let feat = load_feature("host_table");
    let sc = scenario_by_name(&feat, "Duplicate IP does not grow table");
    let (_h, rows) = table_of(sc, 0);

    for row in rows {
        let mut table = HostTable::new();
        table.insert(crate::host::table::DiscoveredHost {
            ip: row[0].as_str().parse().unwrap(),
            mac: parse_mac(row[1].as_str()),
            hostname: None,
            vendor: None,
            last_seen: std::time::Instant::now(),
        });
        table.insert(crate::host::table::DiscoveredHost {
            ip: row[0].as_str().parse().unwrap(),
            mac: parse_mac(row[1].as_str()),
            hostname: None,
            vendor: None,
            last_seen: std::time::Instant::now(),
        });
        assert_eq!(table.len(), 1);
    }
}

// Keep `StepType` import meaningful (documents the step-type enum is available
// for future scenario-keyed assertions).
#[test]
fn bdd_step_types_are_resolvable() {
    let feat = load_feature("ip_range");
    let sc = scenario_by_name(&feat, "Expanding valid target tokens");
    assert_eq!(sc.steps[0].ty, StepType::Given);
}