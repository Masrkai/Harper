// src/host/table.rs
// use crate::network::scanner::DiscoveredHost;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub type HostId = usize;

pub struct HostTable {
    hosts: HashMap<HostId, HostEntry>,
    ip_to_id: HashMap<Ipv4Addr, HostId>,
    mac_to_id: HashMap<MacAddr, HostId>,
    next_id: HostId,
}

pub struct HostEntry {
    pub id: HostId,
    pub host: DiscoveredHost,
    pub state: HostState,
    pub added_at: Instant,
    pub scan_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Discovered,
    Poisoning,
    Limited,
    Blocked,
    Error,
}

impl HostTable {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            ip_to_id: HashMap::new(),
            mac_to_id: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn insert(&mut self, host: DiscoveredHost) -> HostId {
        if let Some(&existing_id) = self.ip_to_id.get(&host.ip) {
            if let Some(entry) = self.hosts.get_mut(&existing_id) {
                entry.host.last_seen = host.last_seen;
                if host.vendor.is_some() {
                    entry.host.vendor = host.vendor;
                }
                entry.scan_count += 1;
            }
            return existing_id;
        }

        if let Some(&existing_id) = self.mac_to_id.get(&host.mac) {
            if let Some(entry) = self.hosts.get_mut(&existing_id) {
                self.ip_to_id.remove(&entry.host.ip);
                self.ip_to_id.insert(host.ip, existing_id);
                entry.host.ip = host.ip;
                entry.host.last_seen = host.last_seen;
                if host.vendor.is_some() {
                    entry.host.vendor = host.vendor;
                }
                entry.scan_count += 1;
            }
            return existing_id;
        }

        let id = self.next_id;
        self.next_id += 1;

        let entry = HostEntry {
            id,
            host,
            state: HostState::Discovered,
            added_at: Instant::now(),
            scan_count: 1,
        };

        self.ip_to_id.insert(entry.host.ip, id);
        self.mac_to_id.insert(entry.host.mac, id);
        self.hosts.insert(id, entry);

        id
    }

    /// Reassigns all IDs in ascending IP order.
    ///
    /// Call this once after a bulk insert (e.g. after a full scan) so that
    /// ID 1 always means "lowest IP on the network", ID 2 the next, and so on.
    /// Any code that stored an old HostId (e.g. the spoofer) must refresh its
    /// references afterwards — this is intentionally a post-scan, pre-display
    /// operation.
    pub fn reindex_by_ip(&mut self) {
        // Pull every entry out, sorted by IP
        let mut entries: Vec<HostEntry> = self.hosts.drain().map(|(_, e)| e).collect();
        entries.sort_by_key(|e| e.host.ip.octets());

        // Rebuild all three maps from scratch with sequential IDs
        self.ip_to_id.clear();
        self.mac_to_id.clear();
        self.next_id = 1;

        for entry in entries {
            let new_id = self.next_id;
            self.next_id += 1;

            let reindexed = HostEntry {
                id: new_id,
                ..entry
            };

            self.ip_to_id.insert(reindexed.host.ip, new_id);
            self.mac_to_id.insert(reindexed.host.mac, new_id);
            self.hosts.insert(new_id, reindexed);
        }
    }

    pub fn get_by_id(&self, id: HostId) -> Option<&HostEntry> {
        self.hosts.get(&id)
    }

    pub fn get_by_id_mut(&mut self, id: HostId) -> Option<&mut HostEntry> {
        self.hosts.get_mut(&id)
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&HostEntry> {
        self.ip_to_id.get(&ip).and_then(|id| self.hosts.get(id))
    }

    pub fn get_by_mac(&self, mac: MacAddr) -> Option<&HostEntry> {
        self.mac_to_id.get(&mac).and_then(|id| self.hosts.get(id))
    }

    pub fn update_state(&mut self, id: HostId, state: HostState) -> bool {
        if let Some(entry) = self.hosts.get_mut(&id) {
            entry.state = state;
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, id: HostId) -> Option<HostEntry> {
        let entry = self.hosts.remove(&id)?;
        self.ip_to_id.remove(&entry.host.ip);
        self.mac_to_id.remove(&entry.host.mac);
        Some(entry)
    }

    pub fn clear(&mut self) {
        self.hosts.clear();
        self.ip_to_id.clear();
        self.mac_to_id.clear();
        self.next_id = 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = &HostEntry> {
        self.hosts.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut HostEntry> {
        self.hosts.values_mut()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn display(&self) {
        println!(
            "\n{:<5} {:<16} {:<18} {:<12} {:<6} {:<24} {}",
            "ID", "IP Address", "MAC Address", "Status", "Seen", "Vendor", "Hostname"
        );
        println!("{}", "-".repeat(100));

        // IDs are already in IP order after reindex_by_ip(), so sort by ID
        // rather than re-sorting by IP — they are equivalent and cheaper.
        let mut entries: Vec<&HostEntry> = self.hosts.values().collect();
        entries.sort_by_key(|e| e.id);

        for entry in &entries {
            let age = format_duration(entry.host.last_seen.elapsed());
            let vendor = entry.host.vendor.as_deref().unwrap_or("Unknown");
            let hostname = entry.host.hostname.as_deref().unwrap_or("Unknown");

            println!(
                "{:<5} {:<16} {:<18} {:<12} {:<6} {:<24} {}",
                entry.id,
                entry.host.ip,
                entry.host.mac,
                format!("{:?}", entry.state),
                age,
                if vendor.len() > 22 {
                    format!("{:.21}…", vendor)
                } else {
                    vendor.to_string()
                },
                hostname,
            );
        }

        println!("{}\n", "-".repeat(100));
        println!("Total hosts: {}", self.len());
    }

    pub fn get_stale_hosts(&self, max_age: Duration) -> Vec<HostId> {
        self.hosts
            .values()
            .filter(|e| e.host.last_seen.elapsed() > max_age)
            .map(|e| e.id)
            .collect()
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

impl Default for HostTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovered host
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub last_seen: std::time::Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Builds a minimal DiscoveredHost with just enough fields set.
    fn make_host(last_octet: u8) -> DiscoveredHost {
        DiscoveredHost {
            ip: Ipv4Addr::new(10, 0, 0, last_octet),
            mac: MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_octet),
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        }
    }

    /// Builds a DiscoveredHost whose `last_seen` is artificially old.
    /// We cannot rewind `Instant`, but we *can* set it to `Instant::now()`
    /// and then call `get_stale_hosts` with a very short `max_age` — see the
    /// stale-host tests for the idiom.
    fn make_host_aged(last_octet: u8) -> DiscoveredHost {
        DiscoveredHost {
            ip: Ipv4Addr::new(10, 0, 0, last_octet),
            mac: MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_octet),
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        }
    }

    // ── Already-existing tests (kept for context) ─────────────────────────────
    // test_host_table_insertion
    // test_reindex_by_ip

    // ─────────────────────────────────────────────────────────────────────────
    // remove()
    // ─────────────────────────────────────────────────────────────────────────

    /// Removing a host that exists returns the entry and shrinks the table.
    #[test]
    fn test_remove_existing_host() {
        let mut table = HostTable::new();
        let id = table.insert(make_host(10));

        let removed = table.remove(id);

        assert!(removed.is_some(), "remove() should return the entry");
        assert_eq!(table.len(), 0, "table should be empty after remove");
    }

    /// After removal the IP and MAC indexes no longer resolve.
    #[test]
    fn test_remove_cleans_up_ip_and_mac_indexes() {
        let mut table = HostTable::new();
        let host = make_host(20);
        let ip = host.ip;
        let mac = host.mac;
        let id = table.insert(host);

        table.remove(id);

        assert!(
            table.get_by_ip(ip).is_none(),
            "IP index should be cleared after remove"
        );
        assert!(
            table.get_by_mac(mac).is_none(),
            "MAC index should be cleared after remove"
        );
    }

    /// Removing a host that doesn't exist returns None without panicking.
    #[test]
    fn test_remove_nonexistent_host_returns_none() {
        let mut table = HostTable::new();
        let result = table.remove(9999);
        assert!(result.is_none());
    }

    /// Removing one host doesn't disturb the others.
    #[test]
    fn test_remove_does_not_affect_other_hosts() {
        let mut table = HostTable::new();
        let id_a = table.insert(make_host(1));
        let id_b = table.insert(make_host(2));
        let id_c = table.insert(make_host(3));

        table.remove(id_b);

        assert!(table.get_by_id(id_a).is_some(), "host A should still exist");
        assert!(table.get_by_id(id_b).is_none(), "host B should be gone");
        assert!(table.get_by_id(id_c).is_some(), "host C should still exist");
        assert_eq!(table.len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // update_state()
    // ─────────────────────────────────────────────────────────────────────────

    /// A freshly inserted host starts in the Discovered state.
    #[test]
    fn test_initial_state_is_discovered() {
        let mut table = HostTable::new();
        let id = table.insert(make_host(30));
        let state = table.get_by_id(id).unwrap().state;
        assert_eq!(state, HostState::Discovered);
    }

    /// update_state returns true and the new state is readable back.
    #[test]
    fn test_update_state_returns_true_on_success() {
        let mut table = HostTable::new();
        let id = table.insert(make_host(40));

        let ok = table.update_state(id, HostState::Poisoning);

        assert!(ok, "update_state should return true for a known host");
        assert_eq!(table.get_by_id(id).unwrap().state, HostState::Poisoning);
    }

    /// Cycling through every variant confirms each one is stored correctly.
    #[test]
    fn test_update_state_all_variants() {
        let mut table = HostTable::new();
        let id = table.insert(make_host(50));

        for state in [
            HostState::Poisoning,
            HostState::Limited,
            HostState::Blocked,
            HostState::Error,
            HostState::Discovered, // back to start — allowed
        ] {
            table.update_state(id, state);
            assert_eq!(table.get_by_id(id).unwrap().state, state);
        }
    }

    /// update_state on a missing ID returns false without panicking.
    #[test]
    fn test_update_state_missing_id_returns_false() {
        let mut table = HostTable::new();
        let ok = table.update_state(9999, HostState::Poisoning);
        assert!(!ok, "update_state on unknown ID should return false");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // get_stale_hosts()
    //
    // Strategy: we cannot rewind Instant, so we test with two max_age values:
    //   • Duration::ZERO  → every host is stale (elapsed() is always > 0)
    //   • Duration::MAX   → no host is ever stale
    //
    // This gives us deterministic, non-sleeping tests for the clock-dependent
    // path.  The idiomatic long-term fix is to inject `now` as a parameter
    // (see the note in the TDD guide), but we can test the *logic* soundly
    // with these boundary conditions today.
    // ─────────────────────────────────────────────────────────────────────────

    /// With max_age = ZERO every host in the table is reported as stale.
    #[test]
    fn test_get_stale_hosts_zero_max_age_returns_all() {
        let mut table = HostTable::new();
        let id_a = table.insert(make_host(1));
        let id_b = table.insert(make_host(2));

        // elapsed() on any host is always ≥ 1 ns, so Duration::ZERO makes
        // every host stale.
        let mut stale = table.get_stale_hosts(Duration::ZERO);
        stale.sort_unstable();

        let mut expected = vec![id_a, id_b];
        expected.sort_unstable();

        assert_eq!(stale, expected);
    }

    /// With max_age = MAX no host is ever stale — even one inserted long ago.
    #[test]
    fn test_get_stale_hosts_max_age_returns_none() {
        let mut table = HostTable::new();
        table.insert(make_host(1));
        table.insert(make_host(2));

        let stale = table.get_stale_hosts(Duration::MAX);
        assert!(
            stale.is_empty(),
            "nothing should be stale with Duration::MAX"
        );
    }

    /// An empty table always returns an empty stale list.
    #[test]
    fn test_get_stale_hosts_empty_table() {
        let table = HostTable::new();
        assert!(table.get_stale_hosts(Duration::ZERO).is_empty());
        assert!(table.get_stale_hosts(Duration::MAX).is_empty());
    }

    /// After removing a host it no longer appears in the stale list.
    #[test]
    fn test_get_stale_hosts_excludes_removed_host() {
        let mut table = HostTable::new();
        let id_a = table.insert(make_host(1));
        let id_b = table.insert(make_host(2));

        table.remove(id_b);

        let stale = table.get_stale_hosts(Duration::ZERO);
        assert!(stale.contains(&id_a));
        assert!(!stale.contains(&id_b), "removed host should not appear");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // clear()
    // ─────────────────────────────────────────────────────────────────────────

    /// After clear() the table is empty.
    #[test]
    fn test_clear_empties_table() {
        let mut table = HostTable::new();
        table.insert(make_host(1));
        table.insert(make_host(2));

        table.clear();

        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    /// After clear() the IP and MAC indexes no longer resolve any address.
    #[test]
    fn test_clear_empties_indexes() {
        let mut table = HostTable::new();
        let host = make_host(10);
        let ip = host.ip;
        let mac = host.mac;
        table.insert(host);

        table.clear();

        assert!(table.get_by_ip(ip).is_none(), "IP index should be cleared");
        assert!(
            table.get_by_mac(mac).is_none(),
            "MAC index should be cleared"
        );
    }

    /// After clear() next_id resets so the first new insert gets ID 1 again.
    #[test]
    fn test_clear_resets_id_counter() {
        let mut table = HostTable::new();
        table.insert(make_host(1));
        table.insert(make_host(2));

        table.clear();

        // The next host inserted should receive ID 1, not ID 3.
        let new_id = table.insert(make_host(99));
        assert_eq!(new_id, 1, "ID counter should restart at 1 after clear()");
    }

    /// A table that was cleared can accept new inserts without corruption.
    #[test]
    fn test_clear_then_reinsert_works() {
        let mut table = HostTable::new();
        table.insert(make_host(1));
        table.clear();

        let id = table.insert(make_host(2));
        assert_eq!(table.len(), 1);
        assert!(table.get_by_id(id).is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // get_by_id / get_by_ip / get_by_mac — cross-index consistency
    // ─────────────────────────────────────────────────────────────────────────

    /// All three lookup paths return the same host after a single insert.
    #[test]
    fn test_lookup_consistency_after_insert() {
        let mut table = HostTable::new();
        let host = make_host(77);
        let ip = host.ip;
        let mac = host.mac;
        let id = table.insert(host);

        let by_id = table.get_by_id(id).map(|e| e.id);
        let by_ip = table.get_by_ip(ip).map(|e| e.id);
        let by_mac = table.get_by_mac(mac).map(|e| e.id);

        assert_eq!(by_id, Some(id));
        assert_eq!(by_ip, Some(id));
        assert_eq!(by_mac, Some(id));
    }

    /// Inserting a duplicate IP updates the record but does not add a second entry.
    #[test]
    fn test_duplicate_ip_does_not_grow_table() {
        let mut table = HostTable::new();
        table.insert(make_host(5));

        // Same IP, same MAC — should be an update, not a new row.
        table.insert(make_host(5));

        assert_eq!(table.len(), 1);
    }
}
