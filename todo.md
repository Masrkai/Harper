# Harper  Completed & Researched Work

This checklist captures all features, modules, and research **implemented and tested** in the codebase.

---

## ARP Scanning Engine (`src/scanner/`)

- [x] Multi-pass scanning with configurable passes, send interval, inter-pass delay, idle cutoff, hard timeout
- [x] Wireless-aware configs (auto-detects wlan*/wlp*/wlo*; 5+ passes, 2s inter-pass vs 3 passes, 500ms for ethernet)
- [x] Pre-wake UDP probes to port 9 before scan (pulls 802.11 power-save radios from deep sleep)
- [x] Decoupled send/receive: dedicated blocking receiver thread + async sender
- [x] Adaptive collection window: min post-send wait + idle cutoff + hard timeout ceiling
- [x] Passive ARP sniffing: 10s pre-scan + 5s post-scan (gratuitous ARP, DHCP renewals, non-responders)
- [x] Targeted `resolve_hosts()`: bypasses full scan with `--target`; 3 ARP requests per IP, 500ms gaps
- [x] Backpressure handling: exponential backoff on ENOBUFS/WouldBlock from kernel TX buffer
- [x] Research documented: `Docs/Topics_Research/Scanning.md` (229 lines on 802.11 PSM, Proxy ARP, client isolation, race conditions, TX buffer saturation, adaptive timeouts, multi-technique pipeline)

---

## Host Registry (`src/host/table.rs`)

- [x] Triple-index storage: HashMap + ip_to_id + mac_to_id for O(1) lookups
- [x] Deduplication: insert by IP updates last_seen/vendor/scan_count; insert by MAC reassigns IP (DHCP churn)
- [x] `reindex_by_ip()`: reassigns sequential IDs sorted by IP after bulk insert
- [x] State machine: Discovered → Poisoning → Limited/Blocked/Error with bool return
- [x] Stale detection: `get_stale_hosts(max_age)` for MITM auto-manager eviction
- [x] Full CRUD: insert, remove (cleans indexes), clear (resets ID counter), get_by_*
- [x] 15 BDD scenarios: `tests/features/host_table.feature` (insert/reindex, duplicate IP/MAC, remove, state, stale, clear)

---

## ARP Spoofer (`src/spoofer/`)

- [x] Per-victim dedicated AF_PACKET sockets (no shared mutex, no single point of failure)
- [x] Jittered intervals: victim 4s ±20%, gateway 8s ±20% (reduces ARP storm signature)
- [x] Bidirectional poisoning: victim told "gateway at our MAC", gateway told "victim at our MAC"
- [x] Immediate first poison on start, then timer-driven
- [x] Graceful stop: 5 restore packets (victim + gateway) at 100ms intervals
- [x] One-sided mode (`--one-sided`): gratuitous ARP takeover for strict ARP inspection
- [x] BDD tests: `tests/features/spoofer.feature` (victim-direction, gateway-direction, restore frames)

---

## Packet Forwarder (`src/forwarder/`)

- [x] Independent datalink channel (does not share scanner's receiver)
- [x] IPv4 fragmentation: reassembles GSO super-frames (64KB) → ≤1514-byte frames per RFC 791
- [x] IPv6 pass-through: no fragmentation, copies payload + rewrites MAC
- [x] ARP relay: caps at 42 bytes, rewrites MAC
- [x] MAC rewrite: swaps dst/src to forward between victim ↔ gateway
- [x] Retry with exponential backoff on ENOBUFS/WouldBlock (max 4 retries: 1/2/4/8ms)
- [x] Fatal errors logged once and dropped (never blocks forwarding loop)
- [x] eBPF kernel relay option (`--kernel`): offloads to tc BPF via `forwarder/ebpf.rs`
- [x] 20+ MockSender unit tests: MAC rewrite, length truncation, GSO fragmentation, reassembly, MF bit, retry logic, payload preservation, ip_checksum

---

## MITM Auto-Manager (`src/mitm_auto.rs`)

- [x] Seeds from initial scan: marks initial victims as "managed" for staleness tracking
- [x] Own passive ARP sniffer (dedicated datalink channel) for new/re-seen devices
- [x] Deduplication: re-seen managed victim only refreshes last_seen, no double-add
- [x] Gateway exclusion: never MITMs the gateway/uplink IP
- [x] Dynamic victim lifecycle: on_seen → add_victim (poison + forward + shape) → managed
- [x] Staleness sweep (30s interval, 300s timeout): evicts silent victims (stop poison, disable forward, remove shaping, remove from host table)
- [x] Pool mode support: re-applies shared HTB class on every add/evict
- [x] Clean shutdown: evicts all, tears down tc/nft
- [x] 5 BDD scenarios: `tests/features/mitm_auto.feature` (seed, non-gateway add, gateway ignore, re-seen dedup, late join)

---

## Gateway Mode (`src/gateway_mode.rs`)

- [x] Cache-first discovery: reads `/proc/net/arp` via `utils/neighbors.rs` (instant, zero packets)
- [x] Scan fallback: only runs active ARP scan if kernel cache is empty
- [x] Pool mode (`--pool`): all victims share ONE HTB class (single MARK_POOL fwmark); attacker keeps rest via passthrough
- [x] Per-host mode (`--bandwidth`): individual HTB classes per victim
- [x] Uplink exclusion (`--uplink IP|MAC`): removes bottleneck device from victim pool; falls back to self-exclusion if unresolved
- [x] `--all` auto-select: shapes every discovered client except uplink, non-interactive
- [x] `--target` bypass: skips discovery, resolves only given IPs
- [x] Interactive selector (`TargetSelector`) when neither `--all` nor `--target`
- [x] Shared IP expansion logic with MITM mode via `utils/ip_range.rs`

---

## TC Shaping Engine (`src/utils/tc.rs`)

- [x] Architecture: HTB + IFB + nftables
- [x] Upload (egress): physical NIC HTB root → per-victim leaf classes matched by fw filter on fwmark
- [x] Ingress redirect: ONE catch-all u32 match 0 0 filter → action connmark → mirred redirect to ifb0
- [x] Download (ifb0 egress): HTB root → per-victim leaf classes matched by fw filter (mark set by nftables FORWARD)
- [x] Why it works: download packets arrive before FORWARD runs → catch-all redirects to ifb0 → connmark restores ct mark → nftables sets fwmark → fw filter matches
- [x] Per-host shaping (`limit_host`): unique slot (fwmark = classid minor), HTB leaf + SFQ on NIC and ifb0
- [x] Pool shaping (`limit_pool`): single static class MARK_POOL (0xFFE), created **once**; re-apply only refreshes nftables ruleset
- [x] Blocking (`kbps=0`): nftables drop rules in FORWARD chain (cleaner than 1bit HTB)
- [x] Burst calculation: max(rate_bps / 100, 1600) bytes (satisfies HTB minimum)
- [x] Atomic nftables rebuild: nft -f - stdin flush+replace per add/remove
- [x] NixOS rp_filter integration: NftGate adds accept rule to rpfilter-allow chain for MITM mode
- [x] Cleanup: removes qdiscs, ifb0, nftables table, restores ip_forward/rp_filter
- [x] Root-free state tracking: apply_host_slot / clear_host_slot pure functions for BDD tests
- [x] Technical docs: `Docs/Qos.md` (270 lines: packet journeys, HTB layout, nftables rules, CONNMARK bridge, NixOS notes, detection hardening)
- [x] BDD tests: `tests/features/tc_shaping.feature` (6 scenarios), `tests/features/shaping_modes.feature` (8 scenarios)

---

## Neighbor Cache Discovery (`src/utils/neighbors.rs`)

- [x] Parses `/proc/net/arp`  kernel's authoritative neighbour table
- [x] Filters by interface name, excludes own IP
- [x] Returns Vec<DiscoveredHost> for direct HostTable insertion
- [x] Used by Gateway mode as primary discovery (cache-first), with scan fallback
- [x] 4 BDD scenarios: `tests/features/neighbors.feature`

---

## IP Range Expansion (`src/utils/ip_range.rs`)

- [x] Single IP: "192.168.1.5"
- [x] CIDR: "192.168.1.0/24" → host addresses only (excludes network/broadcast)
- [x] Last-octet range: "192.168.1.10-20" (inclusive)
- [x] Multi-target: expand_targets(&[String])  expands all, dedupes, sorts
- [x] Shared by MITM mode (main.rs) and Gateway mode (gateway_mode.rs)
- [x] Unit tests: table-driven valid/invalid inputs, dedupe+sort, empty input, error handling

---

## CLI & UX (`src/cli/`, `src/main.rs`)

- [x] Two modes: MITM (default, ARP spoof + forward + shape) and Gateway (`--gateway-mode`, kernel routes + tc only)
- [x] Flags: -i/--interface, -g/--gateway, -t/--target (repeatable, CIDR/range/IP), -b/--bandwidth (0=block, omit=unlimited)
- [x] Flags: --one-sided (gratuitous ARP), --all (auto-select all non-gateway), --pool (shared class), --uplink IP|MAC, --kernel (eBPF relay)
- [x] Interactive selection: pretty table (ID, IP, MAC, Status, Vendor), input formats (3, 1-3, 1,3,5, all), bandwidth prompt (skipped if --pool)

---

## BDD Test Framework (`src/bdd.rs` + `tests/features/*.feature`)

- [x] 9 feature files, 40+ scenarios
- [x] `host_table.feature` (15), `neighbors.feature` (4), `gateway_discovery.feature` (2), `shaping_modes.feature` (8), `tc_shaping.feature` (6), `mitm_auto.feature` (5), `spoofer.feature` (3), `forwarder.feature` (unit tests), `kernel_relay.feature` (placeholder)
- [x] Helpers: load_feature, scenario_by_name, step_texts, table_of, host_table_from, arp_cache_from, parse_mac, FakeTc, MitmHarness, drained_fwd_victims, drained_spoof_victims
- [x] Run: cargo test bdd_(all), cargo test bdd_<name> (single feature)

---

## Infrastructure (`src/infra/`)

- [x] KernelState: sets ip_forward=0, rp_filter=0, send_redirects=0 on start; restores on cleanup
- [x] NftGate: installs/removes NixOS rpfilter-allow accept rule for MITM interface
- [x] ShutdownManager: ordered cleanup of all Cleanupable components (tc, nft, kernel state)
- [x] spawn_shutdown_listener: Ctrl-C + q+Enter handling via ctrlc crate

---

## Network Packet Building (`src/network/packet.rs`)

- [x] ArpRequest, ArpReply, ArpPoison, ArpRestore  raw byte construction
- [x] Ethernet + IPv4 + IPv6 header parsing helpers
- [x] Used by scanner, spoofer, forwarder

---

## Vendor OUI Lookup (`src/utils/oui.rs`)

- [x] Uses oui-data crate for MAC → vendor mapping
- [x] Called during host discovery for display table

---

## Documentation

- [x] `Docs/Qos.md`  270 lines: tc/nftables architecture, packet flows, HTB, CONNMARK, NixOS, detection
- [x] `Docs/Topics_Research/Scanning.md`  229 lines: ARP scanning failure modes, 802.11 PSM, Proxy ARP, ideal scanner design
- [x] `Docs/legality.md`  Legal notice (educational/research only)
- [x] `README.md`  Full CLI reference, modes, target formats, shutdown procedure
- [x] `AGENTS.md`  Agent instructions: test patterns, module map, architectural debt notes

---

## Known Gaps (Not Done)

- [ ] `src/scanner/engine.rs`  God Object (800+ lines, violates SRP)  needs extraction (passive sniff, sender, receiver, config)
- [ ] `src/utils/`  Junk drawer (12 files, unclear boundaries)  needs reorganization
- [ ] Duplicate `shutdown.rs`  `src/infra/shutdown.rs` + `src/utils/shutdown.rs`  consolidate
- [ ] IPv6 MITM  No NDP spoofing; victims with IPv6 bypass MITM
- [ ] Kernel relay (`--kernel`)  eBPF attach exists but untested in CI (needs kernel headers)
- [ ] Root-free live tests  #[ignore] tests need real interface + root

---

## Commands Reference

```bash
# Enter dev shell (Nix)
nix-shell

# Build release
build
# or: cargo build --release

# Run all tests (unit + BDD, no root)
cargo test

# Run BDD only
cargo test bdd_

# Open coverage report (run test first)
review

# Run ignored live tests (requires root + interface)
sudo cargo test -- --ignored
```
