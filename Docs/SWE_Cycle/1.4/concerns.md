# Missing Parts Analysis: Obfuscation & Performance

Below is a defensive-security audit of the gap between what the codebase does and what a fully hardened MITM tool would do. I cite file/function locations and explain *why* each gap is detectable or slow.

---

## A. Obfuscation Gaps (Network Detection Evasion)

### A.1 ARP Poisoning — Timing & Pattern Signatures

**Location:** `src/spoofer/poison.rs`

| Issue | Current State | Detection Vector |
|---|---|---|
| Fixed base intervals | `VICTIM_INTERVAL_MS = 25_000`, `GATEWAY_INTERVAL_MS = 30_000`, `GARP_INTERVAL_MS = 120_000` | Statistical IDS (arpwatch, arpguard, Suricata `arp-spoof` rules) flag periodic ARP-reply bursts. 25s ± 20% jitter still produces a detectable periodicity after ~10 samples. |
| Jitter seed is monotonic | `jitter()` uses `SystemTime::now().subsec_nanos()` as seed — same across all victims in the same millisecond | With N victims the aggregate rate is N× base, all clustering around the same ±window. Should use per-victim independent RNG seeded from `host_id` + process start. |
| Only ARP Reply op used | `ArpPoison::to_bytes()` always sets `ArpOperations::Reply` | Unsolicited ARP replies are *the* classic signature. Some hosts accept ARP *Requests* as cache updates too — alternating request/reply (or using IS-AT/InARP) is far stealthier. |
| GARP interval too regular | 120 s ± 20% | Real OS GARP events are tied to interface up/link-local events, not periodic. Either drop GARP entirely after initial announcement or trigger it only on carrier events. |
| No inter-victim staggering | All `PoisonLoop` tasks start at the same `Instant::now()` | Even with jitter, the initial burst across N victims is simultaneous. Should offset each victim's phase by `hash(host_id) % base_interval`. |

**Recommended additions:**

- Phase-offset each victim: `next_victim = now + (hash(host_id) % VICTIM_INTERVAL_MS) + jitter(...)`.
- Replace 20% uniform jitter with a Poisson-distributed interval (exponential inter-arrival) so the autocorrelation drops to zero.
- Occasionally send a *legitimate-looking* ARP request to the gateway ("who has victim IP?") instead of a poison reply — many IDS don't flag request-based cache updates.
- Add a "stealth mode" that poisons only on ARP-cache-miss observation (sniff victim's ARP requests, reply to them — fully reactive, zero unsolicited traffic).

### A.2 MAC & Layer-2 Detection

**Location:** `src/spoofer/poison.rs`, `src/network/packet.rs`

| Issue | Detection Vector |
|---|---|
| MITM uses the real interface MAC for all spoofed IPs | Switch CAM table sees the same MAC on one port answering for many IPs. Managed switches with port-security / dynamic ARP inspection flag this immediately. **Missing:** optional locally-administered MAC randomization (bit 1 of first octet set) per-victim, or periodic MAC rotation with coordinated GARP. |
| Poison frame has `arp.target_hw_addr = victim_mac` (not zero) | RFC 826 allows `target_hw_addr` to be unspecified in unsolicited replies. Some IDS check this field. |
| No source-MAC randomization for ARP scans | `ArpRequest::to_bytes()` always uses `sender_mac` = our real MAC. ARP scans are trivially attributed. |
| Switch port-security not handled | If a managed switch enforces "one MAC per port", the GARP broadcast in `poison.rs::run()` will trip it. **Missing:** detection of port-security (sniff for IEEE 802.1X EAP, or check `/sys/class/net/<iface>/duplex` + bridge flags) and graceful fallback to one-sided mode. |

### A.3 IP-Layer Forwarding Signatures

**Location:** `src/forwarder/engine.rs::relay_ipv4`, `src/forwarder/ebpf.rs` (eBPF programs)

This is the **single biggest detection gap** in the codebase:

| Issue | Why It's Detectable |
|---|---|
| **TTL not decremented** | `relay_ipv4()` rewrites dst/src MAC but never decrements `ipv4.ttl`. RFC 1812 §5.3.1 requires routers to decrement TTL. A victim doing `traceroute` will see the MITM as a zero-TTL-cost hop — instant detection. |
| **IP ID not randomized** | Original IP ID is preserved. Some IDS correlate IP ID sequences across flows to detect MITM (the MITM's own OS IP ID sequence bleeds into forwarded packets). |
| **No TCP timestamp scrubbing** | TCP timestamps leak the MITM host's uptime to anyone who compares the forwarded packet's TCP TS against the expected sender's clock skew. |
| **Forwarded packets have the MITM's MAC as src** | Correct for L2, but a victim comparing `arp -n` (gateway MAC = our MAC) with the MAC on received frames can correlate. Consider implementing L3 NAT for stealth scenarios. |
| **Fragmentation leaks** | When `relay_ipv4` fragments GSO super-frames, the fragment IDs form a recognizable pattern (incrementing per fragment). Real OS fragmentation uses per-flow IDs. |
| **No DF-bit handling** | The code explicitly ignores DF ("we ignore the DF bit"). PMTU discovery breaks; victims see ICMP Frag-Needed coming from the MITM MAC. |

**Recommended:** Add a `--stealth` flag that:

1. Decrements TTL and emits ICMP Time Exceeded when TTL hits 0.
2. Randomizes IP ID via a per-flow hash.
3. Strips TCP options like TS at the cost of breaking PAWS.
4. Reconstructs the L3 path so PMTU works correctly.

### A.4 Host Discovery / Scanner Signatures

**Location:** `src/network/scanner/engine.rs`, `src/scanner/config.rs`

| Issue | Detection Vector |
|---|---|
| Sequential IP sweep | `range.iter()` produces IPs in ascending order — a textbook scan signature. Nmap-style randomization missing. |
| Fixed 8 ms send interval | `ScanConfig::send_interval_ms = 8` for both wired/wireless. Statistically distinguishable from background ARP. |
| `pre_wake` UDP-to-port-9 burst | One UDP datagram per host, all from same source port, all to port 9, all within ~1 RTT. Trivial signature. |
| ARP request frames are byte-identical except target IP | Some IDS fingerprint scanners by entropy of ARP frame contents. |
| No source-IP spoofing on probes | ARP requests carry real `local_ip` as sender. Could use 0.0.0.0 (DHCP-style) to reduce attribution. |
| Passive sniff duration is fixed (10s + 5s + 3s) | Pattern recognizable if the tool is run repeatedly. |

### A.5 Kernel / System-Level Indicators

**Location:** `src/infra/components.rs`

| Issue | Detection Vector |
|---|---|
| `/proc/sys/net/ipv4/ip_forward` flipped to 0, then restored on exit | A host-based IDS (auditd, sysmon-for-linux, falco) sees the write. Should at minimum verify the original value is what's expected and only write if needed. |
| `rp_filter` set to 0 globally | Some security baselines (CIS, STIG) flag this. Should scope to the interface only (`/proc/sys/net/ipv4/conf/<iface>/rp_filter`) — the code partially does this but also touches `all/`. |
| `nft` rules installed in `nixos-fw` table | The `NftGate::install` call modifies the host's existing nftables table — visible to any admin who runs `nft list ruleset`. Should create a dedicated `harper` table (which `TcManager` does, but `NftGate` doesn't). |
| No `/proc/net/arp` cleanup on exit | After poisoning, the victim's ARP cache contains stale entries. The restore packets fix this, but the *MITM host's own* `/proc/net/arp` retains evidence. |

### A.6 Traffic-Analysis Leaks

| Issue | Detection Vector |
|---|---|
| No decoy / chaff traffic | A quiet network with sudden periodic ARP from one host is suspicious. Mixing in random ARP requests to non-existent IPs ("ARP noise floor") masks the poison pattern. |
| Forwarding throughput observable | Bandwidth shaping asymmetry (victim is throttled, gateway isn't) is visible in flow statistics. An ISP or upstream NDR tool sees victim↔MITM↔gateway as a 3-hop path with the MITM doing the shaping. |
| No TLS / QUIC interception opt-out | The MITM is transparent; traffic patterns (SNI, packet sizes) still leak through. (Out of scope for this tool, but worth noting.) |

### A.7 eBPF Detection Surface

**Location:** `src/forwarder/ebpf.rs`, `ebpf/*.bpf.c`

| Issue | Detection Vector |
|---|---|
| `tc.bpf.c` returns `TC_ACT_SHOT` on map miss | Drops unknown unicast traffic to our MAC. A monitor pinging the MITM host during operation sees packet loss — distinguishable from a normal host. Should `TC_ACT_OK` for unknown unicast that *originated* locally. |
| XDP program visible via `bpftool prog show` | Any blue-team tool listing BPF programs sees `harper_relay`. **Missing:** program name randomization, or loading via BPF link with `BPF_F_REPLACE`. |
| Maps visible via `bpftool map show` | `harper_map`, `harper_own`, `egress_iface_map` are named identifiers. **Missing:** pin to a randomized bpffs path, or use anonymous maps. |
| No BPF program self-unload on signal | If the process is killed -9, the eBPF link stays attached until the fd is reaped. Should set `BPF_F_STRICT` and use `bpf_link__destroy` with a signal handler. |

---

## B. Performance Optimization Gaps

### B.1 Packet Forwarder (Userspace Path) — `src/forwarder/engine.rs`

This is the hottest path and has the most opportunity.

| Issue | Impact | Fix |
|---|---|---|
| **O(N) rule lookup per packet** | `rules_guard.values().find_map(...)` scans every rule for every packet. With 20 victims at 100 kpps, that's 2M comparisons/sec. | Use a `HashMap<MacAddr, MacAddr>` keyed by *both* victim_mac and gateway_mac (store 2 entries per rule), giving O(1) lookup. Or use a `DashMap` for lock-free reads. |
| **Per-packet `Vec<u8>` allocation** | `original[..len].to_vec()` allocates and frees a buffer for *every* packet. At 100 kpps that's 100k allocs/sec. | Use a `thread_local!` reusable buffer, or `bytes::BytesMut` from a pool. The `tokio_util::bytes` ecosystem has `BytesMut` which can be reused. |
| **Per-fragment allocation** | `relay_ipv4` allocates `vec![0u8; frame_len]` per fragment. | Pre-allocate a 1514-byte scratch buffer once per forwarder, reuse for all fragments. |
| **Mutex held across packet processing** | `rules.blocking_lock()` is acquired on every packet. Even uncontended, this is a CAS + memory barrier per packet. | Use `arc_swap::ArcSwap<HashMap<...>>` for wait-free reads; writers replace the entire map atomically. |
| **Single receive thread** | One `spawn_blocking` task drains the socket. Cannot benefit from multi-core. | Open multiple AF_PACKET sockets with `SO_REUSEPORT`, one per core. Or use `TPACKET_V3` ring buffer (zero-copy, mmap'd). |
| **No `MSG_DONTWAIT` batching** | Each `send_to` is a syscall. | Use `sendmmsg` (Linux) to batch multiple frames per syscall. pnet doesn't expose this; would need raw `libc` calls. |
| **No zero-copy send** | `send_to` copies the buffer to kernel space. | `MSG_ZEROCOPY` (Linux 4.14+) avoids the copy, at the cost of deferred completion notifications. |
| **`ip_checksum` recomputed from scratch** | Linear scan over header for each fragment. | Incremental update (RFC 1624) is O(1) when only TTL/ID/flags change. For fragmentation this isn't applicable, but for the common 1-frame path it would be. |
| **`MockSender` allocation in tests** | Not a production issue, but `VecDeque<io::Error>` could be a smallvec. | N/A. |

### B.2 Forwarder — Specific Code-Level Issues

```rust
// engine.rs — relay_ipv4 fast path
let mut buf = original[..frame_end].to_vec();  // <-- ALLOCATION
Self::rewrite_eth_header(&mut buf, new_dst_mac, our_mac);
Self::send_with_retry(sender, &buf);
```

**Missing:** a `relay_packet_no_alloc` variant that takes a `&mut [u8]` scratch buffer. The fast path (no fragmentation) should be zero-allocation.

```rust
// engine.rs — send_with_retry
std::thread::sleep(std::time::Duration::from_millis(1 << (retries - 1)));
```

**Missing:** `std::thread::sleep` inside `spawn_blocking` is fine, but the retry budget (4 attempts with 1/2/4ms backoff = 7ms worst case) blocks the receive loop. Should use `tokio::time::sleep` if the sender is async-capable, or drop the packet on first ENOBUFS for high-throughput scenarios (configurable).

### B.3 eBPF / Kernel Relay — `src/forwarder/ebpf.rs` + `ebpf/*.bpf.c`

| Issue | Impact | Fix |
|---|---|---|
| **LRU hash map eviction** | `max_entries = 4096` is generous but LRU eviction under load causes re-lookup misses. | Profile victim count; 256 is more than enough for typical use. Smaller map = better cache locality. |
| **No `BPF_MAP_TYPE_PERCPU_HASH`** | Per-victim MAC lookup is a global hash map — cache-line contention on multi-core. | `BPF_MAP_TYPE_LRU_PERCPU_HASH` (kernel 5.13+) eliminates contention. |
| **`bpf_redirect_map` no `BPF_F_BROADCAST`** | N/A for this use case, but worth noting. | — |
| **XDP mode not pinned to driver** | `XdpMode::Default` may fall back to generic XDP (slower). | Try `XdpMode::Native` first, fall back to `Default`. Also consider `XdpMode::Offloaded` for SmartNICs. |
| **No `bpf_skb_change_head` for fragment injection** | Userspace fragmentation is a fallback; for the eBPF path, oversized SKBs from GRO could be handled in-kernel. | Add a TC program that does `bpf_skb_adjust_room` for MTU clamping instead of dropping. |
| **Map updates not batched** | `KernelRelay::enable` does 2 separate `map.insert()` calls (victim + gateway). Each is a syscall. | Use `BPF_MAP_UPDATE_BATCH` (kernel 5.6+) to update both in one syscall. |
| **No BPF program BTF** | Loading without BTF reduces verifier visibility and may fail on newer kernels. | `EbpfLoader::new().btf()` is not called. Add `.btf()` for better verifier diagnostics and compatibility. |
| **No `BPF_F_NUMA_NODE`** | On multi-NUMA systems, map allocation is NUMA-unaware. | Set `numa_node` from `libnuma` or `/sys/class/net/<iface>/device/numa_node`. |

### B.4 Spoofer — `src/spoofer/poison.rs`, `src/spoofer/engine.rs`

| Issue | Impact | Fix |
|---|---|---|
| **N victims = N sockets + N tasks** | 20 victims → 20 AF_PACKET FDs + 20 tokio tasks. Each task is mostly idle (25s sleep between sends). | Single `PoisonSupervisor` task with a min-heap of (next_fire_time, victim_id). One socket, one task. Reduces context-switch overhead. |
| **`open_sender` opens both tx and rx** | `datalink::channel` always returns `(tx, rx)`. The rx half is dropped but the kernel still allocates a receive buffer. | Use `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` directly with `setsockopt(SO_RCVBUF, 0)` to minimize kernel memory. Or use `libpcap`'s `pcap_open_dead` + `pcap_inject`. |
| **`send_once` has no batching** | Each ARP poison is a separate `send_to` syscall. | With the supervisor pattern above, batch all due poisons into one `sendmmsg` call. |
| **`jitter()` called per sleep** | Cheap, but the LCG is re-seeded every call. | Seed once per victim, store state in `PoisonLoop`. |

### B.5 Scanner — `src/network/scanner/engine.rs`

| Issue | Impact | Fix |
|---|---|---|
| **Sequential ARP sends** | 8ms × 254 hosts × 3 passes = ~6s minimum for a /24. | Parallelize: open K sockets (K = 4-8), each handles 1/K of the range. Aggregate replies via shared `DashMap`. |
| **`guard.next()` is blocking** | The receiver thread is blocked in `recvfrom`. Cannot be interrupted except by `stop_flag` (checked between recvs). | Use `recvmmsg` with a timeout, or set `SO_RCVTIMEO` to 100ms so the stop flag is checked 10×/sec. Currently a stop signal may take up to one packet-arrival's worth of latency. |
| **`results.blocking_lock()` per packet** | Every ARP reply locks the results mutex. | `DashMap` or per-thread local results merged at end. |
| **`println!` per discovery** | `println!` locks stdout on every new host. | Batch-log, or use `tracing` with a non-blocking subscriber. |
| **Pre-wake is sequential** | `sock.send_to` in a loop. | `sendmmsg` for the UDP probes. Or drop pre-wake entirely — modern WiFi power-save clients wake on any unicast, including the ARP itself. |
| **`packets: Vec<[u8; 42]>` rebuilt per pass** | 254 allocations per pass × 3 passes. | Build once, reuse. |
| **`range.iter()` is a u32 incrementor** | Allocates an `Ipv4Addr` per iteration. | Use `u32::from(start)..=u32::from(end)` and convert lazily. |

### B.6 TC / Shaping — `src/utils/tc.rs`

| Issue | Impact | Fix |
|---|---|---|
| **Subprocess per `tc`/`nft` call** | Each `tc class add`, `tc filter add`, etc. is a `fork+exec`. Init does ~10 calls; pool re-apply does 1-2. | Use `rtnetlink` crate (netlink protocol) — zero forks, ~10× faster. The `nft` calls could use `libnftables` FFI or the `nftables` crate. |
| **`nft_apply` spawns `nft -f -`** | One fork per ruleset change. | Use a persistent `nft` process with a unix socket, or netlink directly. |
| **`limit_pool_split` flushes entire chain** | Every victim add/remove rewrites ALL nft rules. | Use `nft add rule` / `nft delete rule` for incremental updates. The current approach is O(N) per change; incremental is O(1). |
| **`teardown_tc` is not idempotent-safe** | Called in `init()` *and* `cleanup()`. Each `tc qdisc del` is a fork even if the qdisc doesn't exist. | Check existence first via `tc qdisc show`, or swallow "No such file" errors silently (already partially done). |
| **`read_link_speed_mbit` does I/O per `init`** | Fine, but `line_rate_str()` is called in every `add_htb_leaf` and allocates a String each time. | Cache the formatted string in `TcManager::line_rate_str_cache: OnceCell<String>`. |
| **`build_nft_rules` iterates all hosts** | O(N) string building per change. | Incremental: maintain the ruleset as a `Vec<String>`, append/remove per host change, join at apply time. |

### B.7 Host Table — `src/host/table.rs`

| Issue | Impact | Fix |
|---|---|---|
| **`reindex_by_ip` drains and rebuilds** | O(N log N) sort + O(N) reinsert. Called after every scan. | Fine for N < 1000, but the `drain().map().collect()` allocates a Vec. Could sort in-place via `BTreeMap` keyed by IP, with a secondary `HashMap<HostId, &HostEntry>`. |
| **`get_stale_hosts` linear scan** | O(N) per sweep (every 30s). | Maintain a min-heap by `last_seen`, pop stale entries. O(log N) per sweep. |
| **`iter()` returns `impl Iterator` over `HashMap` values** | No ordering guarantee; callers (`target_selector.rs`, `display()`) re-sort. | Store hosts in a `BTreeMap<HostId, HostEntry>` — iteration is already sorted by ID. |
| **Three separate indexes (`ip_to_id`, `mac_to_id`, `hosts`)** | Three allocations per insert, three lookups per query. | A single `HashMap<HostId, HostEntry>` + two `HashMap<Key, HostId>` is what's there — fine. But `reindex_by_ip` does `drain + sort + reinsert` which thrashes all three. |

### B.8 Concurrency / Async

| Issue | Impact | Fix |
|---|---|---|
| **`Arc<Mutex<...>>` everywhere** | Many hot-path mutexes (forwarder rules, scanner results, host table). | Use `parking_lot::Mutex` (faster than `std`), `RwLock` for read-heavy, `arc_swap` for read-only-snapshot. |
| **`mpsc::channel(32)` for spoofer** | Buffer 32 commands; if 33rd arrives during a slow `start_poison`, sender blocks. | Bump to 128, or use `tokio::sync::broadcast` for fire-and-forget. |
| **`tokio::task::spawn_blocking` for every scan pass** | Each pass spawns a new blocking task. Thread pool reuse is fine, but the closure captures `packets` by move, forcing a clone per pass. | Build packets once outside the pass loop. |
| **`tokio::time::sleep` in `PoisonLoop`** | With 20 victims, 20 concurrent timers. Tokio's timer wheel is O(1) but the wakeup overhead adds up. | Single supervisor task with a `BinaryHeap<Instant>` of next-fire times. |

### B.9 Memory & Allocation

| Issue | Impact | Fix |
|---|---|---|
| **`format!` in hot paths** | `relay_packet`'s ethertype match allocates nothing, but `engine.rs` logging paths (`paint!(INFO, ...)`) do. | Use `tracing` with lazy evaluation; only formats if the level is enabled. |
| **`String` for interface name** | `TcManager`, `ArpScanner`, `PoisonLoop` each store an owned `String`. | `Arc<str>` shared from a single source. |
| **`Vec<DiscoveredHost>` returned from scan** | Cloned from `HashMap` values. | Return an iterator or `Vec` consumed in-place by the caller. |
| **OUI lookup per host** | `lookup_vendor` called in a loop after scan. The `oui-data` crate is fast but still O(N). | Parallelize with `rayon::par_iter`, or batch-lookup. |
| **`MockSender::sent: Vec<Vec<u8>>`** | Test-only, but each sent frame allocates a Vec. | `Vec<Box<[u8]>>` or a smallvec. |

### B.10 Network I/O / Socket Tuning

| Issue | Impact | Fix |
|---|---|---|
| **No `SO_RCVBUF` / `SO_SNDBUF` tuning** | Default socket buffers are ~208 KB. At 100 kpps × 1500 bytes = 150 MB/s, this overflows in <2ms. | `setsockopt(SO_RCVBUF, 16*1024*1024)` and `SO_SNDBUF` similarly. |
| **No `PACKET_FANOUT`** | Single AF_PACKET socket per interface. | `PACKET_FANOUT_CPU` distributes packets across cores, eliminating the single-thread bottleneck. |
| **No `PACKET_MMAP` (TPACKET_V3)** | `recvfrom` per packet = 2 syscalls (recv + send). | TPACKET_V3 ring buffer: zero-copy recv, ~10× throughput. `libpnet` doesn't support it; would need `afpacket` crate or raw `libc`. |
| **No `SO_BUSY_POLL`** | Default kernel polling has ~50µs latency. | `SO_BUSY_POLL=50` on the socket + `sysctl net.core.busy_poll=50` reduces to ~10µs. |
| **No `SO_ATTACH_REUSEPORT_EBPF`** | For the eBPF relay, could pin RX queues to CPUs. | Advanced; only relevant at >1 Mpps. |

### B.11 Build / Compilation

| Issue | Impact | Fix |
|---|---|---|
| **eBPF compiled with `-O2`** | Good, but `-O2` doesn't enable all BPF optimizations. | Add `-mcpu=v3` (or `v2` for older kernels) to enable BPF ISA v3 instructions (fewer jumps). |
| **No `__attribute__((always_inline))` on hot helpers** | `mac_eq` is `static __always_inline` (good). But `bpf_redirect_map` is called without `__always_inline` wrapper. | Fine — verifier inlines it. |
| **No BPF program pinning** | Reload on every start. | Pin to `/sys/fs/bpf/harper_relay` so the program survives process restart, reducing re-attach cost. |

---

## C. Priority Summary

### Obfuscation (highest detection-risk first)

1. **TTL decrement missing** — trivially detectable by any victim running `traceroute`.
2. **Regular ARP poison intervals** — flagged by every network IDS.
3. **Single MAC answering for multiple IPs** — switch port-security / DAI.
4. **eBPF map/program names visible** — `bpftool` is the first thing a blue team runs.
5. **Sequential ARP scan** — textbook scan signature.

### Performance (highest throughput-impact first)

1. **O(N) rule lookup per packet** in `engine.rs` — replace with `HashMap`.
2. **Per-packet `Vec` allocation** — replace with reusable buffer.
3. **Single-threaded AF_PACKET receive** — use `PACKET_FANOUT` or TPACKET_V3.
4. **Subprocess-per-`tc`-command** — replace with netlink.
5. **N sockets for N victims** — replace with single supervisor + min-heap.

Each of these is independently addressable; the obfuscation items are largely orthogonal to the performance items, so they can be tackled in parallel.
