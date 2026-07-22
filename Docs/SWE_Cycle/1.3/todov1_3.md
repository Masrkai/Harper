# Harper v1.3 — eBPF Relay Improvements

Tracking issues from `concerns.md` validated against `harper-ebpf/harper.bpf.c`.

## Validated Concerns

| # | Category | Concern | Location | Severity |
|---|----------|---------|----------|----------|
| 1 | Correctness | Silent drop on map miss → `TC_ACT_OK` sends frame up stack | `harper.bpf.c:80-82` | P0 |
| 2 | Correctness | No L3/L4 checksum fixup (future NAT/TLS) | N/A (L2-only) | P3 |
| 3 | Performance | `TC_ACT_OK` traverses full kernel stack | `harper.bpf.c:87` | P1 |
| 4 | Performance | tc ingress vs XDP (SKB allocation overhead) | Architecture | P2 |
| 5 | Stealth | No egress tc filter → source MAC leaks on wire | Missing | P2 |
| 6 | Stealth/Correctness | No TTL decrement → relay invisible to traceroute | Missing | P2 |
| 7 | Operational | Map exhaustion (1024 entries, `BPF_F_NO_PREALLOC`) | `harper.bpf.c:37-38` | P0 |

---

## Phase 0 — Prerequisites (0.5 days)

- [ ] 0.1 Add BDD test: map miss behavior (`tests/features/kernel_relay.feature`)
- [ ] 0.2 Add BDD test: map exhaustion / LRU eviction
- [ ] 0.3 Add `aya` XDP program type support to `Cargo.toml` (already 0.14.0)

---

## Phase 1 — P0 Correctness & Operational (1 day)

- [ ] 1.1 **Map miss fix**: Change `harper.bpf.c:81-82` from `TC_ACT_OK` → `TC_ACT_SHOT` (drop)  
  - *Decision*: Use `TC_ACT_SHOT` for now; can add redirect later if needed
- [ ] 1.2 **LRU hash map**: `harper.bpf.c:34-41` change `BPF_MAP_TYPE_HASH` → `BPF_MAP_TYPE_LRU_HASH`, remove `BPF_F_NO_PREALLOC`
- [ ] 1.3 Bump `max_entries` 1024 → 4096 in both C and loader (optional with LRU)
- [ ] 1.4 Update `src/forwarder/ebpf.rs` map creation to match new type
- [ ] 1.5 Run BDD tests: `cargo test bdd_kernel_relay`

---

## Phase 2 — P1 Performance: TC Redirect (1 day)

- [ ] 2.1 Add `BPF_MAP_TYPE_DEVMAP` (`egress_iface_map`) in `harper.bpf.c` — key=0, value=ifindex
- [ ] 2.2 Replace MAC rewrite + `TC_ACT_OK` with `bpf_redirect(egress_iface_map, 0, BPF_F_INGRESS)` + `TC_ACT_REDIRECT`
- [ ] 2.3 `src/forwarder/ebpf.rs`: Populate `egress_iface_map` at attach (resolve ifindex via `nix::net::if_::if_nametoindex`)
- [ ] 2.4 Rename `harper.bpf.c` → `harper_tc.bpf.c` (tc redirect version)
- [ ] 2.5 BDD: "relay skips kernel stack via tc redirect"
- [ ] 2.6 **Default change**: `--kernel` flag now uses tc redirect (not legacy `TC_ACT_OK`)

---

## Phase 3 — P2 Architecture: XDP with Fallback Chain (4-6 days)

### 3.1 XDP Program
- [ ] 3.1.1 Create `harper-ebpf/harper_xdp.bpf.c` with `SEC("xdp")` + `BPF_MAP_TYPE_DEVMAP` + `XDP_REDIRECT`
- [ ] 3.1.2 XDP program: parse Ethernet, lookup `harper_map` (same key/value), redirect via devmap
- [ ] 3.1.3 No SKB allocation — operates on `xdp_md` data pointers

### 3.2 Build System
- [ ] 3.2.1 `build.rs`: Compile both `harper_tc.bpf.c` and `harper_xdp.bpf.c`
- [ ] 3.2.2 Emit cargo features: `xdp` (optional, default false)

### 3.3 Loader & Backend Selection
- [ ] 3.3.1 `RelayBackend` enum: `Xdp`, `TcRedirect`, `TcLegacy`
- [ ] 3.3.2 `probe_xdp_support(iface: &str) -> bool`:
  - Check `/sys/class/net/<iface>/xdp_features`
  - Try loading dummy XDP program
- [ ] 3.3.3 `attach_best_available(iface, prefer_xdp: bool)` → tries XDP → tc redirect → tc legacy
- [ ] 3.3.4 Separate maps per backend (XDP uses devmap, tc uses hash + devmap)

### 3.4 CLI
- [ ] 3.4.1 `--xdp` = prefer XDP (error if unavailable)
- [ ] 3.4.2 `--kernel` = prefer tc redirect (new default, fallback to legacy)
- [ ] 3.4.3 `--legacy` = force tc legacy (`TC_ACT_OK`)
- [ ] 3.4.4 Mutually exclusive group

### 3.5 Tests
- [ ] 3.5.1 BDD: "XDP preferred when available"
- [ ] 3.5.2 BDD: "falls back to tc redirect when XDP unsupported"
- [ ] 3.5.3 Integration (root, `[ignore]`): "XDP relay achieves line rate on 1Gbps"

---

## Backend Matrix

| Flag | Preferred | Fallback | Maps Used |
|------|-----------|----------|-----------|
| `--xdp` | XDP + DEVMAP | ❌ Error | devmap + hash |
| `--kernel` (default) | tc redirect + devmap | tc legacy | hash + devmap |
| `--legacy` | tc legacy (`TC_ACT_OK`) | ❌ | hash only |

---

## Implementation Order

```
Phase 1 → Phase 2 → Phase 3
   │         │         │
   ▼         ▼         ▼
 P0 fix   2-3×      XDP +
 & LRU    throughput fallback
```

---

## Notes

- **Map miss**: `TC_ACT_SHOT` chosen over redirect — simpler, correct for "unknown victim" case. Can add redirect later if gateway MAC known.
- **LRU hash**: Auto-evicts oldest entry on insert when full. No userspace cleanup needed.
- **XDP probe**: Check `xdp_features` sysfs first (fast), then try-load dummy program (reliable).
- **Default backend**: `--kernel` = tc redirect (Phase 2). Current behavior → `--legacy`.
- **Testing**: Phases 1-2 BDD root-free. Phase 3 needs root + NIC for integration.