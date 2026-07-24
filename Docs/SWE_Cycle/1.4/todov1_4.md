# Harper v1.4 — MITM Obfuscation & Stealth Plan

Comprehensive plan for obfuscating the MITM attack surface. Addresses detection vectors from passive observers, IDS/IPS, ARP monitoring tools, and forensic analysis.

---

## Threat Model: What Detects MITM?

| Detector | Signal | Current Harper Exposure |
|----------|--------|-------------------------|
| **arptables / ebtables** | ARP opcode=2 (reply) with attacker MAC as gateway | Full exposure — static intervals, no jitter |
| **arpwatch / arpalert** | MAC↔IP mapping changes | Full exposure — immediate poison |
| **Wireshark / passive tap** | Bidirectional traffic with attacker MAC as src/dst | Full exposure — no egress rewrite |
| **traceroute** | Missing hop (TTL not decremented) | Full exposure — TTL unchanged |
| **ICMP redirects** | Gateway sends redirect to victim | Not emitted — but absence is signal |
| **NDP (IPv6)** | Neighbor Advertisement spoofing | Not implemented yet |
| **Switch port security** | MAC flapping on port | Possible — single MAC for all victims |
| **NetFlow / sFlow** | Asymmetric flows, unusual MAC pairs | Likely — traffic patterns visible |
| **Host-based IDS** | ARP cache poisoning events | Full exposure |

---

## Phase 1 — ARP Spoofing Stealth (P0, 2 days)

- [ ] **1.1 Adaptive Poison Intervals**  
  - [ ] Dynamic interval based on ARP cache TTL (default 30-60s Linux, 120s Windows) and poison at ~⅔ TTL
  - [ ] Exponential backoff on failure (if poison ARP fails, increase interval exponentially)
  - [ ] Burst + silence pattern (send 2-3 rapid poisons, then silence for random 2-5× interval)
  - [ ] Per-victim randomization (unique base interval + jitter)

- [ ] **1.2 ARP Packet Crafting**  
  - [ ] Randomize ARP hardware type (use 1 but vary padding/dummy bytes)
  - [ ] Vendor MAC spoofing (spoof gateway MAC with same OUI as real gateway)
  - [ ] Gratuitous ARP variation (send as gratuitous target MAC = ff:ff:ff:ff:ff:ff vs unicast)
  - [ ] ARP probe vs reply mix (occasionally send ARP request opcode=1 for gateway IP)

- [ ] **1.3 Gateway Poisoning Strategy**  
  - [ ] Poison gateway less frequently (adaptive gateway ARP cache logic)
  - [ ] Selective gateway poisoning (only poison gateway for victims with active traffic)
  - [ ] MAC rotation (rotate attacker MAC per victim via macvlan/IP aliases)

- [ ] **1.4 ARP Restoration Stealth**  
  - [ ] Gradual restoration (taper over 30-60s with increasing intervals instead of 5 rapid packets)
  - [ ] Match original ARP timing (send restores at same interval poison was sent)
  - [ ] Send to broadcast + unicast

---

## Phase 2 — Traffic Relay Obfuscation (P0, 3 days)

- [ ] **2.1 Egress MAC Rewrite**  
  - [ ] Implement second tc program on egress to rewrite `eth->h_source` back to original sender MAC
  - [ ] Populate BPF `reverse_mac_map` (`victim_mac → original_sender_mac`)
  - [ ] Maintain bidirectional symmetry (Victim→Gateway, Gateway→Victim)
  - [ ] Add BPF map: `reverse_mac_map` (LRU hash, 1024 entries)

- [ ] **2.2 TTL Decrement + Checksum Fix**  
  - [ ] Implement IPv4 TTL decrement (`iph->ttl--`) in eBPF program
  - [ ] Implement IP header checksum update (`bpf_l3_csum_replace`)
  - [ ] Implement TCP/UDP checksum update (`bpf_l4_csum_replace`)
  - [ ] Support ICMP TTL decrement + checksum fix

- [ ] **2.3 ICMP Redirect Suppression**  
  - [ ] Suppress kernel ICMP redirects via `sysctl net.ipv4.conf.all.send_redirects=0` on attach
  - [ ] Optional: Generate fake redirects to decoy targets

---

## Phase 3 — Timing & Behavioral Obfuscation (P1, 2 days)

- [ ] **3.1 Traffic Shaping as Cover**  
  - [ ] Apply tc HTB shaping on attacker's own traffic to mimic normal client
  - [ ] Rate-limit relay to victim's expected rate (WiFi vs Ethernet)
  - [ ] Add micro-jitter to forwarding (0-5ms delay per packet)

- [ ] **3.2 Session Mimicry**  
  - [ ] Match typical RTT of victim↔gateway path for SYN/ACKs
  - [ ] Preserve TCP window scaling options
  - [ ] Preserve TOS/DSCP bits from original packet

- [ ] **3.3 Idle Behavior**  
  - [ ] Send periodic "keepalive" ARP packets to maintain position
  - [ ] Handle DHCP renew requests correctly without poisoning

---

## Phase 4 — Protocol & Payload Obfuscation (P2, 3 days)

- [ ] **4.1 TLS/HTTPS Interception Evasion**  
  - [ ] SNI preservation (never terminate TLS; just forward)
  - [ ] Document certificate pinning limitations

- [ ] **4.2 DNS Handling**  
  - [ ] Forward DNS queries directly without interception
  - [ ] Optional: DNS response modification for targeted testing (opt-in only)

- [ ] **4.3 Protocol Tunneling**  
  - [ ] DNS-over-HTTPS (DoH) tunneling simulation
  - [ ] ICMP tunneling simulation
  - [ ] TLS 1.3 encrypted client hello (ECH) forwarding

---

## Phase 5 — Anti-Forensics & Cleanup (P1, 1.5 days)

- [ ] **5.1 ARP Cache Sanitization**  
  - [ ] Send correct mappings to all victims + gateway on shutdown
  - [ ] Send 10× restores over 10s with increasing intervals
  - [ ] Re-scan ARP cache to confirm successful restoration

- [ ] **5.2 Kernel State Cleanup**  
  - [ ] Restore `ip_forward` system setting
  - [ ] Remove tc qdiscs/filters on shutdown
  - [ ] Flush nftables rules
  - [ ] Verify automatic detach of eBPF programs on socket close

- [ ] **5.3 Log Evasion**  
  - [ ] Disable kernel ARP logging (`sysctl net.ipv4.conf.all.log_martians=0`)
  - [ ] Use `NOTRACK` in nftables for relayed traffic to avoid conntrack table spikes

---

## Phase 6 — Detection Evasion Modules (P2, 2 days each)

- [ ] **6.1 arpwatch/arpalert Evasion**  
  - [ ] Slow poisoning mode (interval > 300s)
  - [ ] MAC consistency across multiple victims

- [ ] **6.2 Switch Port Security Evasion**  
  - [ ] Single MAC per port workaround
  - [ ] Periodic legitimate traffic simulation from each victim MAC

- [ ] **6.3 Wireless (802.11) Specific**  
  - [ ] 802.11 frame injection (monitor mode support)
  - [ ] Deauth avoidance (rely solely on passive injection + ARP)
  - [ ] Channel hopping synchronization

- [ ] **6.4 IPv6 / NDP Spoofing**  
  - [ ] NS/NA spoofing equivalent
  - [ ] Router Advertisement (RA) spoofing

---

## Implementation Architecture

### New Modules
```
src/stealth/
├── mod.rs              # StealthEngine coordinator
├── arp_stealth.rs      # Phase 1: adaptive intervals, packet crafting
├── egress_rewrite.rs   # Phase 2.1: tc egress filter + reverse map
├── ttl_fixup.rs        # Phase 2.2: eBPF TTL + checksum helpers
├── timing.rs           # Phase 3: jitter, shaping, mimicry
├── cleanup.rs          # Phase 5: restoration, verification
└── detectors.rs        # Phase 6: detector-specific evasion
```

### eBPF Extensions
```
harper-ebpf/
├── harper_tc_ingress.bpf.c    # Current + devmap redirect (v1.3)
├── harper_tc_egress.bpf.c     # NEW: egress MAC rewrite
├── harper_xdp.bpf.c           # NEW: XDP fast path
└── helpers/
    ├── ttl_checksum.h         # bpf_l3/l4_csum_replace wrappers
    └── mac_rewrite.h          # inline eth header rewrite
```

---

## Legal & Ethical Guardrails

1. All stealth features are **opt-in only** via the `--stealth` flag group.
2. Default behavior of Harper is completely visible and easily detectable.
3. Keep `Docs/legality.md` up-to-date with stealth-specific warnings.
4. Do not include signatures or code paths that specifically target or evade commercial IDS/IPS by name.
