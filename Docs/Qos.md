# QoS & Bandwidth Shaping — harper Technical Reference

> **Scope:** How harper shapes traffic in both MITM mode and Gateway mode on a Linux/NixOS host.
> The two modes share the same `tc` HTB + IFB + nftables plumbing; only *how traffic arrives* differs.

---

## 1. Conceptual Foundation

### 1.1 Why Two Separate Tools Are Required

**nftables** is a packet *classifier* and *filter*. It can accept/drop packets, rewrite headers, NAT, and — critically — stamp packets with a numeric `fwmark`. It **cannot** buffer and release packets at a controlled rate. Its `limit` expression does *policing* (drops excess traffic immediately), which causes TCP retransmissions and poor application experience.

**tc** (traffic control) operates at the network driver queue level, below netfilter. It *shapes* traffic by buffering packets and releasing them at the requested rate. It cannot perform complex matching on its own without help from nftables.

The correct pattern — and the one harper uses — is:

```
nftables  →  stamps fwmark on packet (based on victim IP)
tc        →  matches fwmark, queues packet into the right HTB class
```

### 1.2 Two Modes, Same Plumbing

**MITM Mode** (`src/main.rs`): harper is not the real router. It ARP-poisons the victim and gateway so that all victim ↔ internet traffic flows through harper's NIC. The `PacketForwarder` then relays packets in userspace. `ip_forward` is set to **0** so the kernel does not duplicate-forward what the userspace forwarder already handles.

**Gateway Mode** (`src/gateway_mode.rs`): harper *is* the router (hotspot / LAN gateway). No ARP poisoning. The kernel already routes traffic through this machine. Only `tc` shaping is applied via `TcManager`.

Both modes call `TcManager::init()` and `TcManager::limit_host()` identically.

---

## 2. The Full Packet Journey

Understanding which kernel hook fires when is critical to getting the nftables marks to land on the right packets at the right time.

### 2.1 Upload (victim → internet)

```
[Victim] ──(Ethernet)──▶ [harper NIC: ingress]
                                │
                     ┌──────────┴───────────┐
                     │  Netfilter PREROUTING │  ← conntrack entry created/looked up
                     │  Netfilter FORWARD    │  ← harper_mangle chain fires here:
                     │                       │    ip saddr <victim>
                     │                       │      meta mark set <slot>
                     │                       │      ct mark set meta mark
                     └──────────┬───────────┘
                                │
                     tc egress qdisc on NIC   ← fw filter matches <slot>
                     HTB class enforces rate
                                │
                         [Gateway] → [Internet]
```

### 2.2 Download (internet → victim)

Linux `tc` can only natively shape **egress** (outgoing) traffic. Download packets *enter* the NIC — that is ingress — so a trick is required.

```
[Internet] → [Gateway] ──(Ethernet)──▶ [harper NIC: ingress]
                                                │
                              ┌─────────────────┴──────────────────┐
                              │  ingress qdisc (handle ffff:)       │
                              │  ONE catch-all u32 filter:          │
                              │    action connmark   ← restore mark │
                              │    action mirred redirect → ifb0    │
                              └─────────────────┬──────────────────┘
                                                │
                              [ifb0 egress qdisc]
                              ← by now netfilter FORWARD has run:
                                ip daddr <victim>  meta mark set <slot>
                              fw filter on ifb0 matches <slot>
                              HTB class enforces rate
                                                │
                                        forward to victim
```

**Why the catch-all redirect, not a per-victim filter on ingress?**

Download packets arrive at physical NIC ingress *before* the netfilter FORWARD hook runs, so they carry no `fwmark` yet. A per-victim `fw` filter on the ingress qdisc would never match. The fix (documented in `src/utils/tc.rs`) is one `u32 match 0 0` filter that blindly redirects *everything* to `ifb0`. By the time those packets exit `ifb0`'s egress qdisc, nftables has had a chance to set the mark (via conntrack restoration or the explicit `ip daddr` rule). This is the architecture described in Docs/Qos.md §7.1 and implemented in `TcManager::init()`.

---

## 3. HTB Hierarchy

HTB (Hierarchical Token Bucket) is the `tc` qdisc harper uses. Key properties:

- `rate` — guaranteed minimum bandwidth for a class.
- `ceil` — hard maximum (harper always sets `rate == ceil` for a strict cap, no borrowing).
- Classes are arranged in a tree; a root class sets the total interface ceiling.

### harper's HTB Layout

```
Physical NIC egress (upload):
  root 1:  htb  default 0xFFF
  └── 1:1  rate LINE_RATE (1000mbit ceiling)
      ├── 1:FFF  passthrough — all unmatched / local traffic
      └── 1:<slot>  per-victim cap  ←  matched by fw handle <slot>
          └── sfq  (fair queuing within the class)

Physical NIC ingress:
  ffff:  ingress qdisc
  └── u32 match-all → connmark restore → mirred redirect → ifb0
      (ONE filter, installed once in init(), covers all victims)

ifb0 egress (download):
  root 2:  htb  default 0xFFF
  └── 2:1  rate LINE_RATE
      ├── 2:FFF  passthrough
      └── 2:<slot>  per-victim cap  ←  matched by fw handle <slot>
          └── sfq
```

Each victim gets two HTB leaf classes (one on the physical NIC tree for upload, one on `ifb0` for download) and one numeric slot ID that serves as both the `fwmark` value and the `classid` minor.

### Burst Calculation

HTB requires a `burst` parameter: the maximum number of bytes that can be sent instantaneously before the rate enforcer kicks in. harper calculates it in `burst_for(kbps)`:

```
burst = max(rate_bps / KERNEL_HZ, BURST_MIN_BYTES)
      where rate_bps = kbps × 1000 / 8
            KERNEL_HZ = 100
            BURST_MIN_BYTES = 1600
```

This ensures the burst is always at least one MTU-sized frame worth of bytes, satisfying HTB's internal minimum.

### SFQ Leaf Qdisc

Each HTB leaf class has an SFQ (Stochastic Fairness Queuing) child qdisc (`sfq perturb 10`). Within a rate-limited class, SFQ ensures individual TCP flows share the available bandwidth fairly — without it, a single connection could starve all others.

---

## 4. nftables Integration

### 4.1 The `harper_mangle` Table

harper creates and owns a dedicated nftables table (`harper_mangle`) with a single chain (`FORWARD`) at `priority mangle`. This avoids interfering with the NixOS-generated `nixos-fw` ruleset.

```nft
table ip harper_mangle {
    chain FORWARD {
        type filter hook forward priority mangle; policy accept;

        # Upload: mark packet and save to conntrack so download can restore it
        ip saddr <victim>  meta mark set <slot>  ct mark set meta mark

        # Download: restore from conntrack (connection already tracked from upload)
        ip daddr <victim>  ct mark != 0  meta mark set ct mark

        # Download: first packet of a new connection (no conntrack mark yet)
        ip daddr <victim>  ct mark == 0  meta mark set <slot>  ct mark set meta mark
    }
}
```

The chain is **rebuilt atomically** (`nft_rebuild_chain`) every time a host is added or removed. This avoids handle-management complexity and is safe because the flush + rewrite is a single `nft -f -` stdin transaction.

### 4.2 The CONNMARK Bridge

This is the subtlety that makes ingress shaping work. The sequence for a download packet:

1. Upload packet from victim arrives → nftables FORWARD sets `meta mark = slot`, saves to `ct mark`.
2. Reply (download) packet arrives at physical NIC ingress → ingress qdisc redirect filter runs `action connmark` which reads the `ct mark` and restores it as the packet's `fwmark`.
3. The packet lands on `ifb0`'s egress qdisc with its `fwmark` already set.
4. The `fw` filter on `ifb0` matches and routes into the correct HTB class.

For new connections whose *first* packet is a download (e.g. a TCP SYN-ACK in response to something the victim initiated), the conntrack entry may have no saved mark yet. The `ct mark == 0` rule in the nftables chain handles this by setting both `meta mark` and `ct mark` on the first-seen download packet.

### 4.3 NixOS Firewall Interaction (MITM Mode Only)

The NixOS default firewall (`nixos-fw`) has a `rpfilter-allow` chain that drops packets whose source IP appears to come from the wrong interface — which is exactly what happens during MITM, where victim packets arrive on the same interface they would normally exit on. `NftGate::install()` adds a single accept rule to `rpfilter-allow` for the active interface, and removes it on teardown.

---

## 5. Blocking vs. Limiting

When `kbps == 0`, harper uses `ShapeMode::Blocked`. Instead of dropping packets with a `tc` drop action (which causes aggressive TCP retransmission storms), it uses nftables `drop` rules in the FORWARD chain:

```nft
ip saddr <victim> drop
ip daddr <victim> drop
```

For limited hosts, `rate 1bit ceil 1bit` is **not** used (that approach produces similar retransmission noise). The nftables drop approach is cleaner and removes the host from the HTB tree entirely.

---

## 6. Multi-Host Scaling

Each host gets a unique **slot** (a `u16`, allocated sequentially from `SLOT_MIN = 2`, skipping reserved values `1` and `0xFFF`). The slot serves as:

- The `fwmark` value written by nftables.
- The HTB class minor number (`1:<slot>` on NIC, `2:<slot>` on `ifb0`).
- The `fw` filter handle on both devices.

This means adding or removing a host requires only: adding/removing two HTB classes, two SFQ qdiscs, two `fw` filters, and rebuilding the nftables chain. No other hosts are disturbed.

---

## 7. Rate Limiting vs. Policing

| | Shaping (`tc htb`) | Policing (`nft limit … drop`) |
|---|---|---|
| Excess traffic | Buffered, released at rate | Dropped immediately |
| TCP behaviour | Smooth, stable throughput | Retransmissions, choppy |
| Used by harper | ✅ `limit_host()` | ❌ not used for rate-limiting |
| Used for blocking | ❌ | ✅ `ShapeMode::Blocked` |

harper uses shaping for all rate-limited hosts and nftables drop only for full blocks.

---

## 8. Teardown

`TcManager::cleanup()` (also called from `Drop`) performs:

```bash
tc qdisc del dev <iface> root       # removes entire egress HTB tree
tc qdisc del dev <iface> ingress    # removes ffff: and the catch-all filter
tc qdisc del dev ifb0 root          # removes ifb0 HTB tree
ip link set ifb0 down
ip link del ifb0
nft delete table ip harper_mangle  # removes all marks and drop rules
```

All `tc` and `nftables` state is runtime-only and evaporates on reboot regardless of cleanup, but explicit teardown is essential to avoid leaving the victim in a degraded state mid-session.

---

## 9. NixOS-Specific Notes

| Concern | Detail |
|---|---|
| `nftables` vs `iptables` | harper uses `nft` directly. NixOS since 21.11 uses `nf_tables` under the hood for everything; there is no legacy `ip_tables` to conflict with. |
| `tc` availability | `pkgs.iproute2` — available in any NixOS environment. |
| Kernel modules | `ifb`, `act_mirred`, `sch_htb`, `sch_sfq`, `cls_fw` — harper loads them via `modprobe` at `init()` time. Add to `boot.kernelModules` for persistence. |
| `rp_filter` | Must be `0` in MITM mode. harper sets it via `/proc/sys/net/ipv4/conf/all/rp_filter` and restores the original value on exit. |
| `ip_forward` | Set to `0` in MITM mode (userspace forwarder only). Set to `1` separately if using Gateway mode without harper managing it. |
| NixOS firewall FORWARD policy | Default is `drop`. In MITM mode, `NftGate` adds an accept rule. In Gateway mode, you are the router — the FORWARD chain should already accept. |
| PATH under `sudo` | `tc` and `nft` are in the Nix store, not `/usr/sbin`. harper calls them by name; ensure the shell PATH used under `sudo` includes `/run/current-system/sw/bin` or use `sudo env PATH=$PATH harper`. |

---

## 10. Detection and Hardening Awareness

**ARP Poisoning (MITM mode only):**

- `arpwatch`, XArp, and most SIEMs detect duplicate IP-to-MAC associations and gratuitous ARP floods.
- Managed switches with Dynamic ARP Inspection (DAI) silently drop forged ARP replies at the port level — the MITM position will never be established on such networks.
- harper's poison intervals (`VICTIM_INTERVAL_MS = 4000`, `GATEWAY_INTERVAL_MS = 8000`) with ±20% jitter reduce the ARP storm signature vs. naive 2-second uniform intervals.

**Bandwidth limiting as a signal:**

- A sudden, consistent throughput ceiling on internet traffic while LAN communication remains fast is a recognisable MITM indicator.
- HTTPS/TLS: content is hidden but rate limiting still applies.
- VPN: the VPN tunnel itself is throttled; individual application traffic is obscured.

**Victim-side mitigations:**

- Static ARP entries for the gateway completely defeat ARP poisoning.
- 802.1X / Dynamic ARP Inspection at the switch layer.
- IPv6: ARP is IPv4-only. harper does not implement NDP spoofing. A victim with a working IPv6 path bypasses MITM entirely.

---

*References: `src/utils/tc.rs` (TcManager), `src/main.rs` (KernelState, NftGate), `src/gateway_mode.rs`, `src/spoofer/poison.rs`, ArchWiki Advanced Traffic Control, nftables.org, NixOS Wiki Networking.*
