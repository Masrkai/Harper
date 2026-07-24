<p align="center">
  <img src="./shared/harper.svg" alt="Harper Logo" width="128">
</p>

# harper

A network tool for bandwidth shaping and traffic management on local networks, written in Rust.

---

## What it does

harper sits between devices on your network and the internet, giving you control over who gets how much bandwidth. It can throttle a connection to a specific speed, block it entirely, or leave it untouched on a per-device basis.

It operates in two modes:

- **MITM mode** — harper positions itself between a target device and the gateway using ARP spoofing, without needing to be the actual router.
- **Gateway mode** — If you *are* the router or hotspot, harper shapes traffic directly without any ARP manipulation.

---

## Requirements

- Linux
- Root privileges (for raw sockets, tc, nftables)
- A wired or wireless network interface
- Kernel modules: `ifb`, `act_mirred`, `sch_htb`, `sch_sfq`, `cls_fw`

---

## Installation

### From source (requires Nix)

```bash
# Enter the Nix development shell
nix-shell

# Build release binary
build
# or: cargo build --release

# Binary at: target/release/harper
```

### Quick test

```bash
# Run unit + BDD + declarative mock tests (no root needed)
cargo test

# Run all tests including live network tests (requires root)
sudo cargo test -- --ignored
```

### Testing on Network Topologies & Declarative Architecture

Harper features a declarative testing architecture combining:
- **`NetBackend` Trait & `MockBackend`**: In-process mock routing and state simulation running in milliseconds during `cargo test`.
- **TOML Topologies & Scenarios**: Declarative specs under `tests/topologies/*.toml` and `tests/scenarios/*.toml` parsed with `serde` + `toml` and asserted via `insta` snapshots and `proptest` invariants.
- **Network Namespaces (`scripts/netns-test.sh`)**: Isolated network topology testing using `ip netns` and veth pairs.
  ```bash
  # Enter Nix shell (includes iperf3, jq, etc.)
  nix-shell

  # Run all topology tests
  sudo ./scripts/netns-test.sh run all

  # Run a specific topology test (e.g. gateway pool)
  sudo ./scripts/netns-test.sh run gateway_pool

  # Interactive MITM setup
  sudo ./scripts/netns-test.sh setup_mitm
  ```
- **NixOS VM Integration Tests (`nixos/tests/harper.nix`)**: VM-level end-to-end TC/XDP validation with `iperf3`.

### Integration test (requires root, iperf3, jq)

```bash
# Run all 9 integration scenarios (MITM + Gateway in netns)
sudo ./scripts/netns-test.sh run all

# Run a specific scenario
sudo ./scripts/netns-test.sh run gateway_pool
```

---

## Usage

### Common options

| Option                           | Description                                                          |
|----------------------------------|----------------------------------------------------------------------|
| `-i, --interface <IFACE>`        | Network interface to use (auto-selected if omitted)                  |
| `-g, --gateway <IP>`             | Gateway IP (MITM mode only, auto-detected if omitted)                |
| `-t, --target <IP\|CIDR\|RANGE>` | Target IP(s) — skips full scan (can repeat)                          |
| `-u, --upload <KBPS>`              | Upload bandwidth cap per host (omit = unlimited)                     |
| `-d, --download <KBPS>`            | Download bandwidth cap per host (omit = unlimited)                   |
| `-b, --bandwidth <KBPS>`           | Bandwidth cap (both upload/download, overridden by -u/-d)            |
| `--pool <KBPS>`                    | Shared upload/download bandwidth pool per host                       |
| `--pool-upload <KBPS>`             | Shared upload bandwidth pool                                         |
| `--pool-download <KBPS>`           | Shared download bandwidth pool                                       |
| `--one-sided`                    | Use gratuitous ARP takeover instead of bidirectional poisoning       |
| `--uplink <IP\|MAC>`             | Explicitly name the bottleneck uplink device to exclude from shaping |

### MITM mode (default)

```bash
# Interactive: scan → pick targets → set bandwidth
sudo harper

# Non-interactive: throttle specific targets at 500 kbps
sudo harper -t 192.168.1.10 -t 192.168.1.20 -b 500

# Block a target entirely
sudo harper -t 192.168.1.5 -b 0

# CIDR range
sudo harper -t 10.0.0.0/24 -b 1024

# Last-octet range
sudo harper -t 192.168.1.10-20 -b 512
```

### Gateway mode (you are the router/AP)

```bash
# Shape all discovered clients at 1 Mbps each
sudo harper --gateway-mode --all -b 1024

# Shape specific targets only (skips scan)
sudo harper --gateway-mode -t 10.0.0.5 -t 10.0.0.10 -b 500

# Pool mode: all shaped clients share ONE bandwidth pool
# Unshaped traffic (the local host / uplink) keeps the rest of the line
sudo harper --gateway-mode --all --pool 2048

# Exclude a repeater/uplink by MAC or IP from the victim pool
sudo harper --gateway-mode --all --uplink AA:BB:CC:DD:EE:FF
```

### Key differences between modes

| Aspect                 | MITM mode                           | Gateway mode                               |
|------------------------|-------------------------------------|--------------------------------------------|
| ARP spoofing           | Yes (bidirectional or one-sided)    | No                                         |
| Requires being gateway | No                                  | Yes                                        |
| Target discovery       | ARP scan + passive sniff            | Kernel ARP cache (instant) + scan fallback |
| `--target`             | Skips scan, resolves only those IPs | Same; skips cache lookup                   |
| `--all`                | N/A                                 | Shape every discovered client              |
| `--pool`               | N/A                                 | Shared bandwidth class for all victims     |
| `--uplink`             | Excludes from poisoning             | Excludes from victim pool                  |

---

## Target specification formats

| Format           | Example                      | Expands to                  |
|------------------|------------------------------|-----------------------------|
| Single IP        | `192.168.1.10`               | 192.168.1.10                |
| CIDR             | `10.0.0.0/24`                | 10.0.0.1 – 10.0.0.254       |
| Last-octet range | `192.168.1.10-20`            | 192.168.1.10 – 192.168.1.20 |
| Multiple         | `-t 10.0.0.1 -t 10.0.0.5-10` | Combined, deduped, sorted   |

---

## Interactive target selection (MITM / Gateway without `--all` / `--target`)

After the scan completes, you'll see a table:

```
==============================================================
                    ARP Spoof — Target Selection
==============================================================
ID   IP              MAC                Status     Vendor
[1]  192.168.1.10    AA:BB:CC:DD:EE:01  Discovered Intel
[2]  192.168.1.11    AA:BB:CC:DD:EE:02  Discovered Unknown
[3]  192.168.1.12    AA:BB:CC:DD:EE:03  Discovered Apple
==============================================================
  Gateway [4] 192.168.1.1 is excluded from selection.

  Formats:  "3"   "1-3"   "1,3,5"   "all"

Select target(s) [1-3] or 'q' to quit:
```

**Input formats:**

- `3` — single host
- `1-5` — inclusive range (skips unavailable IDs)
- `1,3,5` — comma-separated list (deduped, sorted)
- `all` / `ALL` / `All` — all available hosts

Then you'll be prompted for bandwidth (blank = unlimited).

---

## Shutdown & cleanup

Press `Ctrl-C` or `q` + `Enter` at any time. harper will:

1. Stop packet forwarding
2. Stop ARP poisoning
3. Send ARP restore packets (600 ms per host) to fix victim caches
4. Remove tc qdiscs and nftables rules
5. Restore kernel sysctl settings (ip_forward, rp_filter, etc.)

**Never kill -9** the process — victims will lose connectivity until their ARP caches expire (typically 30–60 s).

---

## Legal

This software is provided for **educational and research purposes only**. You are solely responsible for ensuring your use complies with all applicable laws. Only use harper on networks you own or have explicit written permission to test.

See [LICENSE](./LICENSE) for the full MIT license terms.
Also see [Legal Notice](Docs/legality.md) for a statement from the author.

---

## License

MIT © 2026 Masrkai
