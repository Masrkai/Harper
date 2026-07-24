# Testing Strategy for a Network/eBPF Codebase — Declarative Approach

Looking at your `build.rs`, the "black box" actually has **three distinct layers**, and each needs a different treatment:

| Layer | What's opaque | Why it's hard |
|---|---|---|
| **eBPF programs** (`tc.bpf.c`, `xdp.bpf.c`, `legacy.bpf.c`) | Kernel verifier behavior, packet rewriting logic | Needs a real kernel + root |
| **Loader / forwarder** (`src/forwarder/ebpf.rs`) | How the `.o` is attached to interfaces, map lifetimes | Touches netlink + `bpf(2)` syscalls |
| **Network topology** | Whatever interfaces/routes exist on the host | Host-dependent, racy, non-reproducible |

A "declarative approach" means turning all three into *data*: topology is data, scenarios are data, assertions are data. NixOS gives you the reproducible runtime for free.

---

## 1. Make the topology declarative

Right now your forwarder probably takes an interface name as a CLI arg. That couples tests to whatever `eth0` happens to be on the host. Instead, describe the topology as a value:

```toml
# tests/topologies/two-hosts.toml
[topology]
driver = "veth"          # or "nicsim" for pure-Rust mock

[[namespaces]]
name = "client"
interfaces = [{ name = "c0", addr = "10.0.0.2/24", mac = "aa:00:00:00:00:01" }]
routes   = [{ dst = "10.0.0.0/24", dev = "c0" }]

[[namespaces]]
name = "router"
forwarder = true          # attach harper eBPF here
interfaces = [
  { name = "r0", addr = "10.0.0.1/24", mac = "aa:00:00:00:00:02", peer = "c0" },
  { name = "r1", addr = "10.1.0.1/24", mac = "aa:00:00:00:00:03", peer = "s0" },
]

[[namespaces]]
name = "server"
interfaces = [{ name = "s0", addr = "10.1.0.2/24", mac = "aa:00:00:00:00:04" }]
routes   = [{ dst = "default", via = "10.1.0.1", dev = "s0" }]
```

A small Rust interpreter (call it `topo::Materializer`) reads this and produces `ip netns add` / `ip link add type veth` shell commands — or, in the mock backend, builds an in-process graph of `MockInterface` structs. **Same TOML, two runtimes.**

This is the single most important step: every test from now on references a topology by name, never by host state.

## 2. Make scenarios declarative

A scenario is "given topology X, send traffic Y, expect observation Z." Encode it as data:

```toml
# tests/scenarios/tcp-forward.toml
topology = "two-hosts"
backend  = "tc"                 # tc | xdp | legacy | mock

[steps]
  [[steps.send]]
  from   = "client"
  packet = { type = "tcp", src = "10.0.0.2:1234", dst = "10.1.0.2:80", payload = "hello" }
  count  = 10

  [[steps.expect]]
  where   = "server"
  observe = "tcpdump"
  match   = { payload_contains = "hello" }
  count   = 10
  within  = "500ms"

  [[steps.expect]]
  where   = "router"
  observe = "harper-maps"        # introspect BPF maps directly
  match   = { packets_forwarded = 10 }
```

The `observe` field is pluggable: `tcpdump`, `harper-maps` (read BPF maps via libbpf), `netlink-counters`, etc. Each observer is a small trait impl — adding a new probe doesn't change the scenario format.

## 3. Layer your backends behind a trait

The "black box" exists because somewhere there's a concrete `attach_to_interface(ifname: &str)` call. Break it:

```rust
#[async_trait]
pub trait NetBackend {
    fn name(&self) -> &'static str;
    fn attach(&mut self, prog: &EbpfObject, iface: &InterfaceId) -> Result<AttachHandle>;
    fn detach(&mut self, h: AttachHandle) -> Result<()>;
    fn read_map(&self, name: &str) -> Result<MapSnapshot>;
}

pub struct TcBackend     { /* libbpf + netlink */ }
pub struct XdpBackend    { /* libbpf + netlink */ }
pub struct LegacyBackend { /* raw sockets */ }
pub struct MockBackend   { /* in-process packet router */ }
```

- **`MockBackend`** lives in `tests/` and routes packets through a Rust graph — no kernel. Runs in `cargo test` on CI in milliseconds. Useful for forwarder logic, map state transitions, retry/error paths.
- **`TcBackend`/`XdpBackend`** are exercised in NixOS VM tests (see §4). Same scenarios, different `backend =` line.
- **`LegacyBackend`** is the fallback path; needs its own scenario subset.

The scenario runner dispatches on `backend`, so you write the test *once* and run it across all backends. Discrepancies between mock and real become first-class bugs.

## 4. Wrap eBPF compilation tests in NixOS tests

Since clang + libbpf + kernel must agree, push that into a NixOS test (`nixos/tests/harper.nix`):

```nix
{ pkgs, ... }:
let
  harper = pkgs.callPackage ./.. {};
in {
  name = "harper-ebpf";

  nodes.router = { pkgs, ... }: {
    networking.firewall.enable = false;
    environment.systemPackages = [ harper pkgs.tcpdump pkgs.iptables ];
    boot.kernelModules = [ "sch_clsact" ];   # ensure TC clsact qdisc
    # pin kernel for reproducibility
    boot.kernelPackages = pkgs.linuxPackages_6_6;
  };

  nodes.client  = { ... }: { environment.systemPackages = [ pkgs.iperf3 ]; };
  nodes.server  = { ... }: { environment.systemPackages = [ pkgs.iperf3 ]; };

  testScript = ''
    router.wait_for_unit("network.target")
    client.wait_for_unit("network.target")
    server.wait_for_unit("network.target")

    router.succeed("harper attach --backend tc --iface eth1 &")

    client.succeed("iperf3 -c server -t 5 -J > /tmp/result.json")
    assert float(client.succeed("jq -r .end.sum_received.bits_per_second /tmp/result.json")) > 1e6
    router.succeed("harper stats --iface eth1 | grep -q 'forwarded=10'")
  '';
}
```

This is declarative end-to-end: kernel version, packages, topology, and assertions are all in the Nix file. Reproducible byte-for-byte across machines.

## 5. Unit-test the eBPF programs in isolation

The `.bpf.c` files currently compile but aren't tested. Two cheap wins:

- **`bpf_verify_test`** — load each program with `bpf_prog_load` against a pinned kernel in the VM; verifier rejection becomes a test failure, not a runtime surprise.
- **BPF program-level simulation** — feed a constructed `sk_buff`/`xdp_md` through the program using libbpf's skeleton + a `BPF_MAP_TYPE_RINGBUF` to capture verdicts. This works in user space with `BPF_PROG_TYPE_*_TEST_RUN` (supported for TC and XDP via `BPF_PROG_RUN`). You can drive it from Rust:

  ```rust
  // tests/prog_run.rs
  let obj  = EbpfObject::load("tc-ebpf.o")?;
  let prog = obj.program("harper_tc");
  let mut ctx = SkBuffBuilder::new()
      .eth(src=mac_a, dst=mac_b)
      .ipv4(src="10.0.0.2", dst="10.1.0.2")
      .tcp(80)
      .payload(b"hello")
      .build();
  let verdict = prog.test_run(&mut ctx)?;   // TC_ACT_OK / SHOT / etc.
  assert_eq!(verdict, TC_ACT_OK);
  ```

  Property-based testing (`proptest`) over packet shapes pays off massively here — generate 1000 random packets, assert the program never crashes the verifier and always returns a valid verdict.

## 6. Snapshot the maps

BPF maps are the actual state of your program. Snapshot them as JSON after each scenario step and compare with `insta`:

```rust
let snap = router.read_map("flow_table")?;
insta::assert_json_snapshot!("tcp-forward-after-10pkts", snap);
```

Changes in map layout become reviewable diffs instead of regressions you discover in production.

## 7. Suggested directory layout

```
tests/
  topologies/         *.toml   — declarative netns/veth specs
  scenarios/          *.toml   — traffic + assertions
  backends/
    mock.rs           in-process packet router
    real.rs           wraps TcBackend/XdpBackend for VM tests
  observers/
    tcpdump.rs
    harper_maps.rs
    netlink.rs
  runner.rs           reads toml, picks backend, runs scenario
  prog_run.rs         BPF_PROG_RUN unit tests (proptest-driven)
  snapshots/          insta snapshots of map state
nixos/
  tests/harper.nix    VM-level integration
```

## 8. What to do next, concretely

1. **Extract the `NetBackend` trait** — this is the single change that unblocks everything else. Until that exists, every test is a full integration test.
2. **Write `MockBackend` + a topology TOML parser** — small, runs in `cargo test`, gives you a feedback loop under a second.
3. **Port your 3 most important runtime behaviors to scenario TOMLs** and assert them against the mock. Any behavior the mock can't reproduce tells you what's *actually* coupled to the kernel.
4. **Add a NixOS test that runs the same TOMLs against the real TC backend in a VM.** Now you have two runtimes for one spec.
5. **Add `BPF_PROG_RUN` unit tests with `proptest`** for the verifier and verdict correctness of each `.bpf.c`.
6. **Add map snapshotting** so future eBPF refactors are reviewable.

---

### Why this is "declarative"

- **Topology is data** (TOML), interpreted by a small engine — not shell scripts that drift.
- **Scenarios are data** — assertions are fields, not code branches.
- **Backends are swappable via a trait** — the same scenario exercises mock and kernel.
- **Environment is pinned by Nix** — kernel, libbpf, clang versions are inputs, not ambient.
- **eBPF state is observed via snapshots** — diffs are reviewable, not logs to eyeball.

The black box becomes three smaller boxes, each with its own data contract, each testable on its own clock (mock = ms, prog_run = ms, VM = seconds), and each producing reviewable artifacts.
