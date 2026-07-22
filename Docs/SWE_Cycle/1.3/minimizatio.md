### 1. The Redundant Dependency: `ctrlc`

```toml
ctrlc = { version = "3.5.2", features = ["termination"] }
```

**Recommendation: Remove entirely.**
**Why:** You are already using `tokio` as your async runtime, and in your `src/utils/shutdown.rs` file, you are already using `tokio::signal::ctrl_c()`. The `ctrlc` crate is completely redundant here and just adds an extra thread and unnecessary C bindings. Your code already handles Ctrl+C perfectly via Tokio.

### 2. The Overbloated Feature Set: `tokio`

```toml
tokio = { version = "1.53.0", features = ["full", "rt-multi-thread"] }
```

**Recommendation: Disable `full`, enable specific features.**
**Why:** The `"full"` feature flag pulls in *every* Tokio module (including `fs`, `io-util`, `process`, etc.), many of which you don't use. Furthermore, `"rt-multi-thread"` is already included in `"full"`, so specifying both is redundant.
**Change to:**

```toml
tokio = { version = "1.53.0", features = ["rt-multi-thread", "macros", "net", "process", "signal", "sync", "time"] }
```

*Note: I included `process` because you use `tokio::process::Command` in your `tc.rs` and `network/scanner.rs` files.*

### 3. The Potentially Unused Dependency: `rtnetlink`

```toml
rtnetlink = "0.21.0"
```

**Recommendation: Remove (unless used in files not shared with me).**
**Why:** Based on the codebase you provided, you fetch interfaces using `pnet::datalink::interfaces()` (in `utils/net.rs`), read `/proc/net/route` for gateways (in `utils/gateway.rs`), and use `tokio::process::Command` to run `tc` and `ip link` commands (in `utils/tc.rs`). I don't see any `rtnetlink::` imports anywhere. If it's not being called, removing it will save a massive amount of compile time, as `rtnetlink` and its transitive dependencies (like `netlink-packet-route`) are huge.

### 4. The Debug-Only Dependency: `object`

```toml
object = "0.39.1"
```

**Recommendation: Remove or make it optional.**
**Why:** You are using the `object` crate exclusively in `src/forwarder/ebpf.rs` inside the `dump_elf` function for debugging eBPF bytecode during development. This is a heavy parsing dependency.
If you want to keep the function for debugging, you can gate it behind a feature flag:

```toml
[dependencies]
# ... other deps ...
object = { version = "0.39.1", optional = true }

[features]
default = []
debug-ebpf = ["dep:object"]
```

Then in `ebpf.rs`:

```rust
#[cfg(feature = "debug-ebpf")]
fn dump_elf(bytes: &[u8], path: &str) { ... }
```

Run with `cargo run --features debug-ebpf` when you need to inspect the bytecode, and leave it out for normal releases.

### 5. Minor Optimization: `nix`

```toml
nix = { version = "0.31.3", features = ["user", "net"] }
```

**Recommendation: Keep, but be aware of scope.**
**Why:** You use `nix` for `geteuid()` (user) and `if_nametoindex()` (net). This is perfectly fine. If you wanted to be hyper-minimalist, you could replace `nix` with direct `libc` calls (which is already an indirect dependency), but `nix` is safe and idiomatic, so I recommend leaving it as is.

### 6. The `oui-data` Trade-off

```toml
oui-data = "0.2.1"
```

**Recommendation: Keep, but understand the cost.**
**Why:** This crate embeds the entire IEEE OUI database directly into your binary. This makes your compiled binary larger (usually adding a few megabytes). For a security tool, having offline MAC vendor resolution is highly valuable, so this is a good trade-off. I would leave it.

---

### The Minimized `Cargo.toml`

Here is your optimized `Cargo.toml`:

```toml
[package]
name = "harper"
version = "0.1.2"
edition = "2024"

[dependencies]
tokio = { version = "1.53.0", features = ["rt-multi-thread", "macros", "net", "process", "signal", "sync", "time"] }
nix = { version = "0.31.3", features = ["user", "net"] }
pnet = "0.35.0"
oui-data = "0.2.1"
clap = { version = "4.6.2", features = ["derive"] }
aya = "0.14.0"
# object = { version = "0.39.1", optional = true } # Enable via feature if needed

[dev-dependencies]
gherkin = "0.16.0"

[features]
default = []
# debug-ebpf = ["dep:object"]
```
