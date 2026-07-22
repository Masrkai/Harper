### 1. What is Missing & Not Well-Thought-Out

**A. DHCP Interference**
If a victim's DHCP lease expires while you are spoofing, the DHCP Renewal (unicast to the original gateway) will hit your Linux box instead of the gateway. If your forwarder doesn't handle UDP port 67/68 properly, the victim loses their IP address entirely.

* **Fix:** You need to either transparently forward DHCP traffic in your userspace/eBPF forwarder, or exclude DHCP traffic from the MITM interception.

**B. Hardcoded Line Rate (`tc.rs`)**
You have `const LINE_RATE: &str = "1000mbit";`. This is a critical design flaw. If the actual internet connection is 100 Mbit/s, your HTB classes allow traffic to exceed the physical line rate, causing massive bufferbloat and latency. If it's 2.5 Gbit/s, you are artificially capping the attacker's speed.

* **Fix:** Use `ethtool` or parse `/sys/class/net/<iface>/speed` to dynamically discover the link speed and set `LINE_RATE` accordingly.

---

### 2. Missing Kernel Parameters & System Tuning

Your code handles `ip_forward`, `send_redirects`, and `rp_filter`. However, to act as a high-performance MITM without introducing latency or instability, you are missing several critical sysctl parameters:

1. **`net.ipv4.conf.all.accept_redirects = 0`** and **`net.ipv4.conf.default.accept_redirects = 0`**
    * *Why:* If the router sends an ICMP Redirect, it could tell the victim to bypass your Linux box. You must ignore these.
2. **`net.ipv4.tcp_mtu_probing = 1`**
    * *Why:* When you fragment packets in `engine.rs`, PMTUD (Path MTU Discovery) can break. Enabling this tells the kernel to fall back to slower MSS sizes if it suspects fragmentation issues, preventing "black hole" connections where TCP stalls.
3. **`net.core.rmem_max` / `net.core.wmem_max` (and the `_default` variants)**
    * *Why:* Acting as a forwarder means your NIC buffers fill up rapidly. If the buffers are too small, you will drop packets during high-speed transfers, causing TCP retransmissions. Increase these to at least `16777216` (16MB).
4. **`net.ipv4.ip_local_port_range = 10000 65535`**
    * *Why:* If the Linux box is making its own connections while simultaneously managing thousands of forwarded connections, you can exhaust ephemeral ports.
5. **`net.netfilter.nf_conntrack_tcp_loose = 1`**
    * *Why:* Since you are using `nftables` with `ct mark`, you want conntrack to pick up forwarding entries even if it sees the middle of a TCP stream (which is common in MITM).

---

### 3. Bad Design Choices in the Application

**A. `PoisonLoop` Intervals are Too Aggressive (4s/8s)**
Sending ARP poison every 4 seconds is a Denial of Service against the network's ARP tables. It generates massive broadcast noise, wastes airtime on WiFi, and is a massive red flag for any IDS.

* *Better Approach:* The default ARP cache timeout on Linux is ~60 seconds. Poisoning every 30 seconds is perfectly sufficient. Better yet, implement *Passive ARP Maintenance*: only send a poison packet when you sniff a legitimate ARP request/reply from the gateway or victim attempting to correct their cache.

**B. `ceil` equals `rate` in `add_htb_leaf` (`tc.rs`)**

```rust
"rate", &rate_str, "ceil", &rate_str, "burst", &burst,
```

In HTB, `rate` is the guaranteed minimum, and `ceil` is the maximum allowed. By making them equal, you completely forbid bursting. TCP relies on bursting to test available bandwidth. If you set `rate = 1mbit` and `ceil = 1mbit`, TCP throughput will tank and latency will spike.

* *Fix:* Set `rate` to 80% of the victim's allocation, and `ceil` to 100%, or let `ceil` equal `LINE_RATE` so they can burst when the attacker isn't using the bandwidth.

**C. Synchronous `std::thread::sleep` in Async `PoisonLoop`**
In `poison.rs`, you use `tokio::select!` with `tokio::time::sleep_until`, but the actual packet sending (`send_once`) is synchronous. While fast, doing this inside a Tokio task without `spawn_blocking` can theoretically block the async executor thread if the socket buffer is full.

---

### 4. How to Implement Percentage-Based Bandwidth Allocation

To give the Linux box priority while distributing a *percentage* of the total bandwidth to victims, you need to restructure the HTB tree.

Since HTB doesn't natively understand "percentages" (it needs absolute bitrates), you must dynamically calculate the rates based on the interface speed.

**The HTB Tree Structure:**

```text
Root (1:) -> rate = LINE_RATE (e.g., 100mbit)
 ├── Class 1:10 (Attacker / Default) -> rate 90%, ceil 100%  [Priority]
 └── Class 1:20 (Victim Pool)        -> rate 10%, ceil 100%  [Shaped]
      ├── Class 1:100 (Victim 1)     -> rate 5%, ceil 10%
      └── Class 1:200 (Victim 2)     -> rate 5%, ceil 10%
```

**How this achieves your goal:**

1. The Attacker class (1:10) gets a guaranteed 90% of the line rate.
2. The Victim Pool class (1:20) gets a guaranteed 10%.
3. If the Attacker is downloading at 95mbit, the victims are strictly capped at 10mbit (because 90+10 = 100, the root limit). The attacker gets the vast majority.
4. If the Attacker is idle (using 0mbit), the victims can *burst* up to 100% (`ceil 100%`), utilizing the whole line. As soon as the attacker starts downloading, the HTB scheduler instantly prioritizes the Attacker class, pushing the victims back down to their 10% pool.

**Implementation changes in `tc.rs`:**
Instead of hardcoding `1000mbit`, do:

```rust
let line_rate_mbit = read_interface_speed(&self.interface); // read from /sys/class/net/.../speed
let attacker_rate = format!("{}mbit", line_rate_mbit * 9 / 10); // 90%
let pool_rate = format!("{}mbit", line_rate_mbit / 10);         // 10%

// In init():
// Create Class 1:10 (Attacker passthrough)
run_check(&["tc", "class", "add", "dev", &self.interface, "parent", "1:", "classid", "1:10", "htb", "rate", &attacker_rate, "ceil", &format!("{}mbit", line_rate_mbit)]).await?;

// In limit_pool():
// Create Class 1:20 (Victim Pool)
run_check(&["tc", "class", "add", "dev", &self.interface, "parent", "1:10", "classid", "1:20", "htb", "rate", &pool_rate, "ceil", &format!("{}mbit", line_rate_mbit)]).await?;
```

*Note: This is a simplified view. You will need to apply this logic to both the egress (upload) and the IFB (download) trees.*

---

### 5. Why the Router Disconnects the Linux Box (and How to Fix It)

This is a very common issue when performing MITM on managed switches or modern routers. There are three primary reasons this happens:

**Reason 1: MAC Flapping / Port Security**
You are sending ARP replies claiming to be the gateway. The router sees its own IP resolving to your MAC address. Some routers/switches have Port Security enabled. When they see your MAC address rapidly switching between the port you are plugged into and the router's port, they shut down your port (Err-Disable) to prevent ARP poisoning.

* **Fix:** Use the `--one-sided` flag you already implemented. One-sided MITM only poisons the *victim*. You tell the victim "I am the gateway," but you do *not* tell the gateway "I am the victim." The victim's traffic goes to you, you forward it to the gateway. The gateway never sees MAC flapping on its own port.

**Reason 2: DHCP Lease Expiration**
As mentioned earlier, if your DHCP lease expires, the renewal request goes to the gateway but is intercepted by your Linux box. If you drop it, the Linux box loses its IP and the router drops the connection.

* **Fix:** Ensure your `PacketForwarder` flawlessly forwards UDP 67/68 traffic, or add an `nftables` rule to bypass MITM for DHCP traffic entirely: `nft add rule inet harper FORWARD udp dport 67 accept`.

**Reason 3: ARP Poison Flood Overwhelming the Router**
Your `PoisonLoop` sends ARP packets every 4 seconds. On enterprise routers (like Cisco or Ubiquiti), processing a flood of unsolicited ARP replies can trigger control-plane policing (CoPP), which silently drops packets from your MAC address to protect the router's CPU.

* **Fix:** Increase the poison interval to 30-45 seconds. As long as you send the poison before the victim's ARP cache expires (usually 60s), the MITM stays active without flooding the router.

**Reason 4: Missing Gratuitous ARP for Self-Preservation**
When you start spoofing, the network gets confused about where your Linux box actually is.

* **Fix:** When initializing the spoofer, send a Gratuitous ARP for your *own* IP and MAC. This tells the router, "Hey, I am still here at my real MAC." Do this periodically (every 2 minutes) to keep your own layer-2 path stable in the router's CAM table.
