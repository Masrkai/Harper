To successfully ship this stealth phase, your tests need to go beyond "does it compile and intercept packets." You are building a transparent bridge; the tests must prove that the traffic looks exactly like it would if your machine wasn't in the middle.

Here are the critical tests that must pass, categorized by the phase they validate:

### 1. The "Invisible Man" Tests (Phase 2.1 & 2.2)

These tests prove you are successfully rewriting egress MACs and decrementing TTLs without breaking checksums.

* **Traceroute Hop-Count Test:**
  * *Setup:* Victim runs `traceroute` (Linux/macOS) or `tracert` (Windows) to an external IP (e.g., 8.8.8.8).
  * *Pass Condition:* The output shows exactly **one** more hop than a baseline traceroute run without Harper. The attacker's IP/MAC *must never appear* in the traceroute output.
  * *Why:* If TTL isn't decremented, the hop count remains the same (detection). If you don't generate ICMP Time Exceeded when TTL hits 0, traceroute breaks.
* **Gateway ARP Cache Integrity Test:**
  * *Setup:* Run Harper MITM. While active, check the Gateway's ARP table (`arp -n` or `show arp`).
  * *Pass Condition:* The Gateway's ARP table shows the **Victim's real MAC** mapped to the Victim's IP. It should *not* show the Attacker's MAC for the Victim's IP.
  * *Why:* Proves the egress eBPF program is successfully rewriting `eth->h_source` back to the victim's MAC before packets hit the wire.
* **Checksum Validation Test (Scapy/Rigorous):**
  * *Setup:* Victim sends TCP, UDP, and ICMP packets to an external server. Capture packets on the Gateway interface using `tcpdump`.
  * *Pass Condition:* Run the capture through Wireshark. Zero "Bad checksum" errors must be present for IPv4, TCP, or UDP.
  * *Why:* eBPF `bpf_l3_csum_replace` is notoriously tricky. If NIC offloading is active and you miscalculate the diff, the receiving host will silently drop the packets, breaking the connection.
* **Passive Wireshark Tap Test:**
  * *Setup:* Connect a 3rd machine to a mirror/SPAN port of the switch. Run Wireshark on it while Victim browses the web.
  * *Pass Condition:* Filtering by `eth.src == <attacker_mac>` or `eth.dst == <attacker_mac>` returns zero packets. The attacker's MAC should only appear in standard ARP broadcasts, never in the IP flow.
  * *Why:* This is the ultimate test of L2 transparency.

### 2. The Timing & Behavioral Tests (Phase 1)

These tests prove your adaptive intervals and jitter work without causing Denial of Service (DoS).

* **Zero-DoS Graceful Shutdown Test:**
  * *Setup:* Start an `iperf3` transfer between Victim and Gateway. Kill the Harper process with `SIGINT` (Ctrl+C).
  * *Pass Condition:* The `iperf3` transfer drops for a maximum of 1-3 seconds, then automatically resumes without crashing. Both Victim and Gateway ARP caches are restored to the correct MACs.
  * *Why:* Proves Phase 5.1 (ARP Restoration) works under load. If the restoration fails, the switch CAM table and host ARP caches will point to the dead attacker MAC, permanently breaking the victim's internet until ARP times out.
* **Adaptive Interval Memory Test:**
  * *Setup:* Run Harper against a Linux victim (default ARP timeout ~60s).
  * *Pass Condition:* Harper's internal logs (or `strace`) show it sending poison packets at an interval safely below 60s (e.g., ~40s), with randomized jitter (e.g., 35s, 42s, 38s). It must *not* send them every 2 seconds (which triggers arpwatch) or every 90 seconds (which causes the victim's cache to expire and drop traffic).
* **Long-Run Stability Test (24-hour soak):**
  * *Setup:* Leave Harper running overnight between a victim and gateway.
  * *Pass Condition:* Memory usage of the Rust daemon does not grow unbounded (check for eBPF map leaks). No connection resets occur due to missed ARP renewals.

### 3. eBPF & Kernel Stability Tests (Phase 2.3)

Because you are injecting C code into the kernel, you must test for edge cases that could panic the kernel or drop packets.

* **Fragmented Packet Test:**
  * *Setup:* Victim pings an external host with a payload large enough to require IP fragmentation (e.g., `ping -s 4000 8.8.8.8`).
  * *Pass Condition:* The eBPF program correctly handles fragmented packets. It must either decrement the TTL on all fragments correctly, or pass them through safely without crashing the eBPF program.
  * *Why:* eBPF TC programs parse packet headers. If your C code assumes a full TCP header is present but receives an IP fragment, it will read out of bounds and the eBPF verifier will drop the packet (or worse, fail to attach).
* **Non-IP Traffic Passthrough Test:**
  * *Setup:* Send ARP, STP (Spanning Tree), or mDNS traffic across the network.
  * *Pass Condition:* The eBPF program safely ignores these packets (`bpf_pass()`) without attempting to cast them as `struct iphdr`.
  * *Why:* If your eBPF code blindly assumes `ethhdr` is followed by `iphdr`, it will drop critical L2 keepalives (like STP), taking down the whole switch network.
* **NIC Offloading Toggle Test:**
  * *Setup:* Run Harper on a machine with a modern Intel/Mellanox NIC. Check `ethtool -k <iface>`.
  * *Pass Condition:* Harper either successfully manipulates `sk_buff` checksums dynamically, OR it explicitly issues the `ethtool` commands to disable `tx-checksumming` and `gso` on attach, restoring them on detach.
  * *Why:* If you modify a TTL but the NIC hardware calculates the final checksum based on the *old* TTL, the packet will be dropped at the destination.

### 4. Detection Evasion Baseline Tests (Phase 6)

* **Arpwatch Cleanliness:**
  * *Setup:* Run `arpwatch` on a monitoring machine. Start Harper.
  * *Pass Condition:* `arpwatch` does *not* send "changed ethernet address" alerts for the initial poisoning (if using the gratuitous/burst stealth method), or if it does, it stops alerting during the maintenance phase.

### Automated Testing Approach (Rust)

To automate the network-level tests, consider using `pnet` to craft specific packets (like the traceroute probes or fragmented ICMP) and `libpcap` on a tap interface to capture the egress traffic and assert that the MACs are rewritten and TTLs are decremented correctly.

You can use Rust's `#[cfg(test)]` to spin up network namespaces (`ip netns add`) via `std::process::Command` to simulate Victim, Gateway, and Attacker on a single Linux machine without needing physical hardware.
