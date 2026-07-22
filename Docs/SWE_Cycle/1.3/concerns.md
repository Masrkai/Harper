There are several meaningful improvements possible, from performance to correctness to stealth:

## Correctness gaps

**No checksum fixup for L3/L4.** You're only rewriting MACs (L2), which is fine checksum-wise — but if the tool ever needs to rewrite IP addresses or ports (e.g. for NAT-style interception of HTTPS where you want to terminate TLS locally), you'd need `bpf_l3_csum_replace()` / `bpf_l4_csum_replace()`. Right now the scope is pure L2 relay so this is fine, just a future-proofing note.

**Silent drop on map miss.** If a frame arrives addressed to you but has no entry in `harper_map`, you return `TC_ACT_OK` — the frame continues up the stack and gets processed by the normal network stack as if it arrived for *you*. Depending on your kernel config this may silently consume the frame rather than forwarding it. A more correct fallback might be `TC_ACT_SHOT` or an explicit redirect to the right interface.

## Performance ceiling

**`TC_ACT_OK` goes up the stack then back out.** For pure relay traffic that should never touch the local stack, this is wasteful — the frame climbs through the kernel network stack unnecessarily. Using `bpf_redirect()` + `TC_ACT_REDIRECT` to push it directly to the egress queue of the correct interface skips the entire local stack traversal. This is a significant throughput improvement at high packet rates.

**XDP instead of tc ingress.** XDP runs before even the SKB is allocated — it's the earliest possible hook point, operating directly on DMA buffers. For a pure relay where you never need SKB metadata, XDP + `XDP_REDIRECT` is substantially faster than tc + `TC_ACT_REDIRECT`. The tradeoff is that XDP requires NIC driver support (most modern drivers have it) and the programming model is slightly more constrained (no `skb` helpers, raw packet pointer only).

## Stealth / operational considerations

**Egress tc filter too.** Right now you only filter ingress. A careful observer watching the wire sees frames with your MAC as source going to both victim and gateway — the ARP-poisoned hosts see your MAC as their gateway/peer, which is expected, but any out-of-band observer sees bidirectional traffic through you. If stealth matters, an egress filter that rewrites the source MAC back to the original sender before frames leave the wire can make the relay invisible to passive observers on the segment.

**No TTL decrement.** A real router decrements IP TTL and updates the checksum. Your relay doesn't, so traceroute from victim to gateway won't show your hop — which is either a stealth advantage or a correctness problem depending on your goal.

**Rate limiting / map exhaustion.** `harper_map` has 1024 entries max with `BPF_F_NO_PREALLOC`. If something floods new source MACs (broadcast storm, MAC randomization) and you're not filtering inserts from the kernel side, the map fills and misses silently. A `BPF_MAP_TYPE_LRU_HASH` would evict the oldest entry instead of silently failing new ones.

## Architecture improvement

The most significant upgrade would be moving to **XDP + `bpf_redirect_map()`** with a `BPF_MAP_TYPE_DEVMAP` holding the target interface index. That path is zero-copy, pre-SKB, and can hit line rate on a modern NIC in a way the tc ingress path fundamentally can't — the tc path still allocates an SKB per frame even for traffic that never needs one. For high-throughput interception (gigabit+ links) this matters a lot; for typical LAN rates the tc approach is perfectly adequate.
