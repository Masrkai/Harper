/*
 * in-kernel MITM relay for Harper.
 *
 * Attached as a tc ingress filter on the MITM interface. For every frame whose
 * Ethernet destination equals the local MAC, we look up the correct next-hop
 * MAC in the `harper_map` BPF hash map (keyed by source MAC) and rewrite the
 * Ethernet header in place, then let the kernel re-transmit it. This replaces
 * the userspace PacketForwarder copy + fragment + retry path.
 *
 * The map is populated from userspace as victims are enabled/disabled.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_ALEN 6

/* key = 6-byte source MAC, value = 6-byte next-hop (rewrite) MAC. */
struct mac_key {
    __u8 mac[ETH_ALEN];
};

/* BTF-style map definitions (aya 0.14 requires these in the `.maps` section
 * with BTF debug info; the legacy `struct bpf_map_def SEC("maps")` form is no
 * longer supported by aya 0.11+). The `__uint(...)` macros expand to BTF
 * metadata that the ELF parser reads to create the maps. */

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

static __always_inline int mac_eq(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
           a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

SEC("classifier")
int harper_relay(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u32 own_key = 0;
    __u8 *own = bpf_map_lookup_elem(&harper_own, &own_key);
    if (!own)
        return TC_ACT_OK;

    if (!mac_eq(eth->h_dest, own))
        return TC_ACT_OK;

    struct mac_key key;
    __builtin_memcpy(&key.mac, eth->h_source, ETH_ALEN);

    __u8 *next = bpf_map_lookup_elem(&harper_map, &key);
    if (!next)
        return TC_ACT_OK; // FIX: Let local traffic pass to the kernel

    __builtin_memcpy(eth->h_dest, next, ETH_ALEN);
    __builtin_memcpy(eth->h_source, own, ETH_ALEN);

    return TC_ACT_OK;
}
