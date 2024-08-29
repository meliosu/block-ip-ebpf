#include <linux/bpf.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/xdp_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, int);
    __uint(max_entries, 4096 * 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

struct {
    __uint(priority, 30);
    __uint(XDP_PASS, 1);
    __uint(XDP_DROP, 1);
} XDP_RUN_CONFIG(filter);

SEC("xdp")
int filter(struct xdp_md *ctx) {
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_cursor cursor;

    cursor.pos = data;

    if (parse_ethhdr(&cursor, data_end, &ethhdr) < 0) {
        bpf_printk("error parsing Ethernet header\n");
        return XDP_PASS;
    }

    if (parse_iphdr(&cursor, data_end, &iphdr) < 0) {
        bpf_printk("error parsing IP header, eth proto: %hu\n",
                   ethhdr->h_proto);
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&blocklist, &iphdr->saddr)) {
        bpf_printk("dropped packet with src ip %pI4\n", &iphdr->saddr);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
