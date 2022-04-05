#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>
#include "parser.h"
#include "warp_struct.h"
#include <linux/in.h>

struct bpf_elf_map warp SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct warp_key),
    .size_value = sizeof(warp_rid),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 16
};

const char __license[] SEC("license") = "GPL";

SEC("egress")
int tc_egress(struct __sk_buff *skb) {
    void *data = skb->data;
    void *data_end = skb->data_end;
    int eth_proto, ip_proto, udp_len;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct ipv6hdr *ip6hdr;
    struct udphdr *udphdr;
    struct hdr_cursor nh = {data};
    struct warp_key key = {0};
    warp_rid rid = {0}, *prid;
    eth_proto = parse_ethhdr(&nh, data_end, &ethhdr);
    if (eth_proto < 0) return TC_ACT_OK;
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ip_proto = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_proto < 0 || ip_proto != IPPROTO_UDP) return TC_ACT_OK;
        key.dst_addr.ip4_addr.addr = iphdr->daddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip_proto = parse_ip6hdr(&nh, data_end, &ip6hdr);
        if (ip_proto < 0 || ip_proto != IPPROTO_UDP) return TC_ACT_OK;
        key.dst_addr.ip6_addr = ip6hdr->daddr;
    } else return TC_ACT_OK;
    udp_len = parse_udphdr(&nh, data_end, &udphdr);
    if (udp_len < 0) return TC_ACT_OK;
    if (nh.pos + 4 > data_end) return TC_ACT_OK;
    key.src_port = udphdr->source;
    key.dst_port = udphdr->dest;
    prid = bpf_map_lookup_elem(&warp, &key);
    if (prid == NULL) return TC_ACT_OK;
    rid = *prid;
    rid.v[0] = *((char*)nh.pos);
    bpf_skb_store_bytes(skb, nh.pos - data, &rid, sizeof(rid), BPF_F_RECOMPUTE_CSUM);
    return TC_ACT_OK;
}

SEC("ingress")
int tc_ingress(struct __sk_buff *skb) {
    void *data = skb->data;
    void *data_end = skb->data_end;
    int eth_proto, ip_proto, udp_len;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct ipv6hdr *ip6hdr;
    struct udphdr *udphdr;
    struct hdr_cursor nh = {data};
    struct warp_key key = {0};
    warp_rid rid = {0}, *prid;
    eth_proto = parse_ethhdr(&nh, data_end, &ethhdr);
    if (eth_proto < 0) return TC_ACT_OK;
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ip_proto = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_proto < 0 || ip_proto != IPPROTO_UDP) return TC_ACT_OK;
        key.dst_addr.ip4_addr.addr = iphdr->saddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip_proto = parse_ip6hdr(&nh, data_end, &ip6hdr);
        if (ip_proto < 0 || ip_proto != IPPROTO_UDP) return TC_ACT_OK;
        key.dst_addr.ip6_addr = ip6hdr->saddr;
    } else return TC_ACT_OK;
    udp_len = parse_udphdr(&nh, data_end, &udphdr);
    if (udp_len < 0) return TC_ACT_OK;
    if (nh.pos + 4 > data_end) return TC_ACT_OK;
    key.src_port = udphdr->dest;
    key.dst_port = udphdr->source;
    prid = bpf_map_lookup_elem(&warp, &key);
    if (prid == NULL) return TC_ACT_OK;
    rid.v[0] = *((char*)nh.pos);
    bpf_skb_store_bytes(skb, nh.pos - data, &rid, sizeof(rid), BPF_F_RECOMPUTE_CSUM);
    return TC_ACT_OK;
}