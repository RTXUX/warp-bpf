#pragma once
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

struct hdr_cursor {
    void *pos;
};

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encap_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto) {
    return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr, __u16 *vlan_id) {
    struct ethhdr *eth = (struct ethhdr*)(nh->pos);
    struct vlan_hdr *vlan_h;
    __u16 h_proto;
    if (nh->pos + sizeof(*eth) > data_end) 
        return -1;
    nh->pos += sizeof(*eth);
    *ethhdr = eth;
    vlan_h = nh->pos;
    h_proto = eth->h_proto;
    if (!proto_is_vlan(h_proto))
        return h_proto;
    if (vlan_h + 1 > data_end)
        return h_proto;
    h_proto = vlan_h->h_vlan_encap_proto;
    if (vlan_id) {
        *vlan_id = bpf_ntohs(vlan_h->h_vlan_TCI);
    }
    nh->pos = vlan_h + 1;
    return h_proto;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr) {
    return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr) {
    struct iphdr *iph = nh->pos;
    unsigned int hdrsize;
    if (iph + 1 > data_end)
        return -1;
    
    hdrsize = iph->ihl * 4;
    if (hdrsize < sizeof(*iph)) 
        return -1;
    
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;
    return iph->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr) {
    struct ipv6hdr *ip6h = nh->pos;
    if (ip6h + 1 > data_end)
        return -1;

    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;
    return ip6h->nexthdr;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh, void *data_end, struct udphdr **udphdr) {
    int len;
    struct udphdr *udph = nh->pos;
    if (udph + 1 > data_end)
        return -1;
    
    nh->pos = udph + 1;
    *udphdr = udph;

    len = bpf_ntohs(udph->len) - sizeof(*udph);
    if (len < 0)
        return -1;

    return len;
}