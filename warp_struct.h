#pragma once
#include <linux/ipv6.h>
#include <linux/ip.h>

struct warp_key {
    union {
        struct in6_addr ip6_addr;
        struct {
            char __padding[12];
            __be32 addr;
        } ip4_addr;
    } dst_addr;
    __u16 src_port;
    __u16 dst_port;
};

typedef union {
    __u32 __id;
    char v[4];
} warp_rid;