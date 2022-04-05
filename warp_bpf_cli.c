#include <stddef.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "warp_struct.h"
#include <syscall.h>
#include <errno.h>

const char map_path[] = "/sys/fs/bpf/tc/globals/warp";

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}


static inline void check_euid() {
    if (geteuid() != 0) {
        fprintf(stderr, "We need root privilege to execute this operation\n");
        exit(1);
    }
}

static inline int parse_key(char* argv[], struct warp_key *key) {
    if (!inet_pton(AF_INET6, argv[0], &(key->remote_addr.ip6_addr))) {
        fprintf(stderr, "Invalid remote address\n");
        return 0;
    }
    unsigned long port;
    char *str_end;
    port = strtoul(argv[1], &str_end, 10);
    if ((port == 0 && *str_end != '\0') || port > 65535) {
        fprintf(stderr, "Malformed local port\n");
        return 0;
    }
    key->local_port = __cpu_to_be16((__u16)port);

    port = strtoul(argv[2], &str_end, 10);
    if ((port == 0 && *str_end != '\0') || port > 65535) {
        fprintf(stderr, "Malformed remote port\n");
        return 0;
    }
    key->remote_port = __cpu_to_be16((__u16)port);
    return 1;
}

static inline int parse_rid(char* argv[], warp_rid *rid) {
    unsigned long b;
    char *str_end;
    for (int i = 0; i < 3; ++i) {
        b = strtoul(argv[i], &str_end, 10);
        if ((b == 0 && *str_end != '\0') || b > 255) {
            fprintf(stderr, "Malformed %d-th byte of routing id\n", i + 1);
            return 0;
        }
        rid->v[i+1] = (char)b;
    }
    return 1;
}

int add_key(int argc, char* argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Not enough arguments. For this operation we need remote address, local port, remote port and the 3-byte routing id\n");
        return 1;
    }
    struct warp_key key = {0};
    warp_rid rid = {0};
    if (!parse_key(argv, &key)) {
        fprintf(stderr, "Failed to parse warp key\n");
        return 1;
    }
    if (!parse_rid(&argv[3], &rid)) {
        fprintf(stderr, "Failed to parse routing id\n");
        return 1;
    }
    union bpf_attr attr = {0};
    attr.pathname = map_path;
    int fd = sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (fd <= 0) {
        fprintf(stderr, "Failed to get warp BPF map: %s\n", strerror(errno));
        return 1;
    }
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = &key;
    attr.value = &rid;
    attr.flags = BPF_ANY;
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) != 0) {
        fprintf(stderr, "Failed to update BPF map: %s\n", strerror(errno));
        return 1;
    }
    printf("Updated\n");
    return 0;
}

int delete_key(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Not enough arguments. For this operation we need remote address, local port and remote port\n");
        return 1;
    }
    struct warp_key key;
    if (!parse_key(argv, &key)) {
        fprintf(stderr, "Failed to parse warp key\n");
        return 1;
    }
    union bpf_attr attr = {0};
    attr.pathname = map_path;
    int fd = sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (fd <= 0) {
        fprintf(stderr, "Failed to get warp BPF map: %s\n", strerror(errno));
        return 1;
    }
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = &key;
    if (sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) != 0) {
        fprintf(stderr, "Failed to delete BPF map element: %s\n", strerror(errno));
        return 1;
    }
    printf("Deleted\n");
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "No operation specified.\n");
        return 1;
    }
    char* op = argv[1];
    if (strcmp(op, "add") == 0) {
        return add_key(argc - 2, &argv[2]);
    } else if (strcmp(op, "del") == 0) {
        return delete_key(argc - 2, &argv[2]);
    } else {
        fprintf(stderr, "Unsupported operation\n");
        return 1;
    }
    return 0;
}