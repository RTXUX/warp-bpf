#!/bin/bash

function attach() {
    tc qdisc add dev $1 clsact || true
    tc filter add dev $1 ingress bpf da obj warp_bpf.o sec ingress
    tc filter add dev $1 egress bpf da obj warp_bpf.o sec egress
}

function detach() {
    tc filter del dev $1 egress
    tc filter del dev $1 ingress
}

function teardown() {
    rm /sys/fs/bpf/tc/globals/warp;
}

case $1 in
    attach )
        attach ${@:2}
        ;;
    detach )
        detach ${@:2}
        ;;
    teardown )
        teardown
        ;;
esac


