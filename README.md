# Cloudflare Warp BPF Filter

## Introduction
A simple & stupid tool that mangles warp packets to emulate official Cloudflare Warp client.

It uses 4-tuple (Remote Address, Local Port, Remote Port, UDP) to match packets.

### Limitations
- Only ethernet interfaces are supported
- IPv6 Option Headers are not supported
- Only support at most 1 level VLAN header

## Build
### Dependencies
- libbpf
- clang

### Build
- Just cd into this directory and type
```sh
make
```

## Usage
### Setup
1. Attach BPF programs

   - ` warp_bpf.sh attach <devname> `

2. Add tuple and routing id to BPF map

   - ` warp_bpf_cli add <remote_addr> <local_port> <remote_port> <routing id delimited with spaces> `
   - IPv4 address show be presented in IPv6-compact format: `::a.b.c.d`

3. Enjoy!

### Teardown
1. Detach BPF programs
   - ` warp_bpf.sh detach <devname> `

2. Unpin BPF map so that it can be destroyed
   - `warp_bpf.sh teardown`

## Notes
1. I assume your bpf filesystem is mounted at `/sys/fs/bpf`