CC = gcc
CFLAGS = -O2 -g
CLANG = clang

all: cli warp_bpf

cli:
	$(CC) $(CFLAGS) -o warp_bpf_cli warp_bpf_cli.c

warp_bpf:
	$(CLANG) $(CFLAGS) -I /usr/include/x86_64-linux-gnu -target bpf -c -o warp_bpf.o warp_bpf.c

clean:
	rm *.o warp_bpf_cli