CLANG ?= clang

default: deps
	# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	# ${CLANG}  -g -O2 -I ./libbpf/src/root/usr/include -I .  -target bpf -D__TARGET_ARCH_x86 -c ipaddr.bpf.c -o ipaddr.bpf.o
	${CLANG}  -g -O2  -I .  -target bpf -D__TARGET_ARCH_x86 -c ipaddr.bpf.c -o ipaddr.bpf.o
	bpftool gen skeleton ipaddr.bpf.o > ipaddr.skel.h
	# gcc ipaddr.c -I ./libbpf/src/root/usr/include -L ./libbpf/src/root/usr/lib64  -lbpf -o ipaddr
	gcc ipaddr.c   -lbpf -o ipaddr
deps:
	@bpftool version > /dev/null
	@ls /sys/kernel/btf/vmlinux > /dev/null

clean:
	rm vmlinux.h ipaddr.bpf.o ipaddr.skel.h ipaddr

.PHONY: default clean deps