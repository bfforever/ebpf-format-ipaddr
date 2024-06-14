#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_log.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/inet_csk_get_port")
int BPF_KPROBE(inet_csk_get_port, struct sock *sk, unsigned short snum)
{
	u64 ip = bpf_htonl(3232235777);  /* 192.168.1.1 */
	u64 ip1 = 3232235623;  /* 192.168.1.1 */
	__u16 port = 8;
	__u32 port1 = 8000;
	__u32 port0 = 10004;
	BPF_LOG(DEBUG, KMESH, "i want to print addr %s:%u HHHHH", ip2str(&ip, 1), port1);
/* ==================================================================================================== */
	bpf_printk("test ipv6");
	u32 ip6[4] = {0};
	// IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    // Split into four 32-bit parts
    ip6[0] = bpf_htonl(0x20010db8);
    ip6[1] = bpf_htonl(0x85a30000);
    ip6[2] = bpf_htonl(0x00008a2e);
    ip6[3] = bpf_htonl(0x03707334);
	bpf_printk("user_ip6 [%pI6]", ip6);
	BPF_LOG(DEBUG, KMESH, "i want to print addr %s:%u HHHHH", ip2str(ip6, 0), port1);
	return 0;
}

SEC("cgroup/connect6")
int test_connect6(struct bpf_sock_addr *ctx) {

	bpf_printk("test ipv6");
	u32 ip6[4];
	// IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    // Split into four 32-bit parts
    ip6[0] = bpf_htonl(0x20010db8);
    ip6[1] = bpf_htonl(0x85a30000);
    ip6[2] = bpf_htonl(0x00008a2e);
    ip6[3] = bpf_htonl(0x03707334);
	bpf_printk("user_ip6 :%pI6", ip6);
	return 0;
}