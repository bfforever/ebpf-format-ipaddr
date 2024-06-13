#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_log.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/inet_csk_get_port")
int BPF_KPROBE(inet_csk_get_port, struct sock *sk, unsigned short snum)
{
	// pid_t pid;
	// // const char *filename;

	// pid = bpf_get_current_pid_tgid() >> 32;
	// // filename = BPF_CORE_READ(name, name);
    
	// bpf_printk("KPROBE ENTRY pid = %d, snum = %d\n", pid, snum);

	u64 ip = 3232235777;  /* 192.168.1.1 */
	u64 ip1 = 3232235623;  /* 192.168.1.1 */
	__u16 port = 8;
	__u32 port1 = 8000;
	__u32 port0 = 10004;
	BPF_LOG(DEBUG, KMESH, "i want to print addr %pI4h:%u HHHHH",&ip1, port);
	return 0;
}

SEC("kretprobe/inet_csk_get_port")
int BPF_KRETPROBE(inet_csk_get_port_exit, int ret)
{
	return 0;
}