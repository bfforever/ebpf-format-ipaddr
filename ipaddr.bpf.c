#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct log_event {
    __u32 ret;
    char msg[MAX_MSG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct log_event);
} heap SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/inet_csk_get_port")
int BPF_KPROBE(inet_csk_get_port, struct sock *sk, unsigned short snum)
{
	pid_t pid;
	// const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	// filename = BPF_CORE_READ(name, name);
    
	bpf_printk("KPROBE ENTRY pid = %d, snum = %d\n", pid, snum);
	/* 
	
	
	 */
	struct log_event *e;
	__u32 zero = 0;
	__u32 ret;
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 0;
	}
	__u32 ip = 3232235777;  /* 192.168.1.1 */
	__u16 port = 5000;
	ret = kmesh_snprintf(e->msg, "i want to print addr %pI4h:%u, HHHHH", ip, port);
	e->ret = ret;
	bpf_printk("e->ret:%d", ret);
	bpf_printk("msg:%s", e->msg);
	return 0;
}

SEC("kretprobe/inet_csk_get_port")
int BPF_KRETPROBE(inet_csk_get_port_exit, int ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %d\n", pid, ret);
	return 0;
}