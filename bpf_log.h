#include "common.h"

#define Hello hello
#define Hello2 hello2

struct log_event {
    __u32 ret;
    char msg[MAX_BUF_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct log_event);
} heap SEC(".maps");

#define Kmesh_BPF_SNPRINTF(out, out_size, fmt, args...)		\
({								\
	unsigned long long ___param[___bpf_narg(args)];		\
	kmesh_snprintf(out, fmt,			\
		     ___param, sizeof(___param));		\
})

#define BPF_LOG(l, t, f, args...)                                                                                      \
    do {                                                                                                           \
        const char fmt[MAX_BUF_LEN] = "[" #t "] " #l ": " f "";                                                \
        struct log_event *e;                                                                               \
        __u32 zero = 0;                                                                                        \
        int ret;  \
        e = bpf_map_lookup_elem(&heap, &zero);     \
        if (!e) {                                    \
            break;                       \
        }                                             \
        unsigned long long ___param[___bpf_narg(args)];		\
        ___bpf_fill(___param, args);				\
        ret = kmesh_snprintf(e->msg, fmt, ___param, sizeof(___param));      \
        bpf_printk("ret is%d", ret);		\
        bpf_printk("after fmt msg :%s", e->msg);		\
    } while (0)
