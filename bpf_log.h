#include "common.h"

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

#define BPF_LOG(l, t, f, args...)                                              \
  do {                                                                         \
    const char fmt[MAX_BUF_LEN] = "[" #t "] " #l ": " f "";                    \
    struct log_event *e;                                                       \
    __u32 zero = 0;                                                            \
    int ret;                                                                   \
    e = bpf_map_lookup_elem(&heap, &zero);                                     \
    if (!e) {                                                                  \
      break;                                                                   \
    }                                                                          \
    bpf_printk("before msg:%s", fmt);                                          \
    ret = kmesh_snprintf(e->msg, fmt);                                         \
    bpf_printk("ret is%d", ret);                                               \
    bpf_printk("after msg :%s", e->msg);                                       \
    ret = bpf_trace_printk(e->msg, ret+1, 3232235623, 5000);          \
    bpf_printk("ret is:%d", ret);                                              \
  } while (0)