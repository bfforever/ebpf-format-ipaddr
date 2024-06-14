#include "common.h"

#define NULL ((void *)0)
#define MAX_IP4_LEN  16
#define MAX_IP6_LEN  40

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

struct buf {
    char data[MAX_IP6_LEN];
    __u32 ret;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct buf);
} tmp_buf SEC(".maps");

#define BPF_LOG(l, t, f, ...)                                                                                          \
    do {                                                                                                               \
        char fmt[] = "[" #t "] " #l ": " f "";                                                                     \
        bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__);                                                         \
    } while (0)

static inline void convert_v4(char* data, u32 ip) {
    u8 ip1 = (ip >> 24) & 0xFF;
    u8 ip2 = (ip >> 16) & 0xFF;
    u8 ip3 = (ip >> 8) & 0xFF;
    u8 ip4 = (ip >> 0) & 0xFF;

    char tmp[MAX_IP4_LEN];
    tmp[2] = '0' + (ip1 % 10);
    ip1 /= 10;
    tmp[1] = '0' + (ip1 % 10);
    ip1 /= 10;
    tmp[0] = '0' + (ip1 % 10);
    tmp[3] = '.';

    tmp[6] = '0' + (ip2 % 10);
    ip2 /= 10;
    tmp[5] = '0' + (ip2 % 10);
    ip2 /= 10;
    tmp[4] = '0' + (ip2 % 10);
    tmp[7] = '.';

    tmp[10] = '0' + (ip3 % 10);
    ip3 /= 10;
    tmp[9] = '0' + (ip3 % 10);
    ip3 /= 10;
    tmp[8] = '0' + (ip3 % 10);
    tmp[11] = '.';

    tmp[14] = '0' + (ip4 % 10);
    ip4 /= 10;
    tmp[13] = '0' + (ip4 % 10);
    ip4 /= 10;
    tmp[12] = '0' + (ip4 % 10);

    *data++ = tmp[12];
    *data++ = tmp[13];
    *data++ = tmp[14];
    *data++ = tmp[11];
    *data++ = tmp[8];
    *data++ = tmp[9];
    *data++ = tmp[10];
    *data++ = tmp[7];
    *data++ = tmp[4];
    *data++ = tmp[5];
    *data++ = tmp[6];
    *data++ = tmp[3];
    *data++ = tmp[0];
    *data++ = tmp[1];
    *data++ = tmp[2];
    
    *data = '\0';
}

static const char hex_digits[16] = "0123456789abcdef";
static inline void convert_v6(char* data, u32* ip6) {

    for (int i = 0; i < 4;i++) {
        u32 ip = *(ip6 + i); 
        u16 ip_1 = (ip >> 0) & 0xFFFF;
        u16 ip_2 = (ip >> 16) & 0xFFFF;
        for (int j = 0; j < 2;j++) {
            u16 ip_1 = (ip) & 0xFFFF;
            u8 h_1 = (ip_1 >> 0) & 0xFF; 
            u8 h_2 = (ip_1 >> 8) & 0xFF; 
            *data++ = hex_digits[(h_1 >> 4) & 0xF]; 
            *data++ = hex_digits[(h_1 >> 0) & 0xF]; 
            *data++ = hex_digits[(h_2 >> 4) & 0xF];
            *data++ = hex_digits[(h_2 >> 0) & 0xF]; 
            *data++ = ':';
            ip = ip >> 16;
        }
    }
    data--;
    *data = '\0';
}
/* 2001:0db8:3333:4444:CCCC:DDDD:EEEE:FFFF */
/* 192.168.000.001 */
static inline char* ip2str(u32* ip_ptr, bool v4) {
	struct buf* buf;
    int zero = 0;
    int ret;
    buf  = bpf_map_lookup_elem(&tmp_buf, &zero);
    if (!buf)
        return NULL;
    if (v4) {
        u32 ip = *ip_ptr;
        convert_v4(buf->data, ip);
    }else {
        convert_v6(buf->data, ip_ptr);
    }
	return buf->data;
}