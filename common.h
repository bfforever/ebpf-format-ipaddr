
#define MAX_MSG_LEN 150
#define	EINVAL		22	/* Invalid argument */

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif

#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif

#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_fill0(arr, p, x) do {} while (0)
#define ___bpf_fill1(arr, p, x) arr[p] = x
#define ___bpf_fill2(arr, p, x, args...) arr[p] = x; ___bpf_fill1(arr, p + 1, args)
#define ___bpf_fill3(arr, p, x, args...) arr[p] = x; ___bpf_fill2(arr, p + 1, args)
#define ___bpf_fill4(arr, p, x, args...) arr[p] = x; ___bpf_fill3(arr, p + 1, args)
#define ___bpf_fill5(arr, p, x, args...) arr[p] = x; ___bpf_fill4(arr, p + 1, args)
#define ___bpf_fill6(arr, p, x, args...) arr[p] = x; ___bpf_fill5(arr, p + 1, args)
#define ___bpf_fill7(arr, p, x, args...) arr[p] = x; ___bpf_fill6(arr, p + 1, args)
#define ___bpf_fill8(arr, p, x, args...) arr[p] = x; ___bpf_fill7(arr, p + 1, args)
#define ___bpf_fill9(arr, p, x, args...) arr[p] = x; ___bpf_fill8(arr, p + 1, args)
#define ___bpf_fill10(arr, p, x, args...) arr[p] = x; ___bpf_fill9(arr, p + 1, args)
#define ___bpf_fill11(arr, p, x, args...) arr[p] = x; ___bpf_fill10(arr, p + 1, args)
#define ___bpf_fill12(arr, p, x, args...) arr[p] = x; ___bpf_fill11(arr, p + 1, args)
#define ___bpf_fill(arr, args...) \
	___bpf_apply(___bpf_fill, ___bpf_narg(args))(arr, 0, args)

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static inline int convert(int r, char* temp) {
    temp[0] = '0';
    temp[1] = '0';
    temp[2] = '0';
    temp[3] = '0';

    int i;
    if (r < 10) {
        temp[0] = '0' + r;
        return 1;        
    }else if (r >= 10 && r < 100) {
        i = 1;
        while (r > 0 && i >= 0) {
            temp[i] = '0' + (r % 10);
            r /= 10;
            i--;
        }
        return 2;
    }else {
        i = 2;
        while (r > 0 && i >= 0) {
            temp[i] = '0' + (r % 10);
            r /= 10;
            i--;
        }
        return 3;
    }
}

static inline int convert_port(u64 port, char *temp) {
    temp[0] = '0';
    temp[1] = '0';
    temp[2] = '0';
    temp[3] = '0';
    temp[4] = '0';
    temp[5] = '0';

    if (port == 0) {
        return 4;
    }
    int len = 0;
    int i = 4;
    while (port > 0 && i >= 0)
    {
        temp[i] = '0' + (port % 10);
        port /= 10;
        i--;
        len++;
    }
    return 5 - len;
}

static inline int format_ipv4addr(u32 ip, char *ip4_str) {
    u8 iparr[4];
    iparr[0] = (ip >> 24) & 0xFF;
    iparr[1] = (ip >> 16) & 0xFF;
    iparr[2] = (ip >> 8) & 0xFF;
    iparr[3] = (ip >> 0) & 0xFF;

    char *ip4_ptr = ip4_str;
    int ip_l = 0;
    int ret;
    for (int i = 0; i < 4; i++) {
        u8 r = iparr[i];
        char temp[4];
        ret = convert(r, temp);
        ip_l += ret;
        char *d = temp;
        for (int k = 0; k < ret; k++) {
            *ip4_ptr++ = *d++;
        }
        if (i < 3) {
            *ip4_ptr++ = '.';
            ip_l++;
        }
    }
    return ip_l;
}

static inline __u32 kmesh_snprintf(char *msg, const char *fmt, u64 *data, u32 data_len) {
    int i = 0;
    int mod = 0;
    int num_args;
    int ret;

    num_args = data_len / 8;
    bpf_printk("num_args : %d", num_args);
    bpf_printk("num_args 1: %lld", data[0]);
    bpf_printk("num_args 2: %d", data[1]);
    bpf_printk("num_args 3: %d", data[2]);
    while (i < MAX_MSG_LEN )
    {
        if (!*fmt)
            break;
        switch (*fmt)
        {
        case '%':
            fmt++;
            while (i < MAX_MSG_LEN) {
                if (*fmt == 'h') {
                    char ip4_str[sizeof("255.255.255.255")];
                    int ip_l = 0;
                    u32 ip = *(u32 *)(data[mod]);
                    ip_l = format_ipv4addr(ip, ip4_str);
                    char *ip4_ptr = ip4_str;
                    bpf_printk("len is %d",ip_l);
                    for (int k = 0; k < ip_l; k++) {
                        *msg++ = *ip4_ptr++;
                    }
                    mod++;
                    i += ip_l;
                    break;
                }else if(*fmt == 'u') {
                    char tmp_port[6];  /* max len of 16 bit unsigned number is 65535 */
                    u64 port = *((u64 *)data + mod);
                    if (port >= 65535)
                        return -EINVAL;
                    ret = convert_port(port, tmp_port);
                    char *d = tmp_port + ret;
                    int cnt = 5 - ret;
                #pragma unroll  
                    for (int k = 0; k < cnt - 1; k++) {
                        *msg++ = *d++;
                    }
                    *msg++ = *d;
                    mod++;
                    i += cnt;
                    break;
                }
                fmt++;
            }
            break;
        default:
            break;
        }
        if (*fmt == 'h' || *fmt == 'u') {
            fmt++;
            continue;
        }
        *msg++ = *fmt++;
        i++;
    }
    return i;
}