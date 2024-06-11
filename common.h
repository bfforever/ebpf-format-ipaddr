
#define MAX_BUF_LEN 100
#define MAX_IP4_LEN 15
#define MAX_PORT_LEN 5
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
    temp[3] = '\0';

    // int i;
    // for (int k = 2;k >= 0;k--) {

    // }
    // if (r < 10) {
    //     temp[0] = '0' + r;
    //     return 1;        
    // }else if (r >= 10 && r < 100) {
    //     i = 1;
    //     while (r > 0 && i >= 0) {
    //         temp[i] = '0' + (r % 10);
    //         r /= 10;
    //         i--;
    //     }
    //     return 2;
    // }else {
    //     i = 2;
    //     while (r > 0 && i >= 0) {
    //         temp[i] = '0' + (r % 10);
    //         r /= 10;
    //         i--;
    //     }
    //     return 3;
    // }
    temp[2] = '0' + (r % 10);
    r /= 10;
    temp[1] = '0' + (r % 10);
    r /= 10;
    temp[0] = '0' + (r % 10);
    return 3;
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

static inline int format_ipv4addr(u64 ip, char ip4_str[MAX_IP4_LEN]) {
    u8 iparr[4];
    iparr[0] = (ip >> 24) & 0xFF;
    iparr[1] = (ip >> 16) & 0xFF;
    iparr[2] = (ip >> 8) & 0xFF;
    iparr[3] = (ip >> 0) & 0xFF;

    int ip_l = 0;
    int ret;
    int i = 0;
#pragma clang loop unroll(full)
    for (int n = 0; n < 4; n++) {
        u8 r = iparr[n];
        char temp[4];
        ret = convert(r, temp);
        ip_l += ret;
        ip4_str[i++] = temp[0];
        ip4_str[i++] = temp[1];
        ip4_str[i++] = temp[2];
        if (n < 3) {
            ip4_str[i++] = '.';
            ip_l++;
        }
    }
    bpf_printk("i is %d",i);
    return ip_l;
}

static __always_inline __u32 kmesh_snprintf(char *msg , const char fmt[MAX_BUF_LEN], u64 *data, u64 data_len) {
    int i = 0;
    int flag = 0;
    int j = 0;
    int mod = 0;

#pragma clang loop unroll(full)
    for (i = 0; i < MAX_BUF_LEN; i++) {
        if (fmt[i] == '\0')
            break;
        // if (fmt[i] == '%' && i+1 < MAX_BUF_LEN && fmt[i+1] == 'p') {
            // flag = 1;
            // continue;
        // }
        if (fmt[i] == '%') {
            flag = 1;
            continue;
        }
        if (flag && fmt[i] == 'h') {
            u64 ip = (u64)*(u64*) *(data + mod);
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

            *msg++ = tmp[0];
            *msg++ = tmp[1];
            *msg++ = tmp[2];
            *msg++ = tmp[3];
            *msg++ = tmp[4];
            *msg++ = tmp[5];
            *msg++ = tmp[6];
            *msg++ = tmp[7];
            *msg++ = tmp[8];
            *msg++ = tmp[9];
            *msg++ = tmp[10];
            *msg++ = tmp[11];
            *msg++ = tmp[12];
            *msg++ = tmp[13];
            *msg++ = tmp[14];
            j += MAX_IP4_LEN;
            mod++;
            flag = 0;
            continue;
        }
        if (flag && fmt[i] == 'u') {
            
            u64 p = data[mod];
            if (p > 65535)
                return -EINVAL;
            char tmp[MAX_PORT_LEN];
            tmp[4] = '0' + p % 10;
            p /= 10;
            tmp[3] = '0' + p % 10;
            p /= 10;
            tmp[2] = '0' + p % 10;
            p /= 10;
            tmp[1] = '0' + p % 10;
            p /= 10;
            tmp[0] = '0' + p % 10;

            *msg++ = tmp[0];
            *msg++ = tmp[1];
            *msg++ = tmp[2];
            *msg++ = tmp[3];
            *msg++ = tmp[4];
            j += MAX_PORT_LEN;
            mod++;
            flag = 0;
            continue;
        }
        if (flag)
            continue;
        *msg++ = fmt[i];
        j++;
    }
    return j;
}