#define __BPF_BUILTINS__
#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_MSG_LEN 100

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

static inline int convert_port(__u16 port, char *temp) {
    temp[0] = '0';
    temp[1] = '0';
    temp[2] = '0';
    temp[3] = '0';
    temp[4] = '0';

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

static inline __u32 kmesh_snprintf(char *msg, char *fmt, __u32 ip, __u16 port) {

    /* 
    encounter %p, format ip to xxx.xxx.xxx.xxx
     */
    char ip4_str[sizeof("255.255.255.255")];
    u8 iparr[4];
    iparr[0] = (ip >> 24) & 0xFF;
    iparr[1] = (ip >> 16) & 0xFF;
    iparr[2] = (ip >> 8) & 0xFF;
    iparr[3] = (ip >> 0) & 0xFF;

    char *ip4_ptr = ip4_str;
    int ip_l = 0;
    int ret;
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        u8 r = iparr[i];
        char temp[4];
        ret = convert(r, temp);
        ip_l += ret;
        char *d = temp;
        bpf_memcpy(ip4_ptr, d, ret);
        ip4_ptr += ret;
        if (i < 3) {
            *ip4_ptr++ = '.';
            ip_l++;
        }
    }
    // ip4_ptr = ip4_str;
    // for (int k= 0; k < ip_l; k++) {
    //     bpf_printk("ip cc:%c", *ip4_ptr++);
    // }


    int i = 0;
    int mod = 0;
    while (i < MAX_MSG_LEN && mod <= 2)
    {
        // if (*fmt == '%') 
        if (!*fmt)
            break;
        switch (*fmt)
        {
        case '%':
            fmt++;
            while (i < MAX_MSG_LEN) {
                if (*fmt == 'h') {
                    ip4_ptr = ip4_str;
                    bpf_printk("len is %d",ip_l);
                    bpf_memcpy(msg, ip4_ptr, ip_l);
                    msg += ip_l;
                    mod++;
                    i += ip_l;
                    break;
                }else if(*fmt == 'u') {
                    char tmp_port[5];  /* max len of 16 bit unsigned number is 65535 */
                    ret = convert_port(port, tmp_port);
                    char *d = tmp_port;
                    int cnt = 5 - ret;
                    bpf_memcpy(msg, d+ret, cnt);
                    msg += cnt;
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