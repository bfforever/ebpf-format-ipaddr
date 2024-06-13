#define MAX_BUF_LEN 100

static __always_inline __u32 kmesh_snprintf(char *msg , const char fmt[MAX_BUF_LEN]) {
    int i = 0;
    int flag = 0;
    int j = 0;
    int mod = 0;

#pragma clang loop unroll(full)
    for (i = 0; i < MAX_BUF_LEN; i++) {
        if (fmt[i] == '\0')
            break;
        if (fmt[i] == '%' && i+1 < MAX_BUF_LEN && fmt[i+1] == 'p') {
            flag = 1;
            continue;
        }
        if (flag && fmt[i] == 'h') {
            *msg++ = '%';   
            *msg++ = 'u';
            j+=2;
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