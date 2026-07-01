/*
 * Freestanding aarch64 PID-1 for the HVF egress relay live-proof guest.
 *
 * Reads `mvm.egress_target=<host:port>` from /proc/cmdline (the harness injects
 * the discovered LAN address there — never hardcoded), connects the vsock egress
 * port, sends "<target>\n" then "ping", and prints the proxied reply. The target
 * is newline-delimited because the host run loop relays the guest's egress stream
 * byte-for-byte to the endpoint UDS: vsock frame boundaries are lost, so the
 * endpoint recovers the target by reading up to the first '\n' (the same framing
 * the in-guest SOCKS egress client uses).
 *
 * No libc: raw arm64 syscalls via `svc #0`. Built by build.sh.
 */

static long sc(long n, long a, long b, long c, long d, long e) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}

#define SYS_WRITE 64
#define SYS_READ 63
#define SYS_CLOSE 57
#define SYS_OPENAT 56
#define SYS_SOCKET 198
#define SYS_CONNECT 203
#define SYS_MOUNT 40
#define AT_FDCWD -100

/* vsock guest ports — must match mvm_guest::vsock. */
#define EGRESS_PORT 5253
#define WORKLOAD_EXIT_PORT 5251
#define AF_VSOCK 40
#define SOCK_STREAM 1
#define VMADDR_CID_HOST 2

static long slen(const char *s) {
    long n = 0;
    while (s[n]) n++;
    return n;
}
static void out(const char *s, long n) { sc(SYS_WRITE, 1, (long)s, n, 0, 0); }
static void outs(const char *s) { out(s, slen(s)); }

/* Connect an AF_VSOCK stream to the host (cid 2) on `port`; -1 on failure. */
static long vconnect(unsigned port) {
    long s = sc(SYS_SOCKET, AF_VSOCK, SOCK_STREAM, 0, 0, 0);
    if (s < 0) return -1;
    unsigned char addr[16];
    for (int i = 0; i < 16; i++) addr[i] = 0;
    addr[0] = AF_VSOCK;            /* svm_family */
    addr[4] = port & 0xff;        /* svm_port, LE u32 */
    addr[5] = (port >> 8) & 0xff;
    addr[6] = (port >> 16) & 0xff;
    addr[7] = (port >> 24) & 0xff;
    addr[8] = VMADDR_CID_HOST;     /* svm_cid */
    if (sc(SYS_CONNECT, s, (long)addr, 16, 0, 0) != 0) {
        sc(SYS_CLOSE, s, 0, 0, 0, 0);
        return -1;
    }
    return s;
}

void _start(void) {
    outs("\n>>> USERSPACE: egress relay test (vsock-only) <<<\n");

    /* procfs, so we can read the kernel cmdline the harness injected the target into. */
    sc(SYS_MOUNT, (long)"proc", (long)"/proc", (long)"proc", 0, 0);

    static char cmd[2048];
    long fd = sc(SYS_OPENAT, AT_FDCWD, (long)"/proc/cmdline", 0, 0, 0);
    long n = 0;
    if (fd >= 0) {
        n = sc(SYS_READ, fd, (long)cmd, sizeof(cmd) - 1, 0, 0);
        sc(SYS_CLOSE, fd, 0, 0, 0, 0);
    }
    if (n < 0) n = 0;
    cmd[n] = 0;

    /* Extract mvm.egress_target=<value> up to a space/newline. */
    static const char key[] = "mvm.egress_target=";
    long klen = sizeof(key) - 1;
    static char tgt[128];
    long tlen = 0;
    for (long i = 0; i + klen <= n; i++) {
        long j = 0;
        while (j < klen && cmd[i + j] == key[j]) j++;
        if (j == klen) {
            long p = i + klen;
            while (p < n && cmd[p] != ' ' && cmd[p] != '\n' && cmd[p] != 0 &&
                   tlen < (long)sizeof(tgt) - 1) {
                tgt[tlen++] = cmd[p++];
            }
            break;
        }
    }
    tgt[tlen] = 0;

    if (tlen > 0) {
        long s = vconnect(EGRESS_PORT);
        if (s >= 0) {
            sc(SYS_WRITE, s, (long)tgt, tlen, 0, 0); /* target... */
            sc(SYS_WRITE, s, (long)"\n", 1, 0, 0);   /* ...newline-delimited */
            sc(SYS_WRITE, s, (long)"ping", 4, 0, 0); /* request bytes */
            static char buf[128];
            long r = sc(SYS_READ, s, (long)buf, sizeof(buf), 0, 0);
            if (r > 0) {
                outs(">>> egress reply over vsock: ");
                out(buf, r);
                outs("\n");
            } else {
                outs(">>> no egress reply (refused)\n");
            }
            sc(SYS_CLOSE, s, 0, 0, 0, 0);
        } else {
            outs(">>> egress connect failed\n");
        }
    } else {
        outs(">>> no mvm.egress_target in cmdline\n");
    }

    /* Transient run-to-exit: report exit code 0 on the workload-exit port. */
    long e = vconnect(WORKLOAD_EXIT_PORT);
    if (e >= 0) {
        unsigned char code[4] = {0, 0, 0, 0};
        sc(SYS_WRITE, e, (long)code, 4, 0, 0);
        sc(SYS_CLOSE, e, 0, 0, 0, 0);
    }
    for (;;) asm volatile("" ::: "memory");
}
