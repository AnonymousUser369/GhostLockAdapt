/* tracefs_dump.c -- dump raw `caller` values from sched_blocked_reason
 * Build: $NDK/clang tracefs_dump.c -o tracefs_dump -static -O2
 * Run on device; prints one caller per line (hex) so the host can derive the KASLR slide.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define SLIDE_EVENT_ID   108

static volatile sig_atomic_t g_timed_out;
static void on_alarm(int s) { (void)s; g_timed_out = 1; }

static int tracefs_write(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n == (ssize_t)strlen(val);
}

/* dynamically find `caller` field offset from the event format file */
static int caller_field_offset(void) {
    int fd = open("/sys/kernel/tracing/events/sched/sched_blocked_reason/format", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[1024]; ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd);
    if (n <= 0) return -1; buf[n] = 0;
    char *p = strstr(buf, "caller");
    if (!p) return -1;
    int off = -1;
    sscanf(p, "caller;	offset:%d", &off);
    if (off < 0) sscanf(p, "caller; offset:%d", &off);
    if (off < 0) sscanf(p, "field:unsigned long caller; offset:%d", &off);
    return off;
}

static int parse_page(const unsigned char *pg, size_t pg_len, int coff, uint64_t *out, int maxout, int *nout) {
    int n = 0;
    if (pg_len < 20) return n;
    uint64_t commit; memcpy(&commit, pg + 8, sizeof(commit));
    size_t data_len = (size_t)(commit & 0xfffULL);
    size_t end = 16 + data_len; if (end > pg_len) end = pg_len;
    for (size_t pos = 16; pos + 4 <= end;) {
        uint32_t hd; memcpy(&hd, pg + pos, sizeof(hd));
        uint32_t t = hd & 0x1fU;
        if (t == 30) { pos += 8; continue; }
        if (t == 31) { pos += 12; continue; }
        if (t == 0 || t >= 29) break;
        size_t rec_len = (size_t)t * 4;
        size_t rec = pos + 4;
        if (rec + rec_len > end) break;
        uint16_t eid; memcpy(&eid, pg + rec, sizeof(eid));
        if (eid == SLIDE_EVENT_ID && rec_len >= (size_t)(coff + 8) && coff >= 0) {
            uint64_t caller; memcpy(&caller, pg + rec + coff, sizeof(caller));
            if (n < maxout) out[n++] = caller;
        }
        pos = rec + rec_len;
    }
    *nout = n;
    return n;
}

int main(void) {
    signal(SIGALRM, on_alarm);
    int coff = caller_field_offset();
    if (coff < 0) { fprintf(stderr, "[dump] cannot read caller offset\n"); return 1; }
    fprintf(stderr, "[dump] caller field offset=%d\n", coff);

    if (!tracefs_write("/sys/kernel/tracing/tracing_on", "0") ||
        !tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "1") ||
        !tracefs_write("/sys/kernel/tracing/tracing_on", "1")) {
        fprintf(stderr, "[dump] tracefs enable failed errno=%d\n", errno);
        return 1;
    }
    usleep(1000000);

    int nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t *all = malloc(sizeof(uint64_t) * 8192); int total = 0;
    for (int cpu = 0; cpu < nprocs && total < 8192; cpu++) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        unsigned char *buf = malloc(262144); ssize_t got = 0;
        /* trace_pipe_raw is not pollable; use a blocking read bounded by SIGALRM */
        g_timed_out = 0;
        alarm(2);
        while ((size_t)got < 262144) {
            ssize_t r = read(fd, buf+got, (size_t)(262144-got));
            if (r <= 0 || g_timed_out) break;
            got += r;
        }
        alarm(0);

        fprintf(stderr, "[dump] cpu=%d got=%zd\n", cpu, got);
        if (got > 0 && total == 0 && cpu == nprocs - 1) {
            fprintf(stderr, "[dump] first bytes: ");
            for (int d = 0; d < (got < 32 ? (int)got : 32); d++) fprintf(stderr, "%02x ", buf[d]);
            fprintf(stderr, "\n");
        }
        for (ssize_t off = 0; off < got && total < 8192;) {
            uint64_t commit; memcpy(&commit, buf+off+8, sizeof(commit));
            size_t data_len = (size_t)(commit & 0xfffULL);
            size_t page_end = off + 16 + data_len; if (page_end > (size_t)got) page_end = (size_t)got;
            int nout = 0; uint64_t out[64];
            parse_page(buf+off, page_end-off, coff, out, 64, &nout);
            for (int i = 0; i < nout && total < 8192; i++) all[total++] = out[i];
            off = (page_end + 15) & ~(size_t)15;
        }
        free(buf); close(fd);
    }
    tracefs_write("/sys/kernel/tracing/events/sched/sched_blocked_reason/enable", "0");
    tracefs_write("/sys/kernel/tracing/tracing_on", "0");

    fprintf(stderr, "[dump] %d caller values:\n", total);
    for (int i = 0; i < total; i++) printf("%016llx\n", (unsigned long long)all[i]);
    return 0;
}
