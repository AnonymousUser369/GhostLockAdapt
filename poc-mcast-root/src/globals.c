//
// globals.c — definitions for extern globals declared in common.h but not
// defined by pipe.c / util.c / root.c (these were in exploit-finale main.c).
//
#include "common.h"

/* KASLR state (also set by poc_mcast_root.c main after tracefs leak) */
int kaslr_done = 0;
uint64_t kaslr_base = 0;
uint64_t kaslr_slide = 0;

/* kernelsnitch memfd leak handle (util.c references it) */
int memfd_leak = -1;

/* pipe async-prepare handshake flags (pipe.c references them; this variant
 * prepares synchronously via prepare_pipe_buffer_page's forked child, so these
 * are only used inside reset_pipe_attempt / install_pipe_physrw as no-ops). */
#include <stdatomic.h>
atomic_int pipe_prepare_request = 0;
atomic_int pipe_prepare_done = 0;

/* runtime-resolved slide symbol (util.c log_startup_context references it) */
uintptr_t slide_random_boot_id_data = 0;

/* legacy physrw proof page base (used by dead install_pipe_physrw in pipe.c) */
uintptr_t page_base = 0;

/* elapsed-seconds timestamp helper for progress logs */
double now_s(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    static double start = -1;
    double cur = tv.tv_sec + tv.tv_usec / 1e6;
    if (start < 0) start = cur;
    return cur - start;
}
