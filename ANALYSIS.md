# CVE-2026-43499 (GhostLock) — POCO air (5.15.180 GKI) port analysis

Target: Redmi 13C 5G / POCO M6 5G, codename `air`, build `AP3A.240905.015.A2`,
kernel **5.15.180-android13 GKI**. Baseline = upstream CyberMeowfia/IonStack
`CVE-2026-43499` (6.x GKI ports).

================================================================================
1) TL;DR
================================================================================
The pselect stack-overwrite technique (used by the 6.x Pixel ports) is **NOT
VIABLE on 5.15.180 GKI**. Confirmed by disassembling the real
`kernel_5-15-180-vmlinux.elf`. Same blocker oppo-ghostlock hit on 5.10
("waiter 120 bytes below fd_set, fdset cannot reach it"). The exploit fails at
physrw init, not at KASLR. The tokay alternate TCP route is also structurally a
miss on 5.15 (analyzed separately below).

What already works on-device: KASLR base (SLIDE_KERNEL_BASE_KNOWN, slide=0), the
boot_id .data offset (0x02dc5a19), MINIMAL_INSTALL build, and the preload.so
launch. The remaining blocker is a kernel stack-frame incompatibility, not a code
bug. The merged run logs are in RUNLOGS.md.

================================================================================
2) Evidence — 5.15.180 frame sizes (from Target/kernel_5-15-180-vmlinux.elf)
================================================================================
Disassembled with llvm-objdump (no DWARF/BTF in the elf, so pahole fails):
- __arm64_sys_pselect6 : SUB SP,#0xa0   (fffffc00857da30)
- core_sys_select      : SUB SP,#0x1c0  (fffffc00857c454)
- do_select            : stp [sp,#-0x60]! + SUB SP,#0x360 = 0x3c0 (fffffc00857cbf0)
- core_sys_select fd_set bitmaps at sp+0x100 (stp xzr at [sp,#0x100..0x140])
- do_select poll_wqueues/rt_mutex_waiter at sp+0xe0 (add x0,sp,#0xe0)
- core_sys_select zeroes the select_waiter/rt_mutex_waiter at sp+0xc0..sp+0xe0
  (stp xzr at [sp,#0xc0/#0xd0/#0xe0]) — this is the dangling waiter slot.

oppo measured (5.10, IDA): fd_set @ stack_top-0x210, waiter @ stack_top-0x288,
gap 0x78=120B. fdset grows DOWN toward lower addrs; waiter is at HIGHER addr
(deeper stack) -> unreachable. SAME gap on 5.15.180 because frame sizes identical.

KEY: on 5.15 do_select is INLINED into core_sys_select, so the dangling
rt_mutex_waiter pointer lives in core_sys_select's OWN frame at sp+0xc0. The
fd_set bitmaps start at sp+0x100 — 0x40 (64 bytes) ABOVE the waiter, growing
away from it. The exploit's prepare_pselect_fdsets writes fd_set words 0-3
(sp+0x100+), which can never reach sp+0xc0.

================================================================================
3) Why the run fails the way it does (see RUNLOGS.md)
================================================================================
- KASLR base OK: bootid_data=ffffff8002dc5a19 (hardcoded off correct),
  slide-kaslr-known base=ffffffc008000000 slide=0. SLIDE_KERNEL_BASE_KNOWN works.
- "bad leaked pointer=d14b57df18a6ea32" = the LITERAL boot_id UUID bytes (first 8
  LE). Means /proc/sys/kernel/random/boot_id served the real UUID -> the pselect
  corruption NEVER overwrote boot_id.data. Harmless (base-known path doesn't use it).
- sched_ok=0 last_sched_ret=-1 every attempt: sched_setattr reorders the waiter
  but the faked fdset words don't overlap the real rt_mutex_waiter fields.
- pipe physrw read_ok=0 write_ok=0 rw64=0/0 -> physrw never established -> no root.

================================================================================
4) The real bug (stack-layout, not offset)
================================================================================
src/slide.c:107 words[] table (word 0..13 -> fd_set bytes) is tuned for 6.x GKI
frame layout (tokay/fuxi/lamu are all 6.6.x). On 5.15 the waiter is NOT overlapped
by fd_set, so the corruption lands nowhere. Why 6.x works (oppo adaptation-guide):
"Pixel 10 success: pselect's stack_fds coincide with rt_waiter on the kernel
stack" — 6.x reshuffled core_sys_select/do_select so fd_set sits ON the waiter.
5.15/5.10 do not.

================================================================================
5) Exploit architecture (what pselect actually does)
================================================================================
The fake kernel page is built ENTIRELY in USER memory (skb_buf) with correct
layout: rt_mutex_waiter (fake_w0), rt_mutex (fake_lock), task_struct (fake_task),
file_operations (fake_fops). See prepare_skb_payload() in util.c:444.

The pselect corruption's ONLY job: overwrite a kernel STACK pointer (the
rt_mutex_waiter pointer left by the GhostLock futex UAF) so it points at our USER
page. Then the futex PI chain walk reads the fake waiter from user memory -> kernel
treats our page as a real kernel object -> install_pipe_physrw() reclaims it as a
pipe_buffer -> arbitrary physrw.

Our air fork route structure (shared src/, NOT tokay's):
- main.c waiter_thread -> do_pselect_fake_lock_route() (fops.c:88) -> route_done
- fops.c:88 do_pselect_fake_lock_route(): prepare_pselect_fdsets() writes
    in[0]=fake_w0, ex[0]=init_task, ex[1]=fake_lock, ex[2]=3 (WORDS 0-3 only)
  then pselect(PSELECT_ROUTE_NFDS,...) + consumer sched_setattr reorder.
  On success -> try_cfi_stage() (fops.c:287) -> install_pipe_physrw() + root.

Struct offsets (rt_mutex_waiter etc.) are STABLE across GKI 5.10->6.6, so the bug
is purely frame layout, not struct layout.

================================================================================
6) PATH A — different stack-overlapping syscall
================================================================================
Goal: a syscall whose userspace-controlled buffer overlaps the freed
rt_mutex_waiter location on 5.15, to redirect the dangling pointer to our user
page. oppo suggested process_vm_readv iovec, binder, io_uring, setsockopt.

CONCLUSION (from frame analysis): will NOT work as a replacement for pselect,
because the dangling waiter pointer lives in core_sys_select's OWN frame (sp+0xc0),
reachable ONLY by a syscall that writes into THAT frame. Only pselect writes fd_set
there; its fd_set is 64B too high. A different corruption syscall writes into ITS
OWN frame, not core_sys_select's.

================================================================================
7) PATH B — tokay TCP route (do_tcp_fake_lock_route), analyzed 2026-07-16
================================================================================
tokay's fops.c has an ALTERNATE route (do_tcp_fake_lock_route @431) our shared
fork lacks. It does NOT use pselect:
- opens a TCP socketpair, builds a stack-local zc[0x40] in the waiter thread,
- fills zc with fake fields: waiter_task @ zc+0x28, fake_lock @ zc+0x30,
- calls getsockopt(IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc, &len) while a
  sched_setattr consumer thread is armed (same punch mechanism as pselect).
Mechanism: TCP_ZEROCOPY_RECEIVE copy_from_user()s the user zc onto the kernel
stack; if that slot coincides with the frozen rt_mutex_waiter from the futex PI
requeue race, the waiter pointer is redirected to the fake page.

5.15.180 vmlinux frame analysis:
- futex_wait_requeue_pi frame = 0x1b0  (waiter thread's rt_mutex_waiter local at
  the TOP of this frame, sp+0 of that frame).
- tcp_zerocopy_receive frame = 0x60 + 0x1d0 = 0x230.
  The zc struct is copied to ~sp+0xd0 .. sp+0x150 (confirmed: stack zeroing of
  [x24,#0x70..#0xf0] where x24 = sp+0x60, just before copy_from_user fills zc).
- Same-thread geometry: after futex_wait_requeue_pi returns (waiter at old sp+0,
  i.e. 0x1b0 below the new entry sp), the thread enters tcp_zerocopy_receive and
  its zc lands at sp+0xd0. That is 0x1b0 - 0xd0 = 0xe0 bytes ABOVE the old waiter
  slot. => zc does NOT coincide with the dangling waiter on 5.15 either.

CONCLUSION: the TCP route targets a DIFFERENT frame than pselect, but on 5.15 its
zc buffer is also 0xe0 bytes away from the frozen rt_mutex_waiter. Same structural
miss as pselect (different offset). Porting it would need a 6.x vmlinux to prove
the coincidence exists there, or retuning zc offsets — unlikely to help since the
gap is fixed by frame size, not field layout.

================================================================================
8) VERDICT — 6.1 vs 5.15 frame diff (CONFIRMED with vmlinux-6.1.elf)
================================================================================
6.1 GKI ELF built from boot-6.1-allsyms.img (kernel6.1_unpack/vmlinux-6.1.elf).
Frame sizes are IDENTICAL between 6.1 and 5.15 for every function except the
syscall wrapper:

  Function                  | 6.1 frame | 5.15 frame
  --------------------------|-----------|-----------
  __arm64_sys_pselect6      | 0x90      | 0xa0
  core_sys_select           | 0x1c0     | 0x1c0
  do_select                 | 0x3c0     | 0x3c0 (INLINED into core_sys_select on 5.15)
  futex_wait_requeue_pi     | 0x1b0     | 0x1b0
  tcp_zerocopy_receive      | 0x230     | 0x230

THE KEY DIFFERENCE: on 5.15 `do_select` is INLINED into `core_sys_select`, so the
select_waiter / rt_mutex_waiter lives inside core_sys_select's own frame at
sp+0xc0. On 6.1 `do_select` is a SEPARATE function (distinct symbol), so the
rt_mutex_waiter lives in do_select's OWN frame, which sits DEEPER on the stack
(below core_sys_select's fd_set region). That is why 6.x fd_set overlaps the
waiter but 5.15's does not: the inline expansion moved the waiter UP into
core_sys_select's frame, 64 bytes ABOVE the fd_set bitmaps (sp+0x100).

CONFIRMED: this exploit variant (pselect/tcp stack-overwrite -> physrw) is
INCOMPATIBLE with 5.15.180 GKI specifically because of the do_select inlining.
6.x works only because do_select is a separate function. The frame SIZES are the
same; the INLINING is the shift. oppo confirmed no working 5.15/5.10 pselect
alternative exists in any repo (their physrw was never completed; slide pselect
marked BLOCKED/DEAD).

OPTIONS TO ACTUALLY GET ROOT ON 5.15:
  (a) Force do_select to be a separate function / match the 6.1 layout — NOT
      feasible without rebuilding the kernel (inlining is a compiler decision).
      A kernel build flag or Clang version change could alter it, but that is
      out of scope for a runtime exploit.
  (b) Find a DIFFERENT primary exploit primitive for 5.15 (a 5.15-specific UAF/
      heap bug). Out of scope for this repo.
  (c) Accept that this GhostLock chain targets 6.x GKI only; 5.15 needs a
      different CVE/primitive.

================================================================================
9) What is already correct (do NOT touch)
================================================================================
- SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x02dc5a19 (exlog5-verified, correct).
- boot_id resolver removal / MINIMAL_INSTALL / common.h kmalloc guards /
  SLIDE_KERNEL_BASE_KNOWN / SLIDE_MAX_ATTEMPTS=8.
- Build works (system lld symlinked to NDK ld.lld; clang->clang-21).
- In-file modifications are documented in MODIFICATIONS.md.

================================================================================
10) rt_mutex_waiter offsets assumed (from lamu/fuxi target.h, GKI 6.6 — stable)
================================================================================
WAITER_TREE_ENTRY_OFF 0x00, WAITER_PI_TREE_ENTRY_OFF 0x18, WAITER_TASK_OFF 0x30,
WAITER_LOCK_OFF 0x38, WAITER_WAKE_STATE_OFF 0x40, WAITER_PRIO_OFF 0x44,
WAITER_DEADLINE_OFF 0x48, WAITER_WW_CTX_OFF 0x50
FAKE_WAITER_TREE_PRIO_OFF 0x18, FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28,
FAKE_WAITER_PI_TREE_PRIO_OFF 0x40, FAKE_WAITER_TASK_OFF 0x50, FAKE_WAITER_LOCK_OFF 0x58
These are STABLE across GKI (rt_mutex_waiter layout unchanged 5.10->6.6).

================================================================================
11) Key files
================================================================================
- exploit/src/slide.c : words[] @107, slide_pselect_stack_copy @139, sched_setattr @248
- exploit/src/fops.c  : do_pselect_fake_lock_route @88, prepare_pselect_fdsets @73
- exploit/src/targets/air-AP3A.240905.015.A2/target.h
- Target/kernel_5-15-180-vmlinux.elf (5.15 symbols, NO DWARF/BTF, use llvm-objdump)
- kernel6.1_unpack/vmlinux-6.1.elf (6.1 GKI ELF, built from boot-6.1-allsyms.img
  via libmagiskboot.so unpack + vmlinux-to-elf; used to confirm the do_select
  inlining difference vs 5.15)
- RUNLOGS.md (merged exlog*.txt), MODIFICATIONS.md (in-file changes)
- github_repos/adaptations/oppo-ghostlock-main/{AGENTS.md,docs/adaptation-guide.md}
- github_repos/adaptations/exploit_targets_fuxi-*/ and exploit_target_lamu_PD/
  (6.6 ports; same words[] as ours, plus tokay's do_tcp_fake_lock_route)
