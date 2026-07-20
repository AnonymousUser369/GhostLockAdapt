# CVE-2026-43499 (GhostLock) — POCO air (5.15.180 GKI) port analysis

Target: Redmi 13C 5G / POCO M6 5G, codename `air`, build `AP3A.240905.015.A2`
(Android 15), kernel **5.15.180-android13 GKI**. Baseline = upstream
CyberMeowfia/IonStack `CVE-2026-43499` (6.x GKI ports).

## 1) TL;DR
The pselect stack-overwrite technique (used by the 6.x Pixel ports) is **NOT
VIABLE on 5.15.180 GKI**. Confirmed by disassembling the real
`kernel_5-15-180-vmlinux.elf`. This is the same blocker oppo-ghostlock hit
on 5.10 ("waiter 120 bytes below fd_set, fd_set cannot reach it"). The
exploit fails at physrw init, not at KASLR. The tokay alternate TCP route
is also structurally a miss on 5.15 (analyzed below).

What already works on-device: KASLR base (SLIDE_KERNEL_BASE_KNOWN, slide=0),
the boot_id .data offset (0x02dc5a19), MINIMAL_INSTALL build, and the
preload.so launch. The remaining blocker is a kernel stack-frame
incompatibility, not a code bug. The merged run logs are in RUNLOGS.md.

## 2) Evidence — 5.15.180 frame layout (from kernel_5-15-180-vmlinux.elf)
Disassembled with llvm-objdump (no DWARF/BTF in the ELF, so pahole fails):
- __arm64_sys_pselect6 : SUB SP,#0xa0   (0xffffffc00857da30)
- core_sys_select      : SUB SP,#0x1c0  (0xffffffc00857c454)
- do_select            : SEPARATE function (NOT inlined). Prologue
  `stp x29,x30,[sp,#-0x60]!` + `sub sp,#0x360` => 0x3c0 frame (0xffffffc00857cbf0).
  Called by core_sys_select at 0x57c6bc.
- core_sys_select fd_set bitmaps at sp+0x100 (stp xzr at [sp,#0x100..0x140]).
- core_sys_select zeroes sp+0xc0..0xe0 (stp xzr) — these are poll_wqueues/select
  LOCALS, NOT the futex rt_mutex_waiter. The real rt_mutex_waiter is frozen in
  the FUTEX frame (futex_requeue / futex_lock_pi), a SEPARATE concurrent call chain.
- NOTE: this GKI uses SHADOW_CALL_STACK (str x30,[x18],#8 in prologue) — return
  addresses live on the x18 shadow stack, not the normal stack.

oppo measured (5.10, IDA): fd_set @ stack_top-0x210, waiter @ stack_top-0x288,
gap 0x78=120B. fd_set grows DOWN toward lower addrs; waiter is at HIGHER addr
(deeper stack) -> unreachable. SAME structural miss on 5.15.180.

KEY (verified): the pselect route relies on the fd_set buffer, once copied into
core_sys_select's kernel-stack frame (sp+0x100), landing on the SAME stack address
where the dangling rt_mutex_waiter pointer lives (frozen in the concurrent futex
frame). This is a per-frame OFFSET COINCIDENCE, not a total call-chain depth
issue: re-tracing downward call depths (analysis-scripts/find_chain_depths.py) shows
BOTH pselect (chain depth 0x1cec0) and io_uring (0x1cd60) far exceed the
856B (0x358) threshold — so depth is NOT the blocker. 6.x works because its
frame layout places fd_set ON the waiter offset; 5.15.180 does not.

The earlier "0 chains >= 0x358 / insufficient depth" reading came from a TOOLING
BUG in find_deep_chains.py (upward trace + paciasp-gating missed do_select);
do NOT rely on it. The real, empirically-confirmed blocker (RUNLOGS: corruption
never lands; oppo: BLOCKED/DEAD on 5.10/5.15) is the frame-offset
mismatch — the fd_set words do not coincide with the frozen waiter pointer on 5.15.

## 3) Why the run fails the way it does (see RUNLOGS.md)
- KASLR base OK: boot_id_data=ffffff8002dc5a19 (hardcoded off correct),
  slide-kaslr-known base=ffffffc008000000 slide=0. SLIDE_KERNEL_BASE_KNOWN works.
- "bad leaked pointer=d14b57df18a6ea32" = the LITERAL boot_id UUID bytes (first 8
  LE). Means /proc/sys/kernel/random/boot_id served the real UUID -> the pselect
  corruption NEVER overwrote boot_id.data. Harmless (base-known path doesn't use it).
- sched_ok=0 last_sched_ret=-1 every attempt: sched_setattr reorders the waiter
  but the faked fd_set words don't overlap the real rt_mutex_waiter fields.
- pipe physrw read_ok=0 write_ok=0 rw64=0/0 -> physrw never established -> no root.

## 4) The real bug (stack-layout, not offset)
src/slide.c:107 words[] table (word 0..13 -> fd_set bytes) is tuned for 6.x GKI
frame layout (tokay/fuxi/lamu are all 6.6.x). On 5.15 the waiter is NOT
overlapped by fd_set, so the corruption lands nowhere. Why 6.x works
(oppo adaptation-guide): "Pixel 10 success: pselect's stack_fds coincide with
rt_waiter on the kernel stack" — 6.x reshuffled core_sys_select/do_select so
fd_set sits ON the waiter. 5.15/5.10 do not.

## 5) Exploit architecture (what pselect actually does)
The fake kernel page is built ENTIRELY in USER memory (skb_buf) with correct
layout: rt_mutex_waiter (fake_w0), rt_mutex (fake_lock), task_struct (fake_task),
file_operations (fake_fops). See prepare_skb_payload() in util.c:444.

The pselect corruption's ONLY job: overwrite a kernel STACK pointer (the
rt_mutex_waiter pointer left by the GhostLock futex UAF) so it points at our
USER page. Then the futex PI chain walk reads the fake waiter from user memory ->
kernel treats our page as a real kernel object -> install_pipe_physrw() reclaims it as
a pipe_buffer -> arbitrary physrw.

Our air fork route structure (shared src/, NOT tokay's):
- main.c waiter_thread -> do_pselect_fake_lock_route() (fops.c:88) -> route_done
- fops.c:88 do_pselect_fake_lock_route(): prepare_pselect_fdsets() writes
    in[0]=fake_w0, ex[0]=init_task, ex[1]=fake_lock, ex[2]=3 (WORDS 0-3 only)
  then pselect(PSELECT_ROUTE_NFDS,...) + consumer sched_setattr reorder.
  On success -> try_cfi_stage() (fops.c:287) -> install_pipe_physrw() + root.

Struct offsets (rt_mutex_waiter etc.) are STABLE across GKI 5.10->6.6, so the
bug is purely frame layout, not struct layout.

## 6) PATH A — alternate stack-overlapping syscall (DEAD END)
Goal: a syscall whose user-space-controlled buffer overlaps the frozen
rt_mutex_waiter location on 5.15, to redirect the dangling pointer to our
user page. oppo suggested process_vm_readv iovec, binder, io_uring, setsockopt.

CONCLUSION (from frame analysis): will NOT work as a replacement for pselect,
because the dangling waiter pointer lives in the FUTEX frame (futex_lock_pi), not
in core_sys_select's frame. A different corruption syscall writes into ITS OWN
frame, not the futex frame, so it cannot reach the waiter. pselect is the only
syscall that writes into core_sys_select's frame, and its fd_set is too high
(by the frame-offset gap described in section 2).

A static offset-coincidence scanner was built to find any unprivileged syscall
whose user->kernel-stack copy lands on the waiter address. This is NOT
statically decidable: the coincidence depends on the two concurrent threads'
kernel-stack BASE addresses (THREAD_SIZE / stack-slab coloring), a runtime
property not attacker-chosen. Static enumeration only yields a noisy,
unvalidatable candidate list (false-positive reachability via shared library
functions). The on-device test is the only ground truth and is NEGATIVE.
=> No pselect-style stack-overwrite primitive can rescue GhostLock on 5.15.180.

## 7) PATH B — tokay TCP route (do_tcp_fake_lock_route), re-checked 2026-07-20
tokay's fops.c has an ALTERNATE route (do_tcp_fake_lock_route @431) our shared
fork lacks. It does NOT use pselect:
- opens a TCP socketpair, builds a stack-local zc[0x40] in the waiter thread,
- fills zc with fake fields: waiter_task @ zc+0x28, fake_lock @ zc+0x30,
- calls getsockopt(IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc, &len) while a
  sched_setattr consumer thread is armed (same punch mechanism as pselect).
Mechanism: TCP_ZEROCOPY_RECEIVE copy_from_user()s the user zc onto the
kernel stack; if that slot coincides with the frozen rt_mutex_waiter from the
futex PI requeue race, the waiter pointer is redirected to the fake page.

5.15.180 vmlinux frame analysis (verified via llvm-objdump on
ghostlock_repo/Target/kernel_5-15-180-vmlinux.elf):
- futex_wait_requeue_pi frame = 0x1b0 (waiter thread's rt_mutex_waiter local at
  the TOP of this frame, sp+0 of that frame).
- tcp_zerocopy_receive frame = 0x1d0 (NOT 0x230 as previously written).
  The zc struct is copied to a stack slot near sp+0x60..sp+0xc0 (x24 = sp+0x60
  at entry; optval copy target via add x..,sp,#0x.. around the copy_from_user call).
- Same-thread geometry: after futex_wait_requeue_pi returns (waiter at old sp+0,
  i.e. 0x1b0 below the new entry sp), the thread enters tcp_zerocopy_receive
  (frame 0x1d0 — LARGER than futex_wait_requeue_pi's 0x1b0) and its zc lands
  at a LOW sp offset (sp+0x60..0xc0). The frozen waiter was at the HIGH end of
  the now-returned futex frame (sp+0x190-ish). => zc does NOT coincide with the
  dangling waiter on 5.15 either.

CONCLUSION: the TCP route targets a DIFFERENT frame than pselect, but on 5.15 its
zc buffer is also far from the frozen rt_mutex_waiter (low-sp vs high-sp). Same
structural miss as pselect (different offset). Re-checked against the real 5.15
ELF on 2026-07-20: the only change vs the earlier write-up is the verified frame
size (tcp_zerocopy_receive = 0x1d0, not 0x230) — the conclusion is unchanged.
Porting it would need a 6.x vmlinux to prove the coincidence exists there, or
retuning zc offsets — unlikely to help since the gap is fixed by frame size, not
field layout.

## 8) VERDICT — 6.1 vs 5.15 frame diff (CONFIRMED with vmlinux-6.1.elf)
6.1 GKI ELF built from boot-6.1-allsyms.img (Target/vmlinux-6.1.elf, in the
GitHub repo `Target/` directory alongside the 5.15 vmlinux). Frame sizes are
IDENTICAL between 6.1 and 5.15 for every function except the syscall wrapper:

    Function                  | 6.1 frame | 5.15 frame
    --------------------------|-----------|-----------
    __arm64_sys_pselect6      | 0x90      | 0xa0
    core_sys_select           | 0x1c0     | 0x1c0
    do_select                 | 0x360     | 0x360 (SEPARATE function on BOTH)
    futex_wait_requeue_pi     | 0x1b0     | 0x1b0
    futex_lock_pi             | 0x1a0     | 0x1a0
    tcp_zerocopy_receive      | 0x1d0     | 0x1d0

CORRECTED KEY DIFFERENCE: on BOTH 5.15 and 6.1, `do_select` is a
SEPARATE function (the earlier "5.15 inlines do_select" claim was WRONG —
disassembled and confirmed: do_select @0x57cbf0 is called by core_sys_select
@0x57c6bc, real symbol, own frame). The select thread's fd_set lives in
core_sys_select's frame (sp+0x100); the frozen rt_mutex_waiter lives in the
FUTEX thread's frame (a separate concurrent call chain). The pselect route only
works when the fd_set buffer's address coincides with the dangling waiter
pointer's address on the kernel stack — an OFFSET COINCIDENCE. This is NOT a
total call-chain depth problem: re-tracing downward depths
(analysis-scripts/find_chain_depths.py) shows pselect 0x1cec0 and io_uring
0x1cd60 — both far exceed the 856B (0x358) threshold, so depth is irrelevant.
6.x works because its frame LAYOUT places fd_set on the waiter offset; 5.15.180
does not.

CONFIRMED: this exploit variant (pselect/tcp stack-overwrite -> physrw) is
INCOMPATIBLE with 5.15.180 GKI because the fd_set offset does not coincide
with the frozen waiter pointer (frame-layout mismatch). 6.x aligns them. oppo
confirmed no working 5.15/5.10 pselect alternative exists in any repo (their
physrw was never completed; slide pselect marked BLOCKED/DEAD).

OPTIONS TO ACTUALLY GET ROOT ON 5.15:
  (a) [DEAD END — do not pursue] A different kernel-stack write whose buffer
      coincides in address with the frozen rt_mutex_waiter. The coincidence is
      not statically decidable (runtime per-thread stack base / slab coloring);
      the on-device test is negative. Brute-forcing the stack base is infeasible.
  (b) A DIFFERENT primary exploit primitive for 5.15 (a 5.15-specific UAF /
      heap bug reachable unprivileged). This is the ONLY viable path: monitor
      5.15.180 GKI-reachable CVEs (binder / ashmem / userfaultfd / io_uring /
      BPF / AF_UNIX per config-analysis.md) and OTAs. Keep the GhostLock
      KASLR / mm_struct / physrw / root stages as a re-usable harness — when a
      new unpriv-reachable UAF drops, only Stage 3 (the trigger) needs replacing.
  (c) Accept that this GhostLock chain targets 6.x GKI only; 5.15 needs a
      different CVE / primitive.

## 9) What is already correct (do NOT touch)
- SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x02dc5a19 (exlog5-verified, correct).
- boot_id resolver removal / MINIMAL_INSTALL / common.h kmalloc guards /
  SLIDE_KERNEL_BASE_KNOWN / SLIDE_MAX_ATTEMPTS=8.
- Build works (system ld symlinked to NDK ld.lld; clang->clang-21).
- In-file modifications are documented in MODIFICATIONS.md.

## 10) rt_mutex_waiter offsets assumed (from lamu/fuxi target.h, GKI 6.6 — stable)
WAITER_TREE_ENTRY_OFF 0x00, WAITER_PI_TREE_ENTRY_OFF 0x18, WAITER_TASK_OFF 0x30,
WAITER_LOCK_OFF 0x38, WAITER_WAKE_STATE_OFF 0x40, WAITER_PRIO_OFF 0x44,
WAITER_DEADLINE_OFF 0x48, WAITER_WW_CTX_OFF 0x50
FAKE_WAITER_TREE_PRIO_OFF 0x18, FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28,
FAKE_WAITER_PI_TREE_PRIO_OFF 0x40, FAKE_WAITER_TASK_OFF 0x50,
FAKE_WAITER_LOCK_OFF 0x58
These are STABLE across GKI (rt_mutex_waiter layout unchanged 5.10->6.6).

## 11) Key files
- CVE-2026-43499/exploit/src/slide.c : words[] @107, slide_pselect_stack_copy @139, sched_setattr @248
- CVE-2026-43499/exploit/src/fops.c  : do_pselect_fake_lock_route @88, prepare_pselect_fdsets @73
- CVE-2026-43499/exploit/src/targets/air-AP3A.240905.015.A2/target.h
- Target/vmlinux-6.1.elf (6.1 GKI ELF, in the GitHub repo `Target/`; built from
   boot-6.1-allsyms.img via libmagiskboot.so unpack + vmlinux-to-elf; used to
   confirm the do_select frame difference vs 5.15)
- Target/kernel_5-15-180-vmlinux.elf (5.15 symbols, NO DWARF/BTF, use llvm-objdump)
- RUNLOGS.md (merged exlog*.txt), MODIFICATIONS.md (in-file changes)
- reference-targets/oppo-ghostlock-main/{AGENTS.md,docs/adaptation-guide.md}
- reference-targets/exploit_targets_fuxi-*/ and exploit_target_lamu_PD/
  (6.6 ports; same words[] as ours, plus tokay's do_tcp_fake_lock_route)
