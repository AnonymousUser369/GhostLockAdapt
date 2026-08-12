# GhostLock — CVE-2026-43499 futex PI UAF privilege escalation

**GhostLock** is the public name for **CVE-2026-43499**:
a futex priority-inheritance UAF. The kernel leaves a `struct rt_mutex_waiter` dangling
on a kernel stack after a `FUTEX_CMP_REQUEUE_PI` / PI-cycle (`FUTEX_WAIT_REQUEUE_PI` +
`FUTEX_CMP_REQUEUE_PI`) race. An unprivileged adb shell can
then overwrite that waiter — which lives in *attacker-reachable* kernel-stack
memory — with fake fields, redirecting the kernel's `rt_mutex_adjust_prio_chain`
walk into attacker-controlled memory. That yields an arbitrary kernel
read/write primitive, which is used to patch `cred` (uid/gid → 0, full caps)
and set `selinux_state->enforcing = 0`.

> **Target device:** POCO air / Redmi 13C 5G / POCO M6 5G — codename `air`,
> build `AP3A.240905.015.A2`, Android 15, kernel **5.15.180-android13 GKI**

Work done by AI since its beyond what i could ever do 😅

---

## 1. Variant status

| Variant | Status | Role |
|---|---|---|
| [`exploit-finale/`](exploit-finale/) | **Primary — working** | Full LPE. Combines tracefs KASLR, UAF stamp (mcast/sendmsg), PI-walk consumer, pipe physrw, and embedded su daemon. This is the active development target. |
| [`poc_air/`](poc_air/) | **Partial success** | Proved the `sendmmsg` iovec spray lands on the dangling waiter (`iov[0]` = `waiter->lock`, +0x38 displacement). Could not reach root because every static kernel-symbol `fake_lock` candidate faults (`pmd=0`/`pgd=0`) on POCO 5.15.180. Pivoted to physrw concept; its probe methodology and spray layout are reused in `exploit-finale`. |
| [`poc-mcast/`](poc-mcast/) | **Partial success** | Proved the IPv4 `MCAST_BLOCK_SOURCE` setsockopt stamp works and derived `WAITER_OFF = 0x60` via PROBE. Did not implement escalation. Its probe methodology, frame analysis, and stamp layout are reused in `exploit-finale`. |
| [`exploit-mcast/`](exploit-mcast/) | **Failed** | Native 64-bit arm64 `MCAST_JOIN_SOURCE_GROUP` writer. The 0x108 copy is geometrically insufficient on POCO 5.15.180 (waiter sits outside the copy window). Kept for reference only. |
| [`exploit-pselect/`](exploit-pselect/) | **Failed** | Port of zainarbani a54x `COMPACT_RT_MUTEX_WAITER` pselect layout. Structurally sound but the pselect fd_set spray does not reliably trigger the CFI misroute on POCO 5.15.180. Superseded by `exploit-finale`'s pipe-based physrw, which achieves the same arbitrary R/W without depending on CFI. Kept for reference only. |

**In short:** `exploit-finale` is the only variant that reaches root. `poc_air` and
`poc-mcast` were research stepping stones. `exploit-mcast` and `exploit-pselect`
are dead ends on this kernel.

---

## 1. Basic  GhostLock info

### The exploit primitive (shared by all variants)
1. **KASLR leak.** The kernel text base is recovered at runtime. All variants
   use the **tracefs `sched_blocked_reason` leak** (event id 108, modal `caller`
   @ offset 16; `perf_event_paranoid = -1` on POCO, so it is allowed), with the
   perf-event leak and the boot_id/slide leak as fallbacks. `KIMAGE_TEXT_BASE =
   0xffffffc008000000`; runtime VA = `base + slide + link_off`.
2. **PI-cycle topology.** Two threads build a futex PI deadlock cycle
   (`-EDEADLK` via `FUTEX_CMP_REQUEUE_PI`) that leaves a `rt_mutex_waiter`
   dangling on the *waiter* thread's kernel stack (`current->pi_blocked_on`
   points at it). That waiter is the corruption target.
3. **Stack overwrite.** A *second* syscall copies attacker bytes into its own
   kernel-stack frame in a position that **coincides** with the dangling waiter.
   The bytes fake `waiter.task` / `waiter.lock` so the next
   `rt_mutex_adjust_prio_chain` (triggered by the consumer's
   `sched_setattr`/`sched_setscheduler`) walks into a fake object.
4. **physrw + root.** The fake chain reclaims the sprayed page as a
   pipe buffer → arbitrary kernel read/write, then patches `cred` and
   `selinux_state->enforcing`.

### The 5.15.180 landscape — the shared blocker
The whole exploit hinges on **step 3**: the second syscall's stack frame must
*coincide* in address with the dangling waiter. This is a per-boot,
per-thread **frame-offset coincidence**, not a total call-depth issue.

- `rt_mutex_waiter` on 5.15.180 GKI is **compact**: `task @ +0x30`,
  `lock @ +0x38` (authoritative offsets in
  `Target/manual_offsets_5-15-180.md`; confirmed by
  `task_blocks_on_rt_mutex` disassembly). Earlier notes claiming
  `task@0x50/lock@0x58` are **outdated** — see `PATHS.md` §"Flagged
  contradictions".
- `rt_mutex_adjust_prio_chain` prologue (5.15.180): `x19 = x0` = the **task**
  (1st arg), `x28 = task->0x8b0` = `task->pi_top_task` = the dangling waiter,
  and the fault at `+0x1b0` dereferences `*(waiter->lock)` (i.e. `x27 =
  waiter->lock`).
- The "frame-gap" that blocks one technique is **technique-specific**: it
  depends on the distance between the futex frame and the *specific* overwrite
  syscall's frame. Different syscalls → different gaps.

### Common constraints
- `randomize_kstack_offset` is **off** on this GKI build → displacement is
  deterministic per-boot (not parity-limited).
- `CONFIG_DEBUG_RT_MUTEXES` is **not** set; `CONFIG_ANDROID_BINDER_IPC=y`.
---

## 2. Exploit-finale — the working LPE

The active variant. End-to-end path:

1. **KASLR leak** — tracefs `sched_blocked_reason` (primary; exact slide), perf
   min-kernel-IP (fallback), or slide/boot_id leak (tertiary).
2. **Stage controlled page** — `prepare_good_kernel_page()` places `fake_lock`,
   `fake_fops`, and `binwrite_target` on a kernel page obtained via pipe-buffer
   UAF + KernelSnitch.
3. **PI futex topology + UAF stamp** — three threads (waiter/owner/consumer):
   - Waiter locks `f_pi_chain`, then `FUTEX_WAIT_REQUEUE_PI` on `f_wait`
     (creates dangling `rt_mutex_waiter` on its kernel stack).
   - Owner locks `f_pi_target`, then `f_pi_chain` (forms PI cycle).
   - Main calls `FUTEX_CMP_REQUEUE_PI` → kernel detects cycle, returns
     `-EDEADLK`. Main sets `f_wait=1` + fence, sends `SIGUSR1` to waiter.
   - Waiter restarts, returns `-EAGAIN`, issues ONE stamp
     (`setsockopt MCAST_BLOCK_SOURCE` or `sendmmsg` iovec, selected via
     `TRIGGER`), then spins syscall-free.
4. **Consumer fires** — `sched_setattr(waiter_tid)` triggers
   `rt_mutex_adjust_prio_chain`, which reads the stamped `waiter->lock ==
   fake_lock` and walks into the self-consistent fake tree (kernel stays alive).
5. **Pipe physrw primitive** — configfs ashmem fd + pipe buffer manipulation
   gives arbitrary physical kernel R/W (independent of the unreliable CFI
   misroute).
6. **Escalation** — via physrw: patch `cred` (uid=0, gid=0, full caps,
   securebits=0, selinux sid=KERNEL_SID), clear seccomp bits, write
   `selinux_state.enforcing = 0`, fork root child (`setgid(0)`/`setuid(0)`),
   install embedded `su` daemon to `/data/local/tmp/su`.

**Key design decisions:**
- Bypasses the POCO-unreliable `fake_fops` CFI misroute entirely; physrw is
  wired directly after the UAF route.
- `WAITER_OFF` is derived per-run via PROBE (`MCAST_PROBE_INDEX=1`), not
  hardcoded. Default `0x60` matches poc-mcast's proven value for the same
  futex(1-frame) → stamp(1-frame) topology.
- Private futex flags (`FUTEX_*_PRIVATE`) are required to match the kernel path
  so the waiter lands inside the 0x108 copy window.
- `nr_wake=1` is mandatory for `FUTEX_CMP_REQUEUE_PI` (kernel rejects 0 with
  EINVAL); `nr_requeue=0`, `cmpval=NULL`.

**Docs:** `docs/EXPLOIT-PATH.md` traces the full execution path with ASCII
timing diagram. `docs/WRITE-PRIMITIVES.md` covers both stamps. `docs/KASLR-METHODS.md`
covers all three leak methods. `docs/ESCALATION.md` covers root. `docs/FAKE-FOPS.md`
documents the bypassed CFI route for reference.

---

## 3. The shared primitive — what the research variants proved

The exploit primitive is the same across all variants:

1. **KASLR leak.** The kernel text base is recovered at runtime. All variants
   use the **tracefs `sched_blocked_reason` leak** (event id 108, modal `caller`
   @ offset 16; `perf_event_paranoid = -1` on POCO, so it is allowed), with the
   perf-event leak and the boot_id/slide leak as fallbacks. `KIMAGE_TEXT_BASE =
   0xffffffc008000000`; runtime VA = `base + slide + link_off`.
2. **PI-cycle topology.** Two threads build a futex PI deadlock cycle
   (`-EDEADLK` via `FUTEX_CMP_REQUEUE_PI`) that leaves a `rt_mutex_waiter`
   dangling on the *waiter* thread's kernel stack (`current->pi_blocked_on`
   points at it). That waiter is the corruption target.
3. **Stack overwrite.** A *second* syscall copies attacker bytes into its own
   kernel-stack frame in a position that **coincides** with the dangling waiter.
   The bytes fake `waiter.task` / `waiter.lock` so the next
   `rt_mutex_adjust_prio_chain` (triggered by the consumer's
   `sched_setattr`/`sched_setscheduler`) walks into a fake object.
4. **physrw + root.** The fake chain reclaims the sprayed page as a
   pipe buffer → arbitrary kernel read/write, then patches `cred` and
   `selinux_state->enforcing`.

### The 5.15.180 landscape — the shared blocker
The whole exploit hinges on **step 3**: the second syscall's stack frame must
*coincide* in address with the dangling waiter. This is a per-boot,
per-thread **frame-offset coincidence**, not a total call-depth issue.

- `rt_mutex_waiter` on 5.15.180 GKI is **compact**: `task @ +0x30`,
  `lock @ +0x38` (authoritative offsets in
  `Target/manual_offsets_5-15-180.md`; confirmed by
  `task_blocks_on_rt_mutex` disassembly). Earlier notes claiming
  `task@0x50/lock@0x58` are **outdated** — see `PATHS.md` §"Flagged
  contradictions".
- `rt_mutex_adjust_prio_chain` prologue (5.15.180): `x19 = x0` = the **task**
  (1st arg), `x28 = task->0x8b0` = `task->pi_top_task` = the dangling waiter,
  and the fault at `+0x1b0` dereferences `*(waiter->lock)` (i.e. `x27 =
  waiter->lock`).
- The "frame-gap" that blocks one technique is **technique-specific**: it
  depends on the distance between the futex frame and the *specific* overwrite
  syscall's frame. Different syscalls → different gaps.

### Common constraints
- `randomize_kstack_offset` is **off** on this GKI build → displacement is
  deterministic per-boot (not parity-limited).
- `CONFIG_DEBUG_RT_MUTEXES` is **not** set; `CONFIG_ANDROID_BINDER_IPC=y`.

---

## 3. Build & run

<details>
<summary>Expand for build & run instructions (device-specific, reboot required)</summary>

All variants use `NDK r29` at `/mnt/Data/AI_Workspace/android-ndk-r29`.
Each variant directory has `build.sh`, `run.sh`, `getpanic.sh`. The device is
single; no serial needed. `run.sh` may reboot the device on a successful
pivot — output is captured to `runlogs/` (partial).

### exploit-finale (active target)
```bash
cd exploit-finale
./build.sh                       # make -> build/.../bin/preload.so
./run.sh gate                    # LD_PRELOAD into sh, run full LPE
./run.sh 'TRIGGER=mcast'         # mcast stamp (default)
./run.sh 'TRIGGER=sendmsg'       # sendmsg stamp
./getpanic.sh                    # pull console-ramoops-0, extract panic
```

### poc_air (research binary)
```bash
cd poc_air
./build.sh                       # clang -O2 -static -pthread -> ./poc_air
./run.sh v7                      # push + run (tag)
./run.sh probe "PROBE=1"         # PROBE mode: spray sentinels to learn iov idx
./getpanic.sh
```

### exploit-mcast (reference only — geometrically insufficient)
```bash
cd exploit-mcast
./build.sh
./run.sh
./getpanic.sh
```

### exploit-pselect (reference only — CFI route unreliable)
```bash
cd exploit-pselect
./build.sh
./run.sh
./getpanic.sh
```

</details>

---

## 4. External links & references

Public / upstream repositories used during this work:

- **CyberMeowfia / IonStack — CVE-2026-43499** (upstream):
  https://github.com/NebuSec/CyberMeowfia
- **zainarbani / Root-My-Galaxy-Payloads** — a54x `COMPACT_RT_MUTEX_WAITER`
  pselect breakthrough (write-0 to `selinux_state->enforcing` on 5.15.189):
  https://github.com/zainarbani/Root-My-Galaxy-Payloads (branch `a54x`)
- **oppo-ghostlock** — 5.10 analysis / "waiter 120 bytes below fd_set"
  frame-gap proof: https://github.com/pubglite55/oppo-ghostlock
- probably more

## 5. Documentation

- `exploit-finale/docs/EXPLOIT-PATH.md` — end-to-end execution trace with ASCII
  timing diagram
- `exploit-finale/docs/WRITE-PRIMITIVES.md` — both UAF stamps (mcast / sendmmsg)
- `exploit-finale/docs/KASLR-METHODS.md` — tracefs / perf / slide leak methods
- `exploit-finale/docs/ESCALATION.md` — cred/selinux/seccomp patch + su daemon
- `exploit-finale/docs/FAKE-FOPS.md` — configfs CFI route (bypassed, documented
  for reference)
- `exploit-finale/docs/KERNELSNITCH.md` — mm_struct leak primitive
- `exploit-finale/docs/TARGETS.md` — per-device target configuration + BTF
  contradictions
- `exploit-finale/docs/OBSERVATIONS.md` — on-device empirical findings
- `exploit-finale/docs/VERIFICATION.md` — numbered verification items
- `Target/README.md` — offset verification proof (production vs debug kernel,
  BTF contradictions, disassembly reference)

---

## Disclaimer

Research / educational use only. Targets the author's own device. `exploit-finale`
is the only variant documented as functional for privilege escalation on POCO
air 5.15.180 GKI. `poc_air` and `poc-mcast` proved the primitive but did not
complete the full chain. `exploit-mcast` and `exploit-pselect` are documented
as non-functional on this kernel due to frame-gap / CFI reliability issues.
