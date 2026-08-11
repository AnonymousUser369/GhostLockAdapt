# GhostLock — POCO air (5.15.180 GKI) privilege-escalation ports

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

## 2. The variants and how they differ

| Variant | Entry / technique | Stack-overwrite syscall |
|---|---|---|
| [`exploit-mcast/`](exploit-mcast/) | Native (64-bit arm64) `MCAST_JOIN_SOURCE_GROUP` kernel-stack writer; `preload.so` (rename of the old 32-bit `exploit-exp32`). MCAST 0x108 copy is **geometrically insufficient** on POCO 5.15.180 (frame gap); candidate next step is to pivot the active spray to **`sendmmsg` iovec** (corrections confirm it lands); see `exploit-mcast/docs/` | `setsockopt` `MCAST_JOIN_SOURCE_GROUP` (native, 0x108 copy) — candidate pivot: sendmmsg |
| [`exploit-pselect/`](exploit-pselect/) | Port of zainarbani a54x `COMPACT_RT_MUTEX_WAITER` pselect layout; `preload.so` (supersedes the pre-compact `CVE-2026-43499/` fork, whose analysis is archived in `exploit-pselect/docs/STACK_STAMP_FRAME_GAP.md`). **(failed path)** | `pselect6` `fd_set` (compact words) |
| [`poc_air/`](poc_air/) | Standalone static aarch64 binary; adapted from a54x `poc.c` | `sendmmsg` iovec (iovlen ≤ 8) |

**How the three active variants differ in approach**
- **exploit-mcast** (native 64-bit, renamed from the old 32-bit `exploit-exp32`)
  sprays via a native `setsockopt` `MCAST_JOIN_SOURCE_GROUP` optval (0x108-byte
  `group_source_req` copy). On POCO 5.15.180 the 0x108 copy is **geometrically
  insufficient** to reach the dangling waiter (frame gap: the waiter sits deeper
  than the copy window), so the candidate next step is to pivot the active spray
  primitive to **`sendmmsg` iovec** (same as poc_air) — which corrections confirm
  lands on POCO air 5.15.180.
- **pselect** sprays via the `pselect6` `fd_set` bitmap copied into
  `core_sys_select`'s frame. Uses the a54x *compact* word layout
  (`out[1]` = `waiter+0x30` = `task`, `out[2]` = `waiter+0x38` = `lock`) and
  the 5.15.180-corrected `FAKE_*` offsets. **(failed path)** The compact port is
  structurally sound; remaining unknowns are the absolute frame shift and
  `wake_state` value (see `exploit-pselect/docs/PORT_COMPACT.md`).
- **poc_air** sprays via `sendmmsg` iovecs (must stay iovlen ≤ 8 so the copy is
  on-stack, not kmalloc'd to the heap). The `sendmmsg` spray *empirically lands*
  on the dangling waiter on this kernel (`iov[0]` = `waiter->lock`, +0x38
  displacement), but every static `fake_lock` anchor faults (`pmd=0`/`pgd=0`),
  so the candidate next step is to pivot to the **physrw primitive** (arbitrary
  physical RW, no mapped kernel-symbol anchor needed). See `poc_air/CONTEXT.md`.

---

## 3. Build & run

<details>
<summary>Expand for build & run instructions (device-specific, reboot required)</summary>

All variants use `NDK r29` at `/mnt/Data/AI_Workspace/android-ndk-r29`.
Each variant directory has `build.sh`, `run.sh`, `getpanic.sh`. The device is
single; no serial needed. `run.sh` may reboot the device on a successful
pivot — output is captured to `runlogs/` (partial).

### poc_air (standalone binary)
```bash
cd poc_air
./build.sh                       # clang -O2 -static -pthread -> ./poc_air
./run.sh v7                      # push + run (tag)
./run.sh probe "PROBE=1"         # PROBE mode: spray sentinels to learn iov idx
./getpanic.sh                    # pull console-ramoops-0, extract panic
```

### exploit-pselect (preload.so)
```bash
cd exploit-pselect
./build.sh                       # ANDROID_NDK_HOME=… make -> build/.../bin/preload.so
./run.sh                         # LD_PRELOAD into sh (expect reboot/panic)
./getpanic.sh
```

### exploit-mcast (preload.so, native 64-bit MCAST)
```bash
cd exploit-mcast
./build.sh                       # make preload (native MCAST writer)
./run.sh                         # LD_PRELOAD into sh (expect reboot/panic)
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

---

## Disclaimer

Research / educational use only. Targets the author's own device. The 5.15.180
port is documented as **non-functional for privilege escalation** as of this
writing, due to kernel-stack-layout incompatibilities.
