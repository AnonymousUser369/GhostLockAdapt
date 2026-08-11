# poc_air — CVE-2026-43499 GhostLock port to POCO air 5.15.180 GKI

## What this is

poc_air is a local privilege escalation exploit for the POCO air (MT6835, 23128PC33I) running kernel 5.15.180 GKI. It targets CVE-2026-43499 (GhostLock) — a use-after-free in the PI-futex chain walk that allows an unprivileged shell process to overwrite a dangling `rt_mutex_waiter` on its own kernel stack via `sendmmsg` iovec spray, then trigger `rb_erase` to NULL-write an arbitrary kernel address.

**Target outcome:** `selinux_state->enforcing` flipped from 1 to 0 (permissive).

> **Status (2026-08-11):** the `rt_mutex`/`rb_erase` selinux-forge stage is blocked — every static `fake_lock` anchor faults with `pmd=0`/`pgd=0` on this build (no image `.data`/`.bss`/GAP symbol is mapped at the vmlinux-predicted VA). The active work has **pivoted to the physrw primitive** (exploit-pselect / CVE-2026-43499), which obtains arbitrary physical RW and needs no mapped kernel-symbol anchor. The UAF + `sendmmsg` spray + tracefs KASLR remain the entry primitive. See `CONTEXT.md`.

**Device:** POCO air 5.15.180 GKI, shell uid=2000, `perf_event_paranoid = -1`.

---

## Build

```bash
bash /mnt/Data/AI_Workspace/ghostlock_repo/poc_air/build.sh
```

Uses NDK r29 `aarch64-linux-android35-clang`. Output: `poc_air` (static, ~2.1 MB).

---

## Run (manual — push/run/getpanic by hand)

`/data/local/tmp/` is wiped on every reboot. Push fresh each run.

```bash
# 1) Push
adb push poc_air /data/local/tmp/poc_air_<tag>
adb shell chmod 755 /data/local/tmp/poc_air_<tag>

# 2) Run with live capture (device will panic)
adb exec-out "cd /data/local/tmp && <ENV> ./poc_air_<tag> 2>&1" \
  | tee runlogs/run_<tag>.out

# 3) After reboot, retrieve panic from pstore
bash getpanic.sh <tag>

# 4) Check if exploit landed
adb shell cat /sys/fs/selinux/enforce   # expect 0
```

Key env vars:
- `IOV_IDX=d` — spray displacement (0–7). Controls which iov slot maps to `waiter->lock`. **On POCO 5.15.180 the iovec spray overlaps the freed waiter with a +0x38 displacement, so `iov[0]` = `waiter->lock` (+0x38). The `li` (lock slot) MUST be `0` (write `fake_lock` into `iov[0]`), NOT `3` as in the a54x reference. `tree_entry`/`task` (+0x00..+0x37) are NOT covered by `iov[0..]` under this displacement — PHASE2 RB-tree targets need re-mapping.** See `docs/OBSERVATIONS.md` "CORRECTED mapping".
- `PROBE=1` — sprays valid sentinel values `0xabcdef00|i<<8` in all waiter fields except `lock=fake_lock` and `task=init_task`. Runs full two-phase (settle + write); panic contains sentinel `0xabcdef00xx` patterns revealing the iov→field mapping. `enforce=0` confirms success directly.
- `SPRAY=writev` — alternate spray via `writev` instead of `sendmmsg` (experimental).
- `SAFE_WRITE=1` — write `empty_zero_page` (low byte 0x00, byte2 nonzero) instead of raw NULL, keeping `selinux_state->initialized=1`. Enabled by default in v2.

---

## Current status

| Component | Status |
|---|---|
| KASLR leak (tracefs `sched_blocked_reason`; replaced perf) | ✅ confirmed (exact slide, matches oops `Kernel Offset`) |
| Topology (`FUTEX_CMP_REQUEUE_PI` → `-EDEADLK`) | ✅ every run |
| `sendmmsg` iovec spray co-locates with freed `rt_mutex_waiter` (`iov[0]`=`lock`, +0x38 displacement) | ✅ confirmed |
| `pselect6` fd_set spray | ❌ ruled out (5.15 doesn't work) |
| Static `fake_lock` anchor (`uid_lock+0x200`, `selinux_state`, `init_task`, `kmalloc_caches`, `security_hook_heads`, …) | ❌ ALL fault (`pmd=0`/`pgd=0`) — no image `.data`/`.bss`/GAP symbol is mapped at the vmlinux-predicted VA on this build |
| rt_mutex `rb_erase` selinux forge (`PHASE2`) | ⛔ blocked — abandoned; `tree_entry` (+0x00..+0x37) also unreachable under the +0x38 spray |
| **Pivot → physrw primitive** (exploit-pselect / CVE-2026-43499) | 🔄 in progress — arbitrary physical RW replaces the `rt_mutex` fake_lock / selinux-forge stage; the UAF + `sendmmsg` spray + tracefs KASLR are retained as the entry primitive |

---

## Known constraints

- `randomize_kstack_offset` is OFF → displacement is deterministic per binary layout.
- `iovlen` MUST be ≤ 8 (otherwise kernel heap-sprays, never reaches stack waiter).
- `CONFIG_DEBUG_RT_MUTEXES` is NOT set → compact `rt_mutex_waiter` layout: `tree_entry@0x00`, `task@0x30`, `lock@0x38`, 88 bytes (0x58) total.
- The a54x reference uses `d=1` (`iov[1]=parent_color`, `iov[2]=rb_left`, `iov[4]=task/lock`). **POCO's displacement is now KNOWN: the iovec spray overlaps the waiter at +0x38, so `iov[0]` = `waiter->lock` and `li` must be `0`.** The old `iov[0]=parent_color / iov[3]=task|lock` claim in prior docs is WRONG.

---

## Dead ends / ruled out

| Path | Reason |
|---|---|
| `pselect6` fd_set spray | User confirmed it does not work on 5.15 |
| `inet6_protos+0x90` as fake_lock | RO data on this GKI build |
| poc2.c (`inet6_protos+0xb8` fake_lock2) | Different device (P0/AP3A); RO on POCO air; not directly portable |

---

## Files

| File | Purpose |
|---|---|
| `poc_air.c` | Main exploit source |
| `build.sh` | NDK build script |
| `getpanic.sh` | Pull panic from pstore, save to `runlogs/` |
| `run.sh` | Push + run via exec-out with env passthrough (mirrors the manual commands above) |
| `docs/OBSERVATIONS.md` | Detailed empirical data from all valid runs |

---

## Reference implementations

| File | Purpose |
|---|---|
| `poc-ref/poc.c` | a54x reference (5.15.189, P0/AP3A); confirmed selinux permissive on that device |
| `poc-ref/selinux_permissive.c` | Author's refined version: writes safe non-NULL value (`callstack_buf+0x808`) and rotates `fake_lock2` through window array; uses tracefs KASLR leak |
| `poc-ref/el02.c` | Early proof-of-concept for the UAF itself (no selinux flip) |

Note: `poc-ref/selinux_permissive.c` is NOT directly portable to POCO air — it uses `inet6_protos`-based fake locks (RO on POCO GKI) and tracefs KASLR leak (different kernel). poc_air adapts the same write primitive to POCO's writable BSS `uid_lock+0x200/0x300` and perf-event KASLR leak.
| `runlogs/` | Per-run output (`run_<tag>.out`) and panics (`panic_<tag>.txt`) |
