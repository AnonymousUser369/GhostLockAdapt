# GhostLock (CVE-2026-43499) — POCO air fork

Privilege-escalation exploit port for the **POCO air** (a.k.a. Redmi 13C 5G / POCO M6 5G),
device codename `air`, build `AP3A.240905.015.A2` (Android 15), kernel **5.15.180-android13 GKI**.

This is a fork of the public [CyberMeowfia/IonStack](https://github.com/NebuSec/CyberMeowfia) `CVE-2026-43499` exploit (which
targets 6.x GKI Pixels). The `air` target is added and tuned for 5.15.180.

Work mostly done by AI since it is out of my league. 😅

> **Status: does NOT achieve root on 5.15.180.** All setup/infrastructure works;
> the core kernel stack-corruption primitive is incompatible with the 5.15 stack
> layout. Details in `ANALYSIS.md`.

## Build & run

```bash
cd exploit
make PROJECT=air-AP3A.240905.015.A2 NDK_ROOT=<path-to-ndk>

adb push build/air-AP3A.240905.015.A2/bin/preload.so /data/local/tmp/preload.so
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/sh -c "true"' 2>&1 | tee exlog.txt
```

`preload.so` is `-shared` (entry 0x0) and must be `LD_PRELOAD`ed, never run directly.
The `MINIMAL_INSTALL` build only touches `/data/local/tmp` (drops `su` there); it does
not touch `/apex`, install wallpaper, kill `system_server`, or `setns` into adbd.

## What works (verified on-device)

The exploit runs through 6 stages. Everything up to and including building the fake
kernel page works on 5.15.180:

| Stage | What it does | Status |
|-------|--------------|--------|
| 0. Load | `preload.so` `LD_PRELOAD`ed into `sh`; runs unprivileged (uid 2000). | works |
| 1. KASLR base | `SLIDE_KERNEL_BASE_KNOWN` → known base `0xffffffc008000000`, `slide=0`. | works |
| 2. Fake page | Forged `rt_mutex_waiter` / `rt_mutex` / `task_struct` / `file_operations` page built in user memory with correct 5.15 offsets. | works |
| 3. Stack corruption | pselect `fd_set` overwrite redirects the dangling `rt_mutex_waiter` to the fake page. | fails on 5.15 |
| 4. Pipe physrw | Reclaim fake page as pipe buffer → arbitrary kernel read/write. | not reached |
| 5. Root | Overwrite `cred` (uid/gid→0, full caps) + disable SELinux. | not reached |
| 6. Drop `su` | Write `su` to `/data/local/tmp`. | works (no root to use it) |

Confirmed on-device (see `RUNLOGS.md`): `slide-kaslr-known base=ffffffc008000000 slide=0`,
and `boot_id_data=ffffff8002dc5a19` (correct `random_table[boot_id].data` offset).

## What is broken

Stage 3 must overwrite a kernel stack pointer (the `rt_mutex_waiter` left dangling by
the GhostLock futex UAF) to point at the fake page from Stage 2. On 5.15.180 this
never lands. From disassembling `kernel_5-15-180-vmlinux.elf` (no DWARF/BTF, use
`llvm-objdump`):

- `do_select` is a **separate function** (`0xffffffc00857cbf0`), called by `core_sys_select`
  at `0x57c6bc` — NOT inlined.
- The `fd_set` bitmap is copied into `core_sys_select`'s kernel-stack frame at `sp+0x100`.
- The dangling `rt_mutex_waiter` pointer is frozen in the **futex** frame
  (`futex_lock_pi`, waiter at its `sp+0x78`) — a *different, concurrent* call chain.
- The pselect route only works when the `fd_set` buffer's **address coincides** with
  the dangling waiter pointer's address on the kernel stack. This is a *frame-layout
  OFFSET COINCIDENCE*, not a total call-chain depth issue: re-tracing downward
  call depths shows both pselect (`0x1cec0`) and io_uring (`0x1cd60`) far exceed
  the 856B (0x358) threshold, so depth is irrelevant. 6.x lays frames out so
  `fd_set` lands ON the waiter offset; 5.15.180 does not.

This is the same blocker oppo-ghostlock hit on 5.10 ("waiter 120 bytes below
fd_set, fdset cannot reach it", marked NOT VIABLE). The on-device symptom (in
`RUNLOGS.md`): every attempt logs the literal `boot_id` UUID (corruption missed),
`sched_ok=0`, then `pipe physrw read_ok=0 write_ok=0` → no root. KASLR is fine
because it is known from symbols.

The tokay target's alternate TCP route (`do_tcp_fake_lock_route`, `TCP_ZEROCOPY_RECEIVE`)
was also analyzed: on 5.15 its `zc` stack buffer is `0xe0` bytes from the frozen waiter —
same structural miss (different offset).

## Analysis

Full root-cause, frame evidence, exploit architecture, and the Path A/B investigation
are in `ANALYSIS.md`. In-file source changes are in `MODIFICATIONS.md`. Merged on-device
run logs (exlog.txt … exlog6.txt) are in `RUNLOGS.md`.

## External resources (provided separately)

The following were used during this port but live in other people's repositories, not
in this one. Add links here:

- CyberMeowfia/IonStack `CVE-2026-43499` (upstream, 6.x targets) — https://github.com/NebuSec/CyberMeowfia
- oppo-ghostlock (5.10 analysis, BLOCKER 1 proof) — https://github.com/pubglite55/oppo-ghostlock
- 6.6 GKI ports (tokay/fuxi/lamu) referenced for `rt_mutex_waiter` offsets and the
  alternate TCP route — https://github.com/NebuSec/CyberMeowfia/pull/42 & https://github.com/NebuSec/CyberMeowfia/pull/36

## Repository layout

- `CVE-2026-43499/exploit/src/targets/air-AP3A.240905.015.A2/target.h` — the `air` port (offsets,
  `SLIDE_KERNEL_BASE_KNOWN`, `MINIMAL_INSTALL`, 5.15 kmalloc tuning).
- `CVE-2026-43499/exploit/src/{slide,fops,preload,common,main,util,pipe,root}.c` — shared source
  (route logic; core engine unchanged from upstream).
- `CVE-2026-43499/exploit/Makefile` — build.
- `CVE-2026-43499/poc/poc.c` — minimal PoC.
- `Target/kernel_5-15-180-vmlinux.elf` — 5.15 GKI vmlinux (frame analysis, no DWARF/BTF).
- `Target/kernel_5-15-180-symbols.txt` — kallsyms offsets (in GitHub repo `Target/`).
- `Target/kernel_5-15-180.config` — extracted GKI build config (CONFIG_IKCONFIG) for CVE reachability filtering.
- `Target/vmlinux-6.1.elf` — 6.1 GKI ELF; used to confirm the `do_select` frame
  difference vs 5.15.
- `ANALYSIS.md`, `MODIFICATIONS.md`, `RUNLOGS.md` — this fork's notes.

## Disclaimer

Research / educational use only. Targets the author's own device. The 5.15.180 port is
documented as **non-functional for privilege escalation** due to a kernel stack-layout
incompatibility, not a code defect.
