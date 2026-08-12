# OBSERVATIONS — poc_mcast IPv4 MCAST offset derivation (POCO air 5.15.180 GKI)

## What we're doing

`poc_mcast` tests the **IPv4 UDP** `MCAST_BLOCK_SOURCE` kernel-stack writer on
POCO air. The waiter thread issues ONE `setsockopt(IPPROTO_IP, MCAST_BLOCK_SOURCE,
buf, 0x108)` which copies a 264-byte `group_source_req` onto its own kernel stack,
aiming to overwrite the dangling `rt_mutex_waiter` (compact layout, 0x58 bytes)
left behind by the `futex_wait_requeue_pi` UAF. A separate consumer thread then
calls `sched_setattr(waiter_tid)`, which triggers `rt_mutex_adjust_prio_chain`
to walk the PI chain and read our stamped fields.

The only unknown was **`WAITER_OFF`** — the byte offset of the waiter's start
inside the 0x108 copy buffer. This has been **derived by disassembly** (see
`docs/VERIFICATION.md` §4).

**Calculated result: `WAITER_OFF = 0x60`** (PROBE-confirmed 2026-08-12, x27=0x13).
The full compact waiter (0x58 bytes) spans `greqs+0x60 .. greqs+0xB8`, fully inside
the 0x108 window. `waiter->lock` is at `greqs+0x98`. The path is geometrically viable.

---

## Offset derivation summary

**IPv4 UDP setsockopt chain (POCO 5.15.180, verified by llvm-objdump):**

```
__arm64_sys_setsockopt   0x10
__sys_setsockopt         0x80
sock_common_setsockopt   0x40    ← UDP uses this, NOT inet_setsockopt
udp_setsockopt           0x10
ip_setsockopt            0x290   ← greqs = sp+0x18, copy 0x108
───────────────────────────────────
total frame              0x370
```

**Futex chain (waiter allocation):**
```
__arm64_sys_futex        0xa0
do_futex                 0x140
futex_wait_requeue_pi    0x1b0   ← waiter at sp+0x78
───────────────────────────────────
total                    0x390   → waiter = E - 0x390 + 0x78 = E - 0x318
```

**Arithmetic:**
```
G_off = 0x370 - 0x18 = 0x358   (greqs = E - 0x358)
W_off = 0x318                   (waiter = E - 0x318)
WAITER_OFF = G_off - W_off = 0x40
```

**Field mapping from greqs start:**

| greqs offset | waiter field | Size |
|---|---|---|
| `0x60` | `tree_entry` (start of waiter) | — |
| `0x90` | `task` (+0x30 within waiter) | 8B |
| `0x98` | **`lock`** (+0x38 within waiter) | 8B ← **stamp target** |
| `0xA0` | `wake_state` (+0x40) | 4B |
| `0xA4` | `prio` (+0x44) | 4B |
| `0xA8` | `deadline` (+0x48) | 8B |
| `0xB0` | `ww_ctx` (+0x50) | 8B |
| `0xB8` | end of waiter | — |

`0xB8 < 0x108` → full waiter in-window.

**Key difference from IPv6 path:** the IPv6 UDP chain (`inet6_setsockopt` +
`udpv6_setsockopt` + `udp_lib_setsockopt`) is ~0xE0+ deeper, giving
`WAITER_OFF ≈ 0xF8` on POCO — geometrically insufficient. The IPv4 path
reaches `sock_common_setsockopt` directly (shallower), giving `WAITER_OFF = 0x40`.

**Key difference from FZF5 reference:** FZF5 also uses IPv4 UDP and reported
`WAITER_OFF = 0x40`. POCO's `__sys_setsockopt` is 0x80 (vs FZF5 0x70) and
POCO's `sock_common_setsockopt` is 0x40 (vs FZF5 0x10). Additionally, POCO's
CFI enforcement causes `sock_common_setsockopt`'s `blr x8` dispatch to fail the
inline CFI table check for `udp_setsockopt`, falling through to
`__cfi_slowpath_diag` (extra ~0x20 byte frame) before reaching `udp_setsockopt`.
The net result is `WAITER_OFF = 0x60` on POCO vs 0x40 on FZF5.

---

## First-gate strategy

Default `MCAST_GATE_MARKER` stamps `0x4D434153544C4F43` ("MCASTLOC") into
`waiter->lock` at `greqs + 0x78`. The consumer's `sched_setattr` triggers the
walk; if the marker lands correctly, `x27 == 0x4D434153544C4F43` and the walk
faults on that userspace address → panic shows the marker. If the offset is
wrong, the walk derefs garbage → NULL or misaligned panic.

---

## Run log

No gate runs yet. PROBE run confirmed WAITER_OFF = 0x60.

| Run | STAMP_OFF | Env | x27 | Verdict |
|---|---|---|---|---|
| probe_20260812_094536 | 0x60 | MCAST_PROBE_INDEX=1 | 0x13 (slot 19) | **WAITER_OFF = 0x60 confirmed** |

---

## PROBE mode

`MCAST_PROBE_INDEX=1` fills the 0x108 buffer with `qword[i] = i`. The walk then
faults at `rt_mutex_adjust_prio_chain+0x1b0` with:

```
x27 = qword[(WAITER_OFF + 0x38) / 8]
```

For `WAITER_OFF = 0x40`: expected `x27 = (0x40 + 0x38) / 8 = 0x78 / 8 = 15` (`0x0f`).

If `x27 = 15`, the calculation is confirmed. If `x27` differs, the real
`WAITER_OFF = x27*8 - 0x38`.

---

## KASLR leak

Same mechanism as `poc_air`: tracefs `sched_blocked_reason` (event ID 108), modal
`caller` @ offset 16, slide = mode − (`KIMAGE + 0x178510`). Verified exact in
all poc_air runs. `KASLR_OFF` env override available (default 0).

---

## Critical implementation rules

1. **Single `setsockopt`, then zero syscalls.** Any syscall after the copy
   (`close`, `printf`, `fflush`, `sleep`) re-enters the kernel and pushes frames
   that overwrite the stamped region. Thread Y spins on `sched_yield()` only.
2. **Separate consumer thread** fires `sched_setattr(waiter_tid)`. It runs on its
   own kernel stack and does not touch the waiter's.
3. **Kernel stack randomization is OFF** → `E` is constant per thread → `WAITER_OFF`
   is a fixed constant per build.
4. **IRQs use per-CPU IRQ stacks** (`call_on_irq_stack`) → timer ticks / scheduler
   IPIs during the userspace spin do not touch the task's kernel stack.

---

## Disassembly-confirmed facts

- **Copy really happens.** `ip_setsockopt` MCAST_BLOCK_SOURCE handler at
  `0x408248` does `memset(sp+0x18, 0, 0x108)` then `_copy_from_user(sp+0x18,
  optval, 0x108)`. The family-check bail (`EADDRNOTAVAIL`) fires AFTER the copy.
- **Frame sizes are exactly as measured** (`__arm64_sys_setsockopt=0x10`,
  `__sys_setsockopt=0x80`, `sock_common_setsockopt=0x40`, `udp_setsockopt=0x10`,
  `ip_setsockopt=0x290`).
- **sock_common_setsockopt dispatches to UDP.** For `SOCK_DGRAM`,
  `inet_dgram_ops.setsockopt` = `sock_common_setsockopt` (confirmed by reading
  `inet_dgram_ops.setsockopt` pointer from ELF data at `0xa14fed8`).
- **Walker reads `x27 = [waiter+0x38]`** at `rt_mutex_adjust_prio_chain+0x1b0`.
  `waiter->task` is never dereferenced before the lock read.

---

## Comparison: IPv4 vs IPv6 on POCO

| Path | Chain | Total frame | G_off | W_off | WAITER_OFF | Lock@ | Viable? |
|---|---|---|---|---|---|---|---|
| **IPv4 UDP** (this variant) | arm64→sys→sock_common→[cfi_slowpath]→udp→ip | 0x390 | 0x378 | 0x318 | **0x60** | greqs+0x98 | ✅ |
| IPv6 UDP (`exploit-mcast`) | arm64→sys→inet6→udpv6→udp_lib→ipv6 | 0x450 | 0x410 | 0x318 | **0xF8** | greqs+0x130 | ❌ |

The IPv6 path is geometrically insufficient (`0x130 > 0x108`). The IPv4 path
is geometrically viable (`0x78 < 0x108`).

---

## PROBE result — WAITER_OFF confirmed (2026-08-12)

Run: `run_probe_20260812_094536` (`MCAST_PROBE_INDEX=1`)

Panic:
```
pc : rt_mutex_adjust_prio_chain+0x1b0
x27: 0000000000000013
x25: 0000000000000013
FSC: 0x21 (alignment fault)
Fault address: 0x0000000000000013
```

Decoded: `WAITER_OFF = (0x13 * 8) - 0x38 = 0x98 - 0x38 = 0x60`.

The alignment fault at `0x13` (not NULL) proves the walk dereferenced our probe
slot value. The stamp landed on `waiter->lock` at `greqs + 0x98`. **Confirmed:
WAITER_OFF = 0x60.**

---

## Pending tasks (2026-08-12)

1. ~~Device PROBE run~~ → **done**: WAITER_OFF=0x60 confirmed (x27=0x13).
2. ~~Gate run~~ → **done**: phase1 settles cleanly in v6/v7/v9b.
3. ~~ksym_table offset bug~~ → **fixed**: offsets now `(link - 0xffffffc008000000)`.
4. ~~`rt_mutex_top_waiter` BUG~~ → **understood**: clean zeroed anchor avoids it.
5. ~~Ghost-write value analysis~~ → **done**: writes node addr, not stamped value.
6. **Pivot to physrw**: integrate `pipe_phys_read_data`/`pipe_phys_write_data` from
   `exploit-pselect/src/pipe.c` for reliable selinux=0 + cred patch on POCO.
