# poc_air — Empirical Observations

> **2026-08-18 CORRECTION — the "page-table mismatch / pivot to physrw" conclusion is wrong.**
> The `pmd=0`/`pgd=0` faults documented below were computed at the **raw** nm `ksym_offs[]`
> offsets (+0x8000000 too high for BSS/DATA), so they landed 128 MB above the genuinely-mapped
> `.bss` block. The slide/leak was correct; the **offsets** were wrong. poc-mcast PROVED `.bss` is
> mapped on this exact POCO air device (selinux flip via `z_pagemap_global+0x1200`). The fix
> (subtract `0x8000000` from every `ksym_offs[]` entry, matching poc-mcast's values) was applied
> 2026-08-18 — see `CONTEXT.md` "LATEST (2026-08-18)". Re-test the DEFAULT `uid_lock` anchor with
> the offset fix before pivoting to physrw. Blocker B (sendmsg `D=+0x38` can't reach `tree_entry`)
> remains the genuine blocker for the `rt_mutex` forge.

## Code versions

| Version | Write primitive | PROBE sentinels | Status |
|---|---|---|---|
| v1 (poc_air.c pre-v2) | raw NULL (0) | `(i<<44)` invalid | Panic confirms spray lands, but NULL write unstable |
| v2 (current poc_air.c) | `empty_zero_page` safe value | `0xabcdef00\|i<<8` valid | Ready for PROBE + exploit runs |

All data below is from runs **after** the `run.sh` env-passing bug was fixed (i.e., `IOV_IDX`, `PROBE`, `SPRAY` actually reached the device). Runs before `run_probe_20260808_200403` are invalid and were deleted from `runlogs/`.

**PROBE runs before this session used sentinel encoding `(i<<44)`, which produces
invalid kernel addresses and never appears in panics.** Those PROBE runs are
therefore uninformative about iov mapping. New PROBE runs use sentinels
`0xabcdef00|i<<8` and run full two-phase (settle + write).

---

## Run log index

| Tag | d | li | Panic? | PC offset | x27 | x19 | Verdict |
|---|---|---|---|---|---|---|---|
| probe_200403 | 1 | 4 | yes | +0x49c | non-NULL | — | **OLD SENTINELS (i<<44) — uninformative** |
| probe_200929 | 1 | 4 | yes | +0x49c | non-NULL | — | **OLD SENTINELS — uninformative** |
| probe_213200 | 1 | 4 | yes | +0x49c | non-NULL | — | **OLD SENTINELS — uninformative** |
| iov0 | 0 | 3 | yes | +0x1b0 | **0 (NULL)** | `ffffff80ac9f8000` | NULL deref — lock field zeroed |
| iov1 | 1 | 4 | yes | +0x49c | non-NULL | `ffffff8055ae4800` | alignment fault |
| d2 | 2 | 5 | yes | +0x1b0 | **0 (NULL)** | `ffffff809b8eec00` | NULL deref |
| d3 | 3 | 6 | yes | +0x49c | non-NULL | `ffffff805a200000` | alignment fault |
| d3fix | 3 | 4 | yes | +0x14ac | non-NULL | `ffffff8062ff3600` | BUG at rtmutex_common.h:118 |
| d4 | 4 | 7 | yes | +0x49c | non-NULL | `ffffff800cf80000` | alignment fault |
| d5 | 5 | 8 | yes | +0x49c | non-NULL | `ffffff8077ba8000` | alignment fault |
| d5fix | 5 | 4 | yes | +0x1b0 | **0 (NULL)** | `ffffff8072b7a400` | NULL deref |
| d6 (old li) | 6 | 9 | no | — | non-NULL | — | no panic, enforce=1 |
| d7 (old li) | 7 | 10 | timeout | — | — | — | exec-out timeout |
| v6 (old li) | 0 | 3 | yes | +0x1b0 | **0 (NULL)** | `ffffff806b342400` | NULL deref (pre-fix, Aug 6) |
| wvprobe | — | — | yes | +0x1b0 | **0 (NULL)** | `ffffff8056328000` | NULL deref (writev probe) |

**Note:** `li` column shows the actual `li` used. For old `li=d+3` code, `li` was `d+3`.
For `d3fix`/`d5fix`/current code, `li=4` (sendmsg) or `li=0` (writev).

### New PROBE runs (post-sentinel-fix)

| Tag | Mode | PC offset | FSC | x27 | x19 | Sentinel in panic? | Verdict |
|---|---|---|---|---|---|---|---|
| probe_v2_20260810_121651 | PROBE=1 | +0x1b0 | level 0 translation (0x04) | `abcdef0000000000` | `ffffff80bff59200` | **YES — SENT(0) in x27 and fault addr** | `iov[0]` is dereferenced first; sentinel survives walk |
| v2safe_20260810_120332 | IOV_IDX=1 (default) | +0x49c | alignment (0x21) | `ffffff808648964c` | `ffffff8086489200` | no | alignment fault at lock deref; x27-x19=0x44c |
| iov0_v2_20260810_122440 | IOV_IDX=0 | +0x49c | alignment (0x21) | `ffffff8040c9844c` | `ffffff8040c9800` | no | same pattern; x27-x19=0x44c |

### Disambiguation + KASLR runs (2026-08-10, this session)

PROBE rewritten with DISTINCT sentinels per base/len (`SENT(100+i)` base, `SENT(200+i)` len) to pin base-vs-len and the displacement D.

| Tag | Mode | Spray | PC offset | FSC | x27 | Verdict |
|---|---|---|---|---|---|---|
| probe_disamb_sm_20260810_200740 | PROBE | sendmsg | +0x1b0 | translation (0x04) | `abcdef000000c800` = **SENT(200)=iov[0].iov_len** | **D=+0x30, base-first**: lock=`iov[0].iov_len`; `li=0` correct |
| probe_disamb_wv_20260810_201115 | PROBE | writev | +0x1b0 | translation (0x06) | `0` | lock NOT covered by spray (D>+0x38) |
| probe_disamb_pvmw_20260810_201847 | PROBE | pvmw | +0x49c | alignment (0x21) | `x19+0x44c` (garbage) | lock NOT covered; shallower frame |
| probe_disamb_keyctl_20260810_203011 | PROBE | keyctl | +0x49c | alignment (0x21) | `x19+0x44c` (garbage) | lock NOT covered; shallower frame |
| phase1_lifix_20260810_203526 | no PROBE | sendmsg, `li=0` | +0x1b0 | translation (0x06) | `fake_lock = 0xffffffdfb2dca880` | **perf KASLR leak base 128 MB too high** (perf era only — now FIXED by tracefs leak; see below) |

### KASLR + fake_lock runs (2026-08-11 — tracefs leak + FAKE_MEM probe)

KASLR leak REPLACED: perf → tracefs `sched_blocked_reason` (event ID 108, modal `caller` @ offset 16, slide = mode − (KIMAGE+0x178510)). Verified exact: leaked slide equals oops `Kernel Offset` in every run below. `FAKE_MEM` env added to probe the `fake_lock` anchor without recompiling.

| Tag | FAKE_MEM | PC offset | FSC | Fault addr / x27 | Kernel Offset (slide) | Verdict |
|---|---|---|---|---|---|---|
| tfix2z_20260810_232441 | `zero` (empty_zero_page) | +0x1b0 | 0x06 level-2 | `ffffffd624d53000` | 0x1612000000 | `pmd=0` translation fault — `empty_zero_page` (`.bss`) NOT mapped |
| tfix3s_20260811_085950 | `selinux_state` | +0x1b0 | 0x06 level-2 | `ffffffd83d3a9d78` | 0x182a600000 | `pmd=0` translation fault — `selinux_state` (`.bss`) NOT mapped |
| tfix4i_20260811_091317 | `init_task` | +0x1b0 | 0x06 level-2 | `ffffffe7cba43640` | 0x27b8e00000 | `pmd=0` translation fault — `init_task` (GAP `__init_end`..`.bss`) NOT mapped. (Prior "PHASE1 OK" note was WRONG — this also faults.) |
| tfix_kmc_20260811_100144 | `kmalloc_caches` | +0x1b0 | 0x06 level-2 | `ffffffefd6564a60` | 0x2fc4400000 | `pmd=0` translation fault — `kmalloc_caches` (low pre-init `.data`) ALSO NOT mapped |
| tfix_shh_20260811_101440 | `security_hook_heads` | +0x1b0 | 0x06 level-2 | `ffffffec82b617e0` | 0x2c70a00000 | `pgd=0` (fully unmapped) — `security_hook_heads` (low pre-init `.data`) ALSO NOT mapped |

**Blocker A (KASLR) = FIXED** (tracefs leak, exact slide). The fault in all runs is NOT KASLR: in each, `fault = KIMAGE + slide + image_off` is byte-correct (slide matches oops; image_off matches nm). The page-table dump shows `pmd=0000000000000000` (or `pgd=0`) → the block for that address is absent.

**Blocker B (`tree_entry` unreachable)** unchanged: only `sendmsg` covers the lock at D=+0x38; `tree_entry` (+0x00..+0x2F) is before the spray window → PHASE2 `rb_erase` write cannot be aimed. No tested spray yields D≤0.

**DEFINITIVE: ALL static kernel-symbol fake_lock candidates FAIL (2026-08-11).** Five symbols tested, spanning the entire image range — `.bss` (empty_zero_page/selinux_state/uid_lock), GAP (`init_task`), and low pre-init `.data` (`kmalloc_caches`/`security_hook_heads`) — every one faults with `pmd=0`/`pgd=0`. The only address that IS mapped is `.text` code (the tracefs leak reads `worker_thread+0x7c` fine, and the faulting PC `rt_mutex_adjust_prio_chain` is itself `.text` and executes). 

**Conclusion:** the running kernel's `.text` layout matches the vmlinux (so the slide/leak is correct), but **no kernel-image `.data`/`.bss`/GAP symbol is mapped at the vmlinux-predicted virtual address.** Either (a) the booted `Image` (`Target/boot.img` → `kernel_5-15-180`) lays out `.data`/`.bss` at a different link offset than the provided `vmlinux.elf` (GKI core vs combined image mismatch), or (b) arm64 maps image `.text` and `.data`/`.bss` from different bases on this build. Either way: **a static kernel-symbol fake_lock is not viable with the current offset table.** Pivot to the physrw primitive (exploit-pselect / CVE-2026-43499), which obtains arbitrary physical RW and needs no mapped kernel-symbol anchor.

See `CONTEXT.md` "Status (2026-08-11)" for the full plan and next device tests.

**Key finding from probe_v2:** The sentinel `abcdef0000000000` (`SENT(0)`) appears as the fault address and in `x27`/`x25`. This proves:
1. The new sentinel encoding `0xabcdef00|i<<8` is valid and survives the chain walk.
2. **`iov[0]` = `waiter->lock` (+0x38)** — it is the field dereferenced at `+0x1b0` (`ldar w8,[x27]`) AND at `+0x49c` (`ldar x8,[x27,#0x18]`). Disassembly confirms both read `lock->owner` from `[waiter+0x38]`.
3. The fault is a level-0 translation fault (page-not-present), confirming the sentinel is an invalid kernel address.

**What this means for the mapping:** The prior table (iov[0]=parent_color) is WRONG. With the +0x38 displacement, `iov[0]` overlays `waiter+0x38` = `lock`. The `lock` field is therefore controllable directly via `iov[0]` (`li=0`), but `tree_entry`/`task` (+0x00..+0x37) are NOT covered by the spray in the current displacement and need re-mapping for PHASE2.

### Confirmed POCO 5.15.180 layout from kernel source

From `/mnt/Data/AI_Workspace/xiaomi_kernel_5.15.94/include/linux/rbtree_types.h` and `kernel/locking/rtmutex_common.h`, confirmed via BTF (`pahole -C rt_mutex_waiter kernel_5-15-180.btf`):

```c
struct rb_node {
    unsigned long __rb_parent_color;  /* +0x00 */
    struct rb_node *rb_right;         /* +0x08 */
    struct rb_node *rb_left;          /* +0x10 */
};  // 24 bytes total

struct rt_mutex_waiter {
    struct rb_node tree_entry;        /* +0x00, 24 bytes */
    struct rb_node pi_tree_entry;     /* +0x18, 24 bytes */
    struct task_struct *task;         /* +0x30, 8 bytes */
    struct rt_mutex_base *lock;       /* +0x38, 8 bytes */
    unsigned int wake_state;          /* +0x40 */
    int prio;                         /* +0x44 */
    u64 deadline;                     /* +0x48 */
    struct ww_acquire_ctx *ww_ctx;    /* +0x50 */
};  // 88 bytes total
```

**Critical difference from a54x assumption:** `struct rb_node` is **24 bytes** on this kernel, not 16. This shifts every field after `tree_entry` by +8 bytes.

> ⚠️ **THIS TABLE IS WRONG — DO NOT USE.** It was derived from source inspection only
> and is contradicted by the PROBE panic (see below). `iov[0]` is **NOT**
> `tree_entry.__rb_parent_color`; it is `waiter->lock`. The real displacement is
> +0x38, not +0x00. See "CORRECTED mapping (this session)".

~~(old, incorrect table)~~

| iov index | waiter offset | field |
|---|---|---|
| `iov[0]` | +0x00 | `tree_entry.__rb_parent_color` ❌ (actually `lock`) |
| `iov[3].iov_len` | +0x38 | `lock` ❌ (actually `iov[0]`) |
| `iov[3].iov_base` | +0x30 | `task` ❌ |

---

## CORRECTED mapping (this session — disassembly + PROBE proven)

Two independent proofs now fix the mapping:

1. **Disassembly of `rt_mutex_adjust_prio_chain`** (base `0xffffffc009770fa4`, len 0x14c0):
   - `+0x49c` → file `0xffffffc009771440`: `ldar x8,[x27,#0x18]` reads `lock->owner`; `x27 = [waiter+0x38]`.
   - `+0x1b0` → file `0xffffffc009771154`: `ldar w8,[x27]` reads `lock->owner`; `x27 = [waiter+0x38]`.
   - `x28 = [task+0x8b0]` = `task->pi_blocked_on` (BTF: `pi_blocked_on` @ task+2224/0x8b0) = dangling waiter; `x27 = [x28+0x38]` = `waiter->lock`.
2. **PROBE panic** (`runlogs/panic_probe_v2_20260810_121651.txt`): `x27 = 0xabcdef0000000000 = SENT(0)` = content of **`iov[0]`** → `iov[0]` is the field dereferenced as `waiter->lock`, i.e. **`iov[0]` = `waiter+0x38`**.

**The iovec spray overlaps the freed waiter with a +0x38 displacement** (each `struct iovec` is 0x10 bytes):

| iov index | waiter offset | field |
|---|---|---|
| `iov[0]` | +0x38 | **`lock`** ✅ (this is where `fake_lock` MUST go) |
| `iov[1]` | +0x48 | `wake_state` (4) + `prio` (4) |
| `iov[2]` | +0x58 | `ww_ctx` (8) + beyond struct |
| `iov[3]` | +0x68 | **beyond the 0x58-byte waiter** (where buggy `li=3` wrote `fake_lock`) |

**Consequences for exploit:**
- `li` (lock slot) = **0** (not 3). `fake_lock` must be written into `iov[0]`.
- `struct rb_node` is still 24 bytes; `rt_mutex_waiter` is 88 bytes (0x58): `task` @0x30, `lock` @0x38.
- With the +0x38 displacement, `tree_entry` (+0x00..+0x37) and `task` (+0x30) are **NOT** covered by `iov[0..]`. The PHASE2 RB-tree write that previously targeted `parent_color`/`rb_left` must be re-mapped — either the spray displacement must shift earlier (different `g_iov_idx`/pad) or the parent_color/rb_left targets are at negative/uncovered offsets and need a different approach.
- The a54x `poc2.c` layout (`iov[1]`=parent, `iov[4]`=task/lock) and the old POCO table are **both wrong**.

---

## fake_lock fault — ROOT CAUSE (verified 2026-08-11; **superseded 2026-08-18 — see top CORRECTION**)

**Question:** if `ksym_offs[]` values are correct (verified via nm + VERIFICATION.md), why does `fake_lock` translation-fault?

**Method:** cross-checked the device's own reference artifacts — `pahole -C rt_mutex_waiter` / `rt_mutex_base` on `Target/kernel_5-15-180.btf`, `llvm-nm` on `kernel_5-15-180-vmlinux.elf`, `Target/manual_offsets_5-15-180.md`, `Target/waiter_field_offsets_5-15-180.md`, `Target/target_h_verification.md`, and the `rt_mutex_adjust_prio_chain` disasm (`Target/disasm/`).

### 1. Offsets & struct layout are CORRECT (not the cause)
- pahole: `rt_mutex_waiter`: tree_entry@0x0, pi_tree_entry@0x18, task@0x30, lock@0x38, wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50 (size 0x58). `rt_mutex_base`: wait_lock@0, waiters@8, owner@24.
- nm: `init_task=0xac43640`, `selinux_state=0xada9d78`, `empty_zero_page=0xad53000`, `uid_lock=0xadca680` — all match `ksym_offs[]`.
- Tracefs slide matches oops `Kernel Offset` exactly in tfix2z/tfix3s/tfix4i. So `fake_lock = KIMAGE + slide + image_off` is byte-correct.

### 2. The fault is a genuine `pmd=0` level-2 translation fault
Every panic dump shows `pgd=.., p4d=.., pud=.., pmd=0000000000000000`. The computed virtual address is correct but that 2MB block has no mapping. Decomposed fault addresses all reduce to `KIMAGE + slide + image_off` with the right offsets, then fault at `ldar w8,[x27]` (+0x1b0) reading `*fake_lock`.

### 3. The pattern: all candidates are in the UNMAPPED high-image region
Image layout (from nm + objdump `-h`): `_text`=0x8000000, `__init_begin`=0xa870000, `__init_end`=0xaaf0000, `.bss`=0xad4ea00..0xadf0000, `_end`=0xadf0000.

| Symbol | image off | region | faulted? |
|---|---|---|---|
| `security_hook_heads` 0xa1617e0 | pre-`__init_begin` | **low (mapped?) — UNTESTED** | ? |
| `kmalloc_caches` 0xa164a60 | pre-`__init_begin` | **low (mapped?) — UNTESTED** | ? |
| `modprobe_path` 0xab24120 | GAP (`__init_end`..`.bss`) | high | (by analogy) |
| `init_cred` 0xabfd698 | GAP | high | — |
| `init_task` 0xac43640 | GAP | high | **yes (tfix4i)** |
| `init_mm` 0xac87a28 | GAP | high | — |
| `selinux_state` 0xada9d78 | `.bss` | high | **yes (tfix3s)** |
| `empty_zero_page` 0xad53000 | `.bss` | high | **yes (tfix2z)** |
| `uid_lock` 0xadca680 / +0x200 | `.bss` | high | **yes (default)** |
| `root_task_group` 0xad57ac0 | `.bss` | high | — |

**Conclusion (FINAL, after `kmalloc_caches` + `security_hook_heads` tests):** ALL five tested candidates fault, spanning the entire image — `.bss` (empty_zero_page/selinux_state/uid_lock), GAP (`init_task`), AND low pre-init `.data` (kmalloc_caches `pmd=0`, security_hook_heads `pgd=0`). The ONLY mapped addresses are `.text` code (the tracefs leak reads `worker_thread+0x7c` fine, and the faulting PC is `.text` executing normally). So `.text` layout matches the vmlinux (slide/leak correct) but **no image `.data`/`.bss`/GAP symbol is mapped at the vmlinux-predicted VA.** Root cause is a page-table mapping mismatch between the running `Image` and the provided `vmlinux.elf` (GKI-core vs combined boot image, or split text/data base), NOT an offset/struct error. **A static kernel-symbol fake_lock is not viable.**

### 4. Code note
`poc_air.c` never actually zeroes `fake_lock_addr` — it relies on BSS already being zero. Irrelevant to THIS fault (the fault is the pointer deref at `+0x1b0`, before any content matters). The anchor must be a *mapped, zeroed* region we control; `uid_lock+0x200`/`.bss` symbols don't qualify because they're unmapped.

### 5. Next device tests — DONE (result: all fail)
- `FAKE_MEM=security_hook_heads` and `FAKE_MEM=kmalloc_caches` (low pre-init region) — **both ALSO fault** (`security_hook_heads`: `pgd=0`; `kmalloc_caches`: `pmd=0`). No mapped static anchor exists.
- **Resolution: pivot to physrw primitive** (exploit-pselect / CVE-2026-43499), which obtains arbitrary physical RW and does NOT need a mapped static kernel-symbol fake_lock. The UAF/sendmsg spray + tracefs KASLR still provide the primitive entry; physrw replaces the `rt_mutex` fake_lock/selinux-forge stage.

---

## Key register patterns

> **Correction (this session):** the interpretations below were written before the
> mapping was confirmed. The `+0x49c` alignment fault is **not** a structural
> displacement of the waiter — `x27 = x19+0x44c` is simply the misaligned *garbage
> value* left in `waiter->lock` because the buggy `li=3` wrote `fake_lock` into
> `iov[3]` = `waiter+0x68` (past the struct). The `+0x1b0` NULL panics mean
> `waiter->lock` (at `iov[0]`) was 0. See "CORRECTED mapping" above.

### Non-NULL panics (alignment fault at +0x49c)

`x27 - x19 = 0x44c` consistently. Example (d1):
- `x19 = ffffff8055ae4800` (task at `waiter+0x30`)
- `x27 = ffffff8055ae4c4c` (lock field value = `x19 + 0x44c`)

This offset does NOT match `waiter->lock @ +0x38` from the compact struct layout. `x19` is `waiter+0x30` (task), and `x27` is the **reallocated object's lock field** at `waiter+0x30+0x44c = waiter+0x47c`. This means the spray is hitting an object that starts 0x44c bytes after the task field — i.e., the waiter struct is NOT at `x19`, and `x19` is the task pointer stored at `waiter+0x30`.

### NULL panics (NULL deref at +0x1b0)

`x27 = 0` in v6, iov0, d2, d5fix, wvprobe. The `ldar w8,[x27]` at `+0x1b0` faults because `waiter->lock = 0`. This means the PHASE2 spray DID land on `waiter->lock` but wrote 0 — either because the iov slot mapping was wrong, or because the NULL write happened too early (before the second trigger).

---

## Displacement analysis

### The conflict with `li = d + 3` (old code)

For d ≥ 3, `iov[d+1]` collides with `iov[4]` (task/lock):
- d=3: `iov[4]` = `rb_left=0` AND `task/lock` → second write overwrites first
- d=4: `iov[4]` = `parent_color=selinux-8` AND `task/lock` → CONFLICT
- d=5: `iov[6]` = `rb_left=0`, `iov[4]` = `task/lock` → no conflict but parent at iov[5]
- d=6: `iov[7]` = `rb_left=0`, `iov[4]` = `task/lock` → no conflict but parent at iov[6]
- d=7: `iov[8]` out of bounds

### With `li = 4` (new code, v2)

Valid d values: 0, 1, 2, 5, 6. (d=3,4 conflict; d=7 OOB).

**v2 data (safe-write primitive, PROBE sentinels):**
- `probe_v2` (PROBE=1): FSC = 0x04 (translation fault), PC = +0x1b0. `x27 = abcdef0000000000` (SENT(0)). **Sentinels confirmed working. `iov[0]` is dereferenced first.**
- `v2safe` (IOV_IDX=1, default): FSC = 0x21 (alignment fault), PC = +0x49c. x27-x19 = 0x44c. No sentinels in panic.
- `iov0_v2` (IOV_IDX=0): FSC = 0x21 (alignment fault), PC = +0x49c. x27-x19 = 0x44c. No sentinels in panic.

### What this tells us

The v2 runs show two distinct failure modes, now both explained:
1. **PROBE mode** (`+0x1b0`, translation fault): the sentinel `SENT(0) = 0xabcdef0000000000` in `iov[0]` is an invalid user address, so the walk crashes immediately when dereferencing `iov[0]` = `waiter->lock`. **This proves `iov[0]` = `waiter->lock` (+0x38).**
2. **Normal mode** (`+0x49c`, alignment fault): the spray wrote `fake_lock` into `iov[3]` = `waiter+0x68` (past the 0x58-byte struct), leaving `waiter->lock` as sprayed garbage. That garbage (`x27 = x19+0x44c`, ending `0x4c`) is misaligned → FSC 0x21 at `ldar x8,[x27,#0x18]`. **Root cause = bad `li` (3 instead of 0), NOT alignment of `fake_lock`** (which is 8B-aligned at `uid_lock+0x200`/`+0x300`).

The `x27 - x19 = 0x44c` is just the value of the garbage left in `waiter->lock` (the sprayed content at `waiter+0x38`), not a displacement of the structure.

**We have NOT yet reached PHASE2 in any v2 run.** The selinux write has not been attempted.

---

## Open questions

1. **ANSWERED:** `iov[0]` = `waiter->lock` (+0x38). Proven by disassembly (`+0x1b0`/`+0x49c` both read `[waiter+0x38]`) and by PROBE (`x27 = SENT(0)` = `iov[0]`). It is NOT `tree_entry.__rb_parent_color` (+0x00).

2. **ANSWERED:** `waiter->lock` lands at `iov[0]` (with +0x38 displacement). The buggy `li=3` wrote `fake_lock` into `iov[3]` = `waiter+0x68`, past the struct — leaving `lock` as garbage. Fix: `li=0`.

3. **Why +0x49c (alignment) vs +0x1b0 (translation)?** Both dereference `waiter->lock`. PROBE writes an invalid sentinel → translation fault at `+0x1b0`. Real runs write misaligned garbage → alignment fault at `+0x49c` (`ldar x8,[x27,#0x18]` reads `lock->owner+0x18`). Consistent with `iov[0]` = `lock`.

4. **a54x reference validity for POCO:** poc2.c (P0/AP3A) claims permissive but uses `inet6_protos+0xb8` fake_lock2 which is RO on POCO. Its layout (`iov[1]`=parent, `iov[4]`=task/lock) is **wrong for POCO** — POCO's displacement is +0x38, so `lock` is at `iov[0]`.

5. **Write primitive:** Already switched to `empty_zero_page` safe value in v2. This keeps `selinux_state->initialized=1` while zeroing `enforcing`, avoiding the corruption issues of raw NULL.

6. **OPEN — re-map PHASE2 targets (Blocker B):** With the +0x38 displacement, `tree_entry` (+0x00..+0x37) and `task` (+0x30) are NOT covered by `iov[0..]`. The PHASE2 RB-tree write (parent_color / rb_left) must be re-derived: either shift the spray displacement earlier (different `g_iov_idx` / pad bytes so `iov[0]` lands at `waiter+0x00`), or find where those fields actually land. This is still the next blocking task after the fake_lock anchor is resolved.

7. **ANSWERED — fake_lock fault:** NOT an offset/struct bug. Verified via pahole/nm/disasm: offets & `rt_mutex_waiter`/`rt_mutex_base` layout correct; the computed `fake_lock` address is byte-correct (slide matches oops) but the 2MB block is unmapped (`pmd=0`). All tested candidates live in the high image region (GAP `__init_end`..`.bss` + `.bss`) which is not mapped on this build. Untested mapped candidates: `security_hook_heads`/`kmalloc_caches`. See "fake_lock fault — ROOT CAUSE" section.

---

## Next step

1. **`li=0` DONE** — `fake_lock` is written into `iov[0]` = `waiter->lock` (+0x38). Confirmed by PROBE + disasm. (The remaining fault is the unmapped `fake_lock` anchor, see below — not `li`.)

2. **Find a mapped fake_lock anchor:** run `FAKE_MEM=security_hook_heads` and `FAKE_MEM=kmalloc_caches` on device. If PHASE1 completes clean (no +0x1b0 fault), wire that as the default `fake_lock`. If both fault, pivot to physrw (exploit-pselect / CVE-2026-43499).

3. **Re-map PHASE2 (Blocker B):** determine where `tree_entry.__rb_parent_color` / `rb_left` / `rb_right` (+0x00..+0x37) land under the +0x38 displacement (deeper spray frame for D≤0, or physrw pivot that avoids `tree_entry` forging entirely).

4. **Write primitive:** already switched to `empty_zero_page` safe value in v2.
