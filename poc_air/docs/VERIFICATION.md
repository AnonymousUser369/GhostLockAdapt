# poc_air — Symbol & Offset Verification Notes

## Verified Symbol Offsets (kernel_5-15-180-vmlinux.elf)

These are the link-time offsets used by `poc_air.c` in its `ksym_offs[]` table.
All values below are confirmed via `llvm-nm` on `Target/kernel_5-15-180-vmlinux.elf`
with `_text = 0xffffffc008000000`.

| Symbol | ELF address | Image offset (`addr - _text`) | poc_air.c current value | Match? |
|---|---|---|---|---|
| `empty_zero_page` | `0xffffffc00ad53000` | `0xad53000` | `0xad53000` | ✅ |
| `init_cred` | `0xffffffc00abfd698` | `0xabfd698` | `0xabfd698` | ✅ |
| `init_task` | `0xffffffc00ac43640` | `0xac43640` | `0xac43640` | ✅ |
| `modprobe_path` | `0xffffffc00ab24120` | `0xab24120` | `0xab24120` | ✅ |
| `selinux_state` | `0xffffffc00ada9d78` | `0xada9d78` | `0xada9d78` | ✅ |
| (see note below) | `0xffffffc00ada9e00` | `0xada9e00` | — | pointer, not struct |
| `panic_timeout` | `0xffffffc00ab20680` | `0xab20680` | `0xab20680` | ✅ |
| `inet6_protos` | `0xffffffc00ab0b3f8` | `0xab0b3f8` | `0xab0b3f8` | ✅ |
| `uid_lock` | `0xffffffc00adca680` | `0xadca680` | `0xadca680` | ✅ |
| `memstart_addr` | `0xffffffc00a164a50` | `0xa164a50` | `0xa164a50` | ✅ |
| `kimage_voffset` | `0xffffffc00a164a58` | `0xa164a58` | `0xa164a58` | ✅ |

**Conclusion:** All symbol offsets in `poc_air.c` `ksym_offs[]` are correct for this
kernel. No changes needed.

## Struct Field Offsets Relevant to poc_air

poc_air does not use `target.h`; its offsets are hardcoded in `poc_air.c` based on
the a54x original. The poc_air primitive is deliberately minimal — it avoids fake-page
waiter layouts entirely and instead relies on:

1. **sendmmsg iovec spray** — overwrites the dangling `rt_mutex_waiter` on Y's own
   kernel stack with controlled values.
2. **ZEROED fake_lock** — originally assumed `uid_lock+0x200` (`.bss`) would be a
   writable zeroed `rt_mutex`. **This is WRONG at runtime**: on POCO 5.15.180 the
   high-image region (`__init_end`..`.bss`, plus `.bss` itself) is NOT mapped at the
   vmlinux-predicted addresses → `pmd=0` level-2 translation fault at `+0x1b0`
   (`ldar w8,[x27]` reading `*fake_lock`). All `.bss`/GAP candidates
   (`uid_lock+0x200`, `empty_zero_page`, `selinux_state`, `init_task`) fault identically.
   The vmlinux nm offsets are still correct; the issue is page-table mapping, not values.
   Untested mapped candidates: `security_hook_heads` (0xa1617e0), `kmalloc_caches`
   (0xa164a60) — both in the low pre-init region. See CONTEXT.md "Status" section.
3. **Compact waiter fields** — the spray writes `task` at `waiter+0x30` and `lock` at
   `waiter+0x38`, which match the confirmed compact 5.15.180 layout.

### rt_mutex_waiter fields used by poc_air

> **Correction (this session):** the iov-slot mapping below was based on the OLD,
> WRONG assumption that `iov[0]` = `tree_entry.__rb_parent_color` and `iov[d+3]` =
> `task`/`lock`. Disassembly of `rt_mutex_adjust_prio_chain` + the PROBE panic now
> prove the iovec spray overlaps the freed waiter with a **+0x38 displacement**:
> `iov[0]` = `waiter->lock` (+0x38), `iov[1]` = +0x48, `iov[2]` = +0x58, `iov[3]` =
> +0x68 (past the 0x58-byte waiter). So `lock` is controlled by `iov[0]` (`li=0`),
> NOT `iov[d+3]`. The `task` field (+0x30) and `tree_entry` (+0x00..+0x37) are NOT
> covered by `iov[0..]` under the current displacement and need re-mapping for PHASE2.
> See `docs/OBSERVATIONS.md` "CORRECTED mapping".

| Field | Offset | Used? | Old (WRONG) iov slot | Correct (this session) |
|---|---|---|---|---|
| `task` | `0x30` | ✅ | `iov[d+3].iov_base = kaddr_init_task` ❌ | NOT covered by `iov[0..]` (+0x38 disp); needs re-map |
| `lock` | `0x38` | ✅ | `iov[d+3].iov_len = fake_lock_addr` ❌ | **`iov[0]`** (li=0) ✅ |
| `tree_entry.__rb_parent_color` | `0x00` | ✅ | `iov[d].iov_base = kaddr_selinux - 8` ❌ | NOT covered by `iov[0..]`; needs re-map |
| `tree_entry.rb_right` | `0x08` | ✅ | zeroed | NOT covered |
| `tree_entry.rb_left` | `0x10` | ✅ | zeroed | NOT covered |
| `wake_state` | `0x40` | ❌ not written | left as kernel real value | `iov[1]` (w/ prio) |
| `prio` | `0x44` | ❌ not written | left as kernel real value | `iov[1]` (w/ wake_state) |
| `deadline` | `0x48` | ❌ not written | left as kernel real value | `iov[2]` |
| `ww_ctx` | `0x50` | ❌ not written | left as kernel real value | `iov[2]` |

**Key insight:** poc_air does NOT write `wake_state`, `prio`, `deadline`, or `ww_ctx`
because the NULL child-pointer write into `selinux_state->enforcing` happens via
`rb_erase` on the tree_entry, not via waiter field manipulation. The kernel's own
values for those fields are left intact, which is why the pivot deref fault address
(`waiter->lock`) is the only ambiguity. **That ambiguity is now resolved: `lock` =
`iov[0]` (+0x38 displacement); the remaining open task is re-mapping `tree_entry`
(+0x00..+0x37) so PHASE2's `rb_erase` targets the right tree slot.**

## BTF / pahole Status

- `pahole` on the extracted BTF (`Target/kernel_5-15-180.btf`) works correctly
  for all structs except `task_struct` (whose BTF blob does not match this kernel).
- poc_air does not need `task_struct` offsets — it only uses `rt_mutex_waiter` fields,
  which are confirmed via disassembly.
- `rt_mutex_waiter` compact layout is confirmed: task@0x30, lock@0x38,
  wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50.

## What Needs to Change in poc_air.c (pending user decision)

> **Status update (2026-08-11):** the `rt_mutex` fake_lock / `rb_erase` selinux-forge
> path is **abandoned**. Every static `fake_lock` anchor (`uid_lock+0x200`,
> `selinux_state`, `init_task`, `kmalloc_caches`, `security_hook_heads`) faults with
> `pmd=0`/`pgd=0` — no image `.data`/`.bss`/GAP symbol is mapped at the
> vmlinux-predicted VA on this build (page-table mismatch between the booted
> `Image` and the provided `vmlinux.elf`). The decision is to **pivot to the
> physrw primitive** (exploit-pselect / CVE-2026-43499), which obtains arbitrary
> physical RW and needs no mapped kernel-symbol anchor. The UAF + `sendmmsg` spray
> + tracefs KASLR are retained as the entry primitive; the `tree_entry` PHASE2
> re-map below is therefore moot.

| Item | Current | Needed | Notes |
|---|---|---|---|
| `ksym_offs[]` values | all correct | no change | verified above |
| `g_iov_idx` default | `0` | keep, but meaning changed | default 0 means `iov[0]` = `waiter->lock` (+0x38 displacement). The lock slot `li` MUST be `0` (write `fake_lock` into `iov[0]`). `tree_entry`/`task` (+0x00..+0x37) are NOT covered by `iov[0..]` — PHASE2 re-map pending.
| Panic path comment | `ramoops /sys/fs/pstore/console-ramoops-0` | update to actual retrieval path | kernel panic is retrieved from `/sys/fs/pstore/console-ramoops-0` via adb after reboot |
| `selinux_state` symbol | `0xada9d78` | keep `selinux_state`, NOT `GKI_struct_selinux_state` | `GKI_struct_selinux_state` at `0xada9e00` is an exported POINTER (8 bytes) that points to `selinux_state` at runtime. The actual `struct selinux_state` lives at `0xada9d78` (136 bytes, `.bss`). poc_air must write to `selinux_state->enforcing` at `0xada9d78+0`, not dereference the pointer. Verified via `xiaomi_kernel_5.15.94/security/selinux/vendor_hooks.c`: `struct selinux_state *GKI_struct_selinux_state; EXPORT_SYMBOL_GPL(...)` — pointer-only, set by GKI compat layer. |
| `PROBE` mode | implemented | keep | used to discover `g_iov_idx` at runtime |

## Panic Retrieval

`getpanic.sh` pulls the panic from `/sys/fs/pstore/console-ramoops-0` on the device
after reboot. The poc_air.c comment at line 12 mentions "ramoops" but should be
updated to reflect the actual path:

```
/sys/fs/pstore/console-ramoops-0
```

## Variant Status

- **poc_air**: symbol offsets verified and correct. Struct offsets match confirmed
  compact 5.15.180 layout. No target.h needed (standalone binary with embedded offsets).
- **Spray displacement CONFIRMED this session: +0x38.** `iov[0]` = `waiter->lock`
   (+0x38); the buggy `li=3` (a54x layout) wrote `fake_lock` into `iov[3]`=`waiter+0x68`
   (past the 0x58-byte waiter), leaving `lock` as misaligned garbage → alignment fault
   at `rt_mutex_adjust_prio_chain+0x49c`. Fix: set `li=0`.
- **Current blocker (superseded):** originally the plan was to re-map `tree_entry`
   (+0x00..+0x37) and `task` (+0x30) so the PHASE2 `rb_erase` write lands correctly
   (under +0x38 those fields are NOT covered by `iov[0..]`). That path is now
   **abandoned** — all static `fake_lock` anchors fault (`pmd=0`/`pgd=0`), so the
   decision is to **pivot to the physrw primitive** (exploit-pselect /
   CVE-2026-43499), which replaces the `rt_mutex` fake_lock / selinux-forge stage.
