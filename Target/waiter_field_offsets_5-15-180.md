# rt_mutex_waiter field offsets on POCO air 5.15.180 — disassembly proof

Source: `/mnt/Data/AI_Workspace/ghostlock_repo/Target/kernel_5-15-180-vmlinux.elf`
(`_text = 0xffffffc008000000`). Tool: `llvm-objdump -d` (no DWARF/BTF).
Date: 2026-08-07.

## Confirmed compact layout

```
0x00  tree_entry       (struct rb_node, 24 bytes: 0x00..0x18)
0x18  pi_tree_entry    (struct rb_node, 24 bytes: 0x18..0x30)
0x30  task             (struct task_struct *, 8 bytes)
0x38  lock             (struct rt_mutex *, 8 bytes)
0x40  wake_state       (unsigned int / u32 — read as wakeup state)
0x44  prio             (int, 4 bytes)
0x48  deadline         (u64 / ktime_t, 8 bytes: 0x48..0x50)
0x50  ww_ctx           (struct ww_acquire_ctx *, 8 bytes: 0x50..0x58)
```

This matches the `RMG-Payloads-Pascua` `dm2q` target (Galaxy S23, 5.15.189):
`FAKE_WAITER_WAKE_STATE_OFF 0x40`, `FAKE_WAITER_PRIO_OFF 0x44`,
`FAKE_WAITER_DEADLINE_OFF 0x48`, `FAKE_WAITER_WW_CTX_OFF 0x50`.

## Disassembly evidence

### task_blocks_on_rt_mutex  (0xffffffc00976ffac)  — waiter = x21

```
ffffffc009770048: a9034eb4      stp     x20, x19, [x21, #0x30]
        ; waiter+0x30 = task (x19), waiter+0x38 = lock (x20)
ffffffc009770078: b90046a8      str     w8, [x21, #0x44]
        ; waiter+0x44 = prio  (32-bit store)
ffffffc009770080: f90026a8      str     x8, [x21, #0x48]
        ; waiter+0x48 = deadline (64-bit store)
ffffffc0097700c4: b94046aa      ldr     w10, [x21, #0x44]
        ; read prio@0x44
ffffffc0097700d8: f94026aa      ldr     x10, [x21, #0x48]
        ; read deadline@0x48
```

=> `task@0x30`, `lock@0x38`, `prio@0x44`, `deadline@0x48`. The 4-byte gap
`0x40..0x43` between `lock` (ends 0x40) and `prio@0x44` is `wake_state`.

### rt_mutex_adjust_prio_chain  (0xffffffc009770fa4)  — waiter = x28

```
ffffffc0097710f4: b9404789      ldr     w9, [x28, #0x44]   ; prio@0x44
ffffffc00977111c: f9402789      ldr     x9, [x28, #0x48]   ; deadline@0x48
...
ffffffc009772168: 91010129      add     x9, x9, #0x40
ffffffc009772320: b9404101      ldr     w1, [x8, #0x40]    ; waiter->wake_state @0x40
ffffffc009772324: 97a8c460      bl      0xffffffc0081a34a4 <try_to_wake_up>
        ; wake_state@0x40 is passed as the wakeup state argument
```

=> `wake_state@0x40` (read as a 32-bit field and used as `try_to_wake_up` state).
`ww_ctx@0x50` follows `deadline` (8 bytes, 0x48..0x50) by struct layout and
matches Pascua.

## Correction applied

Previous (wrong) "parked" offsets in both variant `target.h`:
`WAKE_STATE_OFF 0x60`, `WW_CTX_OFF 0x68`, `TREE_PRIO_OFF 0x40`,
`PI_TREE_PRIO_OFF 0x50`, `TREE_DEADLINE_OFF 0x48`, `PI_TREE_DEADLINE_OFF 0x58`.

Corrected to the real compact layout above (wake_state 0x40, prio 0x44,
deadline 0x48, ww_ctx 0x50). The legacy `TREE_PRIO`/`PI_TREE_PRIO` (and
deadline) macros both map to the single compact prio@0x44 / deadline@0x48.
`util.c::prepare_skb_payload` double-writes prio/deadline (to both macros);
with the corrected offsets both writes land on the same correct position, so
the double-write is redundant but harmless.

## Impact
- `exploit-pselect`: pivot sprays waiter fields via fd_set (`word8 -> waiter+0x40`),
  so stack positions were already correct; this fixes the skb fake-page layout
  used by the physrw/fops stage.
- `exploit-mcast`: fixes the skb fake-waiter page (route is frame-gap blocked, so
  currently moot).
- `poc_air`: unaffected (sprays inline, never builds a fake-page waiter).
- `pi_top_task@0x8b0` / `pi_blocked_on@0x8a0` were already disassembly-confirmed
  (see manual_offsets_5-15-180.md / pivot_fault_analysis.md) — not changed.
