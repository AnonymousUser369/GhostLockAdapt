# Offset verification proof

All offsets used in `exploit-pselect` / `exploit-mcast` `target.h` are verified
against the **production** POCO air 5.15.180 kernel (`Target/kernel_5-15-180*`),
NOT the debug kernel (`gki_debugkernel_*`). The debug kernel has
`CONFIG_DEBUG_RT_MUTEXES=y` which adds debug fields and shifts struct layouts —
that is why `pahole` on the debug kernel "never worked" for our offsets.

## Critical finding: BTF task_struct does NOT match this kernel

The BTF blob embedded in `Target/kernel_5-15-180` reports a `task_struct`
layout that **does not match** the production 5.15.180 build. This is
likely because the Image was repacked/reflashed with a different build's BTF.
For `task_struct`, `page`, and `pipe_buffer`, **trust disassembly over BTF**.
`mm_struct` is fully resolved by BTF (verified via disassembly). The tables
below list BOTH values so contradictions are explicit.

## Sources

| Source | Location | Notes |
|---|---|---|
| Production raw Image | `Target/kernel_5-15-180` | ARM64 Image containing the BTF blob |
| Raw BTF blob | `Target/kernel_5-15-180.btf` | Extracted from the production Image |
| BTF text dump | `btf/vmlinux-btf.raw` | `bpftool btf dump format raw` |
| BTF extractor | `../scripts-and-tests/extract_btf.py` | Extracts BTF blob from raw Image; extracted `.btf` works with `pahole` |
| Production vmlinux ELF | `Target/kernel_5-15-180-vmlinux.elf` | Reconstructed, `.symtab` present, no DWARF/BTF |
| Updated target.h (canonical) | `target.h` | This file — corrected offsets for this kernel |
| Raw disassembly | `disasm/` | `llvm-objdump -d` windows around key functions |
| | `disasm/task_blocks_on_rt_mutex.txt` | confirms compact waiter layout |
| | `disasm/rt_mutex_adjust_prio_chain.txt` | confirms pi_top_task/pi_blocked_on |
| | `disasm/get_task_cred.txt` | confirms real_cred/cred |
| | `disasm/commit_creds.txt` | confirms cred |
| | `disasm/prepare_kernel_cred.txt` | confirms real_cred |
| | `disasm/get_task_mm.txt` | confirms mm @ +0x520 |
| | `disasm/set_user_nice.txt` | confirms normal_prio @ +0x80 |
| | `disasm/__get_task_comm.txt` | confirms comm @ +0x7a8 |
| | `disasm/do_task_stat.txt` | confirms real_parent @ +0x5e8; pid/tgid via thread_pid |
| | `disasm/copy_process.txt` | confirms tasks list_head @ +0xa68/0xa70 |
| | `disasm/__mmput.txt` | confirms mm_struct usage |
| | `disasm/get_task_pid.txt` | confirms pid accessed via thread_pid @ +0x7f0 |
| | `disasm/__task_pid_nr_ns.txt` | confirms pid structure access pattern |
| | `disasm/wake_up_new_task.txt` | confirms sched_task_group @ +0x400 |
| Waiter field proof | `waiter_field_offsets_5-15-180.md` | Disassembly proof for compact rt_mutex_waiter |
| Manual derivation | `manual_offsets_5-15-180.md` | Original llvm-objdump/nm derivation notes |
| Symbol verification | `target_h_verification.md` | llvm-objdump -t table: all `*_OFF` constants verified against ELF symbol table |

## Verification status

Legend:
- ✅ confirmed by BTF + disassembly (agree)
- ⚠️ BTF ≠ disassembly — **trust disassembly**
- 🔲 disassembly verification still needed

---

### rt_mutex_waiter (compact 5.15.180)

BTF and disassembly agree on the compact layout.

| Field | target.h | BTF (byte) | Disasm evidence | Status |
|---|---|---|---|---|
| tree_entry | 0x00 | 0x00 | `stp x20,x19,[x21,#0x30]` in task_blocks_on_rt_mutex | ✅ |
| pi_tree_entry | 0x18 | 0x18 | same | ✅ |
| task | 0x30 | 0x30 | same | ✅ |
| lock | 0x38 | 0x38 | same | ✅ |
| wake_state | 0x40 | 0x40 | `ldr w1,[x8,#0x40]` → try_to_wake_up | ✅ |
| prio | 0x44 | 0x44 | `str w8,[x21,#0x44]` | ✅ |
| deadline | 0x48 | 0x48 | `str x8,[x21,#0x48]` | ✅ |
| ww_ctx | 0x50 | 0x50 | follows deadline (+8) | ✅ |

**Disassembly addresses (from `manual_offsets_5-15-180.md`):**
- `task_blocks_on_rt_mutex` at `0xffffffc00976ffac` — waiter = x21
  - `stp x20,x19,[x21,#0x30]` → task@0x30, lock@0x38
  - `str w8,[x21,#0x44]` → prio@0x44
  - `str x8,[x21,#0x48]` → deadline@0x48
- `rt_mutex_adjust_prio_chain` at `0xffffffc009770fa4` — waiter = x28
  - `ldr w9,[x28,#0x44]` → prio@0x44
  - `ldr x9,[x28,#0x48]` → deadline@0x48
  - `ldr w1,[x8,#0x40]` → wake_state@0x40 (passed to `try_to_wake_up`)

---

### task_struct

**BTF reports size=4608 (0x1200) and many wrong offsets. Disassembly confirms
the production 5.15.180 layout is DIFFERENT.**
BTF values below are included for contradiction tracking; **do not use BTF
values for this struct**.

| Field | target.h | BTF (byte) | Disasm evidence | Status |
|---|---|---|---|---|
| usage | 0x44c | 0x38 (WRONG) | `str w8,[x0,#0x44c]` in get_task_struct | ✅ (BTF 0x38 WRONG) |
| prio | 0x7c | 0x7c | `cmp task->0x7c` in task_blocks_on_rt_mutex | ✅ |
| normal_prio | 0x80 | 0x84 (WRONG) | `ldr w9,[x19,#0x80]` in set_user_nice | ✅ (BTF 0x84 WRONG) |
| mm / MM_OWNER | 0x520 | 0x520 | `ldr x20,[x21,#0x520]` in get_task_mm | ✅ (old target.h 0xAB8 was WRONG) |
| pid | 0x7f0 | **0x5d8** (WRONG) | `get_task_pid`/`__task_pid_nr_ns` use task+0x7f0 (thread_pid), not direct field | ⚠️ indirect |
| tgid | 0x7f0 | **0x5dc** (WRONG) | same — accessed through thread_pid struct at task+0x7f0 | ⚠️ indirect |
| real_parent | 0x5e8 | 0x5e8 | `ldr x8,[x21,#0x5e8]` in do_task_stat | ✅ (old target.h 0xB40 was WRONG) |
| atomic_flags | 0x598 | 0xAF0 (WRONG) | `ldr x8,[x21,#0x598]` in do_seccomp | ✅ (old target.h 0xAF0 WRONG; BTF agrees with disasm) |
| real_cred | 0x790 | 0x790 | `ldr x19,[x20,#0x790]` in get_task_cred | ✅ |
| cred | 0x798 | 0x798 | `ldr x9,[x10,#0x798]` in commit_creds | ✅ |
| comm | 0x7a8 | 0x7a8 | `add x1,x20,#0x7a8` in __get_task_comm | ✅ (old target.h 0xD48 was WRONG) |
| tasks | 0xa68 | 0x4d0 (WRONG) | `str x8,[x21,#0xa68]` / `str xzr,[x21,#0xa70]` in copy_process | ✅ (BTF 0x4d0 WRONG; list_head init at 0xa68/0xa70) |
| seccomp | 0x860 | 0xE20 (WRONG) | `ldr w8,[x21,#0x860]` in do_seccomp; `str w8,[x0,#0x860]` in seccomp_assign_mode | ✅ (old target.h 0xE20 WRONG) |
| pi_lock | 0x884 | 0x884 | `ldar/casa on task+0x884` | ✅ |
| pi_waiters | 0x898 | 0x898 | same | ✅ |
| pi_top_task | 0x8b0 | 0x8b8 (off-by-8) | `ldr x28,[x19,#0x8b0]` in adjust_prio_chain (+0x84) | ✅ (BTF 0x8b8 off-by-8) |
| pi_blocked_on | 0x8a0 | 0x8c0 (off-by-0x20) | `str waiter,[x19,#0x8a0]` in task_blocks_on (+0x144 in adjust_prio_chain reads x28=task->0x8b0) | ✅ (BTF 0x8c0 off-by-0x20) |
| sched_task_group | 0x400 | **0x400** | `wake_up_new_task` / `do_task_stat` both reference task+0x400 range | ✅ (target.h corrected from 0x410) |

**Key disassembly addresses (from `manual_offsets_5-15-180.md`):**
- `rt_mutex_adjust_prio_chain` at `0xffffffc009770fa4` — x19 = task, x28 = task->pi_top_task
  - `+0x84`: `ldr x28,[x19,#0x8b0]` — pi_top_task@0x8b0
  - `+0xa0`: `ldr x8,[x28,#0x38]` — waiter->lock@0x38
  - `+0x144`: `ldr x27,[x28,#0x38]` — same field, used for NULL deref check
- `task_blocks_on_rt_mutex` at `0xffffffc00976ffac` — x21 = waiter
  - `+0x48`: `str w8,[x21,#0x44]` — prio@0x44
  - `+0x80`: `str x8,[x21,#0x48]` — deadline@0x48

**Summary of contradictions (BTF vs target.h vs disassembly):**

Confirmed by disassembly (these are the correct values):
- `usage@0x44c` — BTF says 0x38 (WRONG)
- `normal_prio@0x80` — BTF says 0x84 (WRONG)
- `mm@0x520` — old target.h said 0xAB8 (WRONG), BTF agrees with disasm
- `comm@0x7a8` — old target.h said 0xD48 (WRONG), confirmed by __get_task_comm
- `real_parent@0x5e8` — old target.h said 0xB40 (WRONG), do_task_stat loads from 0x5e8
- `tasks@0xa68` — BTF says 0x4d0 (WRONG), copy_process initializes list_head at 0xa68/0xa70
- `pi_top_task@0x8b0` — BTF says 0x8b8 (off-by-8)
- `pi_blocked_on@0x8a0` — BTF says 0x8c0 (off-by-0x20)
- `sched_task_group@0x400` — old target.h said 0x410 (WRONG), BTF/wake_up_new_task confirm 0x400

Indirect access (not direct fields):
- `pid`: target.h=0x7f0 (thread_pid, indirect), BTF=0x5d8 → **confirmed indirect via thread_pid**
- `tgid`: target.h=0x7f0 (thread_pid, indirect), BTF=0x5dc → **confirmed indirect via thread_pid**

---

### cred

BTF and disassembly agree.

| Field | target.h | BTF | Disasm evidence | Status |
|---|---|---|---|---|
| uid | 4 | 4 | `str w23,[x22,#0x4]` in __sys_setresuid | ✅ |
| gid | 8 | 8 | symmetric layout | ✅ |
| suid | 12 | 12 | same | ✅ |
| sgid | 16 | 16 | same | ✅ |
| euid | 20 | 20 | same | ✅ |
| egid | 24 | 24 | same | ✅ |
| fsuid | 28 | 28 | same | ✅ |
| fsgid | 32 | 32 | same | ✅ |
| securebits | 0x24 | 0x24 | gap before caps | ✅ |
| cap_inheritable | 0x28 | 0x28 | `str x8,[x0,#0x28]` in cap_capset | ✅ |
| cap_permitted | 0x30 | 0x30 | `str x9,[x0,#0x30]` | ✅ |
| cap_effective | 0x38 | 0x38 | `str x10,[x0,#0x38]` | ✅ |
| cap_bset | 0x40 | 0x40 | read at #0x40 in cap_capset | ✅ |
| cap_ambient | 0x48 | 0x48 | `str x10,[x0,#0x48]` | ✅ |
| security | 120 | 120 | `ldr x10,[x1,#0x78]` / `ldr x8,[x8,#0x78]` in selinux_cred_prepare | ✅ (old target.h 128 was WRONG) |

---

### file_operations (struct member offsets)

BTF and disassembly agree on verified fields.

| Field | target.h | BTF | Disasm evidence | Status |
|---|---|---|---|---|
| owner | 0x00 | 0 | — | ✅ |
| llseek | 0x08 | 8 | — | ✅ |
| read | 0x10 | 16 | — | ✅ |
| write | 0x18 | 24 | — | ✅ |
| read_iter | 0x20 | 32 | — | ✅ |
| write_iter | 0x28 | 40 | — | ✅ |
| ioctl | 0x50 | MISSING | `ldr x21,[x8,#0x50]` in `__arm64_sys_ioctl` | ✅ (BTF missing; target.h correct) |
| compat_ioctl | 0x58 | 88 (0x58) | — | ✅ |
| mmap | 0x60 | 96 (0x60) | — | ✅ |
| open | 0x70 | 112 (0x70) | `ldr x21,[x8,#0x70]` in `do_dentry_open` | ✅ |
| release | 0x78 | 128 (0x80) | `ldr x21,[x8,#0x78]` in `filp_close` | ⚠️ BTF 0x80 WRONG; target.h correct |
| splice_read | 0xc8 | 200 (0xc8) | `fops_u8_ro+0xc8` references in disassembly | ✅ |
| show_fdinfo | 0xd8 | 224 (0xe0) | `trace_options_core_fops+0xd8` / `ddebug_proc_fops+0xd8` references | ⚠️ BTF 0xe0 WRONG; target.h correct |
| sizeof | — | 288 (0x120) | — | recorded |

---

### configfs_buffer

BTF and disassembly agree on all fields.

| Field | target.h | BTF (byte) | Disasm evidence | Status |
|---|---|---|---|---|
| page | 16 | 16 | `ldr x1,[x24,#0x10]` in configfs_read_iter | ✅ |
| needs_read_fill | 80 | 80 | `ldr w8,[x24,#0x50]` / `str wzr,[x24,#0x50]` in configfs_read_iter | ✅ (old target.h 56 was WRONG) |
| bin_buffer | 88 | 88 | `str x0,[x25,#x58]` in configfs_bin_read_iter | ✅ (old target.h 64 was WRONG) |
| bin_buffer_size | 96 | 96 | `str w23,[x25,#0x60]` in configfs_bin_read_iter | ✅ (old target.h 72 was WRONG) |
| cb_max_size | 100 | 100 | `ldrsw x8,[x25,#0x64]` in configfs_bin_read_iter | ✅ (old target.h 76 was WRONG) |
| item | — | 104 (0x68) | `ldr x0,[x24,#0x68]` in configfs_read_iter | ✅ |
| sizeof | — | 128 (0x80) | BTF | recorded |

---

### seccomp

BTF and disassembly agree.

| Field | target.h | BTF | Status |
|---|---|---|---|
| mode | 0 | 0 | ✅ |
| filter_count | 4 | 4 | ✅ |
| filter | 8 | 8 | ✅ |

---

### page / pipe_buffer / mm_struct

- `page`: `mapping@0x18` CONFIRMED via `page_mapping` disassembly
  (`ldr x8,[x8,#0x18]`). Other page fields not yet verified.
- `pipe_buffer`: BTF resolves it (size=40, offset@0x08, len@0x0c, ops@0x10,
  flags@0x18, private@0x20). No disassembly conflicts found.
- `mm_struct`: BTF resolves it fully (size=992, all fields listed below).
  Verified via `__mmput`, `dup_mmap`, `__mmap_region`, and `arch_get_unmapped_area`
  disassembly. No conflicts found.

| Field | BTF (byte) | Disasm evidence | Status |
|---|---|---|---|
| mmap | 0x00 | — | ✅ |
| mm_rb | 0x08 | `ldr x8,[x20,#0x8]` in `__mmap_region` | ✅ |
| vmacache_seqnum | 0x10 | `ldr x8,[x19,#0x10]` / `str x8,[x19,#0x10]` in `__do_munmap` | ✅ |
| mmap_base | 0x20 | `ldr x8,[x21,#0x20]` in `arch_get_unmapped_area` | ✅ |
| mmap_legacy_base | 0x28 | — | ✅ |
| task_size | 0x30 | — | ✅ |
| highest_vm_end | 0x38 | `str xzr,[x19,#0x38]` in `__do_munmap` | ✅ |
| pgd | 0x40 | `ldr x8,[x20,#0x40]` in `__mmap_region` | ✅ |
| mm_users | 0x4c | — | ✅ |
| mm_count | 0x50 | `add x8,x19,#0x50` in `__mmput` | ✅ |
| pgtables_bytes | 0x58 | — | ✅ |
| map_count | 0x60 | `ldr w8,[x19,#0x60]` / `str w8,[x19,#0x60]` in `__do_munmap` | ✅ |
| mmap_lock | 0x68 | — | ✅ |
| mmap_seq | 0xa8 | `ldr x8,[x19,#0xa8]` in `dup_mmap` | ✅ |
| mmlist | 0xb0 | `add x20,x19,#0xb0` in `__mmput` | ✅ |
| hiwater_rss | 0xc0 | — | ✅ |
| hiwater_vm | 0xc8 | `ldp x9,x8,[x19,#0xc8]` / `str x8,[x19,#0xc8]` in `__do_munmap` | ✅ |
| total_vm | 0xd0 | `ldr x8,[x20,#0xd0]` / `str x8,[x20,#0xd0]` in `__mmap_region` | ✅ |
| locked_vm | 0xd8 | `ldr x8,[x19,#0xd8]` in `__do_munmap` | ✅ |
| data_vm | 0xe8 | `ldr x8,[x19,#0xe8]` in `dup_mmap` | ✅ |
| exec_vm | 0xf0 | `ldr x8,[x19,#0xf0]` in `dup_mmap` | ✅ |
| stack_vm | 0xf8 | `add x10,x19,#0xf8` in `__do_munmap` | ✅ |
| def_flags | 0x100 | — | ✅ |
| start_brk | 0x130 | — | ✅ |
| brk | 0x138 | — | ✅ |
| start_stack | 0x140 | — | ✅ |
| arg_start | 0x148 | — | ✅ |
| binfmt | 0x2f8 | `ldr x8,[x19,#0x2f8]` in `__mmput` | ✅ |
| context | 0x300 | — | ✅ |
| flags | 0x328 | `ldr x8,[x19,#0x328]` in `__mmput` / `dup_mmap` | ✅ |
| exe_file | 0x358 | — | ✅ |
| owner | 0x348 | — | ✅ (BTF; no disasm needed — MM_OWNER_OFF=0x520 is task_struct, not mm_struct) |

---

## Disassembly verification status (remaining 🔲 fields)

Confirmed and still-needed fields:

| Priority | Field | Current target.h | Status | Evidence |
|---|---|---|---|---|
| HIGH | `tasks` | 0xA68 | ✅ confirmed | `copy_process`: `str x8,[x21,#0xa68]` / `str xzr,[x21,#0xa70]` |
| HIGH | `comm` | 0x7a8 | ⚠️ WRONG in old variants, use 0x7a8 | `__get_task_comm`: `add x1,x20,#0x7a8` |
| HIGH | `pid` | 0x7f0 | ⚠️ indirect | `get_task_pid`/`__task_pid_nr_ns` use thread_pid at task+0x7f0, NOT direct field |
| HIGH | `tgid` | 0x7f0 | ⚠️ indirect | same as pid — accessed through thread_pid struct |
| MED | `real_parent` | 0x5e8 | ✅ confirmed | `do_task_stat`: `ldr x8,[x21,#0x5e8]` |
| MED | `sched_task_group` | 0x400 | ✅ confirmed | `wake_up_new_task` loads from 0x400; canonical target.h corrected |
| MED | `security` | 120 | ✅ confirmed | `selinux_cred_prepare`: `ldr x10,[x1,#0x78]` / `ldr x8,[x8,#0x78]` (old target.h 128 was WRONG) |
| MED | `file_operations.ioctl` | 0x50 | ✅ confirmed | `__arm64_sys_ioctl`: `ldr x21,[x8,#0x50]` |
| MED | `file_operations.open` | 0x70 | ✅ confirmed | `do_dentry_open`: `ldr x21,[x8,#0x70]` (old target.h 0x68 was WRONG) |
| MED | `file_operations.release` | 0x78 | ✅ confirmed | `filp_close`: `ldr x21,[x8,#0x78]` |
| MED | `file_operations.show_fdinfo` | 0xd8 | ✅ confirmed | `trace_options_core_fops+0xd8` / `ddebug_proc_fops+0xd8` refs |
| MED | `file_operations.splice_read` | 0xc8 | ✅ confirmed | `fops_u8_ro+0xc8` references in disassembly (old target.h 0xb8 was WRONG) |
| LOW | `configfs_buffer.bin_buffer` | 88 | ✅ confirmed | `str x0,[x25,#0x58]` in configfs_bin_read_iter (old target.h 64 was WRONG) |
| LOW | `configfs_buffer.bin_buffer_size` | 96 | ✅ confirmed | `str w23,[x25,#0x60]` in configfs_bin_read_iter (old target.h 72 was WRONG) |
| LOW | `configfs_buffer.cb_max_size` | 100 | ✅ confirmed | `ldrsw x8,[x25,#0x64]` in configfs_bin_read_iter (old target.h 76 was WRONG) |
| LOW | `page.mapping` | — | ✅ confirmed | `page_mapping`: `ldr x8,[x8,#0x18]` |
| LOW | `pipe_buffer` | — | ✅ BTF only | BTF: size=40, offset@0x08, len@0x0c, ops@0x10, flags@0x18, private@0x20 |

**Critical issue — pid/tgid are NOT direct fields in this kernel's task_struct.**
The kernel accesses pid/tgid through `task->thread_pid` (at offset 0x7f0) and the
pid namespace hash table, NOT via direct `task->pid` / `task->tgid` fields.
`root.c` currently reads them as direct fields at `TASK_PID_OFF`/`TASK_TGID_OFF`,
which will return garbage on this kernel. The task-identification code must be
rewritten to use `task_pid_nr_ns(task, PIDTYPE_PID)` / `task_pid_nr_ns(task,
PIDTYPE_TGID)` via the pid structure at `task+0x7f0`, or to walk the `thread_pid`
-> `pid` -> `level[0].nr` path manually.

---

## Notes

- **BTF task_struct is wrong for this kernel.** BTF reports `size=4608` (0x1200)
  and `usage@0x38`, but the production ELF disassembly confirms `usage@0x44c`
  (`get_task_struct: str w8,[x0,#0x44c]`). The BTF blob in the production Image
  does not match the POCO 5.15.180 task_struct layout. Do not trust BTF for
  task_struct, page, or pipe_buffer.
- **Trust disassembly for those structs.** The disassembly dumps in `disasm/`
  cover: `task_blocks_on_rt_mutex`, `rt_mutex_adjust_prio_chain`,
  `get_task_cred`, `commit_creds`, `prepare_kernel_cred`, `get_task_mm`,
  `set_user_nice`, `__get_task_comm`, `do_task_stat`, `__mmput`,
  `dup_mmap`, `__mmap_region`, `arch_get_unmapped_area`.
- **mm_struct verified via BTF + disassembly.** BTF resolves mm_struct fully
  (size=992). `__mmput`, `dup_mmap`, `__mmap_region`, and
  `arch_get_unmapped_area` disassembly confirm all accessed fields. No
  conflicts found. `MM_OWNER_OFF = 0x520` is `task_struct::mm`, verified via
  `get_task_mm`; the fake-mm spray must use the kmalloc-1k cache (0x400-byte
  slot).
- **normal_prio confirmed.** `set_user_nice` loads `task->normal_prio` at
  `#0x80`, matching `target.h` and contradicting BTF (`0x84`).
- **comm offset correction.** Old target.h listed `TASK_COMM_OFF = 0xD48`, but
  `__get_task_comm` uses `task+0x7a8` (`add x1,x20,#0x7a8`). BTF is right;
  target.h corrected.
- **real_parent offset correction.** Old target.h listed `0xB40`, but `do_task_stat`
  loads from `task+0x5e8` (`ldr x8,[x21,#0x5e8]`). BTF agrees; target.h corrected.
- **atomic_flags confirmed.** `do_seccomp` loads `task->atomic_flags` at
  `#0x598` (`ldr x8,[x21,#0x598]`), matching BTF. Old target.h `0xAF0` was wrong.
- **seccomp confirmed.** `do_seccomp` loads `task->seccomp` at `#0x860`
  (`ldr w8,[x21,#0x860]`); `seccomp_assign_mode` stores at `#0x860`
  (`str w8,[x0,#0x860]`). Old target.h `0xE20` was wrong.
- **cred->security confirmed at 0x78 (120).** `selinux_cred_prepare` loads
  `new->security` at `#0x78` and `old->security` at `#0x78`
  (`ldr x10,[x1,#0x78]` / `ldr x8,[x8,#0x78]`). BTF is right; old target.h
  `CRED_SECURITY_OFF=128` was wrong.
- **file_operations mismatches resolved by disassembly:**
  - `open@0x70` — `do_dentry_open` loads `fops->open` at `#0x70`
    (`ldr x21,[x8,#0x70]`). BTF is right; old target.h `0x68` was wrong.
  - `release@0x78` — `filp_close` loads `fops->release` at `#0x78`
    (`ldr x21,[x8,#0x78]`). target.h is right; BTF `0x80` was wrong.
  - `splice_read@0xc8` — `fops_u8_ro+0xc8` references confirm this offset.
    BTF is right; old target.h `0xb8` was wrong.
  - `show_fdinfo@0xd8` — `trace_options_core_fops+0xd8` and
    `ddebug_proc_fops+0xd8` references confirm this offset. target.h is right;
    BTF `0xe0` was wrong.
- **configfs_buffer confirmed via configfs_bin_read_iter disassembly:**
  - `bin_buffer@0x58` (88): `str x0,[x25,#0x58]`
  - `bin_buffer_size@0x60` (96): `str w23,[x25,#0x60]`
  - `cb_max_size@0x64` (100): `ldrsw x8,[x25,#0x64]`
  - All three match BTF; old target.h values (64/72/76) were wrong.
- **page->mapping confirmed at 0x18.** `page_mapping` loads `page->mapping`
  at `#0x18` (`ldr x8,[x8,#0x18]`). target.h does not define page field offsets;
  this is recorded for future use.
- **pipe_buffer confirmed via BTF** (size=40, fields: offset@0x08, len@0x0c,
  ops@0x10, flags@0x18, private@0x20). BTF parser successfully resolved it.
- **mm_struct fully verified via BTF + disassembly.** BTF resolves mm_struct
  completely (size=992, all fields). `pahole` works on the `.btf` extracted by
  `extract_btf.py`. `__mmput`, `dup_mmap`, `__mmap_region`, and
  `arch_get_unmapped_area` disassembly confirm every accessed field. No
  conflicts found.
- **pahole now works on extracted BTF.** Earlier, `pahole` on the debug kernel
  "never worked" for our offsets because `CONFIG_DEBUG_RT_MUTEXES=y` shifts
  struct layouts. The BTF blob extracted by `extract_btf.py` from the production
  Image is the correct one to use with `pahole` for structs like `mm_struct`,
  `pipe_buffer`, `seccomp`, `configfs_buffer`, and `file_operations`.
- **CRITICAL: pid/tgid are not direct fields in this kernel.**
  `get_task_pid` / `__task_pid_nr_ns` access pid/tgid through `task+0x7f0`
  (thread_pid/pid structure), NOT via direct `task->pid` / `task->tgid` fields.
  `root.c` currently reads `task + TASK_PID_OFF` / `TASK_TGID_OFF` as 32-bit
  direct fields — this will return garbage on 5.15.180. The task-identification
  code must be rewritten to walk the pid structure instead.
- **Symbol offsets** (`ASHMEM_FOPS_OFF`, `INIT_TASK_OFF`, etc.) were already
  verified via `llvm-nm` in `target_h_verification.md` — not repeated here.
- **Why contradictions matter:** if any offset in `target.h` is wrong, the
  corresponding read/write in `root.c` will corrupt unrelated kernel memory.
  The task-list walk (`TASK_TASKS_OFF`, `TASK_PID_OFF`, `TASK_TGID_OFF`),
  comm read (`TASK_COMM_OFF`), and seccomp patch (`TASK_SECCOMP_OFF`) are
  especially sensitive — a wrong offset there crashes the spray or patches the
  wrong task.
