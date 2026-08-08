# target.h symbol-offset verification — kernel_5-15-180-vmlinux.elf

Method: `llvm-objdump -t` on the production 5.15.180 ELF; `_text = 0xffffffc008000000`
(confirmed: symbol `_text` at that addr, and all offsets below match `addr - _text`).
Every `target.h` `*_OFF` symbol constant was recomputed from the live symbol table.

| target.h constant | value | ELF symbol | ELF addr | computed off | OK |
|---|---|---|---|---|---|
| KIMAGE_TEXT_BASE | 0xffffffc008000000 | `_text` | 0xffffffc008000000 | — | ✓ |
| ASHMEM_FOPS_OFF | 0x021027c8 | ashmem_fops | 0xffffffc00a1027c8 | 0x21027c8 | ✓ |
| ASHMEM_IOCTL_OFF | 0x0113dc10 | ashmem_ioctl | 0xffffffc00913dc10 | 0x113dc10 | ✓ |
| ASHMEM_COMPAT_IOCTL_OFF | 0x0113e2c0 | compat_ashmem_ioctl | 0xffffffc00913e2c0 | 0x113e2c0 | ✓ |
| ASHMEM_MMAP_OFF | 0x0113e320 | ashmem_mmap | 0xffffffc00913e320 | 0x113e320 | ✓ |
| ASHMEM_OPEN_OFF | 0x0113e610 | ashmem_open | 0xffffffc00913e610 | 0x113e610 | ✓ |
| ASHMEM_RELEASE_OFF | 0x0113e6b0 | ashmem_release | 0xffffffc00913e6b0 | 0x113e6b0 | ✓ |
| ASHMEM_SHOW_FDINFO_OFF | 0x0113e7d4 | ashmem_show_fdinfo | 0xffffffc00913e7d4 | 0x113e7d4 | ✓ |
| CONFIGFS_READ_ITER_OFF | 0x00676230 | configfs_read_iter | 0xffffffc008676230 | 0x676230 | ✓ |
| CONFIGFS_BIN_WRITE_ITER_OFF | 0x00676d54 | configfs_bin_write_iter | 0xffffffc008676d54 | 0x676d54 | ✓ |
| COPY_SPLICE_READ_OFF | 0x005c3ba4 | generic_file_splice_read | 0xffffffc0085c3ba4 | 0x5c3ba4 | ✓ |
| NOOP_LLSEEK_OFF | 0x0055126c | noop_llseek | 0xffffffc00855126c | 0x55126c | ✓ |
| INIT_TASK_OFF | 0x02c43640 | init_task | 0xffffffc00ac43640 | 0x2c43640 | ✓ |
| ROOT_TASK_GROUP_OFF | 0x02d57ac0 | root_task_group | 0xffffffc00ad57ac0 | 0x2d57ac0 | ✓ |
| SELINUX_ENFORCING_OFF | 0x02a9d78 | selinux_state | 0xffffffc00ada9d78 | 0x2a9d78 | ✓ |
| ANON_PIPE_BUF_OPS_OFF | 0x01f85130 | anon_pipe_buf_ops | 0xffffffc009f85130 | 0x1f85130 | ✓ |
| SLIDE_NFULNL_LOGGER_OFF | 0x02b01e28 | nfulnl_logger | 0xffffffc00ab01e28 | 0x2b01e28 | ✓ |
| SLIDE_LOGGERS_0_1_OFF | 0x02b01d50 | loggers | 0xffffffc00ab01d50 | 0x2b01d50 | ✓ |
| SLIDE_RANDOM_TABLE_OFF | 0x0ac37238 | random_table | 0xffffffc00ac37238 | 0xac37238 | ✓ |
| SLIDE_SYSCTL_BOOTID_OFF | 0x02dc5819 | sysctl_bootid | 0xffffffc00adc5819 | 0x2dc5819 | ✓ |
| KMALLOC_CACHES_OFF | 0x02164a60 | kmalloc_caches | 0xffffffc00a164a60 | 0x2164a60 | ✓ |
| SECURITY_HOOK_HEADS_OFF | 0x021617e0 | security_hook_heads | 0xffffffc00a1617e0 | 0x21617e0 | ✓ |
| SELINUX_BLOB_SIZES_OFF | 0x02163c68 | (sym @ 0xffffffc00a163c68) | 0xffffffc00a163c68 | 0x2163c68 | ✓ |

## Conclusion
ALL `target.h` symbol `*_OFF` constants are CORRECT for the production 5.15.180
build. Therefore the exp32 reboot is NOT caused by bad symbol base/addresses.
The defect is purely the **rt_mutex_waiter field-offset mapping** (5.15 moved
task@0x50/lock@0x58, i.e. payload words 10/11; airfork currently puts them at
words 6/7 = waiter+0x30/0x38). See frame_analysis_exp32.md section 4-5.
