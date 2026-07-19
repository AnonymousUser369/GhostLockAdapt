# In-File Modifications — GhostLock (CVE-2026-43499) port to POCO air (5.15.180 GKI)

This documents every change made to the exploit source for the `air` target.
Baseline = upstream CyberMeowfia/IonStack `CVE-2026-43499` (6.x GKI ports) in
`CyberMeowfia-main/IonStack/`. All paths below are under
`CVE-2026-43499/exploit/src/`.

NOTE: the exploit does NOT achieve root on 5.15.180. These modifications are
correct ports; the remaining blocker is the kernel stack-frame incompatibility,
not a code bug. The merged run logs are in RUNLOGS.md.

================================================================================
1) targets/air-AP3A.240905.015.A2/target.h   [NEW FILE — whole target added]
================================================================================
New per-target config for POCO air. Key values (all verified against the device
kallsyms / on-device runs):

  - BUILD_VARIANT_LABEL  "air_ap3a_240905_015_a2_truephone"
  - BUILD_FINGERPRINT    "POCO/air_p_in/air:15/AP3A.240905.015.A2/OS2.0.206.0.VGQINXM:user/release-keys"
  - KIMAGE_TEXT_BASE     0xffffffc008000000ULL   (from symbols.txt _text)
  - P0_PHYS_OFFSET       0x80000000ULL           (phys delta = 0)
  - SLIDE_RANDOM_TABLE_OFF   0x0ac37238ULL       (random_table[] base)
  - SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02dc5a19ULL  (random_table[boot_id].data;
        index 2: 0xac37238 + 2*0x40 + 8; verified exlog5 "boot_id entry 2 ...")
  - SLIDE_KERNEL_BASE_KNOWN 1                    (exact base known from symbols)
  - MINIMAL_INSTALL 1                            (only touch /data/local/tmp)
  - KMALLOC_SHIFT_HIGH 22                        (5.15: min(MAX_ORDER+12-1,25))
  - KMALLOC_CGROUP_TYPE 1
  - KMALLOC_CACHE_TYPES 2
  - All other symbol *_OFF defines ported from the GKI debug kernel
    (kernel_5-15-180-symbols.txt): init_task, selinux_state, configfs_read_iter,
    anon_pipe_buf_ops, kmalloc_caches, ashmem_*, copy_splice_read, etc.


================================================================================
2) common.h   [MODIFIED]
================================================================================
a) Version-sensitive kmalloc/MM constants wrapped in #ifndef so 5.15 can override
   them (they default to 6.x values in the upstream file):
     + #ifndef MM_STRUCT_SZ        ... #endif
     + #ifndef KMALLOC_SHIFT_HIGH  ... #endif
     + #ifndef KMALLOC_BUCKETS     ... #endif
     + #ifndef KMALLOC_NORMAL_TYPE ... #endif
     + #ifndef KMALLOC_CGROUP_TYPE ... #endif
     + #ifndef KMALLOC_PIPE_INDEX  ... #endif
     + #ifndef KMALLOC_CACHE_TYPES ... #endif
   (air target.h then #defines KMALLOC_SHIFT_HIGH=22, KMALLOC_CGROUP_TYPE=1,
    KMALLOC_CACHE_TYPES=2, etc.)

b) SLIDE_RANDOM_BOOT_ID_DATA changed from a compile-time alias to a runtime var
   (set per-target, hardcoded in slide.c):
     - #define SLIDE_RANDOM_BOOT_ID_DATA \
     -     P0_DATA_ALIAS_CONST(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)
     + extern uintptr_t slide_random_boot_id_data;
     + #define SLIDE_RANDOM_BOOT_ID_DATA slide_random_boot_id_data

================================================================================
 3) slide.c   [MODIFIED]
================================================================================
a) SLIDE_MAX_ATTEMPTS 20 -> 8 (user request).
     - #define SLIDE_MAX_ATTEMPTS 20
     + #define SLIDE_MAX_ATTEMPTS 8

b) Hardcoded boot_id .data link offset (no runtime random_table scan). Added a
   file-scope variable + comment block (lines ~405-418):
     + uintptr_t slide_random_boot_id_data =
     +     P0_DATA_ALIAS_CONST(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
   (value comes from SLIDE_RANDOM_BOOT_ID_DATA_OFF=0x02dc5a19; replaces the
    earlier runtime resolve_boot_id_data() scan that caused "physrw page not
    ready" in the SLIDE child.)

c) SLIDE_KERNEL_BASE_KNOWN short-circuit in slide_leak_kernel_base() (lines ~469-478):
     + #ifdef SLIDE_KERNEL_BASE_KNOWN
     +   kaslr_base = KIMAGE_TEXT_BASE;
     +   kaslr_slide = 0;
     +   kaslr_done = 1;
     +   pr_success("slide-kaslr-known pid=%d base=... slide=0\n", ...);
     +   return 1;
     + #else
     ... (original boot_id self-leak path) ...
     + #endif
   With this, KASLR base is taken from symbols (slide=0) and the exploit never
   hard-fails on the boot_id leak.

================================================================================
 4) preload.c   [MODIFIED — MINIMAL_INSTALL guards]
================================================================================
Wrapped all risky post-exploit behavior behind #ifndef MINIMAL_INSTALL so a
minimal build only touches /data/local/tmp. Changes:
  - Added #ifndef MINIMAL_INSTALL around the /apex su drop:
      - #define SU_DST_DIR "/apex/com.android.virt/bin"
      - #define SU_DST SU_DST_DIR "/su"
      + /* Minimal install: only ever touches /data/local/tmp. ... */
      + #ifndef MINIMAL_INSTALL
      + #define SU_DST_DIR "/apex/com.android.virt/bin"
      + #define SU_DST SU_DST_DIR "/su"
      + #endif
  - Guard the tmpfs /apex mount + apex su path (returns 0 early under MINIMAL_INSTALL).
  - Guard adbd setns / mount namespace tricks.
  - Guard wallpaper install: under MINIMAL_INSTALL prints
      "wallpaper install skipped (minimal install)" and returns 0.
  - Under MINIMAL_INSTALL, su is written to /data/local/tmp (write_embedded_su)
    instead of /apex; daemon exec uses SU_LOCAL.
  (The wallpaper_blob.S / install_embedded_wallpaper code is dead-code-eliminated
   under MINIMAL_INSTALL; only string literals remain in .rodata.)

su_daemon mechanics (verified in SU_DAEMON_NOTES.md):
  - `su_daemon_aarch64_pie` is ONE binary doing dual jobs via argv[1]:
    `su --daemon` = root-shell SERVER on AF_UNIX /data/local/tmp/temp_su.sock
    (chmod 0666); `su` / `su -c` = CLIENT connecting to it. Same file, run twice.
  - Staging: write /data/local/tmp/.su.new.<pid> (root-owned 0755) -> chcon ->
    atomic rename over /data/local/tmp/su. Daemon fork+execl(/system/bin/sh).
  - MINIMAL uses ONE binary for BOTH roles (daemon NOT dropped). Decision:
    build -DMINIMAL_INSTALL; ignore /apex/com.android.virt/bin entirely.
  - Neither mode survives reboot (tmpfs RAM / daemon dies).
    This is expected runtime-root, not a permanent unlock.
  - dm-verity: tmpfs overlay over /apex is RAM-only, cannot trip dm-verity
    (no red-state). /data/local/tmp/su is on f2fs (not verity-protected).

================================================================================
 5) Files UNCHANGED (byte-identical to upstream)
================================================================================
fops.c, main.c, pipe.c, root.c, offset.h, su_blob.S, su_daemon.c,
wallpaper_blob.S, kernelsnitch/.  The core exploitation engine (physrw primitive,
futex PI race, cred/SELinux overwrite) is untouched — only data (offsets) and
build configuration differ.

NOTE: util.c is NO LONGER unchanged — see section 8 (perf KASLR leak ported).

================================================================================
 6) Build artifact
================================================================================
build/air-AP3A.240905.015.A2/bin/preload.so
  - last good build sha (before context-loss rebuild): 1532b7faf7fb8381196c96e831844ac91a3ee47e374a6a948594d27b01bce919
  - rebuilt sha (this session, after boot_id fix): 6a71aa6789ff695fe2cfd2447add11b903f3bedf2ee51fdf7f91a03e6d632c72
  Built with android-ndk-r29 (clang-21); NDK ld.lld symlinked to system /usr/bin/ld.lld.

================================================================================
 7) Known limitation (not a code defect)
================================================================================
pselect fd_set stack-overwrite cannot redirect the dangling rt_mutex_waiter on
5.15.180: waiter at core_sys_select sp+0xc0, fd_set at sp+0x100 (64B too high).
The merged run logs are in RUNLOGS.md.

================================================================================
 8) util.c + main.c + common.h   [MODIFIED — perf KASLR leak ported]
================================================================================
Ported `perf_leak_text_base()` from the lamu/PD targets (other research fork).
It is an ALTERNATE KASLR / text-base leak, NOT an alternate for the root stage.
Our air fork already succeeds at KASLR via the pselect slide leak
(`slide_leak_kernel_base`), so this is redundancy, not a fix for the 5.15
do_select inlining blocker (that blocker is the stack-cover path, unrelated to KASLR).

  util.c:
    - + #include <linux/perf_event.h>
    - + perf_leak_text_base()  (samples kernel IPs via PERF_COUNT_SW_CPU_CLOCK,
      takes lowest kernel-text IP rounded to 2 MiB, derives _text via
      P0_KERNEL_PHYS_DELTA; bails if /proc/sys/kernel/perf_event_paranoid > 1)
  common.h:
    - + uint64_t perf_leak_text_base(void);   (line ~424)
  main.c (KASLR step, ~line 182):
    - try perf first, fall back to slide:
        uint64_t text_base = perf_leak_text_base();
        if (text_base) { kaslr_base = text_base; kaslr_done = 1; (perf) }
        else if (!slide_leak_kernel_base()) { fail; }

Notes:
  - perf needs perf_event_paranoid <= 1; on the air device SELinux may block
    perf_event_open (paranoid > 1) -> silently falls back to the pselect slide
    leak. No regression either way.
  - Uses our existing P0_KERNEL_PHYS_DELTA (which is 0 for GKI, so it yields
    the virtual _text directly). No new target.h constants required.
  - Technique reference: reference-targets/adaptation-knowledge.md (section 4 + perf notes);
    source: pubglite55/oppo-ghostlock lamu/PD targets.
  - Built OK: preload.so sha 86317ae95b6acbe63bc3f0aee5ebc0daa822a6e9e3250f3ea3f3970c574e9d20
    (make NDK_ROOT=/mnt/Data/AI_Workspace/android-ndk-r29).
