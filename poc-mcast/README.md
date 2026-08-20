# poc_mcast — CVE-2026-43499 GhostLock IPv4 MCAST port to POCO air 5.15.180

## What this is

Standalone test of the **IPv4 UDP** MCAST stack-stamp path (`AF_INET` + `SOCK_DGRAM`
+ `IPPROTO_IP` + `MCAST_BLOCK_SOURCE`) on POCO air 5.15.180. Adapted from
`ghostlock-refs-1/mcast_permissive.c`.

**Current status:** stamp confirmed landing (`WAITER_OFF=0x60`, phase1 settles
cleanly) and the **selinux-permissive flip is PROVEN on POCO** via the `rb_erase`
forge (`ghost_write_value` writes `empty_zero_page` to `selinux_state.enforcing`;
run `p1c`, live `/sys/fs/selinux/enforce` read = 0). The working escalation on
POCO is the `rt_mutex` `rb_erase` forge (not configfs physrw — that feature is
absent on POCO). Full-root `cred` patching is pursued in `poc-mcast-root`.

---

## Build

```bash
bash /mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast/build.sh
```

NDK r29 `aarch64-linux-android35-clang`, static. Output: `poc_mcast`.

---

## Run (manual workflow — no scripted reboots)

```bash
# push
adb push poc_mcast /data/local/tmp/poc_mcast_v3
adb shell chmod 755 /data/local/tmp/poc_mcast_v3

# run (device may panic; reboot and pull pstore)
timeout 30 adb exec-out "cd /data/local/tmp && MCAST_DEBUG_RET=1 ./poc_mcast_v3 2>&1" \
  | tee runlogs/run_<tag>.out

# after reboot, retrieve panic
bash getpanic.sh <tag>
```

Key env vars:
- `MCAST_PROBE_INDEX=1` — fills buffer with `qword[i]=i`; panic `x27` reveals
  `WAITER_OFF`. Confirmed: `x27=0x13` → `WAITER_OFF=0x60`.
- `MCAST_DEBUG_RET=1` — prints `setsockopt` ret/errno after copy.
- `FAKE_MEM=<sym>` — override fake_lock anchor (`z_pagemap_global`,
  `dax_host_list`, `kernfs_pr_cont_buf`, `object_map`, etc.).
- `FAKE_OFF=<hex>` — override offset into the anchor (default `0x1200`).
- `KASLR_OFF=<signed>` — override tracefs slide (default 0).

---

## Status

| Component | Status |
|---|---|
| IPv4 MCAST stamp (AF_INET, IPPROTO_IP, MCAST_BLOCK_SOURCE) | ✅ confirmed landing |
| WAITER_OFF | ✅ 0x60 (PROBE-confirmed 2026-08-12) |
| PI cycle topology (`-EDEADLK`) | ✅ confirmed |
| KASLR leak (tracefs event 108) | ⚠️ unstable — candidate-iteration fix added |
| Phase1 settle (ghost → fake_lock) | ✅ clean (v6/v7/v9b) |
| ksym_table offset bug | ✅ fixed (was +0x8000000 too high for BSS/DATA) |
| `rt_mutex_top_waiter` BUG (dirty fake_lock2) | ✅ fixed via clean anchor |
| `getpanic.sh` BUG capture | ✅ updated |
| Ghost-write selinux flip (rb_erase forge) | ✅ PROVEN on POCO (run `p1c`) |
| Full-root cred patch | ⏳ pursued in `poc-mcast-root` |

---

## Files

| File | Purpose |
|---|---|
| `poc_mcast.c` | MCAST UAF + stamp (phase1 solid). Ghost-write kept for settle; physrw TODO. |
| `build.sh` | NDK build script |
| `getpanic.sh` | Pull panic from pstore (now catches BUGs too) |
| `run.sh` | Push + run helper |
| `docs/VERIFICATION.md` | Verification chain |
| `docs/OBSERVATIONS.md` | Run log + offset derivation |
| `CONTEXT.md` | Local analysis (this workspace) |
| `runlogs/` | Per-run output |
| `exploit-pselect/` | Reference physrw primitive (`pipe_phys_read_data`/`pipe_phys_write_data`) — **archived in `backup/`; configfs physrw dead on POCO** |

---

## Offset derivation (final)

- IPv4 UDP setsockopt chain: `__arm64_sys_setsockopt(0x10) → __sys_setsockopt(0x80)
  → sock_common_setsockopt(0x40) → [CFI slowpath +0x20] → udp_setsockopt(0x10)
  → ip_setsockopt(0x290)`. greqs = sp_ip + 0x18.
- G_off = 0x390 - 0x18 = 0x378. W_off = 0x318. WAITER_OFF = 0x60.
- Lock field at greqs + 0x98. Full waiter spans greqs+0x60..0xB8 (0xB8 < 0x108).

## Reference

`ghostlock-refs-1/mcast_permissive.c` — complete working exploit on FZF5 (QEMU).
Uses `creds_hash+0x1000+0x200` as fake_lock and `callstack_buf+0x808` as safe
write value. Those symbols are not exported in POCO's production GKI.
