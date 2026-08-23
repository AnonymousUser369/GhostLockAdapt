# SELinux Write Investigation — POCO 5.15.180 (device-verified 2026-08-22)

## Problem
The ghost-write selinux flip makes the device unresponsive. Two hypotheses:
1. The write corrupts selinux runtime state (e.g., zeroing `initialized` → "unknown SID" loop)
2. The rb_erase primitive itself corrupts kernel memory during tree rebalancing

## Evidence from QEMU runs (2026-08-22)

### Run 1: poc_mcast_root with k_empty_zero_page (all zeros)
- Writes 0x0 to `selinux_state + 0` and 0x0 to `selinux_state + 4`
- QEMU panic at `security_compute_av` with x0 = selinux_state
- Device dmesg: "SELinux: security_sid_to_context_core: called before initial load_policy on unknown SID 1717"
- Root cause: `initialized` byte (+2) was zeroed → SELinux believes policy never loaded

### Run 2: poc_mcast_root with 0x10000ULL (only enforcing=0, initialized=1)
- Writes 0x0000000000010000 to `selinux_state + 0` (byte0=0x00, byte2=0x01)
- QEMU: no panic, runs for 5 minutes without crash
- Device run: `write trigger=0 (value 0x0 -> 0xffffffc00ada9d78)` — write landed
- But device became unresponsive after ~17 minutes
- dmesg panic at `rb_erase+0x140` with READ fault — ghost still linked in tree, later PI walk hit it

### Run 3: poc_mcast with 0x10000ULL (same fix)
- Same write pattern as Run 2
- Device run: selinux flipped, but device unresponsive

## Current Hypothesis
The rb_erase primitive corrupts the fake_lock tree during rebalancing when the ghost node has no replacement. The write itself succeeds, but the tree corruption causes later PI walks to fault.

The SECOND write (to +4) was corrupting selinux policycap, but removing it doesn't fix the unresponsiveness. The FIRST write's rb_erase side-effect is the real blocker.

## Potential Fixes
1. Disarm the ghost after selinux flip (poc_mcastv2 approach: FUTEX_LOCK_PI self-lock to clear pi_blocked_on)
2. Use a smaller write that doesn't trigger rb_erase rebalancing (if possible)
3. Write only the enforcing byte via a different channel (pipe physrw, not rb_erase)
4. Batch multiple small ghost writes instead of one big 8-byte write

## Next Steps
- Test poc_mcast with ONLY the first write fix (0x10000) in QEMU to confirm rb_erase crash
- If confirmed: port poc_mcastv2's DISARM mechanism to poc_mcast
- If disarm isn't enough: investigate smaller write sizes or alternative channels
