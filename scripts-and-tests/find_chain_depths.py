#!/usr/bin/env python3
"""Trace downward syscall call-chain stack depth for candidate Stage-3 writers.

Decides whether any unprivileged syscall on 5.15.180 GKI reaches the >= 856B
(0x358) depth the GhostLock pselect route needs for its fd_set to overlap the
frozen rt_mutex_waiter. Also reports io_uring specifically since CONFIG_IO_URING=y
and io_uring was the one surface flagged USABLE unprivileged in the OPPO analysis.
"""
import struct, sys
from elftools.elf.elffile import ELFFile
import os
sys.setrecursionlimit(100000)

V = os.path.join("/mnt/Data/AI_Workspace/ghostlock_repo/Target/kernel_5-15-180-vmlinux.elf")
MIN_DEPTH = 0x358

with open(V, "rb") as f:
    elf = ELFFile(f)
    t = elf.get_section_by_name(".kernel")
    off = t["sh_offset"]; size = t["sh_size"]; vaddr = t["sh_addr"]
    f.seek(off); data = f.read(size)

# 1) frame sizes from PACIASP + SUB SP (with shift)
funcs = {}
i = 0
while i + 7 < len(data):
    inst = struct.unpack_from("<I", data, i)[0]
    if inst == 0xD503233F:
        n = struct.unpack_from("<I", data, i + 4)[0]
        if (n & 0xFFC003FF) == 0xD10003FF:
            imm12 = (n >> 10) & 0xFFF; sh = (n >> 21) & 3
            fs = imm12 << (sh << 2)
            funcs[vaddr + i] = fs
    i += 4

items = sorted(funcs.items())
def func_of(addr):
    lo, hi, res = 0, len(items) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if items[mid][0] <= addr:
            res = items[mid][0]; lo = mid + 1
        else:
            hi = mid - 1
    return res

# 2) BL edges bucketed into caller function
out = {}
for i in range(0, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 |= ~0x3FFFFFF; imm26 &= 0xFFFFFFFF; imm26 -= (1 << 32)
        tgt = vaddr + i + imm26 * 4; caller = vaddr + i
        cf = func_of(caller); tf = func_of(tgt)
        if cf and tf and cf != tf:
            out.setdefault(cf, set()).add(tf)

# 3) downward depth with cycle guard + memo
memo = {}
def ddepth(a, guard=0):
    if guard > 50000:
        return funcs.get(a, 0)
    if a in memo:
        return memo[a]
    memo[a] = funcs.get(a, 0)  # tentative to break cycles
    fs = funcs.get(a, 0)
    cs = out.get(a, set())
    best = fs
    if cs:
        best = fs + max(ddepth(c, guard + 1) for c in cs)
    memo[a] = best
    return best

# 4) symbol names
syms = {}
with open(V, "rb") as f:
    elf = ELFFile(f)
    for sec in elf.iter_sections():
        if sec['sh_type'] == 'SHT_SYMTAB':
            for s in sec.iter_symbols():
                if s['st_value']:
                    syms[s['st_value']] = s.name
def find(nm):
    a = [x for x, n in syms.items() if n == nm]
    return a[0] if a else None

print(f"funcs={len(funcs)} edges={sum(len(v) for v in out.values())}")
print(f"MIN_DEPTH=0x{MIN_DEPTH:x} ({MIN_DEPTH})\n")

# known syscall entry depths
for nm in ["__arm64_sys_pselect6", "__arm64_sys_futex", "__arm64_sys_io_uring_enter",
           "__arm64_sys_io_uring_setup", "__arm64_sys_io_uring_register",
           "do_futex", "futex_wait_requeue_pi", "io_submit_sqes"]:
    a = find(nm)
    if a:
        print(f"  {nm:34s} frame={hex(funcs.get(a,0)):>6} chain_depth={hex(ddepth(a))}")

# all chains >= MIN_DEPTH
cands = [(a, ddepth(a)) for a in funcs if ddepth(a) >= MIN_DEPTH]
cands.sort(key=lambda x: -x[1])
print(f"\nTotal downward chains >= 0x{MIN_DEPTH:x}: {len(cands)}")
for a, d in cands[:15]:
    print(f"  {hex(a)} {syms.get(a,''):34s} depth={hex(d)}")
