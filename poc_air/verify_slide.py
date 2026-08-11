import sys

KIMAGE = 0xffffffc008000000
SYMFILE = '/mnt/Data/AI_Workspace/ghostlock_repo/Target/kernel_5-15-180-symbols.txt'
LINKED_WORKER_CALLER = 0xffffffc008178510  # ret addr of bl schedule in worker_thread

# load symbols with names, sorted
syms = []
with open(SYMFILE) as f:
    for line in f:
        p = line.split()
        if len(p) < 3: continue
        try: a = int(p[0],16)
        except: continue
        syms.append((a, p[1], ' '.join(p[2:])))
syms.sort()
addrs = [s[0] for s in syms]

import bisect
def nearest_sym(a):
    i = bisect.bisect_right(addrs, a) - 1
    if i < 0: return None
    return syms[i]

callers = []
with open(sys.argv[1]) as f:
    for line in f:
        line=line.strip()
        if len(line)==16:
            try: callers.append(int(line,16))
            except: pass

# derive slide from most common caller assuming it is worker_thread's schedule return
from collections import Counter
c = Counter(callers)
C0 = c.most_common(1)[0][0]
S = C0 - LINKED_WORKER_CALLER
print("most_common_caller =", hex(C0))
print("SLIDE =", hex(S), " base =", hex(KIMAGE + S))
print("slide & 0x1fffff =", hex(S & 0x1fffff), "(2MB-aligned)" if (S & 0x1fffff)==0 else "(NOT 2MB aligned)")

# verify: for each distinct caller, linked must be within image and near a symbol
dc = list(dict.fromkeys(callers))
ok=0
for C in dc:
    linked = C - S
    if KIMAGE <= linked < KIMAGE + 0x4000000:
        ns = nearest_sym(linked)
        if ns and ns[0] <= linked < ns[0] + 0x20000:
            ok += 1
print("distinct callers:", len(dc), " map-into-image:", ok)

# show a few
for C in dc[:12]:
    linked = C - S
    ns = nearest_sym(linked)
    nm = ns[2] if ns else "?"
    off = linked - ns[0] if ns else 0
    print("  caller", hex(C), "->", hex(linked), nm+"+"+hex(off))
