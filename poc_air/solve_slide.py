import sys
from collections import Counter

KIMAGE = 0xffffffc008000000

# load symbol addresses
syms = set()
with open('/mnt/Data/AI_Workspace/ghostlock_repo/Target/kernel_5-15-180-symbols.txt') as f:
    for line in f:
        p = line.split()
        if not p: continue
        try: syms.add(int(p[0], 16))
        except: pass
print("symbols:", len(syms))

# load caller values (one per line, 16 hex digits)
callers = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if len(line) == 16:
            try: callers.append(int(line, 16))
            except: pass
print("caller samples:", len(callers))

dc = list(dict.fromkeys(callers))  # distinct, preserve order
print("distinct callers:", len(dc))

C0 = Counter(callers).most_common(1)[0][0]
# candidate slides from C0: S = C0 - sym
candidates = set(C0 - s for s in syms)
print("initial candidates:", len(candidates))

for C in dc[1:]:
    # keep only S such that C - S is a real symbol
    candidates = set(S for S in candidates if (C - S) in syms)
    if len(candidates) <= 5:
        break

print("remaining candidate slides after intersect:", len(candidates))
for S in candidates:
    print("SLIDE =", hex(S), " base =", hex(KIMAGE + S))
    for C in dc[:8]:
        linked = C - S
        print("   caller", hex(C), "-> linked", hex(linked), "in_syms" if linked in syms else "MISSING")
