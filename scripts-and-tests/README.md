# analysis-scripts

Binary-analysis helpers for the GhostLock (CVE-2026-43499) kernel exploit chain.
They operate on a `vmlinux`-to-ELF image extracted from a target boot image
(via `libmagiskboot.so unpack` + `vmlinux-to-elf`).

Adapted from the OPPO Find N2 research repo; generalized so they run on any
target kernel ELF, not just the hardcoded OPPO image.

## Usage

All scripts accept the ELF path as the first argument, or via the `VMLINUX`
environment variable. The built-in default points at
`../ghostlock_repo/Target/kernel_5-15-180-vmlinux.elf` (the 5.15 air target
image stored in the GitHub repo clone).

```bash
# 5.15 air target (default)
python3 inspect_elf.py
python3 find_deep_chains_v3.py

# any other kernel image
python3 find_deep_chains_v4.py /path/to/vmlinux.elf
VMLINUX=/path/to/vmlinux-6.1.elf python3 inspect_text.py
```

Requires `pyelftools` (`pip install pyelftools`).

## Scripts

- `inspect_elf.py` — dump ELF header + section table (handles `.text`-less
  `vmlinux-to-elf` images that expose code as `.kernel`).
- `inspect_text.py` — scan `.text`/`.kernel` for PACIASP prologues.
- `diagnose_callgraph.py` — sample `BL` targets to debug call-graph recovery.
- `find_deep_chains*.py` — find syscall call chains whose total stack depth
  exceeds the `rt_mutex_waiter` offset (0x358 / 856 bytes). This is the core
  tool for deciding whether a given kernel's stack layout is exploitable via
  the pselect/do_select stack-cover path. v3/v4 handle frames without PACIASP
  and ET_EXEC/ET_REL layouts.
