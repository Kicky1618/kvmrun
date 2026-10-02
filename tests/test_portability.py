#!/usr/bin/env python3
"""Portability guards: the win32 shim must cover every pthread/unistd API
host.c uses, and host.c must not contain unguarded x86-only asm.
Runs anywhere (static checks only)."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOST = (ROOT / "host.c").read_text()
SHIM = (ROOT / "win32" / "include" / "pthread.h").read_text()
UNISTD = (ROOT / "win32" / "include" / "unistd.h").read_text()

# every pthread_* symbol referenced by host.c must exist in the shim
used = set(re.findall(r"pthread_[a-z_]+", HOST))
have = set(re.findall(r"pthread_[a-z_]+", SHIM))
missing = used - have
assert not missing, f"win32 shim missing: {sorted(missing)}"
print(f"pthread shim covers {len(used)} APIs")

# every unistd/POSIX function host.c calls must be covered (getcwd only today)
posix_used = set(re.findall(
    r"\b(getcwd|access|unlink|fileno|isatty|usleep|getpid|chdir|pread|pwrite)\s*\(",
    HOST))
posix_have = set(re.findall(r"#define\s+(\w+)|\b(\w+)\s*\([^)]*\)\s*{", UNISTD))
flat = {x for tup in posix_have for x in tup if x}
missing = posix_used - flat
assert not missing, f"unistd shim missing: {sorted(missing)}"
print(f"unistd shim covers {sorted(posix_used)}")

# rdtsc inline asm must sit behind an arch guard
for m in re.finditer(r'__asm__\s+volatile\("rdtsc"', HOST):
    ctx = HOST[:m.start()]
    # nearest preceding 400 chars must contain an arch ifdef
    assert re.search(r"__x86_64__|__i386__|_M_X64|KVMRUN_GUEST", ctx[-500:]), \
        f"unguarded rdtsc at offset {m.start()}"
print("rdtsc sites arch-guarded")

# icount accessors: weak *definitions* (NULL stubs), not weak undef decls —
# zig's Mach-O linker rejects weak imports.
for name in ("bota", "botb", "engine"):
    pat = rf"KVMRUN_WEAK u64 \*w2c_{name}_kvmrun_icount\(w2c_{name} \*inst\) {{"
    assert re.search(pat, HOST), f"{name}: weak-def stub missing"
print("icount accessors are weak definitions")

print("test_portability: OK")
