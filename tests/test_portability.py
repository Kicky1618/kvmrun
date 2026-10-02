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
    assert re.search(r"__x86_64__|__i386__|_M_X64", ctx[-500:]), \
        f"unguarded rdtsc at offset {m.start()}"
print("rdtsc sites arch-guarded")

# icount accessors: weak *definitions* (NULL stubs), not weak undef decls —
# zig's Mach-O linker rejects weak imports. Each stub must also sit behind
# #ifndef — the same-bot shim aliases w2c_botb_* to w2c_bota_* macros, and
# an unguarded stub re-expands into a duplicate definition.
for name in ("bota", "botb", "engine"):
    fn = f"w2c_{name}_kvmrun_icount"
    pat = rf"#ifndef {fn}\s*\n\s*KVMRUN_WEAK u64 \*{fn}\(w2c_{name} \*inst\) {{"
    assert re.search(pat, HOST), f"{name}: weak-def stub missing/unguarded"
print("icount accessors are #ifndef-guarded weak definitions")

# ---- WHPX driver (Windows sandboxed backend) -----------------------------
# vmm_whpx.c must share the single dispatch implementation — a second copy
# of the hypercall switch would drift out of lockstep with the hardened
# validation in vmm_common.h.
WHPX = (ROOT / "vmm_whpx.c").read_text()
VMMC = (ROOT / "vmm.c").read_text()
COMMON = (ROOT / "vmm_common.h").read_text()
assert '#include "vmm_common.h"' in WHPX, "vmm_whpx.c must share dispatch"
assert '#include "vmm_common.h"' in VMMC, "vmm.c must share dispatch"
assert "case HC_PRINT" not in WHPX and "case HC_PRINT" not in VMMC, \
    "hypercall switch must live only in vmm_common.h"
assert "case HC_PRINT" in COMMON, "dispatch missing from vmm_common.h"
# both drivers provide the hooks vmm_common.h declares
for drv, src in (("vmm.c", VMMC), ("vmm_whpx.c", WHPX)):
    for hook in ("hva", "gptr", "spawn_vcpu"):
        assert re.search(rf"static .*{hook}\(", src), f"{drv}: missing {hook}"
# WHPX memory exits carry no write data: the doorbell must recover the
# mailbox GPA by decoding the store, never assume v->mbx
assert "doorbell_data" in WHPX, "vmm_whpx.c must decode the doorbell store"
assert "dispatch(v, v->mbx)" not in WHPX, "doorbell must not assume v->mbx"
# FS/GS base MSRs are emulated (no KVM_SET_MSRS equivalent under WHPX)
assert "MSR_FS_BASE" in WHPX and "KernelGsBase" in WHPX, \
    "vmm_whpx.c must emulate fs/gs base MSRs"
print("vmm_whpx: shared dispatch + doorbell decode + MSR emulation")

# The Windows shim must cover every pthread symbol used by BOTH drivers.
# *_np calls are Darwin-only (relative_np is inside #ifdef __APPLE__).
vmm_used = {s for s in re.findall(r"pthread_[a-z_]+", VMMC + WHPX + COMMON)
            if not s.endswith("_np")}
missing = vmm_used - have
assert not missing, f"win32 shim missing for vmm: {sorted(missing)}"
print(f"pthread shim covers vmm APIs too ({len(vmm_used - used)} extra)")

# ---- Hypervisor.framework driver + arm64 guest (macOS sandboxed backend) --
HV = (ROOT / "vmm_hv.c").read_text()
assert '#include "vmm_common.h"' in HV, "vmm_hv.c must share dispatch"
assert "case HC_PRINT" not in HV, "hypercall switch must live only in vmm_common.h"
for hook in ("hva", "gptr", "spawn_vcpu", "vmm_commit"):
    assert re.search(rf"static .*{hook}\(", HV), f"vmm_hv.c: missing {hook}"
for drv, src in (("vmm.c", VMMC), ("vmm_whpx.c", WHPX), ("vmm_hv.c", HV)):
    assert re.search(r"static int vmm_commit\(", src), \
        f"{drv}: missing vmm_commit hook"
# doorbell on arm64 is a stage-2 abort: ESR SRT names the stored reg —
# recover the mailbox GPA from the register file, never assume v->mbx
assert "ISS_SRT" in HV and "HV_REG_X0 + srt" in HV, \
    "vmm_hv.c must read the doorbell source register"
assert "dispatch(v, v->mbx)" not in HV, "doorbell must not assume v->mbx"
# demand mapping on stage-2 aborts + sysreg presets for the arm64 guest
for req in ("hv_vm_map", "commit_range", "HV_SYS_REG_TTBR0_EL1",
            "HV_SYS_REG_TCR_EL1", "HV_SYS_REG_SCTLR_EL1",
            "HV_SYS_REG_CPACR_EL1", "HV_EXIT_REASON_EXCEPTION"):
    assert req in HV, f"vmm_hv.c: missing {req}"
print("vmm_hv: shared dispatch + SRT doorbell + sysreg preset")

# arm64 guest pieces
ARCH = (ROOT / "guest" / "arch.h").read_text()
for req in ("guest_tp", "guest_set_tp", "cpu_halt", "rd_cycles",
            "tlb_inval_page", "mmio_fence", "PT_TBL", "PT_LEAF",
            "PT_LEAF2M", "PTE_IS_2M", "tpidr_el1", "cntvct_el0",
            "MSR_FS_BASE" if False else "wrmsr"):
    assert req in ARCH, f"arch.h: missing {req}"
A64 = (ROOT / "guest" / "entry_arm64.S").read_text()
for req in ("_start", "tls_init", "gctx_switch", "setjmp", "longjmp",
            "vbar_el1", "sp_el1", "tpidr_el0", "eret", "exc_report",
            "vectors_el1"):
    assert req in A64.lower() or req in A64, f"entry_arm64.S: missing {req}"
# d8-d15 are callee-saved on aarch64 (unlike x86 XMMs): the ctx switch
# must carry them across gctx_switch or wasm2c FP code corrupts on yield
assert "d8" in A64 and "d15" in A64 and "[sp, #144]" in A64, \
    "gctx_switch: missing callee-saved d8-d15 save/restore"
KLIBC = (ROOT / "guest" / "klibc.c").read_text()
GTHR = (ROOT / "guest" / "gthr.c").read_text()
assert "__aarch64__" in KLIBC and "__aarch64__" in GTHR, \
    "guest C sources must carry aarch64 branches"
SJ = (ROOT / "guest" / "include" / "setjmp.h").read_text()
assert "__aarch64__" in SJ and "jmp_buf[24]" in SJ, \
    "setjmp.h: missing aarch64 jmp_buf"
LD64 = (ROOT / "guest" / "guest_arm64.ld").read_text()
assert "aarch64" in LD64 and "_start" in LD64, "guest_arm64.ld bad"
print("arm64 guest: entry/vectors/pages/setjmp all present")

print("test_portability: OK")
