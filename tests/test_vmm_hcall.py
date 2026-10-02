#!/usr/bin/env python3
# test_vmm_hcall.py — hostile-guest regression tests for the hypercall
# interface. Assembles a minimal guest that issues malformed hypercalls
# through the mailbox/MMIO-doorbell ABI and checks the VMM refuses each
# cleanly instead of crashing or dereferencing bad guest pointers.
#
# Requires /dev/kvm; skipped otherwise.

import os
import pathlib
import struct
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
VMC = ROOT / "vmm.c"
VMM_BUILD = pathlib.Path(tempfile.gettempdir()) / "vmm-hcall-test"

KERNEL_LINK = 0x1000000
BSP_MBX = 0x6000
DOORBELL = 0x800100000                    # 32GiB + 1MiB (RAM_BYTES + 1MiB)

HC = dict(NOP=0, PRINT=1, EXIT=2, NOW=3, SPAWN=4, EXIT_THREAD=5,
          FUTEX_WAIT=6, FUTEX_WAKE=7, REPLAY=8, GFAULT=9, PROF=10)

# guest asm: each case clears the BSP mailbox, fills a hcall, rings the
# doorbell, and counts one point when ret has the expected refuse value.
# Exit code = number of correctly-refused calls.
GUEST_S = r"""
    .text
    .globl _start
_start:
    movabsq $0x800100000, %rbx         // DOORBELL_GPA
    movabsq $0x6000, %rbp              // BSP mailbox page
    xorl   %r12d, %r12d                // score

.macro CLR
    xorl %eax, %eax
    movq %rax, 0(%rbp)
    movq %rax, 8(%rbp)
    movq %rax, 16(%rbp)
    movq %rax, 24(%rbp)
    movq %rax, 32(%rbp)
    movq %rax, 40(%rbp)
.endm
.macro RING
    movq %rbp, (%rbx)
.endm
.macro EXPECT_RET val
    cmpq $\val, 40(%rbp)              // struct hcall.ret @ +0x28
    jne 991f
    incl %r12d
991:
.endm

    // 1. HC_PROF with a GPA past RAM: must refuse. Before the fix the bad
    //    pointer was stored and HC_EXIT NULL-derefed dumping the histogram.
    CLR
    movl $10, 0(%rbp)                  // HC_PROF
    movabsq $0xffffffff00000000, %rax
    movq %rax, 8(%rbp)
    movq $0x1000, 16(%rbp)
    RING
    EXPECT_RET -1

    // 2. HC_PROF len not a multiple of 8: refuse
    CLR
    movl $10, 0(%rbp)
    movq $0x20000, 8(%rbp)
    movq $0x1003, 16(%rbp)
    RING
    EXPECT_RET -1

    // 3. HC_REPLAY len above the 256MiB cap: refuse, no file write
    CLR
    movl $8, 0(%rbp)                   // HC_REPLAY
    movq $0x200000, 8(%rbp)
    movabsq $0x40000000, %rax          // 1 GiB
    movq %rax, 16(%rbp)
    RING
    EXPECT_RET -1

    // 4. HC_PRINT len above the 16MiB cap: refuse
    CLR
    movl $1, 0(%rbp)                   // HC_PRINT
    movq $1, 8(%rbp)                   // fd
    movq $0x100000, 16(%rbp)           // buf
    movabsq $0x40000000, %rax
    movq %rax, 24(%rbp)                // len = 1 GiB
    RING
    EXPECT_RET -1

    // 5. HC_FUTEX_WAIT on a GPA past RAM: ret = 2 (bad pointer)
    CLR
    movl $6, 0(%rbp)                   // HC_FUTEX_WAIT
    movabsq $0xfffffffffffffff0, %rax
    movq %rax, 8(%rbp)
    RING
    EXPECT_RET 2

    // 6. unknown hypercall number: ret = -1
    CLR
    movl $99, 0(%rbp)
    RING
    EXPECT_RET -1

    // 7. HC_NOP sanity: ret = 0 (interface still works)
    CLR
    movl $0, 0(%rbp)                   // HC_NOP
    RING
    EXPECT_RET 0

    // 8. doorbell with a GPA that is not a mailbox: vmm warns + ignores.
    //    (guest cannot observe ret — survives if the run continues)
    movq $0x12345, %rax
    movq %rax, (%rbx)

    // 9. doorbell with an in-arena but unaligned GPA: rejected
    movabsq $0x4000008, %rax
    movq %rax, (%rbx)

    // 10. short doorbell write (1 byte): rejected
    movb $0x60, (%rbx)

    // done: exit code = score
    CLR
    movl $2, 0(%rbp)                   // HC_EXIT
    movq %r12, 8(%rbp)
    RING
    hlt
"""


def make_elf(code: bytes, entry: int, vaddr: int) -> bytes:
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
        2, 0x3E, 1, entry, 0x40, 0, 0, 0x40, 0x38, 1, 0, 0, 0)
    phdr = struct.pack(
        "<IIQQQQQQ", 1, 5, 0x1000, vaddr, vaddr, len(code), len(code), 0x1000)
    return ehdr + phdr + bytes(0x1000 - len(ehdr) - len(phdr)) + code


def main() -> int:
    if not os.path.exists("/dev/kvm"):
        print("test_vmm_hcall: no /dev/kvm — skipped")
        return 0
    clang = os.environ.get("CC", "clang")
    objcopy = "objcopy"

    subprocess.run([clang, "-O2", "-pthread", "-o", str(VMM_BUILD),
                    str(VMC)], check=True)

    with tempfile.TemporaryDirectory(prefix="vmm-hcall-") as td:
        td = pathlib.Path(td)
        s = td / "malguest.S"
        o = td / "malguest.o"
        b = td / "malguest.bin"
        s.write_text(GUEST_S)
        subprocess.run([clang, "-c", "-o", str(o), str(s)], check=True)
        subprocess.run([objcopy, "-O", "binary", "-j", ".text",
                        str(o), str(b)], check=True)
        code = b.read_bytes()
        elf = td / "malguest.elf"
        elf.write_bytes(make_elf(code, KERNEL_LINK, KERNEL_LINK))
        mapp = td / "map.bin"
        mapp.write_bytes(b"\0" * 16)

        p = subprocess.run([str(VMM_BUILD), "--elf", str(elf),
                            "--map", str(mapp), "--no-replay"],
                           capture_output=True, text=True, timeout=30)
        score = p.returncode
        print(f"score = {score}/7 expected-refusals")
        if p.returncode < 0:
            print(f"vmm crashed: signal {-p.returncode}")
            print(p.stderr[:2000])
            return 1
        if score != 7:
            print(p.stdout[:2000])
            print(p.stderr[:2000])
            return 1
        for needle in ("bad mbx gpa", "short doorbell"):
            if needle not in p.stderr:
                print(f"missing expected warning: {needle}")
                print(p.stderr[:2000])
                return 1
        print("test_vmm_hcall: OK")
        return 0


if __name__ == "__main__":
    sys.exit(main())
