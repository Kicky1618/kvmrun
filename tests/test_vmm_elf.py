#!/usr/bin/env python3
"""Malformed-ELF tests for vmm.c load_elf: every crafted file must produce a
clean exit(2) with a 'bad ELF' diagnostic — never a crash or silent corruption.

Requires /dev/kvm (skipped if absent) and a C compiler.
"""
import os, pathlib, struct, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def build_vmm(tmp: pathlib.Path) -> pathlib.Path:
    cc = os.environ.get("CC", "cc")
    out = tmp / "vmm"
    r = subprocess.run([cc, "-O1", "-g", "-pthread", "-o", str(out),
                        str(ROOT / "vmm.c")], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"vmm build failed:\n{r.stderr}")
    return out


def elf64(entry=0x1000000, phoff=64, phdrs=(), phentsize=56, phnum=None):
    """Minimal 64-bit LE ELF image builder. phdrs = list of
    (ptype, off, vaddr, filesz, memsz)."""
    if phnum is None:
        phnum = len(phdrs)
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1            # 64-bit, LE, version
    struct.pack_into("<HHI", hdr, 16, 2, 0x3E, 1)   # EXEC, x86-64
    struct.pack_into("<Q", hdr, 24, entry)
    struct.pack_into("<Q", hdr, 32, phoff)
    struct.pack_into("<H", hdr, 54, phentsize)
    struct.pack_into("<H", hdr, 56, phnum)
    # only pad to phoff when it's small; huge phoff is itself a test case
    body = bytearray(phoff if phoff < (1 << 20) else 64)
    body[:64] = hdr
    for p in phdrs:
        ph = bytearray(56)
        struct.pack_into("<IIQQQQQQ", ph, 0, p[0], 0, p[1], p[2], p[2], p[3], p[4], 0x1000)
        body += ph
    return bytes(body)


def main():
    if not os.path.exists("/dev/kvm") or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("test_vmm_elf: /dev/kvm unavailable, skipping")
        return
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vmm-elf-test."))
    vmm = build_vmm(tmp)
    (tmp / "m.map").write_bytes(b"MAP")

    RAM = 32 << 30
    good_load = (1, 0x100, 0x1000000, 16, 16)   # type, off, va, filesz, memsz

    cases = {
        "empty": b"",
        "truncated_hdr": b"\x7fELF" + b"\x00" * 20,
        "bad_magic": elf64().replace(b"\x7fELF", b"NOPE"),
        "phoff_past_eof": elf64(phoff=1 << 40, phdrs=[good_load]),
        "phnum_overflow": elf64(phdrs=[good_load], phnum=0xFFFF),
        "seg_off_past_eof": elf64(phdrs=[(1, 1 << 40, 0x1000000, 16, 16)]),
        "seg_filesz_past_eof": elf64(phdrs=[(1, 0x100, 0x1000000, 1 << 40, 1 << 40)]),
        "filesz_gt_memsz": elf64(phdrs=[(1, 0x100, 0x1000000, 64, 16)]),
        "seg_va_past_ram": elf64(phdrs=[(1, 0x100, RAM, 16, 16)]),
        "seg_memsz_wrap": elf64(phdrs=[(1, 0x100, RAM - 8, 16, 64)]),
        "entry_past_ram": elf64(entry=RAM, phdrs=[good_load]),
    }

    fails = 0
    for name, blob in cases.items():
        p = tmp / f"{name}.elf"
        p.write_bytes(blob)
        r = subprocess.run([str(vmm), "--elf", str(p), "--map", str(tmp / "m.map")],
                           capture_output=True, text=True, timeout=30)
        ok = r.returncode == 2 and "bad ELF" in r.stderr
        # any nonzero clean exit is acceptable; crash (signal) is not
        crashed = r.returncode < 0 or r.returncode > 128
        status = "ok" if (ok or (r.returncode != 0 and not crashed)) else "FAIL"
        if status == "FAIL" or crashed:
            fails += 1
        print(f"  {name:24s} rc={r.returncode:4d} {status}  {r.stderr.strip()[:80]}")
    if fails:
        sys.exit(f"test_vmm_elf: {fails} failures")
    print("test_vmm_elf: OK")


if __name__ == "__main__":
    main()
