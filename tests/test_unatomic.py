#!/usr/bin/env python3
"""Differential test for unatomic.py: build a .wat module exercising every
lowering path, run it through unatomic -> wasm-validate -> wasm2c -> clang,
then execute the resulting code natively and assert correct results.

Requires wabt tools (wat2wasm, wasm-validate, wasm2c) via WABT_BIN or PATH.
"""
import os, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import unatomic  # noqa: E402


def wabt_bin() -> pathlib.Path:
    exe = "wat2wasm.exe" if os.name == "nt" else "wat2wasm"
    cands = []
    if os.environ.get("WABT_BIN"):
        cands.append(os.environ["WABT_BIN"])
    w = shutil.which("wat2wasm")
    if w:
        cands.append(str(pathlib.Path(w).parent))
    cands += ["/tmp/wabt-pkg/usr/bin", "/usr/bin", "/usr/local/bin"]
    for cand in cands:
        if (pathlib.Path(cand) / exe).is_file():
            return pathlib.Path(cand)
    raise SystemExit("test_unatomic: cannot find wabt tools; set WABT_BIN")


# Each test fn writes memory then performs the atomic op, returning old value.
WAT = r"""
(module
  (memory (export "mem") 1)
  (func (export "mem32") (param i32) (result i32) (i32.load (local.get 0)))

  ;; plain loads (0x10..0x16)
  (func (export "ld32") (result i32)
    (i32.store (i32.const 4) (i32.const -12345))
    (i32.atomic.load (i32.const 4)))
  (func (export "ld64") (result i64)
    (i64.store (i32.const 8) (i64.const -99))
    (i64.atomic.load (i32.const 8)))
  (func (export "ld8u") (result i32)
    (i32.store8 (i32.const 16) (i32.const 0xAB))
    (i32.atomic.load8_u (i32.const 16)))
  (func (export "ld16u") (result i32)
    (i32.store16 (i32.const 18) (i32.const 0xBEEF))
    (i32.atomic.load16_u (i32.const 18)))
  (func (export "ld64_32u") (result i64)
    (i64.store (i32.const 24) (i64.const -1))
    (i64.atomic.store (i32.const 24) (i64.const 0xDEAD0000BEEF))
    (i64.atomic.load32_u (i32.const 24)))

  ;; plain stores (0x17..0x1D)
  (func (export "st32") (result i32)
    (i32.atomic.store (i32.const 32) (i32.const 777))
    (i32.load (i32.const 32)))
  (func (export "st64_16") (result i64)
    (i64.atomic.store16 (i32.const 40) (i64.const 0x1234))
    (i64.load (i32.const 40)))

  ;; rmw ops across lanes
  (func (export "add64") (result i64)
    (i64.store (i32.const 48) (i64.const 100))
    (i64.atomic.rmw.add (i32.const 48) (i64.const 23)))       ;; old 100, mem 123
  (func (export "sub32") (result i32)
    (i32.store (i32.const 56) (i32.const 1000))
    (i32.atomic.rmw.sub (i32.const 56) (i32.const 1)))        ;; old 1000, mem 999
  (func (export "and32_8") (result i32)
    (i32.store (i32.const 64) (i32.const 0xFF00FF))
    (i32.atomic.rmw8.and_u (i32.const 64) (i32.const 0x0F)))  ;; old 0xFF, byte 0x0F
  (func (export "or32_16") (result i32)
    (i32.store (i32.const 68) (i32.const 0x1000))
    (i32.atomic.rmw16.or_u (i32.const 68) (i32.const 0x00FF))) ;; old 0x1000 -> 0x10FF
  (func (export "xor64") (result i64)
    (i64.store (i32.const 80) (i64.const 0xAA))
    (i64.atomic.rmw.xor (i32.const 80) (i64.const 0xFF)))     ;; old 0xAA -> 0x55
  (func (export "xchg32") (result i32)
    (i32.store (i32.const 88) (i32.const 1))
    (i32.atomic.rmw.xchg (i32.const 88) (i32.const 2)))       ;; old 1 -> 2
  (func (export "xchg64_8") (result i64)
    (i64.store (i32.const 96) (i64.const 0x1122334455))
    (i64.atomic.rmw8.xchg_u (i32.const 96) (i64.const 0x77))) ;; old 0x55 -> ..77

  ;; cmpxchg: success + failure, full and subword
  (func (export "cx32_ok") (result i32)
    (i32.store (i32.const 104) (i32.const 42))
    (i32.atomic.rmw.cmpxchg (i32.const 104) (i32.const 42) (i32.const 7)))
  (func (export "cx32_fail") (result i32)
    (i32.store (i32.const 108) (i32.const 42))
    (i32.atomic.rmw.cmpxchg (i32.const 108) (i32.const 1) (i32.const 7)))
  (func (export "cx32_8_ok") (result i32)
    (i32.store (i32.const 112) (i32.const 0xCAFEBEEF))
    (i32.atomic.rmw8.cmpxchg_u (i32.const 112) (i32.const 0xEF) (i32.const 0x01)))
  (func (export "cx64_32_fail") (result i64)
    (i64.store (i32.const 120) (i64.const 0x1111111122222222))
    (i64.atomic.rmw32.cmpxchg_u (i32.const 120)
        (i64.const 0x33333333) (i64.const 0x44444444)))

  ;; fence is a nop in our model; must not corrupt the instruction stream
  (func (export "fnc") (result i32)
    (atomic.fence)
    (i32.const 1234))

  ;; wait with mismatched expected returns 1 without blocking
  (func (export "wait_mismatch") (result i32)
    (i32.store (i32.const 128) (i32.const 5))
    (memory.atomic.wait32 (i32.const 128) (i32.const 6) (i64.const 1000000)))
  ;; notify with zero waiters returns 0
  (func (export "nfy") (result i32)
    (memory.atomic.notify (i32.const 128) (i32.const 1)))
)
"""

# (export, expected u64 result, mem addr to verify as u32, expected u32)
CASES = [
    ("ld32", 0xFFFFCFC7, 4, 0xFFFFCFC7),
    ("ld64", 0xFFFFFFFFFFFFFF9D, 8, 0xFFFFFF9D),
    ("ld8u", 0xAB, None, None),
    ("ld16u", 0xBEEF, None, None),
    ("ld64_32u", 0xDEAD0000BEEF & 0xFFFFFFFF, 24, 0xDEAD0000BEEF & 0xFFFFFFFF),
    ("st32", 777, None, None),
    ("st64_16", 0x1234, None, None),
    ("add64", 100, 48, 123),
    ("sub32", 1000, 56, 999),
    ("and32_8", 0xFF, 64, (0xFF00FF & ~0xFF) | 0x0F),
    ("or32_16", 0x1000, 68, 0x10FF),
    ("xor64", 0xAA, 80, 0x55),
    ("xchg32", 1, 88, 2),
    ("xchg64_8", 0x55, 96, 0x22334477),
    ("cx32_ok", 42, 104, 7),
    ("cx32_fail", 42, 108, 42),
    ("cx32_8_ok", 0xEF, 112, (0xCAFEBEEF & ~0xFF) | 0x01),
    ("cx64_32_fail", 0x22222222, 120, 0x22222222),
    ("fnc", 1234, None, None),
    ("wait_mismatch", 1, None, None),
    ("nfy", 0, None, None),
]

DRIVER_TMPL = r"""
#include <stdint.h>
#include <stdio.h>
#include "wasm-rt.h"
#include "t.h"
int main(void) {
    wasm_rt_init();
    w2c_t inst;
    wasm2c_t_instantiate(&inst);
    int fails = 0;
__CALLS__
    printf("unatomic: %s\n", fails ? "FAILURES" : "all cases pass");
    wasm2c_t_free(&inst);
    wasm_rt_free();
    return fails ? 1 : 0;
}
"""


def gen_driver(tmp: pathlib.Path) -> pathlib.Path:
    calls = []
    for name, exp, chk_addr, chk_val in CASES:
        calls.append(f'    {{ uint64_t r = w2c_t_{name}(&inst);')
        calls.append(f'      if (r != {exp}ULL) {{')
        calls.append(f'        printf("FAIL {name}: got %llu want %llu\\n",')
        calls.append(f'               (unsigned long long)r, {exp}ULL); fails++; }}')
        if chk_addr is not None:
            calls.append(f'      {{ uint32_t m = w2c_t_mem32(&inst, {chk_addr}u);')
            calls.append(f'        if (m != {chk_val & 0xFFFFFFFF}u) {{')
            calls.append(f'          printf("FAIL {name} mem: got %#x want %#x\\n",')
            calls.append(f'                 m, {chk_val & 0xFFFFFFFF}u); fails++; }} }}')
        calls.append('    }')
    p = tmp / "drv.c"
    p.write_text(DRIVER_TMPL.replace("__CALLS__", "\n".join(calls)))
    return p


def sh(cmd):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"FAILED: {' '.join(map(str, cmd))}\n{r.stderr}")
    return r


def main():
    wb = wabt_bin()
    print(f"test_unatomic: wabt at {wb}")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="unatomic-test."))
    (tmp / "t.wat").write_text(WAT)
    sh([wb / "wat2wasm", "--enable-threads",
        tmp / "t.wat", "-o", tmp / "t.wasm"])

    lowered = unatomic.rewrite((tmp / "t.wasm").read_bytes())
    (tmp / "t.low.wasm").write_bytes(lowered)

    # the rewritten module must still be structurally valid wasm
    sh([wb / "wasm-validate", tmp / "t.low.wasm"])

    sh([wb / "wasm2c", tmp / "t.low.wasm", "-o", tmp / "t.c", "-n", "t"])
    drv = gen_driver(tmp)
    cc = os.environ.get("CC", "cc")
    sh([cc, "-O1", "-o", tmp / "t", drv, tmp / "t.c",
        ROOT / "wasm-rt" / "wasm-rt-impl.c",
        ROOT / "wasm-rt" / "wasm-rt-mem-impl.c",
        ROOT / "wasm-rt" / "wasm-rt-exceptions-impl.c",
        f"-I{ROOT / 'wasm-rt'}", f"-I{tmp}"])
    r = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode:
        sys.exit("unatomic functional test FAILED")

    # malformed modules must fail loudly, never miscompile
    try:
        unatomic.rewrite(b"\x00asm\x01\x00\x00\x00" + b"\xfe\xff\x07" * 8)
        sys.exit("FAIL: garbage module accepted")
    except Exception as e:
        print(f"garbage module rejected as expected: {type(e).__name__}")
    print("test_unatomic: OK")


if __name__ == "__main__":
    main()
