#!/usr/bin/env python3
# test_icount.py — icount instrumentation tests:
#   * injected charges count exactly the module's own ops
#   * metering sequences are skipped (post-metering instrumentation)
#   * deterministic, survives unatomic lowering, still valid wasm
#   * dynamic counts match a hand-computed opcode-execution count
#
# Requires wabt tools (wat2wasm, wasm-validate, wasm2c) via WABT_BIN or PATH.

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import icount  # noqa: E402
import unatomic  # noqa: E402
from unswbc import metering  # noqa: E402
from unswbc.metering import next_op, sections, uleb  # noqa: E402


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
    raise SystemExit("test_icount: cannot find wabt tools; set WABT_BIN")


def sh(cmd):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"FAILED: {' '.join(map(str, cmd))}\n{r.stderr}")
    return r


WAT = r"""
(module
  (memory 1)
  (func (export "f") (param i32) (result i32)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_s (local.get $i) (local.get 0))))
    (local.get $i))
  ;; f(n) executes: loop(1) + n*[lg lc ia ls lg lg lt bif](8) + loop-end(1)
  ;;              + local.get(1) + func-end(1)  = 8n + 4
  (func (export "g") (result i32)
    (block $b (br_if $b (i32.const 0)))
    (i32.atomic.rmw.add (i32.const 0) (i32.const 7))
    ;; g: block br_if i32.const end | addr val rmw.end | func-end
    ;; = (block,br_if,i32.const) flush per ENDS_BLOCK + end + rmw ops + end
    ;; block group: block(1) br_if(1:flush w/ i32.const=2 ops..) -> see below
    )
  ;; trap paths: ops up to and including the trapper must count even
  ;; though the segment never reaches its end.
  (func (export "h") (result i32)
    (drop (i32.div_s (i32.const 7) (i32.const 0)))  ;; traps: +3
    (i32.const 9))                                 ;; unreached
  (func (export "v") (param i32) (result i32)
    (i32.load (local.get 0)))                      ;; OOB traps: +2
)
"""

# g() op trace: block(1) i32.const(1) br_if(1) -> falls to end(1)
#   i32.const(1) i32.const(1) i32.atomic.rmw.add(1) -> end is the func end(1)
# total = 8


def bodies(blob: bytes):
    """yield (start, end) of each code body (sans size prefix)."""
    for sid, j, end, _ in sections(blob):
        if sid != 10:
            continue
        n, j = uleb(blob, j)
        for _ in range(n):
            size, j = uleb(blob, j)
            yield j, j + size
            j += size


def real_ops(b: bytes, start: int, end: int,
             rem: int, exh: int, ic: int) -> int:
    """Ops in body excluding metering injections and icount charges."""
    k = start
    count, k = uleb(b, k)
    for _ in range(count):
        _, k = uleb(b, k)
        k += 1
    n = 0
    while k < end:
        m = icount._metering_skip(b, k, rem, exh)
        if m != k:
            k = m
            continue
        # icount charge: 23 ic 42 <sleb> 7c 24 ic
        if b[k] == 0x23:
            g, q = uleb(b, k + 1)
            if g == ic:
                from unswbc.metering import sleb
                _, q = sleb(b, q + 1)          # skip i64.const payload
                if b[q:q + 2] == b"\x7c\x24":
                    g2, q = uleb(b, q + 2)
                    if g2 == ic:
                        k = q
                        continue
        _, k = next_op(b, k)
        n += 1
    return n


def ic_index(blob: bytes) -> int:
    for sid, j, end, _ in sections(blob):
        if sid != 7:
            continue
        n, j = uleb(blob, j)
        for _ in range(n):
            ln, j = uleb(blob, j)
            name = blob[j:j + ln]; j += ln
            kind = blob[j]; j += 1
            idx, j = uleb(blob, j)
            if kind == 3 and name == icount.ICOUNT:
                return idx
    return -1


def main():
    wb = wabt_bin()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="icount-test."))
    (tmp / "t.wat").write_text(WAT)
    sh([wb / "wat2wasm", "--enable-threads", tmp / "t.wat",
        "-o", tmp / "t.wasm"])
    raw = (tmp / "t.wasm").read_bytes()

    # 1) deterministic
    a = icount.rewrite(raw)
    b = icount.rewrite(raw)
    assert a == b, "rewrite not deterministic"
    (tmp / "t.ic.wasm").write_bytes(a)
    sh([wb / "wasm-validate", "--enable-threads", tmp / "t.ic.wasm"])
    print("deterministic + valid")

    # 2) op preservation without metering: real_ops == original op count
    ic = ic_index(a)
    assert ic >= 0, "icount global not exported"
    orig = [real_ops(raw, s, e, -1, -1, ic) for s, e in bodies(raw)]
    got = [real_ops(a, s, e, -1, -1, ic) for s, e in bodies(a)]
    assert orig == got, f"op drift: {orig} vs {got}"
    print(f"raw op counts preserved: {orig}")

    # 3) metering exclusion: meter -> icount -> real ops still == original
    m = metering.instrument(raw)
    mi = icount.rewrite(m)
    (tmp / "t.mi.wasm").write_bytes(mi)
    sh([wb / "wasm-validate", "--enable-threads", tmp / "t.mi.wasm"])
    ic2 = ic_index(mi)
    rem, exh = icount._find_metering_globals(mi,
                                             {s: (j, e) for s, j, e, _
                                              in sections(mi)})
    assert rem >= 0 and exh >= 0
    got2 = [real_ops(mi, s, e, rem, exh, ic2) for s, e in bodies(mi)]
    assert orig == got2, f"metering counted: {orig} vs {got2}"
    print("metering sequences excluded from count")

    # 4) unatomic passthrough
    u = unatomic.rewrite(mi)
    (tmp / "t.u.wasm").write_bytes(u)
    sh([wb / "wasm-validate", "--enable-threads", tmp / "t.u.wasm"])
    print("unatomic passthrough valid")

    # 5) dynamic: wasm2c + driver — f(5)=44, then +f(2)=20 -> 64, g()->8
    drv = tmp / "drv.c"
    drv.write_text(r'''
#include <stdint.h>
#include <stdio.h>
#include "wasm-rt.h"
#include "wasm-rt-exceptions.h"
#include "wasm-rt-impl.h"
#include "t.h"
int main(void) {
    wasm_rt_init();
    w2c_t inst;
    wasm2c_t_instantiate(&inst);
    uint64_t *ic = w2c_t_kvmrun_icount(&inst);
    uint64_t *rem = w2c_t_wasmer_metering_remaining_points(&inst);
    uint64_t rem0 = *rem, base;
    int fails = 0;
    w2c_t_f(&inst, 5);
    if (*ic != 44) { printf("FAIL f(5): %llu\n", (unsigned long long)*ic); fails++; }
    if (*rem >= rem0) { printf("FAIL metering dropped: rem=%llu\n",
                               (unsigned long long)*rem); fails++; }
    w2c_t_f(&inst, 2);
    if (*ic != 64) { printf("FAIL f(2): %llu\n", (unsigned long long)*ic); fails++; }
    w2c_t_g(&inst);
    if (*ic != 72) { printf("FAIL g(): %llu\n", (unsigned long long)*ic); fails++; }

    /* trap paths: ops up to & including the trapper still count */
    base = *ic;
    if (wasm_rt_impl_try() == 0) { w2c_t_h(&inst); printf("FAIL h: no trap\n"); fails++; }
    if (*ic - base != 3) { printf("FAIL h trap count: %llu\n",
                                  (unsigned long long)(*ic - base)); fails++; }
    base = *ic;
    if (wasm_rt_impl_try() == 0) { w2c_t_v(&inst, 1u << 28); printf("FAIL v: no trap\n"); fails++; }
    if (*ic - base != 2) { printf("FAIL v trap count: %llu\n",
                                  (unsigned long long)(*ic - base)); fails++; }
    printf("icount dynamic: %s (ic=%llu)\n",
           fails ? "FAILURES" : "all pass", (unsigned long long)*ic);
    wasm2c_t_free(&inst);
    wasm_rt_free();
    return fails ? 1 : 0;
}
''')
    sh([wb / "wasm2c", tmp / "t.u.wasm", "-o", tmp / "t.c", "-n", "t"])
    cc = os.environ.get("CC", "cc")
    sh([cc, "-O1", "-o", tmp / "t", drv, tmp / "t.c",
        ROOT / "wasm-rt" / "wasm-rt-impl.c",
        ROOT / "wasm-rt" / "wasm-rt-mem-impl.c",
        ROOT / "wasm-rt" / "wasm-rt-exceptions-impl.c",
        f"-I{ROOT / 'wasm-rt'}", f"-I{tmp}"])
    r = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode:
        sys.exit("icount dynamic test FAILED")

    # 6) malformed input must fail loudly
    try:
        icount.rewrite(b"\x00asm\x01\x00\x00\x00" + b"\xfe\xff\x07" * 8)
        sys.exit("FAIL: garbage module accepted")
    except Exception as e:
        print(f"garbage rejected: {type(e).__name__}")
    print("test_icount: OK")


if __name__ == "__main__":
    main()
