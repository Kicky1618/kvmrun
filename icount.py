"""kvmrun-icount: append a dynamic instruction counter to a wasm module.

Adds one exported mutable i64 global `kvmrun_icount` and injects
`icount += N` before every op that may not fall through (control ops and
every potentially-trapping op), where N = ops since the previous segment
boundary. An op is counted iff control reaches it, so counts are exact
even when a trap aborts a segment mid-way (division by zero, OOB memory
access, unreachable, ...).

Run AFTER metering.instrument: metering's own injected sequences
(_check / _charge / _charge_length) are detected and skipped so the count
reflects the module's real ops, not instrumentation overhead.
"""

from __future__ import annotations

from unswbc import metering
from unswbc.metering import (uleb, sleb, put_uleb, put_sleb, next_op,
                             sections, ENDS_BLOCK)

ICOUNT = b"kvmrun_icount"


def _imported_globals(b: bytes, start: int) -> int:
    total = 0
    n, j = uleb(b, start)
    for _ in range(n):
        ln, j = uleb(b, j); j += ln          # module name
        ln, j = uleb(b, j); j += ln          # field name
        kind = b[j]; j += 1
        if kind == 0:
            _, j = uleb(b, j)                # func: typeidx
        elif kind == 1:
            j += 1                           # table: elemtype
            limits = b[j]; j += 1
            _, j = uleb(b, j)
            if limits:
                _, j = uleb(b, j)
        elif kind == 2:
            limits = b[j]; j += 1            # memory: limits
            _, j = uleb(b, j)
            if limits & 1:
                _, j = uleb(b, j)
        else:
            total += 1                       # global
            j += 2                           # valtype + mut
    return total


def instrumented(blob: bytes) -> bool:
    """True iff the module already exports a `kvmrun_icount` global."""
    for sid, j, end, _ in sections(blob):
        if sid != 7:
            continue
        n, j = uleb(blob, j)
        for _ in range(n):
            ln, j = uleb(blob, j)
            name = blob[j:j + ln]; j += ln
            kind = blob[j]; j += 1
            _, j = uleb(blob, j)
            if kind == 3 and name == ICOUNT:
                return True
    return False


def _find_metering_globals(b: bytes, found) -> tuple[int, int]:
    """rem/exh global indices from the export section (scratch = exh+1)."""
    rem = exh = -1
    if 7 in found:
        j, end = found[7]
        n, j = uleb(b, j)
        for _ in range(n):
            ln, j = uleb(b, j)
            name = b[j:j + ln]; j += ln
            kind = b[j]; j += 1
            idx, j = uleb(b, j)
            if kind == 3 and name == metering.REMAINING:
                rem = idx
            elif kind == 3 and name == metering.EXHAUSTED:
                exh = idx
    return rem, exh


def _metering_skip(b: bytes, i: int, rem: int, exh: int) -> int:
    """If a metering injection starts at i, return its end, else i."""
    if rem < 0:
        return i
    try:
        # _check: global.get rem; i64.const 0; i64.lt_s; if void;
        #         i32.const 1; global.set exh; end
        if b[i] == 0x23:
            j = i + 1
            g, j = uleb(b, j)
            if g != rem or b[j] != 0x42:
                return i
            _, j = sleb(b, j + 1)
            c = b[j]; j += 1
            if c == 0x7d:                    # i64.sub -> _charge
                if b[j] != 0x24:
                    return i
                g, j = uleb(b, j + 1)
                return j if g == rem else i
            # _check tail: 53 04 40 41 01 24 <exh> 00 0b
            if (c == 0x53 and b[j:j + 3] == b"\x04\x40\x41"):
                j += 3
                v, j = sleb(b, j)            # const 1 (or any)
                if b[j] == 0x24:
                    g, j = uleb(b, j + 1)
                    if (g == exh and b[j] == 0x00 and b[j + 1] == 0x0b):
                        return j + 2
            return i
        # _charge_length: global.set s; global.get s; global.get rem;
        #   global.get s; i64.extend_i32_u; i64.const sh; i64.shl;
        #   i64.sub; global.set rem
        if b[i] == 0x24:
            j = i + 1
            s, j = uleb(b, j)
            if s in (rem, exh):
                return i
            if b[j] != 0x23:
                return i
            s2, j = uleb(b, j + 1)
            if s2 != s or b[j] != 0x23:
                return i
            g, j = uleb(b, j + 1)
            if g != rem or b[j] != 0x23:
                return i
            s3, j = uleb(b, j + 1)
            if (s3 != s or b[j] != 0xad or b[j + 1] != 0x42):
                return i
            _, j = sleb(b, j + 2)
            if b[j] != 0x88 or b[j + 1] != 0x7d or b[j + 2] != 0x24:
                return i
            g, j = uleb(b, j + 3)
            return j if g == rem else i
    except (IndexError, ValueError):
        return i
    return i


def _charge(ic: int, n: int) -> bytes:
    # global.get ic; i64.const n; i64.add; global.set ic
    return b"\x23" + put_uleb(ic) + b"\x42" + put_sleb(n) + b"\x7c\x24" \
        + put_uleb(ic)


# Segment boundaries = ops that may not fall through. ENDS_BLOCK covers the
# control ops; the rest are ops that can trap. The trapper itself is counted
# (its charge runs before it does).
_SEGMENT_END = frozenset(ENDS_BLOCK) | {
    0x00,                                   # unreachable
    0x25, 0x26,                             # table.get / table.set (OOB)
    *range(0x28, 0x3F),                     # scalar loads/stores (OOB)
    0x6D, 0x6E, 0x6F, 0x70,                 # i32 div/rem
    0x7F, 0x80, 0x81, 0x82,                 # i64 div/rem
    0xA8, 0xA9, 0xAA, 0xAB,                 # i32.trunc_f{32,64}_{s,u}
    0xAE, 0xAF, 0xB0, 0xB1,                 # i64.trunc_f{32,64}_{s,u}
}
# prefixed subs taking a memory operand (all OOB-trappable):
#   0xFC: memory.init/copy/fill, table.init/copy/fill
#   0xFD: v128 load/store family + lane loads/stores
#   0xFE: notify/wait + all RMW ops
_FC_TRAP = {8, 10, 11, 12, 14, 17}
_FD_TRAP = set(range(0, 12)) | set(range(84, 92)) | {92, 93}
_FE_TRAP = {0, 1, 2} | set(range(0x10, 0x4F))
_TRAP_PREFIX = {0xFC: _FC_TRAP, 0xFD: _FD_TRAP, 0xFE: _FE_TRAP}


def _is_segment_end(code: int) -> bool:
    if code in _SEGMENT_END:
        return True
    if code > 0xFFFF:
        return code & 0xFFFF in _TRAP_PREFIX.get(code >> 16, ())
    return False


def _body(b: bytes, start: int, end: int, ic: int,
          rem: int, exh: int) -> bytes:
    k = start
    count, k = uleb(b, k)
    for _ in range(count):
        _, k = uleb(b, k)
        k += 1
    out = bytearray(b[start:k])
    acc = 0
    while k < end:
        m = _metering_skip(b, k, rem, exh)
        if m != k:
            out += b[k:m]              # keep metering bytes, just uncounted
            k = m
            continue
        op = k
        code, k = next_op(b, k)
        acc += 1
        if _is_segment_end(code) and acc:
            out += _charge(ic, acc)
            acc = 0
        out += b[op:k]
    return bytes(out)


def rewrite(blob: bytes) -> bytes:
    if instrumented(blob):
        return blob
    found: dict[int, tuple[int, int]] = {}
    for sid, j, end, _ in sections(blob):
        found.setdefault(sid, (j, end))
    rem, exh = _find_metering_globals(blob, found)

    imported = _imported_globals(blob, found[2][0]) if 2 in found else 0
    defined, gbody = 0, b""
    if 6 in found:
        j, end = found[6]
        defined, after = uleb(blob, j)
        gbody = blob[after:end]
    ic = imported + defined

    globals_section = (put_uleb(defined + 1) + gbody
                       + b"\x7e\x01\x42\x00\x0b")   # i64 mut, init 0

    exported, ebody = 0, b""
    if 7 in found:
        j, end = found[7]
        exported, after = uleb(blob, j)
        ebody = blob[after:end]
    exports_section = (put_uleb(exported + 1) + ebody
                       + put_uleb(len(ICOUNT)) + ICOUNT + b"\x03"
                       + put_uleb(ic))

    j, end = found[10]
    n, j = uleb(blob, j)
    bodies = []
    for _ in range(n):
        size, j = uleb(blob, j)
        bodies.append(_body(blob, j, j + size, ic, rem, exh))
        j += size
    code_section = put_uleb(n) + b"".join(put_uleb(len(x)) + x
                                          for x in bodies)

    replaced = {6: globals_section, 7: exports_section, 10: code_section}
    order = metering.SECTION_ORDER
    out = bytearray(blob[:8])
    written: set[int] = set()
    for sid, j, end, head in sections(blob):
        for missing in (6, 7):
            if missing in found or missing in written:
                continue
            if order.index(sid) > order.index(missing):
                body = replaced[missing]
                out += bytes([missing]) + put_uleb(len(body)) + body
                written.add(missing)
        if sid == 0:
            out += blob[head:end]
        else:
            body = replaced.get(sid, blob[j:end])
            out += bytes([sid]) + put_uleb(len(body)) + body
        written.add(sid)
    return bytes(out)
