#!/usr/bin/env python3
"""Lower wasm threads/atomics to single-threaded equivalents.

Judge-linked C++ bots carry a shared memory import and atomic.* ops. On our
single-vCPU guest an atomic RMW is a plain read-modify-write, so this pass
rewrites them:

  *.atomic.load*/store*   -> the matching plain load/store (memarg kept)
  memory.atomic.notify    -> call $h_notify   (returns 0)
  memory.atomic.wait32    -> call $h_wait32   (1 on mismatch else 2)
  memory.atomic.wait64    -> call $h_wait64
  atomic.fence            -> nop
  *.atomic.rmw.*          -> call $h_<op>     (load; op; store; old)

Helpers are ordinary wasm functions appended at the end of the module's
function index space, so no existing index shifts. The call sites pop the
same operands and push the same results as the original atomic op. The
memory immediate offset is folded in with an i32.add before the call.

Memory declarations/imports lose the shared bit so the result validates
without the threads feature.
"""
import sys

I32, I64 = 0x7F, 0x7E


def uleb(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << s
        if not x & 0x80:
            return v, i
        s += 7


def sleb(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            if x & 0x40 and s < 64:
                v -= 1 << s
            return v, i


def pu(v):
    out = bytearray()
    while True:
        x = v & 0x7F
        v >>= 7
        if v:
            out.append(x | 0x80)
        else:
            out.append(x)
            return bytes(out)


def ps(v):
    out = bytearray()
    while True:
        x = v & 0x7F
        v >>= 7
        done = (v == 0 and not x & 0x40) or (v == -1 and x & 0x40)
        out.append(x if done else x | 0x80)
        if done:
            return bytes(out)


def sections(b):
    i = 8
    while i < len(b):
        sid = b[i]
        size, j = uleb(b, i + 1)
        yield sid, j, j + size
        i = j + size


def _blocktype(b, i):
    if b[i] in (0x40, 0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F, 0x69):
        return i + 1
    return sleb(b, i)[1]


def _memarg(b, i):
    align, i = uleb(b, i)
    if align & 0x40:
        _, i = uleb(b, i)
    off, i = uleb(b, i)
    return align, off, i


def read_limits(b, i):
    fl = b[i]; i += 1
    lo, i = uleb(b, i)
    hi = None
    if fl & 1:
        hi, i = uleb(b, i)
    return fl, lo, hi, i


# ---------------------------------------------------------------- helpers

LOAD_PLAIN = {0x10: 0x28, 0x11: 0x29, 0x12: 0x2C, 0x13: 0x2E, 0x14: 0x30,
              0x15: 0x32, 0x16: 0x34}
STORE_PLAIN = {0x17: 0x36, 0x18: 0x37, 0x19: 0x3A, 0x1A: 0x3B, 0x1B: 0x3C,
               0x1C: 0x3D, 0x1D: 0x3E}
RMW_GROUP = {0x1E: "add", 0x25: "sub", 0x2C: "and", 0x33: "or", 0x3A: "xor",
             0x41: "xchg", 0x48: "cmpxchg"}
RMW_SHAPE = {  # lane -> (valtype, load_op, store_op)
    0: (I32, 0x28, 0x36), 1: (I64, 0x29, 0x37),
    2: (I32, 0x2C, 0x3A), 3: (I32, 0x2E, 0x3B),
    4: (I64, 0x30, 0x3C), 5: (I64, 0x32, 0x3D), 6: (I64, 0x34, 0x3E),
}
BINOP = {"add": {I32: 0x6A, I64: 0x7C}, "sub": {I32: 0x6B, I64: 0x7D},
         "and": {I32: 0x71, I64: 0x83}, "or": {I32: 0x72, I64: 0x84},
         "xor": {I32: 0x73, I64: 0x85}}
SUBWORD_MASK = {2: 0xFF, 3: 0xFFFF, 4: 0xFF, 5: 0xFFFF, 6: 0xFFFFFFFF}

G, S, T = b"\x20", b"\x21", b"\x22"  # local.get/set/tee
CST = {I32: b"\x41", I64: b"\x42"}
EQ = {I32: b"\x46", I64: b"\x51"}
AND = {I32: b"\x71", I64: b"\x83"}
ADD = {I32: b"\x6a", I64: b"\x7c"}
IFT = {I32: b"\x7f", I64: b"\x7e"}


def helper_body(sub) -> tuple[bytes, list[int], int]:
    """(params(i32 addr + value args), result i32/i64) -> body bytes.

    For rmw ops the helper signature is (i32 addr, x:vt) -> vt, or
    (i32 addr, e:vt, r:vt) -> vt for cmpxchg. notify: (i32,i32)->i32.
    wait32: (i32,i32,i64)->i32. wait64: (i32,i64,i64)->i32.
    """
    if sub == 0:      # notify(addr,count) -> 0
        return bytes([0x00, 0x41, 0x00, 0x0B]), [I32, I32], I32
    if sub in (1, 2):  # wait32/64: mismatch->1 else 2 (timeout)
        vt = I32 if sub == 1 else I64
        eq = EQ[vt]
        body = (b"\x00"                                     # no locals
                + G + pu(0) + bytes([0x28]) + b"\x02\x00"   # load32 a
                + G + pu(1) + eq                            # old == exp
                + b"\x04\x7f"                               # if (i32)
                + b"\x41\x02"                               #  -> timeout
                + b"\x05\x41\x01"                           # else -> mismatch
                + b"\x0b"                                   # end if
                + b"\x0b")                                  # end func
        return body, [I32, vt, I64], I32
    base = 0x1E + 7 * ((sub - 0x1E) // 7)
    lane = sub - base
    vt, lop, sop = RMW_SHAPE[lane]
    name = RMW_GROUP[base]
    if name == "cmpxchg":
        mask = SUBWORD_MASK.get(lane)
        eq = EQ[vt]
        cmp_ = G + pu(3) + G + pu(1) + eq
        keep = G + pu(3)
        if mask is not None:
            m = CST[vt] + ps(mask) + AND[vt]
            cmp_ = G + pu(3) + m + G + pu(1) + m + eq
            keep = G + pu(3) + m
        # params 0=a,1=e,2=r; locals: 3=old,4=new
        body = (G + pu(0) + bytes([lop]) + b"\x02\x00" + T + pu(3)
                + cmp_ + s_if(vt)
                + G + pu(2)                                  # rep
                + b"\x05" + keep                             # old(&mask)
                + b"\x0b" + S + pu(4)
                + G + pu(0) + G + pu(4) + bytes([sop]) + b"\x02\x00"
                + b"\x0b")
        return b"\x01\x02" + IFT[vt] + body, [I32, vt, vt], vt
    if name == "xchg":
        body = (G + pu(0) + bytes([lop]) + b"\x02\x00" + T + pu(2)
                + G + pu(0) + G + pu(1) + bytes([sop]) + b"\x02\x00"
                + b"\x0b")
        return b"\x01\x01" + IFT[vt] + body, [I32, vt], vt
    # add/sub/and/or/xor; params 0=a,1=x; locals: 2=old,3=new
    body = (G + pu(0) + bytes([lop]) + b"\x02\x00" + T + pu(2)
            + G + pu(1) + bytes([BINOP[name][vt]]) + S + pu(3)
            + G + pu(0) + G + pu(3) + bytes([sop]) + b"\x02\x00"
            + G + pu(2) + b"\x0b")
    return b"\x01\x02" + IFT[vt] + body, [I32, vt], vt


def s_if(vt):
    return b"\x04" + IFT[vt]


# ---------------------------------------------------------------- scanning


def skip_op(b, op, i):
    if op in (0x02, 0x03, 0x04, 0x06, 0x1F):
        i = _blocktype(b, i)
        if op == 0x1F:
            n, i = uleb(b, i)
            for _ in range(n):
                kind = b[i]; i += 1
                if kind in (0, 1):
                    _, i = uleb(b, i)
                _, i = uleb(b, i)
    elif op in (0x07, 0x08, 0x09, 0x0C, 0x0D, 0x10, 0x12, 0x14, 0x15, 0x18,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x3F, 0x40, 0xD2,
                0xD3, 0xD4):
        _, i = uleb(b, i)
    elif op in (0x11, 0x13):
        _, i = uleb(b, i)
        _, i = uleb(b, i)
    elif op == 0x0E:
        n, i = uleb(b, i)
        for _ in range(n + 1):
            _, i = uleb(b, i)
    elif op == 0x1C:
        n, i = uleb(b, i)
        i += n
    elif 0x28 <= op <= 0x3E:
        _, _, i = _memarg(b, i)
    elif op in (0x41, 0x42):
        _, i = sleb(b, i)
    elif op == 0x43:
        i += 4
    elif op == 0x44:
        i += 8
    elif op == 0xD0:
        i = _blocktype(b, i)
    elif op == 0xFC:
        sub, i = uleb(b, i)
        if sub in (8, 10, 12, 14):
            _, i = uleb(b, i)
            _, i = uleb(b, i)
        else:
            _, i = uleb(b, i)
    elif op == 0xFD:
        sub, i = uleb(b, i)
        if sub in set(range(0, 12)) | {92, 93}:
            _, _, i = _memarg(b, i)
        elif sub in (12, 13):
            i += 16
        elif sub in set(range(21, 35)):
            i += 1
        elif sub in set(range(84, 92)):
            _, _, i = _memarg(b, i)
            i += 1
    elif op == 0xFE:
        sub, i = uleb(b, i)
        if sub in set(range(0x10, 0x50)) | {0, 1, 2}:
            _, _, i = _memarg(b, i)
        elif sub == 3:
            i += 1
    return i


def scan_needed(b):
    """FE subops used anywhere in the module."""
    needed = set()
    for sid, j, end in sections(b):
        if sid != 10:
            continue
        n, i = uleb(b, j)
        for _ in range(n):
            size, i = uleb(b, i)
            fend = i + size
            nd, i = uleb(b, i)
            for _ in range(nd):
                _, i = uleb(b, i)
                i += 1
            while i < fend:
                op = b[i]; i += 1
                if op == 0xFE:
                    sub, i = uleb(b, i)
                    needed.add(sub)
                    if sub in set(range(0x10, 0x50)) | {0, 1, 2}:
                        _, _, i = _memarg(b, i)
                    elif sub == 3:
                        i += 1
                    continue
                i = skip_op(b, op, i)
    return needed


# ---------------------------------------------------------------- rewrite


def patch_import_section(b, start, end):
    out = bytearray()
    n, i = uleb(b, start)
    out += pu(n)
    for _ in range(n):
        ln, i = uleb(b, i)
        out += pu(ln) + b[i:i + ln]; i += ln
        ln, i = uleb(b, i)
        out += pu(ln) + b[i:i + ln]; i += ln
        kind = b[i]; i += 1
        out.append(kind)
        if kind == 0:
            v, i = uleb(b, i)
            out += pu(v)
        elif kind == 1:
            t = b[i]; i += 1
            fl, lo, hi, i = read_limits(b, i)
            out += bytes([t, fl]) + pu(lo) + (pu(hi) if fl & 1 else b"")
        elif kind == 2:
            fl, lo, hi, i = read_limits(b, i)
            fl &= ~2  # drop the shared bit
            out += bytes([fl]) + pu(lo) + (pu(hi) if fl & 1 else b"")
        else:
            out += b[i:i + 2]; i += 2
    return bytes(out)


def patch_memory_section(b, start, end):
    out = bytearray()
    n, i = uleb(b, start)
    out += pu(n)
    for _ in range(n):
        fl, lo, hi, i = read_limits(b, i)
        out += bytes([fl & ~2]) + pu(lo) + (pu(hi) if fl & 1 else b"")
    return bytes(out)


def lower_body(b, start, end, helpers, nparams):
    """Rewrite one function body (sans size prefix)."""
    i = start
    ndecls, i = uleb(b, i)
    decls = []
    for _ in range(ndecls):
        cnt, i = uleb(b, i)
        t = b[i]; i += 1
        decls.append((cnt, t))
    nlocals = nparams + sum(c for c, _ in decls)
    # two scratch locals of each width suffice for every callsite shape
    s32a, s32b, s64a, s64b = nlocals, nlocals + 1, nlocals + 2, nlocals + 3
    extra = pu(ndecls + 2) + b"".join(pu(c) + bytes([t]) for c, t in decls)
    extra += pu(2) + bytes([I32]) + pu(2) + bytes([I64])
    plain_head = pu(ndecls) + b"".join(pu(c) + bytes([t]) for c, t in decls)
    used_scratch = False
    out = bytearray()
    while i < end:
        op_at = i
        op = b[i]; i += 1
        if op != 0xFE:
            i = skip_op(b, op, i)
            out += b[op_at:i]
            continue
        sub, i = uleb(b, i)
        if sub in LOAD_PLAIN:
            m = i; _, _, i = _memarg(b, i)
            out += bytes([LOAD_PLAIN[sub]]) + b[m:i]
        elif sub in STORE_PLAIN:
            m = i; _, _, i = _memarg(b, i)
            out += bytes([STORE_PLAIN[sub]]) + b[m:i]
        elif sub == 3:                      # fence
            i += 1
            out += b"\x01"
        else:
            _, off, i = _memarg(b, i)
            hidx, params, _ = helpers[sub]
            used_scratch = True
            seq = bytearray()
            scr = {I32: (s32a, s32b), I64: (s64a, s64b)}
            vargs = params[1:]              # value args after the i32 addr
            # pop value args, top-of-stack last declared -> use per-type slots
            pops = bytearray()
            push = bytearray()
            slots = {I32: iter(scr[I32]), I64: iter(scr[I64])}
            saved = []
            for pt in reversed(vargs):
                slot = next(slots[pt])
                pops += S + pu(slot)
                saved.append(slot)
            for slot in reversed(saved):
                push += G + pu(slot)
            seq += pops                       # []:  vargs parked
            seq += CST[I32] + ps(off) + ADD[I32]   # [addr+off]
            seq += push                              # [addr+off, args...]
            seq += b"\x10" + pu(hidx)
            out += seq
    body = (extra if used_scratch else plain_head) + bytes(out)
    return body


def rewrite(blob: bytes) -> bytes:
    b = blob
    needed = scan_needed(b)
    helpers = {}   # subop -> (funcidx, params, result)
    # existing types
    types = []     # (params tuple, results tuple)
    for sid, j, end in sections(b):
        if sid == 1:
            n, i = uleb(b, j)
            for _ in range(n):
                assert b[i] == 0x60
                i += 1
                cnt, i = uleb(b, i)
                p = list(b[i:i + cnt]); i += cnt
                cnt, i = uleb(b, i)
                r = list(b[i:i + cnt]); i += cnt
                types.append((tuple(p), tuple(r)))
        elif sid == 3:
            nfuncs, _ = uleb(b, j)

    n_imported_funcs = 0
    for sid, j, end in sections(b):
        if sid != 2:
            continue
        n, i = uleb(b, j)
        for _ in range(n):
            ln, i = uleb(b, i); i += ln
            ln, i = uleb(b, i); i += ln
            kind = b[i]; i += 1
            if kind == 0:
                _, i = uleb(b, i)
                n_imported_funcs += 1
            elif kind == 1:
                i += 1
                fl = b[i]; i += 1
                _, i = uleb(b, i)
                if fl & 1:
                    _, i = uleb(b, i)
            elif kind == 2:
                fl = b[i]; i += 1
                _, i = uleb(b, i)
                if fl & 1:
                    _, i = uleb(b, i)
            else:
                i += 2

    # assign helper func indices (appended after existing funcs)
    existing = n_imported_funcs + nfuncs
    new_types = []
    helper_defs = []
    for sub in sorted(needed):
        if sub in LOAD_PLAIN or sub in STORE_PLAIN or sub == 3:
            continue
        body, params, result = helper_body(sub)
        sig = (tuple(params), (result,))
        if sig in types:
            tidx = types.index(sig)
        else:
            tidx = len(types) + len(new_types)
            new_types.append(sig)
        helpers[sub] = (existing + len(helper_defs), params, result)
        helper_defs.append((tidx, body))

    out = bytearray(b[:8])
    for sid, j, end in sections(b):
        if sid == 1:
            body = b[j:end]
            if new_types:
                n, i = uleb(b, j)
                body = pu(n + len(new_types)) + b[i:end]
                for params, results in new_types:
                    body += b"\x60" + pu(len(params)) + bytes(params)
                    body += pu(len(results)) + bytes(results)
        elif sid == 2:
            body = patch_import_section(b, j, end)
        elif sid == 3:
            n, i = uleb(b, j)
            body = pu(n + len(helper_defs)) + b[i:end]
            for tidx, _ in helper_defs:
                body += pu(tidx)
        elif sid == 5:
            body = patch_memory_section(b, j, end)
        elif sid == 10:
            n, i = uleb(b, j)
            parts = []
            for k in range(n):
                size, i = uleb(b, i)
                tidx = func_typeidx_of(b, k)
                parts.append(lower_body(b, i, i + size, helpers,
                                        nparams_of(b, tidx)))
                i += size
            for _, hbody in helper_defs:
                parts.append(hbody)
            body = pu(len(parts)) + b"".join(pu(len(p)) + p for p in parts)
        else:
            body = b[j:end]
        out += bytes([sid]) + pu(len(body)) + body
    return bytes(out)


_types_cache = {}


def nparams_of(b, tidx):
    # re-read type section (cheap enough: small section)
    for sid, j, end in sections(b):
        if sid != 1:
            continue
        n, i = uleb(b, j)
        for k in range(n):
            assert b[i] == 0x60
            i += 1
            cnt, i = uleb(b, i)
            if k == tidx:
                return cnt
            i += cnt
            cnt, i = uleb(b, i)
            i += cnt
    raise KeyError(tidx)


def func_typeidx_of(b, k):
    for sid, j, end in sections(b):
        if sid != 3:
            continue
        n, i = uleb(b, j)
        for _ in range(n):
            t, i = uleb(b, i)
            if _ == k:
                return t
    raise KeyError(k)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    blob = open(src, "rb").read()
    open(dst, "wb").write(rewrite(blob))
    print(f"{src} -> {dst}")
