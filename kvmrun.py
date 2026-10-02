#!/usr/bin/env python3
"""kvmrun: fast match runner — wasm2c-compiled engine + bots.

Pipeline per bot wasm: judge metering pass -> unatomic lowering -> wasm2c
(-n bota/botb) -> clang -O1. The engine wasm -> wasm2c -n engine. Everything
links with host.c into one native binary that plays a whole match.

usage: kvmrun.py MAP BOT_A BOT_B [--debug N] [--no-replay] [--replay FILE]
                                 [--seed SEED] [--backend native|kvm]
       kvmrun.py --batch JOBSFILE [--jobs N] [--backend native|kvm]
                 [--debug N] [--seed SEED] [-v]
BOT_x is a .wasm file or a source directory (built via unswbc's judge clang).
JOBSFILE lines: MAP BOT_A BOT_B [REPLAY|-]   ('#' lines and blanks skipped)
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import glob
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent


def _unswbc_pkg() -> pathlib.Path:
    """Locate the site-packages directory containing the `unswbc` package."""
    env = os.environ.get("UNSWBC_PKG")
    if env:
        return pathlib.Path(env)
    spec = importlib.util.find_spec("unswbc")
    if spec and spec.submodule_search_locations:
        return pathlib.Path(spec.submodule_search_locations[0]).parent
    exe = shutil.which("unswbc")
    cands: list[pathlib.Path] = []
    if exe:  # console script in a pipx/uv-style venv: <venv>/bin/unswbc
        cands.append(pathlib.Path(exe).resolve().parent.parent)
        try:  # uv/pipx shims point at the venv python via their shebang
            she = pathlib.Path(exe).open("rb").readline().decode().strip()
            if she.startswith("#!"):
                cands.append(pathlib.Path(she[2:]).parent.parent)
        except OSError:
            pass
    for venv in cands:
        for sp in sorted(venv.glob("lib/python*/site-packages")):
            if (sp / "unswbc").is_dir():
                return sp
    for sp in sorted(pathlib.Path.home().glob(
            ".local/share/uv/tools/unswbc/lib/python*/site-packages")):
        if (sp / "unswbc").is_dir():
            return sp
    raise SystemExit(
        "kvmrun: cannot find the `unswbc` package; install it "
        "(`uv tool install unswbc`) or set UNSWBC_PKG to the site-packages "
        "directory containing it")


def _wabt_bin() -> pathlib.Path:
    """Locate the directory containing wabt's wasm2c binary."""
    env = os.environ.get("WABT_BIN")
    if env:
        return pathlib.Path(env)
    env = os.environ.get("WABT")
    if env:
        return pathlib.Path(env) / "bin"
    exe = shutil.which("wasm2c")
    if exe:
        return pathlib.Path(exe).resolve().parent
    raise SystemExit(
        "kvmrun: cannot find wasm2c; install wabt or set WABT_BIN to the "
        "directory containing it")


PKG = _unswbc_pkg()
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(HERE))

from unswbc import clangtool, metering  # noqa: E402
import unatomic  # noqa: E402

ENGINE_WASM = PKG / "unswbc" / "unswbc_engine.wasm"
WABT_BIN = _wabt_bin()
WASM_RT_DIR = HERE / "wasm-rt"  # vendored wasm-rt (patched: exn depth fix)
WABT_INC = WASM_RT_DIR          # generated code only needs wasm-rt headers
CACHE = pathlib.Path(os.environ.get("XDG_CACHE_HOME", pathlib.Path.home() / ".cache")) / "kvmrun"
CLANG = os.environ.get("KVMRUN_CC", "clang")


_TOOLVERS: str | None = None


def tool_versions() -> str:
    """Cache-busting identity of every tool that shapes generated artifacts:
    wasm2c + clang versions, unatomic.py source, unswbc metering source."""
    global _TOOLVERS
    if _TOOLVERS is None:
        wv = subprocess.run([str(WABT_BIN / "wasm2c"), "--version"],
                            capture_output=True, text=True).stdout.strip()
        cv = subprocess.run([CLANG, "--version"], capture_output=True,
                            text=True).stdout.splitlines()[0].strip()
        src = hashlib.sha256(
            (HERE / "unatomic.py").read_bytes()
            + pathlib.Path(metering.__file__).read_bytes()).hexdigest()[:16]
        _TOOLVERS = f"{wv}|{cv}|{src}"
    return _TOOLVERS


def sh(cmd, **kw):
    kw.setdefault("check", True)
    return subprocess.run([str(a) for a in cmd], **kw)


def cache_dir(key: str) -> pathlib.Path:
    d = CACHE / key
    d.mkdir(parents=True, exist_ok=True)
    return d


def _tmp_for(path: pathlib.Path) -> pathlib.Path:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    os.close(fd)
    return pathlib.Path(name)


def bot_wasm(arg: str) -> pathlib.Path:
    path = pathlib.Path(arg)
    if path.is_file() and path.suffix == ".wasm":
        return path
    if path.is_dir():
        return clangtool.build(path)
    if path.is_file() and (path / "").suffix in (".cc", ".cpp"):
        raise SystemExit(f"{arg}: pass the bot's directory, not a source file")
    raise SystemExit(f"{arg}: not a .wasm file or source directory")


def engine_c() -> pathlib.Path:
    key = "engine-" + hashlib.sha256(
        ENGINE_WASM.read_bytes() + tool_versions().encode()).hexdigest()[:24]
    d = cache_dir(key)
    if not (d / "engine.c").is_file():
        tmp = pathlib.Path(tempfile.mkdtemp(prefix=d.name + ".", dir=d.parent))
        try:
            sh([str(WABT_BIN / "wasm2c"), "-n", "engine", "--enable-exceptions",
                "-o", str(tmp / "engine.c"), str(ENGINE_WASM)])
            os.replace(tmp / "engine.h", d / "engine.h")
            os.replace(tmp / "engine.c", d / "engine.c")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return d


def bot_c(wasm: pathlib.Path, mod: str) -> pathlib.Path:
    """wasm -> metered -> unatomic -> wasm2c; returns dir with {mod}.c/.h"""
    blob = wasm.read_bytes()
    key = f"{mod}-" + hashlib.sha256(
        blob + tool_versions().encode()).hexdigest()[:24]
    d = cache_dir(key)
    if not (d / f"{mod}.c").is_file():
        if metering.REMAINING not in blob:
            blob = metering.instrument(blob)
        tmp = pathlib.Path(tempfile.mkdtemp(prefix=d.name + ".", dir=d.parent))
        try:
            lowered = tmp / f"{mod}.lowered.wasm"
            lowered.write_bytes(unatomic.rewrite(blob))
            sh([str(WABT_BIN / "wasm2c"), "-n", mod, "--enable-exceptions",
                "-o", str(tmp / f"{mod}.c"), str(lowered)])
            # .c last: its presence implies .h and .lowered.wasm landed
            for f in (f"{mod}.h", f"{mod}.lowered.wasm", f"{mod}.c"):
                os.replace(tmp / f, d / f)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return d


_RES_INC: pathlib.Path | None = None


def clang_res_inc() -> pathlib.Path:
    global _RES_INC
    if _RES_INC is None:
        out = subprocess.run([CLANG, "-print-resource-dir"], check=True,
                             capture_output=True, text=True).stdout.strip()
        _RES_INC = pathlib.Path(out) / "include"
    return _RES_INC


GUEST_CFLAGS = [
    "-DKVMRUN_GUEST", "-ffreestanding", "-fno-stack-protector", "-fno-pic",
    "-mno-red-zone", "-nostdinc",
    f"-isystem", None,  # filled with clang resource include
    f"-I{HERE / 'guest' / 'include'}",
    "-DWASM_RT_USE_MMAP=1", "-DWASM_RT_MEMCHECK_GUARD_PAGES=1",
    "-DWASM_RT_MEMCHECK_BOUNDS_CHECK=0", "-DWASM_RT_SKIP_SIGNAL_RECOVERY=1",
    "-DWASM_RT_STACK_DEPTH_COUNT=" + os.environ.get("KVMRUN_DEPTHCOUNT", "1"),
    *( ["-DWASM_RT_NONCONFORMING_UNCHECKED_STACK_EXHAUSTION=1"]
       if os.environ.get("KVMRUN_DEPTHCOUNT") == "0" else [] ),
    "-DWASM_RT_MAX_CALL_STACK_DEPTH=262144",
    "-DNDEBUG",
    "-isystem", "/usr/include",   # simde headers for wasm2c SIMD (last resort)
    # Debian/Ubuntu multiarch glibc headers (bits/…) live under
    # /usr/include/<triplet> — add when present so simde->fenv.h resolves
    *sum((["-isystem", d] for d in glob.glob("/usr/include/*-linux-gnu")), []),
]


def guest_cflags() -> list[str]:
    fl = list(GUEST_CFLAGS)
    fl[fl.index(None)] = str(clang_res_inc())
    return fl


def compile_obj(cdir: pathlib.Path, mod: str, extra_inc: pathlib.Path,
                guest: bool = False) -> pathlib.Path:
    flags = (guest_cflags() if guest else
             ["-pthread", "-DWASM_RT_MAX_CALL_STACK_DEPTH=262144"]
             + os.environ.get("KVMRUN_OBJCFLAGS", "").split())
    if os.environ.get("KVMRUN_PROF"):
        flags += ["-finstrument-functions"]
    opt = os.environ.get("KVMRUN_OPT", "-O2")
    tag = hashlib.sha256(tool_versions().encode() +
                         (opt + " -march=native ").encode() +
                         " ".join(flags).encode() +
                         (WASM_RT_DIR / "wasm-rt.h").read_bytes() +
                         (WASM_RT_DIR / "wasm-rt-exceptions.h").read_bytes()
                         ).hexdigest()[:10]
    obj = cdir / f"{mod}.{tag}.o"
    if not obj.is_file():
        tmp = _tmp_for(obj)
        try:
            sh([CLANG, opt, "-march=native", "-c", *flags, f"-I{WABT_INC}",
                f"-I{WASM_RT_DIR}",
                f"-I{cdir}", f"-I{extra_inc}", "-o", str(tmp),
                str(cdir / f"{mod}.c")])
            os.replace(tmp, obj)
        finally:
            tmp.unlink(missing_ok=True)
    return obj


SAME_BOT_SHIM = """\
#include "bota.h"
#define w2c_botb w2c_bota
#define w2c_botb_0x5Fstart w2c_bota_0x5Fstart
#define wasm2c_botb_instantiate wasm2c_bota_instantiate
#define wasm2c_botb_free wasm2c_bota_free
#define wasm2c_botb_min_env_memory wasm2c_bota_min_env_memory
#define wasm2c_botb_max_env_memory wasm2c_bota_max_env_memory
#define wasm2c_botb_is64_env_memory wasm2c_bota_is64_env_memory
#define wasm2c_botb_pagesize_env_memory wasm2c_bota_pagesize_env_memory
#define w2c_botb_wasmer_metering_remaining_points \\
    w2c_bota_wasmer_metering_remaining_points
#define w2c_botb_wasmer_metering_points_exhausted \\
    w2c_bota_wasmer_metering_points_exhausted
"""


RT_SRCS = ("wasm-rt-impl.c", "wasm-rt-exceptions-impl.c",
           "wasm-rt-mem-impl.c")


def runner_key(backend: str, link_objs: list[pathlib.Path],
               same: bool) -> str:
    h = hashlib.sha256()
    h.update(backend.encode() + b"\0")
    for o in link_objs:
        h.update(o.read_bytes())
    h.update(b"shim\0" + SAME_BOT_SHIM.encode() if same else b"noshim\0")
    for f in sorted(WASM_RT_DIR.iterdir()):
        if f.is_file():
            h.update(f.name.encode() + b"\0" + f.read_bytes())
    h.update(b"host.c\0" + (HERE / "host.c").read_bytes())
    if backend == "kvm":
        for rel in ("guest/guest.ld", "guest/klibc.c", "guest/gthr.c",
                    "guest/entry.S"):
            h.update(rel.encode() + b"\0" + (HERE / rel).read_bytes())
        for f in sorted((HERE / "guest" / "include").rglob("*")):
            if f.is_file():
                h.update(f.read_bytes())
    for k in ("KVMRUN_CFLAGS", "KVMRUN_OBJCFLAGS", "KVMRUN_OPT",
              "KVMRUN_DEPTHCOUNT", "KVMRUN_PROF"):
        h.update(k.encode() + b"=" + os.environ.get(k, "").encode() + b"\0")
    return h.hexdigest()[:24]


def vmm_bin() -> pathlib.Path:
    vmm = cache_dir("vmm-" + hashlib.sha256(
        (HERE / "vmm.c").read_bytes() +
        (HERE / "abi.h").read_bytes() +
        tool_versions().encode()).hexdigest()[:16]) / "vmm"
    if not vmm.is_file():
        tmp = _tmp_for(vmm)
        try:
            sh([CLANG, "-O2", "-pthread", "-o", str(tmp),
                str(HERE / "vmm.c")])
            os.replace(tmp, vmm)
        finally:
            tmp.unlink(missing_ok=True)
    return vmm


def build(backend: str, arg_a: str, arg_b: str):
    """wasm->.c->.o staging then cached runner/guest link.
    Returns (binary, vmm_or_None)."""
    t0 = time.monotonic()
    wa, wb = bot_wasm(arg_a), bot_wasm(arg_b)
    same = wa.read_bytes() == wb.read_bytes()

    work = pathlib.Path(tempfile.mkdtemp(prefix="kvmrun-"))
    eng_dir = engine_c()

    mod_dirs: dict[str, pathlib.Path] = {"engine": eng_dir}

    def stage(mod: str, wasm: pathlib.Path) -> pathlib.Path:
        d = bot_c(wasm, mod)
        mod_dirs[mod] = d
        # make headers importable as <mod>.h
        (work / f"{mod}.h").symlink_to(d / f"{mod}.h")
        return compile_obj(d, mod, work, guest=backend == "kvm")

    guest = backend == "kvm"
    objs = [] if guest else [compile_obj(eng_dir, "engine", work)]
    (work / "engine.h").symlink_to(eng_dir / "engine.h")

    ths = []
    errs: list[BaseException] = []
    a_obj: list[pathlib.Path] = []
    def _a():
        try:
            a_obj.append(stage("bota", wa))
        except BaseException as e:
            errs.append(e)
    t = threading.Thread(target=_a); t.start(); ths.append(t)
    if not same:
        b_obj: list[pathlib.Path] = []
        def _b():
            try:
                b_obj.append(stage("botb", wb))
            except BaseException as e:
                errs.append(e)
        t = threading.Thread(target=_b); t.start(); ths.append(t)
    for t in ths:
        t.join()
    if errs:
        raise errs[0]
    objs += a_obj
    if same:
        (work / "botb.h").write_text(SAME_BOT_SHIM)
        mod_dirs["botb"] = mod_dirs["bota"]
    else:
        objs += b_obj

    # the map file is a runtime input: the linked binary depends only on
    # (backend, engine, bota, botb|shim, support sources, flags)
    if guest:
        eng_gobj = compile_obj(eng_dir, "engine", work, guest=True)
        link_objs = [eng_gobj] + objs
    else:
        link_objs = objs
    binary = cache_dir("run-" + runner_key(backend, link_objs, same)) / \
        ("guest.elf" if guest else "runner")
    if binary.is_file():
        print(f"cached runner -> {binary}", file=sys.stderr)
        return binary, vmm_bin() if guest else None
    bout = _tmp_for(binary)

    try:
        if backend == "native":
            # wasm-rt runtime
            rt_objs = []
            rt_extra = os.environ.get("KVMRUN_OBJCFLAGS", "").split()
            for src in RT_SRCS:
                out = work / (pathlib.Path(src).stem + ".o")
                sh([CLANG, "-O1", "-pthread", "-c", *rt_extra,
                    f"-I{WABT_INC}", f"-I{WASM_RT_DIR}",
                    "-o", str(out), str(WASM_RT_DIR / src)])
                rt_objs.append(out)
            extra = os.environ.get("KVMRUN_CFLAGS", "").split()
            sh([CLANG, "-O1", "-pthread", *extra, f"-I{WABT_INC}",
                f"-I{WASM_RT_DIR}",
                f"-I{work}", "-o", str(bout), str(HERE / "host.c"),
                *map(str, objs), *map(str, rt_objs), "-lm"])
            os.replace(bout, binary)
            print(f"built in {time.monotonic() - t0:.1f}s -> {binary}",
                  file=sys.stderr)
            return binary, None

        # backend == "kvm": objects were already compiled with guest flags
        gobjs = link_objs
        grt = []
        for src in RT_SRCS:
            out = work / (pathlib.Path(src).stem + ".guest.o")
            sh([CLANG, "-O1", "-c", *guest_cflags(), f"-I{WABT_INC}",
                f"-I{WASM_RT_DIR}", "-o", str(out), str(WASM_RT_DIR / src)])
            grt.append(out)
        gsup = []
        for src in ("klibc.c", "gthr.c"):
            out = work / (pathlib.Path(src).stem + ".o")
            sh([CLANG, "-O1", "-c", *guest_cflags(), "-o", str(out),
                str(HERE / "guest" / src)])
            gsup.append(out)
        ent = work / "entry.o"
        sh([CLANG, "-c", "-o", str(ent), str(HERE / "guest" / "entry.S")])
        ghost = work / "host.guest.o"
        sh([CLANG, "-O1", "-c", *guest_cflags(), f"-I{WABT_INC}",
            f"-I{WASM_RT_DIR}", f"-I{work}", f"-I{HERE}",
            "-o", str(ghost), str(HERE / "host.c")])
        sh(["ld", "-T", str(HERE / "guest" / "guest.ld"), "--build-id=none",
            "-o", str(bout), str(ent), *map(str, gsup), str(ghost),
            *map(str, gobjs), *map(str, grt)])
        os.replace(bout, binary)
        vmm = vmm_bin()
        print(f"guest built in {time.monotonic() - t0:.1f}s -> {binary}",
              file=sys.stderr)
        return binary, vmm
    finally:
        bout.unlink(missing_ok=True)


def match_argv(backend: str, binary: pathlib.Path, vmm,
               map_path: str, arg_a: str, arg_b: str,
               passthrough: list[str]) -> list[str]:
    if backend == "native":
        return [str(binary), map_path, "--name-a", arg_a, "--name-b",
                arg_b, *passthrough]
    return [str(vmm), "--elf", str(binary), "--map", map_path,
            "--name-a", arg_a, "--name-b", arg_b, *passthrough]


WIN_RE = re.compile(r"team .* wins.*")


def parse_jobs(path: str) -> list[tuple[str, str, str, str | None]]:
    out = []
    for ln, line in enumerate(
            pathlib.Path(path).read_text().splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if len(f) < 3:
            raise SystemExit(f"{path}:{ln}: want MAP BOT_A BOT_B [REPLAY|-]")
        out.append((f[0], f[1], f[2],
                    f[3] if len(f) > 3 and f[3] != "-" else None))
    return out


def batch(jobs_path: str, njobs: int, backend: str,
          gpass: list[str]) -> int:
    specs = parse_jobs(jobs_path)
    if not specs:
        print("batch: no jobs", file=sys.stderr)
        return 2

    wasms: dict[str, pathlib.Path] = {}
    for _, a, b, _ in specs:
        for arg in (a, b):
            if arg not in wasms:
                wasms[arg] = bot_wasm(arg)
    pairs: dict[tuple, tuple[str, str]] = {}
    for _, a, b, _ in specs:
        pairs.setdefault((wasms[a], wasms[b]), (a, b))
    print(f"batch: {len(specs)} match(es), {len(pairs)} unique build(s)",
          file=sys.stderr)

    # phase 1: build each unique (bots) pair once
    built: dict[tuple, tuple | BaseException] = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(len(pairs), njobs))) as ex:
        futs = {ex.submit(build, backend, a, b): k
                for k, (a, b) in pairs.items()}
        for fut in concurrent.futures.as_completed(futs):
            k = futs[fut]
            try:
                built[k] = fut.result()
            except BaseException as e:
                built[k] = e
                print(f"build failed for {pairs[k]}: {e}", file=sys.stderr)

    # phase 2: run matches, up to njobs at once
    def run_one(idx: int):
        m, a, b, replay = specs[idx]
        res = built.get((wasms[a], wasms[b]))
        if not isinstance(res, tuple):
            return idx, -1, "", f"build failed: {res}"
        binary, vmm = res
        pto = list(gpass)
        if replay:
            pathlib.Path(replay).parent.mkdir(parents=True, exist_ok=True)
            pto += ["--replay", replay]
        else:
            pto += ["--no-replay"]
        cp = subprocess.run(match_argv(backend, binary, vmm, m, a, b, pto),
                            capture_output=True, text=True)
        return idx, cp.returncode, cp.stdout, cp.stderr

    ok = 0
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(len(specs), njobs))) as ex:
        futs = {ex.submit(run_one, i): i for i in range(len(specs))}
        for fut in concurrent.futures.as_completed(futs):
            idx = futs[fut]
            try:
                _, rc, out, err = fut.result()
            except BaseException as e:
                rc, out, err = -1, "", str(e)
            win = WIN_RE.search(out or "")
            print(f"[job {idx}] rc={rc}"
                  + (f" | {win.group(0)}" if win else ""))
            if rc != 0:
                for l in ((out or "") + (err or "")).splitlines()[-20:]:
                    print(f"    {l}")
            else:
                ok += 1
    print(f"batch done: {ok}/{len(specs)} ok")
    return 0 if ok == len(specs) else 1


def main() -> int:
    args: list[str] = []
    passthrough: list[str] = []
    backend = "native"
    batch_file: str | None = None
    njobs = min(8, os.cpu_count() or 1)
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--debug", "--replay", "--seed"):
            passthrough += [a, argv[i + 1]]; i += 2
        elif a == "--no-replay":
            passthrough.append(a); i += 1
        elif a == "--backend":
            backend = argv[i + 1]; i += 2
        elif a in ("-v", "--verbose"):
            passthrough.append("-v"); i += 1
        elif a == "--batch":
            batch_file = argv[i + 1]; i += 2
        elif a == "--jobs":
            njobs = int(argv[i + 1]); i += 2
        elif a.startswith("--"):
            print(f"unknown flag: {a}", file=sys.stderr); i += 1
        else:
            args.append(a); i += 1

    if backend not in ("native", "kvm"):
        print(f"unknown backend {backend!r}", file=sys.stderr)
        return 2

    if batch_file is not None:
        # the jobs file owns replay selection; keep -v/--debug globals
        gpass: list[str] = []
        j = 0
        while j < len(passthrough):
            if passthrough[j] == "--replay":
                j += 2
            elif passthrough[j] == "--no-replay":
                j += 1
            else:
                gpass.append(passthrough[j]); j += 1
        return batch(batch_file, njobs, backend, gpass)

    if len(args) < 3:
        print(__doc__)
        return 2
    map_path, arg_a, arg_b = args[0], args[1], args[2]
    binary, vmm = build(backend, arg_a, arg_b)
    return subprocess.run(
        match_argv(backend, binary, vmm, map_path, arg_a, arg_b,
                   passthrough)).returncode


if __name__ == "__main__":
    raise SystemExit(main())
