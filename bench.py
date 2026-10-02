#!/usr/bin/env python3
"""Reproducible kvmrun benchmark harness.

usage: bench.py MAP BOT_A BOT_B [--seeds 11,22] [--runs N]
               [--backends native,kvm] [--sandbox] [--compare]
               [--cold-build] [--json OUT]

Per run: wall time, engine match time, peak RSS of the runner process tree.
--compare writes a replay per (backend,seed) run 0 and byte-compares them.
--sandbox also times `unswbc run --sandbox` per seed (with replay, included
in --compare byte comparison).
--cold-build measures one build+match per backend under a fresh cache dir.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import resource
import statistics
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WIN = re.compile(r"(team [AB] wins|draw) after (\d+) rounds .*?\(([\d.]+)s\)")


# Wrap each run in a tiny python subprocess so RUSAGE_CHILDREN reports the
# max RSS of *this run's* process tree only — getrusage is a cumulative max
# and would otherwise leak peak compiler RSS into every later measurement.
_RSS_SNIP = ("import subprocess,resource,sys;"
             "cp=subprocess.run(sys.argv[2:]);"
             "open(sys.argv[1],'w').write("
             "str(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss));"
             "sys.exit(cp.returncode)")


def run(cmd, env=None):
    t0 = time.monotonic()
    fd, rssf = tempfile.mkstemp(prefix="kv-rss-")
    os.close(fd)
    try:
        cp = subprocess.run([sys.executable, "-c", _RSS_SNIP, rssf]
                            + [str(c) for c in cmd],
                            capture_output=True, text=True, env=env)
        wall = time.monotonic() - t0
        rss = int(pathlib.Path(rssf).read_text() or 0)
    finally:
        os.unlink(rssf)
    return cp, wall, rss


def one_match(map_p, a, b, backend, seed, replay=None, env=None):
    cmd = [sys.executable, HERE / "kvmrun.py", map_p, a, b,
           "--backend", backend, "--seed", str(seed)]
    cmd += ["--replay", replay] if replay else ["--no-replay"]
    cp, wall, rss = run(cmd, env)
    m = WIN.search(cp.stdout)
    return {
        "rc": cp.returncode, "wall_s": round(wall, 3),
        "match_s": float(m.group(3)) if m else None,
        "result": f"{m.group(1)} round {m.group(2)}" if m else None,
        "rss_mb": round(rss / 1024, 1),
        "stderr_tail": cp.stderr.strip().splitlines()[-40:] if cp.returncode else [],
        "replay": replay,
    }


def sandbox_run(map_p, a, b, seed, replay):
    cp, wall, rss = run(["unswbc", "run", map_p, a, b, "--sandbox",
                         "--seed", str(seed), "-o", replay])
    m = WIN.search(cp.stdout + cp.stderr)
    return {"rc": cp.returncode, "wall_s": round(wall, 3),
            "match_s": float(m.group(3)) if m else None,
            "result": f"{m.group(1)} round {m.group(2)}" if m else None,
            "rss_mb": round(rss / 1024, 1), "replay": replay}


def med(rs, k):
    v = [r[k] for r in rs if r[k] is not None]
    return round(statistics.median(v), 3) if v else None


def compare_replays(named):
    """named: {label: path}. Returns (ok, details)."""
    blobs = {}
    for label, p in named.items():
        if p and pathlib.Path(p).exists():
            blobs[label] = pathlib.Path(p).read_bytes()
    if len(blobs) < 2:
        return None, {k: len(v) for k, v in blobs.items()}
    ref = next(iter(blobs.values()))
    return all(b == ref for b in blobs.values()), \
        {k: len(v) for k, v in blobs.items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("map"); ap.add_argument("bot_a"); ap.add_argument("bot_b")
    ap.add_argument("--seeds", default="11")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--backends", default="native,kvm")
    ap.add_argument("--sandbox", action="store_true",
                    help="also time `unswbc run --sandbox` per seed")
    ap.add_argument("--compare", action="store_true",
                    help="byte-compare replays across backends/sandbox")
    ap.add_argument("--cold-build", action="store_true",
                    help="one build+match per backend under a fresh cache dir")
    ap.add_argument("--json", help="write results json")
    args = ap.parse_args()

    seeds = [int(s, 0) for s in args.seeds.split(",")]
    backends = args.backends.split(",")
    env0 = os.environ.copy()
    out = {"map": args.map, "a": args.bot_a, "b": args.bot_b,
           "seeds": seeds, "backends": {}}
    replay_paths = {}   # (backend, seed) -> path

    if args.cold_build:
        for be in backends:
            with tempfile.TemporaryDirectory(prefix="kvmrun-cold-") as td:
                env = dict(env0, XDG_CACHE_HOME=td)
                r = one_match(args.map, args.bot_a, args.bot_b, be,
                              seeds[0], env=env)
                out["backends"].setdefault(be, {})["cold_build"] = r
                print(f"[cold {be}] wall={r['wall_s']}s match={r['match_s']}s",
                      file=sys.stderr)

    for be in backends:
        ent = out["backends"].setdefault(be, {})
        for seed in seeds:
            runs = []
            for i in range(args.runs):
                replay = None
                if args.compare and i == 0:
                    replay = tempfile.mktemp(prefix=f"kv-{be}-{seed}-",
                                             suffix=".replay")
                    replay_paths[(be, seed)] = replay
                r = one_match(args.map, args.bot_a, args.bot_b, be, seed,
                              replay=replay, env=env0)
                runs.append(r)
                print(f"[{be} seed={seed} run{i}] {r['result']} "
                      f"match={r['match_s']}s wall={r['wall_s']}s "
                      f"rss={r['rss_mb']}MB", file=sys.stderr)
            ent[f"seed_{seed}"] = {
                "match_s_med": med(runs, "match_s"),
                "wall_s_med": med(runs, "wall_s"),
                "rss_mb_max": max(r["rss_mb"] for r in runs),
                "result": runs[0]["result"],
            }
            ent.setdefault("runs", []).extend(runs)

    if args.sandbox:
        sb = []
        for seed in seeds:
            replay = None
            if args.compare:
                replay = tempfile.mktemp(prefix=f"kv-sb-{seed}-",
                                         suffix=".replay")
                replay_paths[("sandbox", seed)] = replay
            r = sandbox_run(args.map, args.bot_a, args.bot_b, seed, replay)
            sb.append(r)
            print(f"[sandbox seed={seed}] {r['result']} wall={r['wall_s']}s",
                  file=sys.stderr)
        out["sandbox"] = {"wall_s_med": med(sb, "wall_s"),
                          "result": sb[0]["result"], "runs": sb}

    if args.compare:
        cmp_out = {}
        for seed in seeds:
            named = {be: replay_paths.get((be, seed)) for be in backends}
            if ("sandbox", seed) in replay_paths:
                named["sandbox"] = replay_paths[("sandbox", seed)]
            ok, sizes = compare_replays(named)
            cmp_out[seed] = {"identical": ok, "sizes": sizes}
            print(f"[compare seed={seed}] identical={ok} sizes={sizes}",
                  file=sys.stderr)
        out["replay_compare"] = cmp_out

    print(json.dumps(out, indent=1))
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
