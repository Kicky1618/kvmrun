# kvmrun

A fast match runner for `unswbc` dragon battles: compiles
the judge engine and both bots' wasm to C via `wasm2c`, links everything into
a single binary, and plays a whole match — roughly **50–100× faster** than
`unswbc run --sandbox`, with byte-identical replay output.

## Backends

- **`native`** — links the wasm2c output and the wasm-rt runtime into a normal
  Linux binary. Bots run as host pthreads.
- **`kvm`** — links the same code into a freestanding ELF loaded into a minimal
  KVM guest on a single vCPU (`vmm.c` is the VM). Guest threads are cooperative
  contexts scheduled in-guest; the guest has its own tiny libc (`guest/`), a
  demand-paged heap backed by guest-managed page tables, and per-thread
  demand-paged stacks. Synchronisation and I/O go through hypercalls
  (`abi.h`): an MMIO doorbell plus per-thread mailbox pages, futex wait/wake,
  and a replay-write call.

The KVM backend exists to mirror the real judge's single-CPU contention model:
all bot threads share one vCPU, so CPU-point accounting and wall-clock races
behave like the production sandbox rather than an SMP host.

## Pipeline

For each bot (`.wasm` file or source directory):

```
source dir --(unswbc clangtool)--> bot.wasm
bot.wasm --(metering, if absent)--> metered.wasm
metered.wasm --(unatomic.py)--> lowered.wasm   # threads/atomics -> single-threaded
lowered.wasm --(wasm2c -n bota|botb --enable-exceptions)--> bot.c/.h
bot.c --(clang -O2 -march=native)--> bot.o
engine.wasm --(wasm2c -n engine)--> engine.c --(clang)--> engine.o
```

`host.c` then runs a judge-faithful match: pipes for stdin/stdout,
ENDTURN/stdin-park/exit semantics, 10 s wall clock per turn, CPU-point metering
through the injected `wasmer_metering_*` globals, a virtual clock, and seeded
per-dragon xoshiro RNG (`sha256("{seed:016x}-{team}\0{dragon_id}")`).

Every stage is content-addressed under `~/.cache/kvmrun/` (respects
`XDG_CACHE_HOME`), so rebuilt bots only recompile what changed and repeated
match runs start instantly.

## Benchmarks

Measured on a 12th-gen i7-12700 (20 threads), `apex` vs `kami`, official maps
only. Times are the engine-reported match duration with warm build caches
(kvmrun's first build adds ~10–15 s). Replays verified **byte-identical**
across `native`, `kvm`, and — where run to completion — `--sandbox`.

| map | match length | `unswbc run --sandbox` | kvmrun `native` | kvmrun `kvm` |
|---|---|---|---|---|
| `arena.map` | 44 rounds | 16.8 s | **0.55 s** (~31×) | **0.3 s** (~56×) |
| `schooltime.map` | 179 rounds, 7,115 turns | ~20–30 min (projected) | **16.0 s** (~75–110×) | **16.2 s** (~74–110×) |
| `help.map` | 500 rounds, ~62k turns | not measured (hours) | **171.6 s** | **~172 s** |

Reproduce: `python3 bench.py MAP BOT_A BOT_B --seeds 11 --runs N --backends
native,kvm --compare` — always compare on the same explicit seed set and run
serially (concurrent jobs skew both timing and the per-run peak-RSS sample).

The schooltime sandbox run was killed at round 51/179 after ~6 minutes
(~5–8 s/round and growing with the dragon count); its own pace implies
~20–30 minutes to elimination.

Note that `kvm` can be *slower* than `native` on mid-size matches — that is
the point: one vCPU serialises all bot threads, mirroring the judge's
CPU-point contention model instead of spreading bots across host cores. On
`help.map` the two backends are within noise of each other; run-to-run
variance on a loaded host reaches ±10 %, so treat differences below that as
unresolved.

### Performance notes (this vs the original implementation)

- **rdtsc guest clock** — `clock_gettime` used to be an `HC_NOW` hypercall
  (VM exit) per call; it is now a calibrated TSC read resynced every ~4 s.
  VM exits on `help.map`: ~68k → ~5.5k.
- **Per-primitive wait queues** — guest mutex/cond/futex/join waiters went
  from a global blocked-list scan to intrusive O(1) queues, and
  `pthread_join` is real now (it used to be a no-op that returned without
  waiting and handed back no return value).
- **Event-driven poller** — host writes kick the turn poller only on real
  events (ENDTURN / PARK / exit / first park) instead of broadcasting on
  every output chunk; also fixes a check-then-wait lost-wakeup race.
- **Allocator repair** — stale `heap_tail` after block split/coalesce
  orphaned freed blocks: `help.map` kvm RSS was ~2.2 GB with the bug, now
  ~0.7 GB.
- **wasm2c segue** — on hosts with `fsgsbase` (any modern Intel/AMD) generated
  code is built with `WASM_RT_ALLOW_SEGUE=1`: linear-memory accesses go
  through `%gs` (base = the wasm memory) instead of an explicit base add on
  every load/store. In the KVM backend `gs` becomes per-context state —
  `gctx_switch` saves/restores it, and the VMM sets guest CR4.FSGSBASE only
  when CPUID leaf 7 advertises it. On a loaded box `schooltime.map` in-guest
  time measured 56.9 s → 47.8 s (indicative, not a clean benchmark).
- Wall time on `help.map` (seed 11): native ~172–187 s, kvm ~172–181 s
  across runs vs a ~175 s same-session baseline — parity within machine
  noise. `-O3` was measured *slower* than `-O2` on generated code and is
  not used.
- Security hardening and test coverage are documented in `SECURITY.md`.

## Requirements

- Linux, Python 3
- `clang` and `ld`
- [wabt](https://github.com/WebAssembly/wabt) (`wasm2c` with
  `--enable-exceptions`)
- [simde](https://github.com/simd-everywhere/simde) headers — wasm2c emits
  `<simde/wasm/simd128.h>` for SIMD-enabled modules. Needs a package that
  ships the `wasm/` module (e.g. Arch `simde`); Debian/Ubuntu's
  `libsimde-dev` is too old — install from the upstream source tree.
- the `unswbc` package (the judge toolchain, engine wasm, and metering pass):
  `uv tool install unswbc` — auto-detected from the `unswbc` console script's
  venv, an importable install, or `~/.local/share/uv/tools/unswbc`
- `/dev/kvm` access for the `kvm` backend only

### Environment overrides

| var | meaning |
|---|---|
| `UNSWBC_PKG` | site-packages dir containing the `unswbc` package |
| `WABT_BIN` | dir containing `wasm2c` (or `WABT` = prefix with `bin/`) |
| `XDG_CACHE_HOME` | cache root (default `~/.cache`) |
| `KVMRUN_OPT` | optimization level for generated objects (default `-O2`) |
| `KVMRUN_DEPTHCOUNT` | `0` disables wasm call-depth counting |
| `KVMRUN_PROF` | build guest objects with `-finstrument-functions` |
| `KVMRUN_ICOUNT` | `1` instruments every module with a `kvmrun_icount` global — per-turn and total raw wasm instruction counts are printed after the match and parsed by `bench.py --icount` |
| `KVMDBG=1` | VMM hcall histograms / single-step dumps |

### Instruction counts

`KVMRUN_ICOUNT=1` runs `icount.py` between metering and unatomic: it
appends one exported `i64` global and emits `icount += N` at every block
boundary, where N is the number of original module ops in that block.
Metering's own injected sequences (`_check`/`_charge`/`_charge_length`)
are recognized and excluded, so counts cover the module's real ops only —
the official weighted CPU-point accounting is untouched.

```
team A insns per turn: p50 5.4M  p99 19.9M  mean 5.9M  max 23.2M  (131 turns)
engine insns total: 103.56M
```

Counts are wasm opcodes actually executed (each `block`/`loop`/`end`/`br`
counts once; `unatomic` helper functions are not included). Per-backend
runs are deterministic; backends can differ by a few percent where a
module's executed path depends on host-interaction timing (e.g. how many
`poll_oneoff`/`read` iterations a wait takes). Replays stay byte-identical
regardless of instrumentation.

## Usage

```
python3 kvmrun.py MAP BOT_A BOT_B \
    [--backend native|kvm] [--replay FILE] [--seed N] [--debug N] [--no-replay] [-v]

python3 kvmrun.py --batch JOBSFILE [--jobs N] [--backend native|kvm] [--seed N]
```

- `BOT_x` — a `.wasm` file, or a bot source directory built via unswbc's
  judge clang.
- `--seed` — match RNG seed (default random). The same seed gives
  byte-identical replays across the native and kvm backends.
- `--batch` — one `MAP BOT_A BOT_B [REPLAY|-]` per line (`#` comments and
  blank lines skipped). Unique bot pairs build once; matches run
  concurrently; cache writes are atomic.

Verify parity against the official sandbox:

```
unswbc run MAP A B --sandbox -o official.replay
python3 kvmrun.py MAP A B --backend kvm --seed S --replay kvm.replay
cmp official.replay kvm.replay
```

## Layout

```
kvmrun.py    build/run driver and cache
unatomic.py  wasm threads/atomics lowering pass
host.c       match host (native binary or in-guest payload)
vmm.c        minimal KVM VM (single vCPU, MMIO doorbell hypercalls)
abi.h        guest <-> VMM contract (memory map, hcall numbers)
guest/       freestanding guest environment: entry.S, guest.ld,
             klibc.c (page tables, heap, demand-paged stacks),
             gthr.c (cooperative scheduler), include/ (tiny libc)
wasm-rt/     vendored wasm2c runtime (Apache-2.0, from wabt) with fixes:
             exception payloads grow dynamically and the call-depth
             counter is restored on exception unwind
```

## License

Apache-2.0. `wasm-rt/` is a vendored copy of the wabt wasm2c runtime,
Apache-2.0, Copyright WebAssembly Community Group participants.
