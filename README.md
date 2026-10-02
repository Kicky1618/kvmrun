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

Measured on a 12th-gen i7-12700 (20 threads), `apex` vs `kami`, seed 11,
identical match outcomes verified across all three runs. Times are the
engine-reported match duration; bot wasm builds were already cached for both
tools (kvmrun's first build adds ~12 s).

| map | match length | `unswbc run --sandbox` | kvmrun `native` | kvmrun `kvm` |
|---|---|---|---|---|
| `arena.map` | 44 rounds | 16.8 s | **0.6 s** (~28×) | **0.3 s** (~56×) |
| `schooltime.map` | 179 rounds, 7,115 turns | ~20–30 min (projected) | **~22 s** (~60–80×) | **~24 s** (~50–75×) |

The schooltime sandbox run was killed at round 51/179 after ~6 minutes
(~5–8 s/round and growing with the dragon count); its own pace implies
~20–30 minutes to elimination.

Note that `kvm` can be *slower* than `native` on long matches — that is the
point: one vCPU serialises all bot threads, mirroring the judge's CPU-point
contention model instead of spreading bots across host cores.

## Requirements

- Linux, Python 3
- `clang` and `ld`
- [wabt](https://github.com/WebAssembly/wabt) (`wasm2c` with
  `--enable-exceptions`)
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
| `KVMDBG=1` | VMM hcall histograms / single-step dumps |

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
