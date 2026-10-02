# kvmrun — agent notes

## Build & test

- Single match: `python3 kvmrun.py MAP BOT_A BOT_B --backend native|kvm --seed N --replay OUT`
- Needs `unswbc` 1.2.3 (uv tool) and wabt (`wasm2c`); override discovery with
  `UNSWBC_PKG`, `WABT_BIN`/`WABT`. `KVMRUN_OPT` changes generated-code opt
  level (default `-O2`; `-O3` measured slower — do not flip back blindly).
- Tests:
  - `python3 tests/test_unatomic.py` — wat→lower→validate→wasm2c→run
    differential for every atomic op shape (needs wabt).
  - `python3 tests/test_vmm_elf.py` — malformed guest ELF rejection (no KVM
    needed).
  - `python3 tests/test_vmm_hcall.py` — hostile guest hypercalls (needs
    `/dev/kvm`; skips otherwise).
  - `python3 tests/test_icount.py` — icount instrumentation: op preservation,
    metering-sequence exclusion, unatomic passthrough, and a wasm2c dynamic
    count check (needs wabt).
- Benchmark: `python3 bench.py MAP A B --seeds 11,22 --runs N --backends
  native,kvm --compare --json out.json`. `--compare` writes replays and
  asserts byte-identical output across backends. Always pass explicit seeds
  and compare on the same seed set (paired A/B) — random seeds swing results.
  Run benchmarks **serially** — concurrent jobs contaminate both match time
  and the per-run `RUSAGE_CHILDREN` max-RSS measurement (a cold in-run clang
  build inflates rss to ~2 GB).

## Architecture invariants (do not break)

- `kvm` backend: single BSP vCPU, cooperative in-guest contexts
  (`guest/gthr.c`); never add real parallel vCPUs for bots — the serial
  protocol is what reproduces the judge's CPU-point contention model.
- Demand-paged guest stacks (`stk_alloc`/`stk_free` in `klibc.c`) and TLS
  inside each stack block — thousands of live threads OOM with eager stacks.
- Physical-frame recycling (`phys_free`/`phys2m_free`,
  `arena_unmap_range` freeing empty PT pages) — without it large maps strand
  tens of GiB.
- Wait queues are intrusive (`gctx.wnext/wprev`); a runnable ctx must never
  have `deadline != 0` or sit on a wait queue — `wake_ctx` clears both.
- `pthread_join` recycles gctx through `gpool`; the `in_z` flag owns the
  zombie-list membership — do not `free()` a gctx directly.
- `guest_now()` is rdtsc-calibrated against `HC_NOW` and resyncs every ~4 s;
  deadlines cross to the host as host `CLOCK_MONOTONIC` ns.
- wasm2c "segue" (`WASM_RT_ALLOW_SEGUE`) is enabled when the host has
  `fsgsbase`: generated code accesses linear memory through `%gs` set to the
  memory base at every exported call. In the guest this makes `gs` part of a
  context's state — `gctx_switch` must save/restore `gctx.gs` (offset 128) and
  the VMM sets CR4.FSGSBASE only when CPUID leaf 7 advertises it. Do NOT enable
  `WASM_RT_SEGUE_FREE_SEGMENT`: verified to break call_indirect in this
  pipeline.
- VMM hypercall entry points must validate every guest-controlled pointer
  (`gptr`), length, and mailbox GPA before use — `tests/test_vmm_hcall.py`
  locks this in.
- Cache identity (`runner_key`, `engine_c`, `bot_c`) must cover every input
  that changes the artifact: tool versions, transform sources, flags, runtime
  sources/headers.
- `KVMRUN_ICOUNT=1` inserts `icount.py` between metering and unatomic:
  `icount += N` is emitted before every segment boundary — control ops AND
  every potentially-trapping op (`_SEGMENT_END`) — so an op counts iff
  control reaches it (trap-tail ops are not lost). Metering's injected
  `_check`/`_charge`/`_charge_length` sequences are byte-matched and kept but
  excluded from the count (dropping them silently disables CPU limits — see
  the `_body` `out += b[k:m]` line; never refactor it away).

## Verified numbers (i7-12700, apex vs kami, seed 11)

- `arena.map`: sandbox 16.8 s, native 0.45 s, kvm 0.3 s — replays identical.
- `schooltime.map`: native ~15 s, kvm ~16 s — replays identical.
- `help.map` (500 rounds, ~4.7k dragons): native ~172 s, kvm ~172–181 s;
  same-session baseline ~175 s — parity within ±10 % machine noise; hcall
  exits 68k → 5.5k; kvm RSS ~0.7 GB (a stale `heap_tail` once leaked freed
  blocks to ~2.2 GB — keep split/coalesce tail maintenance intact).
- This box runs unrelated kvmrun batches concurrently — treat any sub-10 %
  wall-time delta as unmeasured.
