# Security audit — kvmrun

Scope: `vmm.c` (KVM VM), `host.c` (match host, compiled both native and
in-guest), `guest/` (freestanding runtime), `unatomic.py` (wasm transform),
`kvmrun.py` (build pipeline/cache).

## Threat model

kvmrun runs *bot code that passed through the official unswbc wasm
toolchain*. The principal trust boundaries:

1. **Guest → host (kvm backend).** The in-guest match payload owns 32 GiB of
   guest RAM but reaches the host only through the mailbox/MMIO-doorbell
   hypercall ABI. Every field of `struct hcall` is attacker-controlled if the
   payload is compromised (e.g. a generated-code bug or corrupted heap).
   The VMM must not let a bad hypercall read/write outside guest RAM, exhaust
   host resources, or crash the VMM.
2. **Bot → bot / bot → engine.** Both bots share one address space (native
   backend: one process; kvm backend: one guest). kvmrun does **not** isolate
   the two bots from each other — a memory-corruption bug in generated bot
   code could read the peer's wasm memory or the engine state. This matches
   the official sandbox's *functional* semantics (bots cannot observe each
   other through the protocol) but is not an isolation guarantee.
3. **Malformed inputs.** `vmm` loads a guest ELF and a map file;
   `unatomic.py` rewrites wasm; `host.c` parses bot output frames and iovs.
4. **Build cache.** Stale or poisoned artifacts under `~/.cache/kvmrun/`
   change what runs.

## Vulnerabilities found and fixed

### `vmm.c`

- **`load_elf`: unchecked ELF fields → host heap OOB write.** `phoff`,
  `phentsize`, `phnum`, segment `offset/filesz/vaddr/memsz`, and `e_entry`
  were trusted blindly; a malformed guest ELF could make the loader copy
  arbitrary file bytes to arbitrary host addresses. Now fully bounds-checked:
  ELF ident/class/data/version, phdr entry size ≥ 56, phdr table inside the
  file, `filesz ≤ memsz`, segment file range inside the ELF, segment virtual
  range inside guest RAM, entry point inside guest RAM.
  (`tests/test_vmm_elf.py` — 11 malformed cases all rejected cleanly.)
- **`HC_REPLAY`: unbounded write.** The guest could request an arbitrary-size
  replay write (disk-fill DoS). Capped at 256 MiB (`REPLAY_MAX`); oversized
  requests return `-1` without touching the disk.
- **MMIO doorbell: unvalidated length/GPA.** A doorbell write shorter than
  8 bytes or naming a GPA outside the BSP mailbox page / aligned 4 KiB
  mailbox-arena slots is now refused instead of dereferenced.
- **`HC_PROF`: bad GPA stored, dereferenced at `HC_EXIT` → VMM NULL deref /
  wild read.** The histogram address is now validated at registration time
  (in-RAM, 8-aligned, ≤ 8 MiB) and re-checked at exit.
- **`HC_PRINT`: unbounded length.** `gptr(0, ~32 GiB)` was valid; a corrupt
  guest could stream the entire guest RAM to stdout. Capped at 16 MiB per
  call — real prints are single diagnostics lines.
- **`futex_wait`: `pthread_cond_timedwait` error loop.** `EINVAL` (e.g. a
  bogus deadline from a guest) retried forever; any non-zero return now ends
  the wait.
- **`spawn_vcpu` stack-slot accounting.** `nstacks`/`stack_tops` overflow
  guards were signed-compare warnings; kept reviewed bounds (`id < MAX_VCPU`,
  `nstacks < MAX_VCPU`).

### `host.c`

- **`fd_writev`/`fd_read`: unbounded iov count.** A guest-provided `n` now
  capped at `MAX_IOV = 4096`; previously each call could loop over
  uncontrolled memory — non-metered host CPU + pointer chasing.
- **`stderr` capture buffer unbounded → OOM.** Capped at 1 MiB
  (`STDERR_CAP`); output beyond the cap is dropped.
- **Lost-wakeup race in the turn poller.** `bot_ask` waited on `out.cv`
  while `done`/`park_at`/`exited`/`parks` were set under different mutexes:
  a signal landing between the poller's predicate check and `timedwait`
  could stall the match until the 10 s wall deadline. The poller is now
  sequence-gated: every poller-visible event funnels through `bot_kick()`
  which bumps `Bot::out_seq` and broadcasts under `out.mu`; the poller
  compares the seq under the same mutex before sleeping.
- **Broadcast storms.** Writers previously broadcast `out.cv` on *every*
  output chunk; now only real events (ENDTURN line, valid PARK marker, bot
  exit, first pipe park) kick the poller — fewer host condvar wakes on
  output-heavy turns.

### `kvmrun.py` (build cache)

- **Cache keys missed toolchain/transform inputs.** Keys now include the
  `wasm2c` and `clang` version strings, the `unatomic.py` source hash, the
  unswbc metering source hash, all compile flags, `abi.h`, and every guest
  runtime source/header — a tool upgrade or transform fix can no longer
  silently reuse a stale runner/guest image.

### `unatomic.py` (wasm threads/atomics lowering)

- **Silent miscompile of unknown prefixed opcodes.** GC-prefixed (`0xFB`) and
  unrecognised threads-prefixed opcodes, and unsupported atomic RMW
  sub-operations, now raise instead of desynchronising the instruction
  stream.
- **Sub-word atomic loads sign-extended.** `atomic.rmw8.*`/loads used
  `i32.load8_s`; unsigned semantics require zero-extension. Fixed for
  `LOAD_PLAIN` and all RMW lane loads (`tests/test_unatomic.py` covers the
  difference, e.g. `xchg64_8`).
- **Helper load/store over-aligned.** Helpers emitted `align=2` for every
  lane — invalid wasm for byte/halfword ops; alignment now follows the lane
  width (`wasm-validate` enforced in the test).
- **`wait64` compared only 32 bits.** The wait helper now loads `i64` for
  64-bit waits, so high-word mismatches block correctly.

### `guest/gthr.c` (cooperative scheduler)

- **Global scan → per-primitive wait queues.** Every block/wake used to scan
  a shared `blocked` list — quadratic once a map parks thousands of dragon
  threads. Mutexes, condvars, join and futex buckets now carry intrusive
  wait queues (`wq`), plus a separate `timed` list for deadlines.
- **`pthread_join` UAF/deadlock.** The old guest `pthread_join` was a no-op
  (joining read stale/garbage state; a first attempt at real join freed a
  gctx still linked on `zombies` → use-after-free into the frame allocator).
  Join now blocks on a per-thread join queue, transfers the return value,
  and recycles the context through `gpool` only after `free_zombies`
  ownership is resolved (`in_z` flag).
- **Timeout/wake double-booking.** A woken-or-timed-out ctx is now unlinked
  from *both* its wait queue and the timed list before being requeued, so a
  runnable context can never keep a live deadline.

## Regression coverage

- `tests/test_unatomic.py` — builds a wat module exercising atomic load /
  store / every RMW op / cmpxchg / wait32/64 / notify, lowers it through
  `unatomic.py`, validates with `wasm-validate`, compiles through `wasm2c` +
  the vendored runtime, executes, and checks returned *and* stored values.
  Also feeds a garbage module and expects rejection.
- `tests/test_vmm_elf.py` — 11 malformed guest ELFs (truncated header, bad
  magic, phdr table past EOF, phnum overflow, segment offsets past EOF,
  `filesz > memsz`, vaddr past RAM, memsz wrap, entry past RAM) — all
  rejected with `bad ELF`.
- `tests/test_vmm_hcall.py` — assembles a hostile guest that issues
  out-of-range PROF/REPLAY/PRINT/FUTEX_WAIT calls, an unknown hcall number,
  a non-mailbox doorbell GPA, an unaligned arena GPA, and a short MMIO
  write; verifies each is refused and the VMM survives (exit code = number
  of correct refusals; also asserts the expected warnings). Skipped without
  `/dev/kvm`.
- `bench.py --compare` — same-map/seed replays across `native` and `kvm`
  must be byte-identical; arena seeds {11,22} and schooltime/help seed 11
  verified.

## Residual risks (accepted, documented)

- **No bot↔bot memory isolation.** Both wasm memories live in one address
  space by design; wasm-level OOB is caught by guard pages → `WASM_RT_TRAP_OOB`,
  but in-bounds writes cannot corrupt the peer's *guest* state because each
  memory reservation is a separate VA region — they can, however, read/write
  each other through shared host structures only via the emulated syscall
  layer, which is protocol-constrained. A generated-code bug (not guest
  malice) could still corrupt adjacent heap.
- **`HC_PRINT`/`HC_REPLAY` caps are DoS valves, not hard isolation** — they
  stop accidents and simple abuse; a deliberately hostile guest could still
  waste ~16 MiB/print or 256 MiB/replay per call.
- **Guest page-table manipulation** is trusted in-payload: a corrupted guest
  could remap and scribble its own RAM (incl. the engine) but cannot reach
  the host — acceptable because the payload is built, not adversarial input.
- **Native backend** runs both bots in-process on host threads — no
  hardware isolation at all; it relies on wasm2c+guard pages for memory
  safety exactly like the guest payload.
- **Metered CPU points** bound bot compute per turn, but a bot turn can still
  burn real time equal to its remaining points before a deadline kill —
  matches stay finite (10 s wall/turn), not tight.
- The `kvm` backend requires `/dev/kvm`; access to that device is itself a
  host-capability decision outside this repository's scope.
