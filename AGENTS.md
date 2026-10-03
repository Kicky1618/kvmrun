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
  The VM driver is per-platform: `vmm.c` (Linux `/dev/kvm`),
  `vmm_whpx.c` (Windows WHPX — WinHvPlatform.dll loaded dynamically),
  and `vmm_hv.c` (macOS arm64 Hypervisor.framework).
  Hypercall dispatch, futex parking, ELF load, replay writer and stats
  are single-sourced in `vmm_common.h` — do NOT duplicate that logic into
  a driver; provide only the `hva`/`gptr`/`spawn_vcpu`/`vmm_commit`
  hooks it declares (`vmm_commit` host-commits a GPA range before
  VMM-side writes — ELF/map loads use it; KVM's is a no-op).
  WHPX memory exits carry no write data, so `doorbell_data` decodes the
  guest's `mov [DOORBELL_GPA], reg` store to recover the mailbox GPA;
  FS/GS/KernelGS-base MSRs are emulated via the segment-register file.
  Guest RAM is VirtualAlloc-reserved then committed+WHPX-mapped in 2MiB
  chunks on unmapped-GPA exits (explicit demand paging); `gptr` refuses
  uncommitted ranges so a hostile guest cannot make the VMM touch
  uncommitted VA. WHPX runtime is not yet hardware-verified — the
  exception-bitmap is left at 0 assuming unmapped vectors are delivered
  to the guest IDT (needed for the demand-paged stack #PF scheme).
  On macOS arm64 the guest is aarch64 (`guest/entry_arm64.S`,
  `guest/arch.h`, `guest/guest_arm64.ld`): HV only runs arm64 guests.
  `gctx_switch` must save d8-d15 (callee-saved on aarch64, unlike x86
  XMMs) — frame is 160B, x30 slot at +88 is the resume target.
  The doorbell is a stage-2 abort — ESR.ISS.ISV+SRT names the stored
  register so no instruction decode is needed (falls back fatal if ISV
  is clear). Sysregs (TTBR0/TCR/MAIR/SCTLR+CPACR/SP_EL0) are preset per
  vcpu; VBAR_EL1/SP_EL1/TPIDR_EL0+1 are guest-owned (`_start`/`tls_init`
  set them). Guest RAM is a PROT_NONE reservation committed via
  mmap-fixed + hv_vm_map on stage-2 aborts. hv_vcpu_create/run happen on
  the vcpu thread itself (HV requires it). The binary needs the
  com.apple.security.hypervisor entitlement — kvmrun.py ad-hoc signs.
  NOT yet runtime-verified on hardware — compile-verified only.
  Darwin has no pthread_condattr_setclock: vmm_common's
  cond_wait_deadline uses pthread_cond_timedwait_relative_np there.
- Demand-paged guest stacks (`stk_alloc`/`stk_free` in `klibc.c`) and TLS
  inside each stack block — thousands of live threads OOM with eager stacks.
- Physical-frame recycling (`phys_free`/`phys2m_free`,
  `arena_unmap_range` freeing empty PT pages) — without it large maps strand
  tens of GiB.
- Wait queues are intrusive (`gctx.wnext/wprev`); a runnable ctx must never
  have `deadline != 0` or sit on a wait queue — `wake_ctx` clears both.
- `pthread_join` recycles gctx through `gpool`; the `in_z` flag owns the
  zombie-list membership — do not `free()` a gctx directly.
- `guest_now()` is counter-calibrated against `HC_NOW` (rdtsc on x86,
  `cntvct_el0` on aarch64) and resyncs every ~4 s; deadlines cross to the
  host as host `CLOCK_MONOTONIC` ns.
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
  the `_body` `out += b[k:m]` line; never refactor it away). The host reads
  the counter through weak *definitions* in `host.c` (NULL stubs overridden
  by the real exports) — weak undefined references do not link under zig's
  Mach-O linker, so keep the `KVMRUN_WEAK` definition pattern.
- `native` backend targets Linux/macOS/Windows: `win32/include` provides
  `<pthread.h>` (CRITICAL_SECTION/CONDITION_VARIABLE/CreateThread shims —
  reserve-only stacks — plus a macro-renamed `clock_gettime` over
  QPC/FileTime so nothing pulls in libwinpthread-1.dll) and `<unistd.h>`
  (`getcwd`); `host.c` uses `rand_s` for seed entropy on `_WIN32` and
  `rd_tsc` is arch-gated (rdtsc / `cntvct_el0` / `real_ns`). Runtime-verified
  on macOS arm64 (byte-identical arena replay vs official sandbox) and
  Windows Server 2022 (llvm-mingw); zig cross-compile also links
  x86_64-windows `runner.exe` and an aarch64-macos Mach-O exe.
- Same-bot builds (`wa == wb` bytes) alias `w2c_botb_*` to `w2c_bota_*`
  via the `SAME_BOT_SHIM` header macros — every `w2c_botb_*` reference in
  `host.c`, including function *definitions*, must stay `#ifndef`-guarded
  so macro expansion cannot produce a duplicate definition.
- `wasm2c` flags are probed (`wasm2c_flags`/`_w2c_help`): `--enable-exceptions`
  was removed in newer wabt (exceptions always on) — never pass it blindly.
  `simde_flags()` probes SIMDE_INC/homebrew/macports prefixes for
  `simde/wasm/simd128.h`; unswbc requires Python ≥ 3.11 or `tomli`.
- Optional passes between metering and unatomic: `wasm-opt -O3` when a
  binaryen ≥ 133 `wasm-opt` is found (`WASM_OPT` overrides the path,
  `KVMRUN_NO_WASMOPT=1` disables; < 133 misparse the new-EH encoding and
  abort, parse failures fall back to the unoptimized module) — charge
  constants are already baked, so replays stay byte-identical.
- `KVMRUN_SPLIT` (default `min(8, ncpu)`, `1` disables) feeds
  `--num-outputs` to wasm2c: the generated C lands in per-shard TUs
  (`{mod}_{i}.c` + `{mod}-impl.h`) that `compile_obj` builds in parallel
  (~30% faster cold builds, replay-identical). Shard functions are extern,
  so cross-TU inlining is lost; `KVMRUN_OBJCFLAGS=-flto=thin` +
  `KVMRUN_CFLAGS="-flto=thin -fuse-ld=lld"` recovers it at link time.

## Verified numbers (i7-12700, apex vs kami, seed 11)

- `arena.map`: sandbox 16.8 s, native 0.45 s, kvm 0.3 s — replays identical.
- `schooltime.map`: native ~15 s, kvm ~16 s — replays identical.
- `help.map` (500 rounds, ~4.7k dragons): native ~172 s, kvm ~172–181 s;
  same-session baseline ~175 s — parity within ±10 % machine noise; hcall
  exits 68k → 5.5k; kvm RSS ~0.7 GB (a stale `heap_tail` once leaked freed
  blocks to ~2.2 GB — keep split/coalesce tail maintenance intact).
- This box runs unrelated kvmrun batches concurrently — treat any sub-10 %
  wall-time delta as unmeasured.
