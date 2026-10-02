// vmm_hv.c — Hypervisor.framework VM for kvmrun guests on macOS arm64.
//
// Mirrors vmm.c (KVM) semantics: same guest ABI from abi.h, same shared
// hypercall dispatch in vmm_common.h — but the guest is aarch64 and the
// host API is Apple's Hypervisor.framework instead of /dev/kvm.
//
// Differences from the KVM/WHPX drivers:
//   - guest ISA is aarch64: vmm presets TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1/
//     CPACR_EL1 and the boot page tables in arm64 descriptor format; the
//     guest owns VBAR_EL1/SP_EL1 (exception stack) from _start.
//   - guest RAM is a PROT_NONE reservation, committed + hv_vm_map()'d in
//     2MiB chunks on stage-2 abort exits (demand paging).
//   - the MMIO doorbell is a stage-2 data abort: ESR_EL2 ISS carries ISV
//     + SRT (source register), so the mailbox GPA is recovered directly
//     from the register file — no instruction decode needed.
//   - no MSR emulation (no MSRs on arm64); WFI parks the vcpu like hlt.
//
// Entitlement: hv_vm_create() requires com.apple.security.hypervisor —
// kvmrun.py ad-hoc signs the vmm binary after linking.
//
// usage: vmm_hv --elf guest.elf --map MAP [--name-a S] [--name-b S]
//               [--debug N] [--no-replay] [-v]
#include <mach/mach_time.h>
#include <sys/mman.h>
#include <Hypervisor/hv.h>

#include "vmm_common.h"

// ------------------------------------------------------------------ memory

static uint8_t *gmem;
#define CHUNK (2ull << 20)
#define NCHUNK (RAM_BYTES / CHUNK)
static uint8_t mapped[NCHUNK / 8];
static pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;

static int commit_range(uint64_t gpa, uint64_t len) {
    uint64_t c0 = gpa / CHUNK, c1 = (gpa + len - 1) / CHUNK;
    if (gpa + len < gpa || c1 >= NCHUNK) return -1;
    pthread_mutex_lock(&map_lock);
    for (uint64_t c = c0; c <= c1; c++) {
        if (mapped[c / 8] & (1u << (c % 8))) continue;
        void *va = mmap(gmem + c * CHUNK, CHUNK, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (va == MAP_FAILED) {
            pthread_mutex_unlock(&map_lock);
            return -1;
        }
        if (hv_vm_map(va, c * CHUNK, CHUNK,
                      HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)) {
            pthread_mutex_unlock(&map_lock);
            return -1;
        }
        mapped[c / 8] |= 1u << (c % 8);
    }
    pthread_mutex_unlock(&map_lock);
    return 0;
}

static int range_mapped(uint64_t gpa, uint64_t len) {
    if (!len || gpa + len < gpa || gpa + len > RAM_BYTES) return 0;
    uint64_t c0 = gpa / CHUNK, c1 = (gpa + len - 1) / CHUNK;
    pthread_mutex_lock(&map_lock);
    for (uint64_t c = c0; c <= c1; c++)
        if (!(mapped[c / 8] & (1u << (c % 8)))) {
            pthread_mutex_unlock(&map_lock);
            return 0;
        }
    pthread_mutex_unlock(&map_lock);
    return 1;
}

static int vmm_commit(uint64_t gpa, uint64_t len) {
    if (gpa >= RAM_BYTES) return -1;
    return commit_range(gpa, len);
}

static void *hva(uint64_t gpa) {
    if (gpa >= RAM_BYTES) return NULL;
    if (commit_range(gpa, 1)) return NULL;
    return gmem + gpa;
}

static uint8_t *gptr(uint64_t gpa, uint64_t n) {
    if (gpa + n > RAM_BYTES || gpa + n < gpa || !range_mapped(gpa, n)) {
        fprintf(stderr, "vmm: bad guest pointer %llx+%llu\n",
                (unsigned long long)gpa, (unsigned long long)n);
        return NULL;
    }
    return gmem + gpa;
}

// ----------------------------------------------------------- boot tables

// arm64 4KiB-granule stage-1 tables in guest RAM (same layout addresses as
// the x86 tables so klibc's arena walker works unchanged):
//   L0 @0x1000: [0] -> L1 @0x2000
//   L1 @0x2000: 1GiB block descriptors covering [0, RAM_BYTES + 1GiB)
//               (the extra 1GiB leaf makes the MMIO doorbell GPA visible
//                to stage-1; stage-2 stays unmapped so stores trap here)
#define ADesc_TBL   0x3ull                        // next-level table
#define ADesc_BLOCK (0x1ull | (1ull << 10) | (3ull << 8))  // AF|SH_INNER

static void setup_tables_arm64(void) {
    memset(hva(0x1000), 0, 0x2000);
    uint64_t *l0 = hva(0x1000), *l1 = hva(0x2000);
    l0[0] = 0x2000 | ADesc_TBL;
    for (uint64_t i = 0; i <= (RAM_BYTES >> 30); i++)
        l1[i] = (i << 30) | ADesc_BLOCK;
}

// --------------------------------------------------------------- vcpu run

static void dump_vcpu(Vcpu *v) {
    uint64_t r[32];
    uint64_t pc = 0, sp0 = 0, elr = 0, spsr = 0, esr = 0, far = 0;
    hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_ELR_EL1, &elr);
    hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_SPSR_EL1, &spsr);
    hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_ESR_EL1, &esr);
    hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_FAR_EL1, &far);
    hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_SP_EL0, &sp0);
    hv_vcpu_get_reg(v->hv, HV_REG_PC, &pc);
    for (int i = 0; i < 31; i++)
        hv_vcpu_get_reg(v->hv, (hv_reg_t)(HV_REG_X0 + i), &r[i]);
    fprintf(stderr,
            "vmm: vcpu %d pc=%llx sp0=%llx elr=%llx spsr=%llx esr=%llx"
            " far=%llx\n",
            v->id, (unsigned long long)pc, (unsigned long long)sp0,
            (unsigned long long)elr, (unsigned long long)spsr,
            (unsigned long long)esr, (unsigned long long)far);
    for (int i = 0; i < 30; i += 6) {
        fprintf(stderr, "     x%-2d=%llx x%-2d=%llx x%-2d=%llx x%-2d=%llx"
                " x%-2d=%llx x%-2d=%llx\n",
                i, (unsigned long long)r[i], i + 1,
                (unsigned long long)r[i + 1], i + 2,
                (unsigned long long)r[i + 2], i + 3,
                (unsigned long long)r[i + 3], i + 4,
                (unsigned long long)r[i + 4], i + 5,
                (unsigned long long)r[i + 5]);
    }
    struct hcall *mm = (struct hcall *)gptr(v->mbx, sizeof *mm);
    if (mm)
        fprintf(stderr, "     mbx nr=%u a=%llx b=%llx c=%llx ret=%llx\n",
                mm->nr, (unsigned long long)mm->a,
                (unsigned long long)mm->b, (unsigned long long)mm->c,
                (unsigned long long)mm->ret);
    uint64_t *l0 = hva(0x1000), *l1 = hva(0x2000);
    fprintf(stderr, "     L0[0]=%llx L1[%d]=%llx\n",
            (unsigned long long)l0[0], (int)(elr >> 30),
            (unsigned long long)l1[elr >> 30]);
}

// EL1t boot state identical for every vcpu: SP_EL0 stack, pc=entry,
// x0=arg, x1=mbx GPA, EL1t w/ DAIF masked, MMU on via EL1 sysregs.
static void init_vcpu_regs(Vcpu *v, uint64_t entry, uint64_t stack_top,
                           uint64_t arg, uint64_t mbx) {
    uint64_t sctlr;
    if (hv_vcpu_get_sys_reg(v->hv, HV_SYS_REG_SCTLR_EL1, &sctlr))
        die("hv get SCTLR");
    sctlr |= 1 | (1 << 2) | (1 << 12);       // M | C | I
    sctlr |= (1 << 4) | (1 << 3);            // SA0 | SA (sp alignment checks)

    // T0SZ=16 (48-bit VA), TG0=4KiB, inner-shareable WBWA, IPS=48-bit
    const uint64_t TCR = (16ull << 0) | (3ull << 8) | (1ull << 10)
                       | (1ull << 12) | (5ull << 32);
    const hv_sys_reg_t sr[] = {
        HV_SYS_REG_TTBR0_EL1, HV_SYS_REG_TTBR1_EL1, HV_SYS_REG_TCR_EL1,
        HV_SYS_REG_MAIR_EL1,  HV_SYS_REG_SCTLR_EL1, HV_SYS_REG_CPACR_EL1,
        HV_SYS_REG_SP_EL0,
    };
    const uint64_t sv[] = {
        0x1000,        // TTBR0: guest L0 table
        0,             // TTBR1 unused
        TCR,
        0xff,          // MAIR attr0 = normal WB WA RA
        sctlr,
        0x300000,      // CPACR: FPEN=11 — no FP/SIMD traps (guest uses SIMD)
        stack_top,     // SP_EL0; SP_EL1/VBAR/TPIDRs are set by _start
    };
    for (size_t i = 0; i < sizeof sr / sizeof sr[0]; i++)
        if (hv_vcpu_set_sys_reg(v->hv, sr[i], sv[i])) {
            fprintf(stderr, "vmm: hv_vcpu_set_sys_reg %u failed\n",
                    (unsigned)sr[i]);
            exit(2);
        }
    hv_vcpu_set_reg(v->hv, HV_REG_PC, entry);
    hv_vcpu_set_reg(v->hv, HV_REG_CPSR, 0x3c4);  // EL1t, DAIF masked
    hv_vcpu_set_reg(v->hv, HV_REG_X0, arg);
    hv_vcpu_set_reg(v->hv, HV_REG_X1, mbx);
    hv_vcpu_set_vtimer_mask(v->hv, true);        // no vtimer exits
}

// ISS fields of an ESR_EL2 stage-2 data abort
#define EC(syn)    (((syn) >> 26) & 0x3f)
#define ISS_ISV(syn) (((syn) >> 24) & 1)
#define ISS_SRT(syn) (((syn) >> 16) & 0x1f)
#define ISS_WNR(syn) (((syn) >> 6) & 1)

static void *vcpu_loop(void *arg) {
    Vcpu *v = arg;

    // hv_vcpu_run() must be called on the thread that owns the vcpu —
    // create + configure here rather than in spawn_vcpu.
    if (hv_vcpu_create(&v->hv, &v->ex, NULL)) {
        fprintf(stderr, "vmm: hv_vcpu_create failed vcpu=%d\n", v->id);
        exit(2);
    }
    init_vcpu_regs(v, v->entry, v->stack_top, v->arg, v->mbx);
    __atomic_store_n(&v->ready, 1, __ATOMIC_RELEASE);

    uint64_t *run_ns = &v->run_ns, *disp_ns = &v->disp_ns;
    while (!vm_dead) {
        if (v->state == 2) break;
        uint64_t t0 = now_ns();
        hv_return_t r = hv_vcpu_run(v->hv);
        uint64_t t1 = now_ns();
        *run_ns += t1 - t0;
        v->nruns++;
        if (v->ex->reason < 64) v->nexits[v->ex->reason]++;
        if (r != HV_SUCCESS) {
            fprintf(stderr, "vmm: hv_vcpu_run vp=%d rc=%d\n", v->id, r);
            dump_vcpu(v);
            exit(2);
        }
        switch (v->ex->reason) {
        case HV_EXIT_REASON_EXCEPTION: {
            uint64_t syn = v->ex->exception.syndrome;
            uint64_t ipa = v->ex->exception.physical_address;
            unsigned ec = EC(syn);
            if (ec == 0x24 || ec == 0x20) {     // data/insn abort @ EL1
                if (ipa == DOORBELL_GPA && ISS_WNR(syn) && ISS_ISV(syn)) {
                    // doorbell store: source reg index is in SRT
                    uint64_t mbx = 0;
                    unsigned srt = ISS_SRT(syn);
                    if (srt < 31) {
                        hv_vcpu_get_reg(v->hv, (hv_reg_t)(HV_REG_X0 + srt), &mbx);
                    } else {
                        mbx = 0;                // XZR: malformed store
                    }
                    // consume the faulting instruction: on an exception
                    // exit the vcpu PC still points at it (ELR_EL1 is
                    // unrelated — the abort went to EL2, not guest EL1)
                    uint64_t pc;
                    hv_vcpu_get_reg(v->hv, HV_REG_PC, &pc);
                    hv_vcpu_set_reg(v->hv, HV_REG_PC, pc + 4);
                    dispatch(v, mbx);
                    *disp_ns += now_ns() - t1;
                    if (v->state == 2) goto out;   // EXIT_THREAD inline
                    continue;
                }
                if (ipa < RAM_BYTES) {          // demand-map guest RAM
                    if (commit_range(ipa & ~(CHUNK - 1), CHUNK)) {
                        fprintf(stderr, "vmm: commit failed ipa=%llx\n",
                                (unsigned long long)ipa);
                        dump_vcpu(v);
                        exit(2);
                    }
                    continue;                   // re-execute the access
                }
                fprintf(stderr, "vmm: bad stage-2 abort ipa=%llx syn=%llx\n",
                        (unsigned long long)ipa, (unsigned long long)syn);
                dump_vcpu(v);
                exit(2);
            }
            if (ec == 0x01) {                   // WFI/WFE trap = idle hlt
                pthread_mutex_lock(&v->mu);
                v->state = 1;
                v->park_addr = 0;
                pthread_cond_wait(&v->cv, &v->mu);
                pthread_mutex_unlock(&v->mu);
                continue;
            }
            if (ec == 0x18) {                   // MSR/MRS trap
                // ESR ISS: dir[0] CRm[4:1] Rt[9:5] CRn[13:10]
                //          Op1[16:14] Op2[19:17] Op0[21:20]
                unsigned dir = syn & 1,        crm = (syn >> 1) & 0xf;
                unsigned rt  = (syn >> 5) & 0x1f, crn = (syn >> 10) & 0xf;
                unsigned op1 = (syn >> 14) & 7, op2 = (syn >> 17) & 7;
                unsigned op0 = (syn >> 20) & 3;
                if (dir && op0 == 3 && op1 == 3 && crn == 14 && crm == 0) {
                    // timer regs: Op2=0 cntfrq_el0, Op2=2 cntvct_el0
                    uint64_t val;
                    if (op2 == 0) {
                        mach_timebase_info_data_t tb;
                        mach_timebase_info(&tb);
                        val = tb.denom ? (uint64_t)(1e9 * tb.denom / tb.numer)
                                       : 24000000;
                    } else if (op2 == 2) {
                        val = mach_absolute_time();
                    } else {
                        goto bad_msr;
                    }
                    if (rt < 31)
                        hv_vcpu_set_reg(v->hv, (hv_reg_t)(HV_REG_X0 + rt),
                                        val);
                    uint64_t pc;
                    hv_vcpu_get_reg(v->hv, HV_REG_PC, &pc);
                    hv_vcpu_set_reg(v->hv, HV_REG_PC, pc + 4);
                    continue;
                }
            bad_msr:
                fprintf(stderr, "vmm: unhandled sysreg trap syn=%llx\n",
                        (unsigned long long)syn);
                dump_vcpu(v);
                exit(2);
            }
            fprintf(stderr, "vmm: unhandled exception ec=%x syn=%llx\n",
                    ec, (unsigned long long)syn);
            dump_vcpu(v);
            exit(2);
        }
        case HV_EXIT_REASON_VTIMER_ACTIVATED:
            continue;                            // masked; keep going
        case HV_EXIT_REASON_CANCELED:
            continue;
        case HV_EXIT_REASON_UNKNOWN:
        default:
            fprintf(stderr, "vmm: vcpu %d exit reason %d\n",
                    v->id, v->ex->reason);
            dump_vcpu(v);
            exit(2);
        }
    }
out:
    hv_vcpu_destroy(v->hv);          // each thread life gets a fresh vcpu
    v->hv = 0; v->ex = NULL;
    pthread_mutex_lock(&vm_mu);
    free_slots[nfree++] = v->id;
    if (v->stack_top && nstacks < MAX_VCPU)
        stack_tops[nstacks++] = v->stack_top;
    pthread_mutex_unlock(&vm_mu);
    return NULL;
}

static int spawn_vcpu(uint64_t entry, uint64_t stack_top, uint64_t arg) {
    uint64_t __st0 = now_ns();
    pthread_mutex_lock(&vm_mu);
    if (!stack_top) {
        if (!nstacks) { pthread_mutex_unlock(&vm_mu); return -2; }
        stack_top = stack_tops[--nstacks];
    }
    int id = nfree ? free_slots[--nfree] : nvcpu++;
    if (id >= MAX_VCPU) { pthread_mutex_unlock(&vm_mu); return -1; }
    Vcpu *v = vcpus[id];
    if (!v) {
        v = calloc(1, sizeof *v);
        v->id = id;
        pthread_mutex_init(&v->mu, NULL);
        // futex deadlines are handled via relative waits on Darwin —
        // no clock attribute exists here
        pthread_cond_init(&v->cv, NULL);
        vcpus[id] = v;
    }
    v->state = 0; v->park_addr = 0; v->deadline = 0; v->park_ret = 0;
    v->in_park_list = 0; v->ready = 0;
    v->mbx = MBX_ARENA_GPA + (uint64_t)id * MBX_SIZE;
    v->stack_top = stack_top;
    v->entry = entry; v->arg = arg;
    pthread_mutex_unlock(&vm_mu);
    pthread_create(&v->th, NULL, vcpu_loop, v);
    pthread_detach(v->th);
    while (!__atomic_load_n(&v->ready, __ATOMIC_ACQUIRE))
        sched_yield();
    __atomic_fetch_add(&spawn_ns, now_ns() - __st0, __ATOMIC_RELAXED);
    return id;
}

// ------------------------------------------------------------------ main

int main(int argc, char **argv) {
    const char *elf = NULL;
    if (parse_args(argc, argv, &elf)) return 2;
    if (getenv("KVMDBG")) g_dbg = 1;

    if (hv_vm_create(NULL) != HV_SUCCESS) {
        fprintf(stderr,
                "vmm: hv_vm_create failed — the binary needs the "
                "com.apple.security.hypervisor entitlement (kvmrun.py "
                "signs it; if you built by hand: codesign -s - "
                "--entitlements ent.plist vmm)\n");
        return 2;
    }

    void *raw = mmap(NULL, RAM_BYTES + CHUNK, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (raw == MAP_FAILED) die("mmap guest ram");
    gmem = (uint8_t *)(((uintptr_t)raw + CHUNK - 1) & ~(CHUNK - 1));

    setup_tables_arm64();
    load_elf(gmem, elf);
    if (load_map_and_bootinfo(elf)) return 2;

    int id = spawn_vcpu(g_entry, BSP_STACK_TOP, 0);
    if (id < 0) { fprintf(stderr, "vmm: failed to spawn BSP\n"); return 2; }
    for (;;) pause();
    return 0;
}
