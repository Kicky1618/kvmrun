// vmm_whpx.c — WHPX (Windows Hypervisor Platform) VM for kvmrun guests.
//
// Mirrors vmm.c (KVM) semantics on Windows x86-64: the same guest ELF,
// same page tables, same mailbox/doorbell ABI from abi.h, same hypercall
// dispatch (vmm_common.h). Requires the "Windows Hypervisor Platform"
// optional feature (Windows 10 1809+) or the Hyper-V role.
//
// Key differences from the KVM driver:
//   - WinHvPlatform.dll is loaded dynamically so no import lib is needed.
//   - Guest RAM is VirtualAlloc-reserved, committed and WHPX-mapped in
//     2MiB chunks on unmapped-GPA exits (demand paging like KVM's
//     MAP_NORESERVE, just explicit).
//   - WHPX's MemoryAccess exit carries no write data, so the MMIO
//     doorbell dispatches on the vcpu's own mailbox GPA (v->mbx) — which
//     is what the guest writes to the doorbell anyway.
//   - FS/GS-base MSRs are emulated in the VMM; other rdmsr reads return
//     zero and wrmsr writes are dropped.
//
// usage: vmm_whpx --elf guest.elf --map MAP [--name-a S] [--name-b S]
//                 [--debug N] [--no-replay] [-v]
#include <windows.h>
#include <winhvplatform.h>
#include <direct.h>
#define mkdir(p, m) _mkdir(p)

#include "vmm_common.h"

// ------------------------------------------------------------- WHPX dynload

static struct {
    HRESULT (WINAPI *GetCapability)(WHV_CAPABILITY_CODE, VOID *, UINT32,
                                    UINT32 *);
    HRESULT (WINAPI *CreatePartition)(WHV_PARTITION_HANDLE *);
    HRESULT (WINAPI *SetPartitionProperty)(WHV_PARTITION_HANDLE,
        WHV_PARTITION_PROPERTY_CODE, const VOID *, UINT32);
    HRESULT (WINAPI *SetupPartition)(WHV_PARTITION_HANDLE);
    HRESULT (WINAPI *MapGpaRange)(WHV_PARTITION_HANDLE, VOID *,
        WHV_GUEST_PHYSICAL_ADDRESS, UINT64, WHV_MAP_GPA_RANGE_FLAGS);
    HRESULT (WINAPI *CreateVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32,
                                             UINT32);
    HRESULT (WINAPI *DeleteVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32);
    HRESULT (WINAPI *RunVirtualProcessor)(WHV_PARTITION_HANDLE, UINT32,
                                          VOID *, UINT32);
    HRESULT (WINAPI *GetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE,
        UINT32, const WHV_REGISTER_NAME *, UINT32, WHV_REGISTER_VALUE *);
    HRESULT (WINAPI *SetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE,
        UINT32, const WHV_REGISTER_NAME *, UINT32,
        const WHV_REGISTER_VALUE *);
} wh;

static void load_whpx(void) {
    HMODULE m = LoadLibraryExA("WinHvPlatform.dll", NULL,
                               LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!m) {
        fprintf(stderr,
                "vmm: WinHvPlatform.dll not found — enable the \"Windows "
                "Hypervisor Platform\" feature or the Hyper-V role\n");
        exit(2);
    }
#define GET(fn) \
    wh.fn = (void *)GetProcAddress(m, "WHv" #fn); \
    if (!wh.fn) { fprintf(stderr, "vmm: missing WHv" #fn "\n"); exit(2); }
    GET(GetCapability);
    GET(CreatePartition);
    GET(SetPartitionProperty);
    GET(SetupPartition);
    GET(MapGpaRange);
    GET(CreateVirtualProcessor);
    GET(DeleteVirtualProcessor);
    GET(RunVirtualProcessor);
    GET(GetVirtualProcessorRegisters);
    GET(SetVirtualProcessorRegisters);
#undef GET
}

// ------------------------------------------------------------------ memory

// Guest RAM is reserved (not committed) at startup; each 2MiB chunk is
// host-committed and WHPX-mapped on the first touch, tracked in `mapped`.
static uint8_t *gmem;
static WHV_PARTITION_HANDLE g_part;
#define CHUNK (2ull << 20)
#define NCHUNK (RAM_BYTES / CHUNK)
static uint8_t mapped[NCHUNK / 8];
static SRWLOCK map_lock = SRWLOCK_INIT;

static int commit_range(uint64_t gpa, uint64_t len) {
    uint64_t c0 = gpa / CHUNK, c1 = (gpa + len - 1) / CHUNK;
    if (gpa + len < gpa || c1 >= NCHUNK) return -1;
    AcquireSRWLockExclusive(&map_lock);
    for (uint64_t c = c0; c <= c1; c++) {
        if (mapped[c / 8] & (1u << (c % 8))) continue;
        void *va = VirtualAlloc(gmem + c * CHUNK, CHUNK,
                                MEM_COMMIT, PAGE_READWRITE);
        if (!va) { ReleaseSRWLockExclusive(&map_lock); return -1; }
        HRESULT hr = wh.MapGpaRange(g_part, va, c * CHUNK, CHUNK,
            WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
        if (FAILED(hr)) { ReleaseSRWLockExclusive(&map_lock); return -1; }
        mapped[c / 8] |= 1u << (c % 8);
    }
    ReleaseSRWLockExclusive(&map_lock);
    return 0;
}

static int range_mapped(uint64_t gpa, uint64_t len) {
    if (!len || gpa + len < gpa || gpa + len > RAM_BYTES) return 0;
    uint64_t c0 = gpa / CHUNK, c1 = (gpa + len - 1) / CHUNK;
    AcquireSRWLockShared(&map_lock);
    for (uint64_t c = c0; c <= c1; c++)
        if (!(mapped[c / 8] & (1u << (c % 8)))) {
            ReleaseSRWLockShared(&map_lock);
            return 0;
        }
    ReleaseSRWLockShared(&map_lock);
    return 1;
}

// VMM-side write path: commits on demand so setup/ELF/map writes land.
static int vmm_commit(uint64_t gpa, uint64_t len) {
    if (gpa >= RAM_BYTES) return -1;
    return commit_range(gpa, len);
}
static void *hva(uint64_t gpa) {
    if (gpa >= RAM_BYTES) return NULL;
    if (commit_range(gpa, 1)) return NULL;
    return gmem + gpa;
}

// Guest-controlled pointer: must be in bounds AND already committed —
// a hostile guest cannot make the VMM dereference uncommitted VA.
static uint8_t *gptr(uint64_t gpa, uint64_t n) {
    if (gpa + n > RAM_BYTES || gpa + n < gpa || !range_mapped(gpa, n)) {
        fprintf(stderr, "vmm: bad guest pointer %llx+%llu\n",
                (unsigned long long)gpa, (unsigned long long)n);
        return NULL;
    }
    return gmem + gpa;
}

// --------------------------------------------------------------- registers

static void set_regs(uint32_t vp, const WHV_REGISTER_NAME *names,
                     WHV_REGISTER_VALUE *vals, uint32_t n) {
    HRESULT hr = wh.SetVirtualProcessorRegisters(g_part, vp, names, n, vals);
    if (FAILED(hr)) {
        fprintf(stderr, "vmm: SetVirtualProcessorRegisters vp=%u hr=%lx\n",
                vp, (unsigned long)hr);
        exit(2);
    }
}

static void get_regs(uint32_t vp, const WHV_REGISTER_NAME *names,
                     WHV_REGISTER_VALUE *vals, uint32_t n) {
    HRESULT hr = wh.GetVirtualProcessorRegisters(g_part, vp, names, n, vals);
    if (FAILED(hr)) {
        fprintf(stderr, "vmm: GetVirtualProcessorRegisters vp=%u hr=%lx\n",
                vp, (unsigned long)hr);
        exit(2);
    }
}

static void init_vp_regs(uint32_t vp, uint64_t entry, uint64_t stack_top,
                         uint64_t arg, uint64_t mbx) {
    enum {
        N_GPR = 5,                        // rip, rsp, rdi, rsi, rflags
        N_CTL = 5,                        // cr0, cr3, cr4, efer, xcr0
        N_SEG = 6,                        // cs, ds, es, ss, fs, gs
        N_TAB = 4,                        // tr, ldtr, gdtr, idtr
        N_EVT = 2,                        // pending interruption, int state
        N_ALL = N_GPR + N_CTL + N_SEG + N_TAB + N_EVT,
    };
    WHV_REGISTER_NAME names[N_ALL];
    WHV_REGISTER_VALUE vals[N_ALL];
    memset(vals, 0, sizeof vals);
    int i = 0;

    names[i] = WHvX64RegisterRip;    vals[i].Reg64 = entry;         i++;
    names[i] = WHvX64RegisterRsp;    vals[i].Reg64 = stack_top;     i++;
    names[i] = WHvX64RegisterRdi;    vals[i].Reg64 = arg;           i++;
    names[i] = WHvX64RegisterRsi;    vals[i].Reg64 = mbx;           i++;
    names[i] = WHvX64RegisterRflags; vals[i].Reg64 = 2;             i++;

    names[i] = WHvX64RegisterCr0;    vals[i].Reg64 = 0x80050033;    i++;
    names[i] = WHvX64RegisterCr3;    vals[i].Reg64 = 0x1000;        i++;
    names[i] = WHvX64RegisterCr4;
    vals[i].Reg64 = 0x20 | 0x200 | 0x400 | 0x40000;                 i++;
    names[i] = WHvX64RegisterEfer;   vals[i].Reg64 = 0x500;         i++;
    names[i] = WHvX64RegisterXCr0;
    {   // mirror host XCR0 so the guest can use -march=native code
        uint32_t lo, hi;
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        vals[i].Reg64 = lo | ((uint64_t)hi << 32);
        i++;
    }

    WHV_X64_SEGMENT_REGISTER code = {0};
    code.Base = 0; code.Limit = 0xffffffff; code.Selector = 0x08;
    code.SegmentType = 11; code.NonSystemSegment = 1;
    code.Present = 1; code.Long = 1; code.Default = 0; code.Granularity = 1;
    WHV_X64_SEGMENT_REGISTER data = {0};
    data.Base = 0; data.Limit = 0xffffffff; data.Selector = 0x10;
    data.SegmentType = 3; data.NonSystemSegment = 1;
    data.Present = 1; data.Long = 0; data.Default = 1; data.Granularity = 1;

    names[i] = WHvX64RegisterCs; vals[i].Segment = code;            i++;
    names[i] = WHvX64RegisterDs; vals[i].Segment = data;            i++;
    names[i] = WHvX64RegisterEs; vals[i].Segment = data;            i++;
    names[i] = WHvX64RegisterSs; vals[i].Segment = data;            i++;
    names[i] = WHvX64RegisterFs; vals[i].Segment = data;            i++;
    names[i] = WHvX64RegisterGs; vals[i].Segment = data;            i++;

    names[i] = WHvX64RegisterTr;
    vals[i].Segment.Base = 0x8000; vals[i].Segment.Limit = 0x67;
    vals[i].Segment.Selector = 0x18;
    vals[i].Segment.SegmentType = 11;          // busy 64-bit TSS
    vals[i].Segment.Present = 1;                                    i++;
    names[i] = WHvX64RegisterLdtr; /* unusable: Present=0 */        i++;
    names[i] = WHvX64RegisterGdtr;
    vals[i].Table.Base = 0x3000; vals[i].Table.Limit = 0x2f;        i++;
    names[i] = WHvX64RegisterIdtr; /* guest loads its own */        i++;

    names[i] = WHvRegisterPendingInterruption;                   i++;
    names[i] = WHvRegisterInterruptState;                        i++;

    set_regs(vp, names, vals, i);
}

// total instruction length for a modrm-bearing insn; modrm at index `mi`,
// `imm` trailing immediate bytes. Returns <0 on truncation.
static int insn_len(const uint8_t *ib, int n, int mi, int imm) {
    if (mi >= n) return -1;
    uint8_t modrm = ib[mi++];
    int mod = modrm >> 6, rm = modrm & 7;
    if (mod == 3) return -1;
    int disp = 0;
    if (rm == 4) {                              // SIB follows
        if (mi >= n) return -1;
        uint8_t sib = ib[mi++];
        if (mod == 0 && (sib & 7) == 5) disp = 4;
    } else if (mod == 0 && rm == 5) disp = 4;
    if (mod == 1) disp = 1;
    else if (mod == 2) disp = 4;
    if (mi + disp + imm > n) return -1;
    return mi + disp + imm;
}

// WHPX memory exits carry no write data. The doorbell store in hcall()
// (guest/klibc.c) is `mov [DOORBELL_GPA], reg` — decode the instruction
// to recover the mailbox GPA that was written. Handles the three forms
// clang can emit: mov m64,r64 (0x89), mov m64,imm32 (0xC7/0), mov
// moffs64,rax (0xA3). Returns instruction length, <0 if unrecognized.
static int doorbell_data(uint32_t vp, const WHV_RUN_VP_EXIT_CONTEXT *ctx,
                         uint64_t *out) {
    const WHV_MEMORY_ACCESS_CONTEXT *ma = &ctx->MemoryAccess;
    const uint8_t *ib = ma->InstructionBytes;
    int n = ma->InstructionByteCount;
    if (n > 15) n = 15;                    // never read past the struct field
    uint8_t tmp[15];
    if (!n) {
        uint8_t *p = gptr(ctx->VpContext.Rip, 15);
        if (!p) return -1;
        memcpy(tmp, p, 15);
        ib = tmp; n = 15;
    }
    int i = 0;
    uint8_t rex = 0;
    while (i < n) {
        uint8_t b = ib[i];
        if (b >= 0x40 && b <= 0x4f) { rex = b; i++; continue; } // REX
        if (b == 0xf0 || b == 0xf2 || b == 0xf3 || b == 0x66 ||
            b == 0x67 || b == 0x26 || b == 0x2e || b == 0x36 ||
            b == 0x3e || b == 0x64 || b == 0x65) { i++; continue; }
        break;
    }
    if (i >= n) return -1;
    uint8_t op = ib[i++];
    if (op == 0x89) {                            // mov r64 -> r/m64
        if (i >= n) return -1;
        uint8_t modrm = ib[i];
        if ((modrm >> 6) == 3) return -1;        // reg-reg: not a store
        int reg = ((modrm >> 3) & 7) | ((rex & 4) ? 8 : 0);
        WHV_REGISTER_NAME gpr[16];
        WHV_REGISTER_VALUE gv[16];
        for (int k = 0; k < 16; k++)
            gpr[k] = WHvX64RegisterRax + k;      // enum order == encoding
        memset(gv, 0, sizeof gv);
        get_regs(vp, gpr, gv, 16);
        *out = gv[reg].Reg64;
        return insn_len(ib, n, i + 1, 0);
    }
    if (op == 0xc7) {                            // mov imm32 -> r/m64
        if (i >= n) return -1;
        if ((ib[i] >> 6) == 3 || ((ib[i] >> 3) & 7) != 0) return -1;
        int len = insn_len(ib, n, i + 1, 4);
        if (len <= 0) return -1;
        uint32_t imm;
        memcpy(&imm, ib + len - 4, 4);
        *out = (uint64_t)(int64_t)(int32_t)imm;  // sign-extended
        return len;
    }
    if (op == 0xa3) {                            // mov rax -> moffs64
        WHV_REGISTER_NAME r = WHvX64RegisterRax;
        WHV_REGISTER_VALUE v = {0};
        get_regs(vp, &r, &v, 1);
        *out = v.Reg64;
        return i + 8;
    }
    return -1;
}

// advance rip past the instruction that caused an exit
static void advance_rip(uint32_t vp, uint64_t rip, uint32_t len) {
    WHV_REGISTER_NAME nm = WHvX64RegisterRip;
    WHV_REGISTER_VALUE v;
    memset(&v, 0, sizeof v);
    v.Reg64 = rip + len;
    set_regs(vp, &nm, &v, 1);
}

// --------------------------------------------------------------- vcpu run

static void dump_vp_state(uint32_t vp) {
    static const WHV_REGISTER_NAME regs[] = {
        WHvX64RegisterRip, WHvX64RegisterRsp, WHvX64RegisterRax,
        WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx,
        WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterR8,
        WHvX64RegisterR11, WHvX64RegisterRflags, WHvX64RegisterCr2,
    };
    WHV_REGISTER_VALUE vals[sizeof regs / sizeof regs[0]];
    memset(vals, 0, sizeof vals);
    if (FAILED(wh.GetVirtualProcessorRegisters(g_part, vp, regs,
            sizeof regs / sizeof regs[0], vals)))
        return;
    fprintf(stderr,
            "vmm: vp %u rip=%llx rsp=%llx rax=%llx rbx=%llx rcx=%llx\n"
            "     rdx=%llx rsi=%llx rdi=%llx r8=%llx r11=%llx fl=%llx cr2=%llx\n",
            vp, (unsigned long long)vals[0].Reg64,
            (unsigned long long)vals[1].Reg64,
            (unsigned long long)vals[2].Reg64,
            (unsigned long long)vals[3].Reg64,
            (unsigned long long)vals[4].Reg64,
            (unsigned long long)vals[5].Reg64,
            (unsigned long long)vals[6].Reg64,
            (unsigned long long)vals[7].Reg64,
            (unsigned long long)vals[8].Reg64,
            (unsigned long long)vals[9].Reg64,
            (unsigned long long)vals[10].Reg64,
            (unsigned long long)vals[11].Reg64);
}

#define MSR_FS_BASE 0xC0000100u
#define MSR_GS_BASE 0xC0000101u
#define MSR_KGS_BASE 0xC0000102u

// rdmsr/wrmsr for FS/GS/KernelGS base; everything else reads 0 / drops.
static void msr_access(uint32_t vp, const WHV_X64_MSR_ACCESS_CONTEXT *msr,
                       uint64_t rip, uint32_t ilen) {
    WHV_REGISTER_NAME rn;
    switch (msr->MsrNumber) {
    case MSR_FS_BASE:  rn = WHvX64RegisterFs;            break;
    case MSR_GS_BASE:  rn = WHvX64RegisterGs;            break;
    case MSR_KGS_BASE: rn = WHvX64RegisterKernelGsBase;  break;
    default:           rn = (WHV_REGISTER_NAME)-1;       break;
    }
    if (msr->AccessInfo.IsWrite) {
        if (rn != (WHV_REGISTER_NAME)-1) {
            uint64_t val = msr->Rax | (msr->Rdx << 32);
            if (msr->MsrNumber == MSR_KGS_BASE) {
                WHV_REGISTER_VALUE v = {0};
                v.Reg64 = val;
                set_regs(vp, &rn, &v, 1);
            } else {
                WHV_REGISTER_VALUE v = {0};
                get_regs(vp, &rn, &v, 1);
                v.Segment.Base = val;
                set_regs(vp, &rn, &v, 1);
            }
        }                                    // unknown wrmsr: drop
    } else {
        uint64_t val = 0;
        if (rn != (WHV_REGISTER_NAME)-1) {
            WHV_REGISTER_VALUE v = {0};
            get_regs(vp, &rn, &v, 1);
            val = (msr->MsrNumber == MSR_KGS_BASE) ? v.Reg64
                                                   : v.Segment.Base;
        }
        WHV_REGISTER_NAME out[2] = { WHvX64RegisterRax, WHvX64RegisterRdx };
        WHV_REGISTER_VALUE ov[2];
        memset(ov, 0, sizeof ov);
        ov[0].Reg64 = (uint32_t)val;
        ov[1].Reg64 = val >> 32;
        set_regs(vp, out, ov, 2);
    }
    advance_rip(vp, rip, ilen ? ilen : 2);
}

static void *vcpu_loop(void *arg) {
    Vcpu *v = arg;
    WHV_RUN_VP_EXIT_CONTEXT ctx;
    uint64_t *run_ns = &v->run_ns, *disp_ns = &v->disp_ns;
    while (!vm_dead) {
        if (v->state == 2) break;
        uint64_t t0 = now_ns();
        HRESULT hr = wh.RunVirtualProcessor(g_part, v->id, &ctx, sizeof ctx);
        uint64_t t1 = now_ns();
        *run_ns += t1 - t0;
        v->nruns++;
        if (ctx.ExitReason < 64) v->nexits[ctx.ExitReason]++;
        if (FAILED(hr)) {
            fprintf(stderr,
                    "vmm: RunVirtualProcessor vp=%d hr=%lx\n",
                    v->id, (unsigned long)hr);
            dump_vp_state(v->id);
            exit(2);
        }
        uint64_t rip = ctx.VpContext.Rip;
        uint32_t ilen = ctx.VpContext.InstructionLength;
        switch (ctx.ExitReason) {
        case WHvRunVpExitReasonMemoryAccess: {
            WHV_MEMORY_ACCESS_CONTEXT *ma = &ctx.MemoryAccess;
            if (ma->Gpa == DOORBELL_GPA && ma->AccessInfo.GpaUnmapped &&
                ma->AccessInfo.AccessType == WHvMemoryAccessWrite) {
                uint64_t mbx;
                int dlen = doorbell_data(v->id, &ctx, &mbx);
                if (dlen <= 0) {
                    fprintf(stderr,
                            "vmm: undecodable doorbell store rip=%llx\n",
                            (unsigned long long)rip);
                    dump_vp_state(v->id);
                    exit(2);
                }
                advance_rip(v->id, rip, ilen ? ilen : (uint32_t)dlen);
                dispatch(v, mbx);
                *disp_ns += now_ns() - t1;
                if (v->state == 2) goto out;   // EXIT_THREAD handled inline
                continue;
            }
            if (ma->AccessInfo.GpaUnmapped && ma->Gpa < RAM_BYTES) {
                uint64_t c0 = ma->Gpa / CHUNK;
                if (commit_range(c0 * CHUNK, CHUNK)) {
                    fprintf(stderr, "vmm: commit failed gpa=%llx\n",
                            (unsigned long long)ma->Gpa);
                    dump_vp_state(v->id);
                    exit(2);
                }
                continue;                      // re-execute the access
            }
            fprintf(stderr,
                    "vmm: bad memory exit gpa=%llx gva=%llx unmapped=%u "
                    "type=%u rip=%llx\n",
                    (unsigned long long)ma->Gpa,
                    (unsigned long long)ma->Gva,
                    ma->AccessInfo.GpaUnmapped, ma->AccessInfo.AccessType,
                    (unsigned long long)rip);
            dump_vp_state(v->id);
            exit(2);
        }
        case WHvRunVpExitReasonX64Halt:
            // idle hlt: park this vcpu until a futex_wake pulls it back
            pthread_mutex_lock(&v->mu);
            v->state = 1;
            v->park_addr = 0;
            pthread_cond_wait(&v->cv, &v->mu);
            pthread_mutex_unlock(&v->mu);
            continue;
        case WHvRunVpExitReasonX64MsrAccess:
            msr_access(v->id, &ctx.MsrAccess, rip, ilen);
            continue;
        case WHvRunVpExitReasonX64Cpuid: {
            WHV_X64_CPUID_ACCESS_CONTEXT *cp = &ctx.CpuidAccess;
            WHV_REGISTER_NAME out[4] = {
                WHvX64RegisterRax, WHvX64RegisterRbx,
                WHvX64RegisterRcx, WHvX64RegisterRdx,
            };
            WHV_REGISTER_VALUE ov[4];
            memset(ov, 0, sizeof ov);
            ov[0].Reg64 = cp->DefaultResultRax;
            ov[1].Reg64 = cp->DefaultResultRbx;
            ov[2].Reg64 = cp->DefaultResultRcx;
            ov[3].Reg64 = cp->DefaultResultRdx;
            set_regs(v->id, out, ov, 4);
            advance_rip(v->id, rip, ilen ? ilen : 2);
            continue;
        }
        case WHvRunVpExitReasonX64Rdtsc: {
            WHV_REGISTER_NAME out[2] = { WHvX64RegisterRax,
                                         WHvX64RegisterRdx };
            WHV_REGISTER_VALUE ov[2];
            memset(ov, 0, sizeof ov);
            ov[0].Reg64 = (uint32_t)ctx.ReadTsc.Tsc;
            ov[1].Reg64 = ctx.ReadTsc.Tsc >> 32;
            set_regs(v->id, out, ov, 2);
            advance_rip(v->id, rip, ilen ? ilen : 2);
            continue;
        }
        case WHvRunVpExitReasonCanceled:
            continue;
        case WHvRunVpExitReasonUnrecoverableException:
        case WHvRunVpExitReasonInvalidVpRegisterValue:
        case WHvRunVpExitReasonUnsupportedFeature:
        case WHvRunVpExitReasonException:
        default:
            fprintf(stderr, "vmm: vp %d exit reason %u rip=%llx\n",
                    v->id, (unsigned)ctx.ExitReason,
                    (unsigned long long)rip);
            dump_vp_state(v->id);
            exit(2);
        }
    }
out:
    // thread exited: return the mailbox slot and guest stack to the
    // free lists; the WHPX VP is deleted and recreated on next spawn.
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
        // guest wants a recycled stack; -2 asks it to malloc a fresh one
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
        pthread_condattr_t ca;
        pthread_condattr_init(&ca);
        pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
        pthread_cond_init(&v->cv, &ca);
        pthread_condattr_destroy(&ca);
        vcpus[id] = v;
    }
    v->state = 0; v->park_addr = 0; v->deadline = 0; v->park_ret = 0;
    v->in_park_list = 0;
    v->mbx = MBX_ARENA_GPA + (uint64_t)id * MBX_SIZE;
    // (re)create the WHPX VP so no state leaks from a previous life
    wh.DeleteVirtualProcessor(g_part, id);       // ok if it didn't exist
    if (FAILED(wh.CreateVirtualProcessor(g_part, id, 0))) {
        pthread_mutex_unlock(&vm_mu);
        return -1;
    }
    v->stack_top = stack_top;
    init_vp_regs(id, entry, stack_top, arg, v->mbx);
    pthread_mutex_unlock(&vm_mu);
    pthread_create(&v->th, NULL, vcpu_loop, v);
    pthread_detach(v->th);
    __atomic_fetch_add(&spawn_ns, now_ns() - __st0, __ATOMIC_RELAXED);
    return id;
}

// ------------------------------------------------------------------ main

int main(int argc, char **argv) {
    const char *elf = NULL;
    if (parse_args(argc, argv, &elf)) return 2;
    if (getenv("KVMDBG")) g_dbg = 1;

    load_whpx();

    WHV_CAPABILITY cap;
    UINT32 written = 0;
    if (FAILED(wh.GetCapability(WHvCapabilityCodeHypervisorPresent,
                                &cap, sizeof cap, &written)) || !cap.HypervisorPresent) {
        fprintf(stderr, "vmm: WHPX hypervisor not present\n");
        return 2;
    }
    if (FAILED(wh.CreatePartition(&g_part))) {
        fprintf(stderr, "vmm: WHvCreatePartition failed\n");
        return 2;
    }
    UINT32 nvp = MAX_VCPU;
    if (FAILED(wh.SetPartitionProperty(g_part,
            WHvPartitionPropertyCodeProcessorCount, &nvp, sizeof nvp))) {
        fprintf(stderr, "vmm: SetPartitionProperty(ProcessorCount) failed\n");
        return 2;
    }
    if (FAILED(wh.SetupPartition(g_part))) {
        fprintf(stderr, "vmm: WHvSetupPartition failed\n");
        return 2;
    }

    gmem = VirtualAlloc(NULL, RAM_BYTES, MEM_RESERVE, PAGE_NOACCESS);
    if (!gmem) { fprintf(stderr, "vmm: guest ram reserve failed\n"); return 2; }

    setup_tables();
    load_elf(gmem, elf);
    if (load_map_and_bootinfo(elf)) return 2;

    // BSP: vcpu 0; HC_EXIT terminates the process
    int id = spawn_vcpu(g_entry, BSP_STACK_TOP, 0);
    if (id < 0) { fprintf(stderr, "vmm: failed to spawn BSP\n"); return 2; }
    for (;;) Sleep(INFINITE);
    return 0;
}
