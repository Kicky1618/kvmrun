// vmm.c — minimal KVM VM for kvmrun guests.
//
//   - one flat 64-bit guest, identity-mapped RAM (1GiB pages)
//   - payload ELF loaded at KERNEL_LINK, BSP starts at ELF entry
//   - guest threads are extra vCPUs spawned via HC_SPAWN
//   - hypercalls: mailbox (per-thread page) + MMIO doorbell
//
// Platform-neutral machinery (hypercall dispatch, futex parking, ELF load,
// replay writer, stats) lives in vmm_common.h, shared with vmm_whpx.c —
// keep guest-input validation single-sourced there.
//
// usage: vmm --elf guest.elf --map MAP [--name-a S] [--name-b S]
//            [--debug N] [--no-replay] [-v]
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/kvm.h>

#include "vmm_common.h"

static void *gmem;                       // guest RAM base (HVA)
static void *hva(uint64_t gpa) {         // gpa -> host (no bounds check w/ valid callers)
    if (gpa >= RAM_BYTES) return NULL;
    return (uint8_t *)gmem + gpa;
}
static uint8_t *gptr(uint64_t gpa, uint64_t n) {
    if (gpa + n > RAM_BYTES || gpa + n < gpa) {
        fprintf(stderr, "vmm: bad guest pointer %llx+%llu\n",
                (unsigned long long)gpa, (unsigned long long)n);
        return NULL;
    }
    return (uint8_t *)gmem + gpa;
}
// guest RAM is fully committed up front (MAP_NORESERVE), nothing to do
static int vmm_commit(uint64_t gpa, uint64_t len) {
    (void)gpa; (void)len; return 0;
}

// ------------------------------------------------------------------ vcpus

static uint64_t next_kvm_id;             // KVM vcpu ids are never reused
static int kvm_fd, vm_fd;
static int g_singlestep;

// KVM_GET_SUPPORTED_CPUID is identical for every vcpu; fetch once.
static struct kvm_cpuid2 *cpuid_blob;

static struct kvm_cpuid2 *get_cpuid(void) {
    if (cpuid_blob) return cpuid_blob;
    int n = 256;
    struct kvm_cpuid2 *cp = calloc(1, sizeof(*cp) + n * sizeof(cp->entries[0]));
    cp->nent = n;
    if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, cp) < 0) { free(cp); return NULL; }
    cpuid_blob = cp;
    return cp;
}

static int host_has_fsgsbase(void) {
    struct kvm_cpuid2 *cp = get_cpuid();
    if (!cp) return 0;
    for (uint32_t i = 0; i < cp->nent; i++)
        if (cp->entries[i].function == 7 && cp->entries[i].index == 0)
            return !!(cp->entries[i].ebx & 1);
    return 0;
}

static struct kvm_sregs init_sregs(void) {
    struct kvm_sregs s;
    memset(&s, 0, sizeof s);
    s.cr3 = 0x1000;
    s.cr0 = 0x80050033;           // PE|MP|ET|NE|WP|PG
    s.cr4 = 0x20 | 0x200 | 0x400 | 0x40000; // PAE|OSFXSR|OSXMMEXCPT|OSXSAVE
    if (host_has_fsgsbase())
        s.cr4 |= 0x10000;       // FSGSBASE: guest may rd/wr fs/gs base
    s.efer = 0x500;               // LME|LMA
    struct kvm_segment code = {
        .base = 0, .limit = 0xffffffff, .selector = 0x08,
        .type = 11, .present = 1, .dpl = 0, .db = 0, .s = 1, .l = 1, .g = 1,
    };
    struct kvm_segment data = {
        .base = 0, .limit = 0xffffffff, .selector = 0x10,
        .type = 3, .present = 1, .dpl = 0, .db = 1, .s = 1, .l = 0, .g = 1,
    };
    s.cs = code;
    s.ds = s.es = s.ss = s.fs = s.gs = data;
    // VMX requires TR usable: point it at the dummy TSS descriptor (sel 0x18)
    s.tr.base = 0x8000; s.tr.limit = 0x67; s.tr.selector = 0x18;
    s.tr.type = 11; s.tr.present = 1; s.tr.s = 0;
    s.ldt.unusable = 1;
    s.gdt.base = 0x3000;
    s.gdt.limit = 0x2f;
    s.idt.base = 0;
    s.idt.limit = 0;
    return s;
}

static void *vcpu_loop(void *arg);

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
    int reuse = v && v->fd >= 0;
    if (!v) {
        v = calloc(1, sizeof *v);
        v->id = id;
        v->fd = -1;
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
    if (!reuse) {
        v->fd = ioctl(vm_fd, KVM_CREATE_VCPU, next_kvm_id++);
        if (v->fd < 0) { pthread_mutex_unlock(&vm_mu); return -1; }
        int runsz = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        v->runsz = runsz;
        v->run = mmap(NULL, runsz, PROT_READ | PROT_WRITE, MAP_SHARED, v->fd, 0);
        struct kvm_cpuid2 *cp = get_cpuid();
        if (cp && ioctl(v->fd, KVM_SET_CPUID2, cp) < 0) {
            pthread_mutex_unlock(&vm_mu); die("KVM_SET_CPUID2");
        }
    }
    struct kvm_sregs s = init_sregs();
    if (ioctl(v->fd, KVM_SET_SREGS, &s) < 0) {
        pthread_mutex_unlock(&vm_mu); die("KVM_SET_SREGS");
    }
    if (reuse) {
        // clear any pending events left over from the previous life
        struct kvm_vcpu_events ev;
        memset(&ev, 0, sizeof ev);
        ioctl(v->fd, KVM_SET_VCPU_EVENTS, &ev);
    }
    // mirror the host XCR0 so the guest can run -march=native code
    {
        uint32_t lo, hi;
        __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        struct kvm_xcrs xc = {0};
        xc.nr_xcrs = 1;
        xc.xcrs[0].xcr = 0;
        xc.xcrs[0].value = lo | ((uint64_t)hi << 32);
        ioctl(v->fd, KVM_SET_XCRS, &xc);
    }
    v->stack_top = stack_top;
    struct kvm_regs r = {0};
    r.rip = entry;
    r.rsp = stack_top;
    r.rdi = arg;
    r.rsi = v->mbx;
    r.rflags = 2;
    if (ioctl(v->fd, KVM_SET_REGS, &r) < 0) {
        pthread_mutex_unlock(&vm_mu); die("KVM_SET_REGS");
    }
    pthread_mutex_unlock(&vm_mu);
    pthread_create(&v->th, NULL, vcpu_loop, v);
    pthread_detach(v->th);
    __atomic_fetch_add(&spawn_ns, now_ns() - __st0, __ATOMIC_RELAXED);
    return id;
}

static void *vcpu_loop(void *arg) {
    Vcpu *v = arg;
    static _Thread_local uint64_t riplog[64];
    static _Thread_local int rl;
    if (g_singlestep && v->id == 1) {
        struct kvm_guest_debug dbg = {
            .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
        };
        int rr = ioctl(v->fd, KVM_SET_GUEST_DEBUG, &dbg);
        fprintf(stderr, "vmm: SET_GUEST_DEBUG -> %d %s\n", rr, strerror(errno));
    }
    uint64_t *run_ns = &v->run_ns, *disp_ns = &v->disp_ns;
    while (!vm_dead) {
        if (v->state == 2) break;
        uint64_t t0 = now_ns();
        int r = ioctl(v->fd, KVM_RUN, 0);
        uint64_t t1 = now_ns();
        *run_ns += t1 - t0;
        v->nruns++;
        if (v->run->exit_reason < 64) v->nexits[v->run->exit_reason]++;
        if (g_singlestep && v->id == 1) {
            struct kvm_regs rr;
            if (ioctl(v->fd, KVM_GET_REGS, &rr) == 0) {
                riplog[rl++ & 63] = rr.rip |
                    ((uint64_t)(v->run->exit_reason & 0xff) << 56);
            }
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "vmm: KVM_RUN failed on vcpu %d: %s\n",
                    v->id, strerror(errno));
            exit(2);
        }
        struct kvm_run *run = v->run;
        if (run->exit_reason == KVM_EXIT_MMIO &&
            run->mmio.phys_addr == DOORBELL_GPA && run->mmio.is_write) {
            if (run->mmio.len < 8) {            // short write: no full GPA
                fprintf(stderr, "vmm: short doorbell write (%u)\n",
                        run->mmio.len);
                continue;
            }
            uint64_t mbx;
            memcpy(&mbx, run->mmio.data, 8);
            dispatch(v, mbx);
            *disp_ns += now_ns() - t1;
            if (v->state == 2) break;              // EXIT_THREAD handled inline
            continue;
        }
        if (run->exit_reason == KVM_EXIT_DEBUG) continue;   // single-step
        if (run->exit_reason == KVM_EXIT_HLT) {
            // idle hlt: park this vcpu until woken (no timer in guest)
            pthread_mutex_lock(&v->mu);
            v->state = 1;
            v->park_addr = 0;
            pthread_cond_wait(&v->cv, &v->mu);     // woken by futex_wake w/ addr0? no
            pthread_mutex_unlock(&v->mu);
            continue;
        }
        if (run->exit_reason == KVM_EXIT_SHUTDOWN ||
            run->exit_reason == KVM_EXIT_FAIL_ENTRY ||
            run->exit_reason == KVM_EXIT_INTERNAL_ERROR) {
            struct kvm_regs rr;
            unsigned long long rip = 0;
            if (ioctl(v->fd, KVM_GET_REGS, &rr) == 0) {
                rip = rr.rip;
                fprintf(stderr,
                        "vmm: vcpu %d regs rip=%llx rsp=%llx rax=%llx rbx=%llx\n"
                        "     rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r11=%llx\n",
                        v->id, (unsigned long long)rr.rip,
                        (unsigned long long)rr.rsp, (unsigned long long)rr.rax,
                        (unsigned long long)rr.rbx, (unsigned long long)rr.rcx,
                        (unsigned long long)rr.rdx, (unsigned long long)rr.rsi,
                        (unsigned long long)rr.rdi, (unsigned long long)rr.r8,
                        (unsigned long long)rr.r11);
                struct hcall *mm = (struct hcall *)gptr(v->mbx, sizeof *mm);
                if (mm)
                    fprintf(stderr, "     mbx nr=%u a=%llx b=%llx c=%llx ret=%llx\n",
                            mm->nr, (unsigned long long)mm->a,
                            (unsigned long long)mm->b, (unsigned long long)mm->c,
                            (unsigned long long)mm->ret);
                // dump the exception frame if the guest was in an exc_ stub
                if (rr.rsp && rr.rsp < RAM_BYTES - 128) {
                    uint64_t *st = (uint64_t *)gptr(rr.rsp, 96);
                    fprintf(stderr, "     stack@%llx:", (unsigned long long)rr.rsp);
                    for (int i = 0; i < 12; i++)
                        fprintf(stderr, " %llx", (unsigned long long)st[i]);
                    fprintf(stderr, "\n");
                }
                // dump raw instruction bytes at the faulting rip
                if (rip && rip < RAM_BYTES - 32) {
                    uint8_t *ib = gptr(rip, 32);
                    fprintf(stderr, "     insn@%llx:", rip);
                    for (int i = 0; i < 24; i++)
                        fprintf(stderr, " %02x", ib[i]);
                    fprintf(stderr, "\n");
                    // check page-table integrity for this address
                    uint64_t *pml4 = hva(0x1000), *pdpt = hva(0x2000);
                    fprintf(stderr, "     pml4[0]=%llx pdpt[%d]=%llx\n",
                            (unsigned long long)pml4[0], (int)(rip >> 30),
                            (unsigned long long)pdpt[rip >> 30]);
                }
            }
            fprintf(stderr, "vmm: vcpu %d shutdown (reason %d, hwfail=%llx, rip=%llx)\n",
                    v->id, run->exit_reason,
                    (unsigned long long)run->fail_entry.hardware_entry_failure_reason,
                    rip);
            fprintf(stderr, "last hcalls (tid:nr a b/chr):");
            for (int i = 0; i < 64 && i < hri; i++) {
                typeof(hring[0]) *h = &hring[(hri - 64 + i) & 255];
                if (h->tid || h->nr || h->a || h->b) {
                    if (h->nr == HC_PRINT && h->b < 0x80 && h->b >= 0x20)
                        fprintf(stderr, " %d:P '%c'", h->tid, (int)h->b);
                    else
                        fprintf(stderr, " %d:%u %llx,%llx", h->tid, h->nr,
                                (unsigned long long)h->a, (unsigned long long)h->b);
                }
            }
            fprintf(stderr, "\nlast rips (er:rip):");
            for (int i = 0; i < 64; i++) {
                uint64_t x = riplog[(rl - 64 + i) & 63];
                if (x) fprintf(stderr, " %u:%llx",
                               (unsigned)(x >> 56), (unsigned long long)(x & ~0xff00000000000000ull));
            }
            fprintf(stderr, "\n");
            exit(2);
        }
        fprintf(stderr, "vmm: vcpu %d exit_reason=%d\n", v->id, run->exit_reason);
        exit(2);
    }
    // thread exited: keep fd + kvm_run mmap so the slot can be re-armed
    // with just SET_SREGS/SET_REGS; return the mailbox slot and guest
    // stack to the free lists.
    pthread_mutex_lock(&vm_mu);
    free_slots[nfree++] = v->id;
    if (v->stack_top && nstacks < MAX_VCPU)
        stack_tops[nstacks++] = v->stack_top;
    pthread_mutex_unlock(&vm_mu);
    return NULL;
}

// ------------------------------------------------------------------ main

int main(int argc, char **argv) {
    const char *elf = NULL;
    if (parse_args(argc, argv, &elf)) return 2;

    if (getenv("KVMDBG")) { g_dbg = 1; g_singlestep = 1; }
    kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) die("/dev/kvm");
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) die("KVM_CREATE_VM");

    gmem = mmap(NULL, RAM_BYTES, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (gmem == MAP_FAILED) die("mmap guest ram");
    struct kvm_userspace_memory_region mr = {
        .slot = 0, .guest_phys_addr = 0,
        .memory_size = RAM_BYTES, .userspace_addr = (uint64_t)gmem,
    };
    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mr) < 0) die("SET_MEM");

    setup_tables();
    load_elf(gmem, elf);
    if (load_map_and_bootinfo(elf)) return 2;

    // BSP: vcpu 0; HC_EXIT terminates the process
    int id = spawn_vcpu(g_entry, BSP_STACK_TOP, 0);
    if (id < 0) { fprintf(stderr, "vmm: failed to spawn BSP\n"); return 2; }
    for (;;) pause();
    return 0;
}
