// vmm.c — minimal KVM VM for kvmrun guests.
//
//   - one flat 64-bit guest, identity-mapped RAM (1GiB pages)
//   - payload ELF loaded at KERNEL_LINK, BSP starts at ELF entry
//   - guest threads are extra vCPUs spawned via HC_SPAWN
//   - hypercalls: mailbox (per-thread page) + MMIO doorbell
//
// usage: vmm --elf guest.elf --map MAP [--name-a S] [--name-b S]
//            [--debug N] [--no-replay] [-v]
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <linux/kvm.h>

#include "abi.h"

// ------------------------------------------------------------------ helpers

static void die(const char *m) { perror(m); exit(2); }
static void *gmem;                       // guest RAM base (HVA)
static inline void *hva(uint64_t gpa) {  // gpa -> host (no bounds check in hcalls w/ valid callers)
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

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

// ------------------------------------------------------------------ vcpus

#define MAX_VCPU (MBX_ARENA_BYTES / MBX_SIZE)

typedef struct Vcpu {
    int fd;
    struct kvm_run *run;
    size_t runsz;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int state;                  // 0 running/ready, 1 parked, 2 dead
    int in_park_list;
    uint64_t park_addr;
    uint64_t deadline;          // ns, 0 = none
    int park_ret;               // value to put in mbx->ret
    uint64_t mbx;               // this vcpu's mailbox GPA
    uint64_t stack_top;         // guest stack top handed to this thread
    int id;
    uint64_t run_ns, disp_ns;   // KVM_RUN vs userspace dispatch time
    uint64_t nruns;             // total KVM_RUN returns (all exit reasons)
    uint64_t nexits[64];        // per-reason exit counts
    uint64_t woke_at;           // set by waker just before cond signal
    uint64_t wake_lat, nwake;   // signal→guest-resume latency sum/count
} Vcpu;

static Vcpu *vcpus[MAX_VCPU];
static int nvcpu;                        // high-water mark of live slots
static int free_slots[MAX_VCPU], nfree;  // recyclable mailbox slots
static uint64_t next_kvm_id;             // KVM vcpu ids are never reused
static uint64_t stack_tops[MAX_VCPU];    // recycled guest thread stacks
static int nstacks;
static pthread_mutex_t vm_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile int vm_dead;
static int kvm_fd, vm_fd;
static uint64_t g_entry;

// ------------------------------------------------------------------ hcalls

static char arg_map[1024], arg_name_a[256], arg_name_b[256];
static int arg_no_replay, arg_debug = 15, arg_verbose, arg_seed_set;
static uint64_t arg_seed;
static const char *arg_replay_path;

static void stem_of(const char *arg, char *out) {
    const char *b = strrchr(arg, '/');
    b = b ? b + 1 : arg;
    if (*b && strcmp(b, ".") && strcmp(b, "..")) { snprintf(out, 128, "%s", b); return; }
    char cwd[1024];
    if (!getcwd(cwd, sizeof cwd)) { snprintf(out, 128, "bot"); return; }
    if (!strcmp(b, "..")) { char *d = strrchr(cwd, '/'); if (d) *d = 0; }
    const char *c = strrchr(cwd, '/');
    snprintf(out, 128, "%s", c ? c + 1 : cwd);
    if (!*out) snprintf(out, 128, "bot");
}

static void hc_replay(struct hcall *m) {
    uint8_t *blob = gptr(m->a, m->b);
    if (!blob) { m->ret = (uint64_t)-1; return; }
    char rpath[1024];
    if (arg_replay_path && arg_replay_path[0]) {
        snprintf(rpath, sizeof rpath, "%s", arg_replay_path);
    } else {
        const char *m_ = strrchr(arg_map, '/');
        char stem[256];
        snprintf(stem, sizeof stem, "%s", m_ ? m_ + 1 : arg_map);
        char *dot = strrchr(stem, '.');
        if (dot) *dot = 0;
        char la[128], lb[128];
        stem_of(arg_name_a, la); stem_of(arg_name_b, lb);
        char stamp[64];
        time_t tt = time(NULL);
        strftime(stamp, sizeof stamp, "%Y-%m-%d-%H%M%S", localtime(&tt));
        snprintf(rpath, sizeof rpath, "replays/%s%s%s-on-%s-%s.replay",
                 la, !strcmp(la, lb) ? "-vs-itself" : "-vs-",
                 !strcmp(la, lb) ? "" : lb, stem, stamp);
    }
    char *sl = strrchr(rpath, '/');
    if (sl) { *sl = 0; mkdir(rpath, 0777); *sl = '/'; }
    FILE *f = fopen(rpath, "wb");
    if (!f) { m->ret = (uint64_t)-1; return; }
    fwrite(blob, 1, m->b, f);
    fclose(f);
    printf("wrote replay: %s\n", rpath);
    fflush(stdout);
    m->ret = 0;
}

// parked vcpus: scanned by futex_wake instead of the whole vcpus[] table.
// lock order: park_mu -> v->mu (never the reverse).
static Vcpu *parked[MAX_VCPU];
static int nparked;
static pthread_mutex_t park_mu = PTHREAD_MUTEX_INITIALIZER;

static void futex_wake(uint64_t addr, uint64_t count) {
    if (!__atomic_load_n(&nparked, __ATOMIC_ACQUIRE)) return;
    int woken = 0;
    pthread_mutex_lock(&park_mu);
    for (int i = 0; i < nparked && (uint64_t)woken < count; ) {
        Vcpu *v = parked[i];
        pthread_mutex_lock(&v->mu);
        if (v->state == 1 && v->park_addr == addr) {
            v->park_ret = 0;
            v->state = 0;
            v->in_park_list = 0;
            v->woke_at = now_ns();
            pthread_cond_signal(&v->cv);
            parked[i] = parked[--nparked];
            woken++;
        } else {
            i++;
        }
        pthread_mutex_unlock(&v->mu);
    }
    pthread_mutex_unlock(&park_mu);
}

static uint64_t hcnt[16];                 // per-hcall totals
static uint64_t prof_gpa, prof_len;       // guest prof histogram
static uint64_t spawn_ns;                 // total time in spawn_vcpu
static uint64_t fw_ns;                    // total time parked in futex_wait
static struct { uint64_t addr; uint64_t n; } wake_hist[1024];
static void unpark(Vcpu *v) {
    pthread_mutex_lock(&park_mu);
    if (v->in_park_list) {                 // waker may have removed us already
        for (int i = 0; i < nparked; i++)
            if (parked[i] == v) { parked[i] = parked[--nparked]; break; }
        v->in_park_list = 0;
    }
    pthread_mutex_unlock(&park_mu);
}

static void futex_wait(Vcpu *v, struct hcall *m) {
    uint64_t addr = m->a, deadline = m->c;
    uint8_t *p = gptr(addr, 4);
    if (!p) { m->ret = 2; return; }
    uint64_t t0 = now_ns();
    // publish the park before re-checking the word: a waker that finds us in
    // parked[] is serialized by v->mu until we sleep, so no wake is lost.
    pthread_mutex_lock(&v->mu);
    v->park_addr = addr;
    v->deadline = deadline;
    v->park_ret = 1;                       // default: timeout
    v->state = 1;
    pthread_mutex_lock(&park_mu);
    parked[nparked++] = v;
    v->in_park_list = 1;
    pthread_mutex_unlock(&park_mu);
    if (*(volatile uint32_t *)p != (uint32_t)m->b) {
        // value changed between the guest-side check and the park
        v->state = 0;
        pthread_mutex_unlock(&v->mu);
        unpark(v);
        m->ret = 2;
        return;
    }
    v->woke_at = 0;
    struct timespec ts = { deadline / 1000000000ull,
                           deadline % 1000000000ull };
    for (;;) {
        int r = deadline ? pthread_cond_timedwait(&v->cv, &v->mu, &ts)
                         : (pthread_cond_wait(&v->cv, &v->mu), 0);
        if (v->state != 1 || r == ETIMEDOUT) break;
    }
    m->ret = v->park_ret;
    v->state = 0;
    if (v->woke_at) {
        v->wake_lat += now_ns() - v->woke_at;
        v->nwake++;
        v->woke_at = 0;
    }
    pthread_mutex_unlock(&v->mu);
    unpark(v);
    __atomic_fetch_add(&fw_ns, now_ns() - t0, __ATOMIC_RELAXED);
}

static int spawn_vcpu(uint64_t entry, uint64_t stack_top, uint64_t arg);
static void *vcpu_loop(void *arg);

// hcall history ring for post-mortem debugging (KVMDBG)
static struct { int tid; uint32_t nr; uint64_t a, b; } hring[256];
static int hri;
static int g_singlestep;
static int g_dbg;

static void dispatch(Vcpu *v, uint64_t mbx_gpa) {
    struct hcall *m = (struct hcall *)gptr(mbx_gpa, sizeof *m);
    if (!m) { fprintf(stderr, "vmm: bad mbx %llx\n", (unsigned long long)mbx_gpa); return; }
    {
        uint64_t bb = m->b;
        if (m->nr == HC_PRINT && m->c == 1) {
            uint8_t *p = gptr(m->b, 1);
            bb = p ? p[0] : 0x3f;
        }
        hring[__atomic_fetch_add(&hri, 1, __ATOMIC_RELAXED) & 255] =
            (typeof(hring[0])){v->id, m->nr, m->a, bb};
    }
    if (m->nr < 16) __atomic_fetch_add(&hcnt[m->nr], 1, __ATOMIC_RELAXED);
    switch (m->nr) {
    case HC_NOP:
        m->ret = 0;
        break;
    case HC_PRINT: {
        uint8_t *b = gptr(m->b, m->c);
        if (b) fwrite(b, 1, m->c, m->a == 2 ? stderr : stdout);
        fflush(m->a == 2 ? stderr : stdout);
        m->ret = m->c;
        break;
    }
    case HC_EXIT: {
        uint64_t trun = 0, tdisp = 0;
        for (int i = 0; i < nvcpu; i++)
            if (vcpus[i]) { trun += vcpus[i]->run_ns; tdisp += vcpus[i]->disp_ns; }
        uint64_t bsp_run = vcpus[0] ? vcpus[0]->run_ns : 0;
        uint64_t bsp_disp = vcpus[0] ? vcpus[0]->disp_ns : 0;
        uint64_t tnruns = 0, tlat = 0, tnwake = 0;
        uint64_t texits[64] = {0};
        for (int i = 0; i < nvcpu; i++) {
            if (!vcpus[i]) continue;
            tnruns += vcpus[i]->nruns;
            tlat += vcpus[i]->wake_lat;
            tnwake += vcpus[i]->nwake;
            for (int k = 0; k < 64; k++) texits[k] += vcpus[i]->nexits[k];
        }
        fprintf(stderr,
                "vmm: hcalls NOP=%llu PRINT=%llu EXIT=%llu NOW=%llu"
                " SPAWN=%llu EXIT_THR=%llu FWAIT=%llu FWAKE=%llu REPLAY=%llu"
                " GFAULT=%llu spawn_ns=%llu fwait_ns=%llu krun_ns=%llu"
                " disp_ns=%llu bsp_run=%llu bsp_disp=%llu nruns=%llu"
                " wake_lat=%llu nwake=%llu\n",
                (unsigned long long)hcnt[0], (unsigned long long)hcnt[1],
                (unsigned long long)hcnt[2], (unsigned long long)hcnt[3],
                (unsigned long long)hcnt[4], (unsigned long long)hcnt[5],
                (unsigned long long)hcnt[6], (unsigned long long)hcnt[7],
                (unsigned long long)hcnt[8], (unsigned long long)hcnt[9],
                (unsigned long long)spawn_ns, (unsigned long long)fw_ns,
                (unsigned long long)trun, (unsigned long long)tdisp,
                (unsigned long long)bsp_run, (unsigned long long)bsp_disp,
                (unsigned long long)tnruns, (unsigned long long)tlat,
                (unsigned long long)tnwake);
        fprintf(stderr, "vmm: exit reasons:");
        for (int k = 0; k < 64; k++)
            if (texits[k]) fprintf(stderr, " [%d]=%llu", k,
                                   (unsigned long long)texits[k]);
        fprintf(stderr, "\n");
        if (prof_gpa && prof_len) {
            uint64_t *h = (uint64_t *)gptr(prof_gpa, prof_len);
            uint64_t nb = prof_len / 8;
            uint64_t total = 0;
            for (uint64_t i = 0; i < nb; i++) total += h[i];
            if (!total) goto prof_done;
            fprintf(stderr, "vmm: prof total=%llu top:\n",
                    (unsigned long long)total);
            for (int t = 0; t < 24; t++) {
                uint64_t bi = 0;
                for (uint64_t i = 1; i < nb; i++)
                    if (h[i] > h[bi]) bi = i;
                if (!h[bi]) break;
                fprintf(stderr, "vmm:   rip=%llx n=%llu (%.1f%%)\n",
                        (unsigned long long)(KERNEL_LINK + (bi << 4)),
                        (unsigned long long)h[bi], 100.0 * h[bi] / total);
                h[bi] = 0;
            }
            prof_done:;
        }
        if (g_dbg) {
            for (int k = 0; k < 8; k++) {
                size_t bi = 0;
                for (size_t i = 1; i < 1024; i++)
                    if (wake_hist[i].n > wake_hist[bi].n) bi = i;
                if (!wake_hist[bi].n) break;
                fprintf(stderr, "vmm:   wake[%d] addr=%llx n=%llu\n", k,
                        (unsigned long long)wake_hist[bi].addr,
                        (unsigned long long)wake_hist[bi].n);
                wake_hist[bi].n = 0;
            }
        }
        exit((int)m->a);
    }
    case HC_NOW:
        m->ret = now_ns();
        break;
    case HC_SPAWN:
        m->ret = (uint64_t)spawn_vcpu(m->a, m->b, m->c);
        break;
    case HC_EXIT_THREAD:
        v->state = 2;
        return;                  // vcpu_loop sees state==2 and stops
    case HC_FUTEX_WAIT:
        futex_wait(v, m);
        break;
    case HC_FUTEX_WAKE:
        futex_wake(m->a, m->b);
        if (g_dbg) {
            uint64_t h = (m->a >> 2) * 2654435761u;
            for (int i = 0; i < 64; i++) {
                size_t s = (h + i) & 1023;
                if (wake_hist[s].addr == m->a) { wake_hist[s].n++; break; }
                if (!wake_hist[s].addr) { wake_hist[s].addr = m->a; wake_hist[s].n = 1; break; }
            }
        }
        m->ret = 0;
        break;
    case HC_REPLAY:
        hc_replay(m);
        break;
    case HC_PROF:
        prof_gpa = m->a; prof_len = m->b;
        m->ret = 0;
        break;
    case HC_GUESTFAULT: {
        uint64_t rip = m->b;
        if (m->a == 99) {
            // heap canary: b=blk addr, c=site (1 malloc-walk, 2 free-arg,
            // 3 free-next, 4 realloc), d=caller arg
            fprintf(stderr, "vmm: heap corrupt site=%llu blk=%llx arg=%llx\n",
                    (unsigned long long)m->c, (unsigned long long)m->b,
                    (unsigned long long)m->d);
            uint64_t *bb = (uint64_t *)gptr(m->b, 48);
            fprintf(stderr, "     blk bytes:");
            for (int i = 0; i < 6; i++)
                fprintf(stderr, " %llx", (unsigned long long)bb[i]);
            fprintf(stderr, "\n");
            m->ret = 0;
            break;
        }
        fprintf(stderr, "vmm: guest fault vec=%llu rip=%llx cr2=%llx\n",
                (unsigned long long)m->a, (unsigned long long)m->b,
                (unsigned long long)m->c);
        if (rip && rip < RAM_BYTES - 32) {
            uint8_t *ib = gptr(rip, 32);
            fprintf(stderr, "     insn@%llx:", (unsigned long long)rip);
            for (int i = 0; i < 24; i++) fprintf(stderr, " %02x", ib[i]);
            fprintf(stderr, "\n");
            uint64_t *pml4 = hva(0x1000), *pdpt = hva(0x2000);
            fprintf(stderr, "     pml4[0]=%llx pdpt[%d]=%llx\n",
                    (unsigned long long)pml4[0], (int)(rip >> 30),
                    (unsigned long long)pdpt[rip >> 30]);
        }
        // scan the faulting thread's stack for code pointers (caller chain)
        uint64_t fr = m->d;
        if (fr >= 0x20000 && fr < RAM_BYTES - 256) {
            uint64_t *st = (uint64_t *)gptr(fr, 256);
            fprintf(stderr, "     callers:");
            for (int i = 0; i < 30; i++) {
                uint64_t x = st[i];
                if (x >= KERNEL_LINK && x < 0x800000)
                    fprintf(stderr, " %llx", (unsigned long long)x);
            }
            fprintf(stderr, "\n");
        }
        m->ret = 0;
        break;
    }
    default:
        fprintf(stderr, "vmm: unknown hypercall %u\n", m->nr);
        m->ret = (uint64_t)-1;
    }
}

// ------------------------------------------------------------------ vm setup

static struct kvm_sregs init_sregs(void) {
    struct kvm_sregs s;
    memset(&s, 0, sizeof s);
    s.cr3 = 0x1000;
    s.cr0 = 0x80050033;           // PE|MP|ET|NE|WP|PG
    s.cr4 = 0x20 | 0x200 | 0x400 | 0x40000; // PAE|OSFXSR|OSXMMEXCPT|OSXSAVE
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

static void setup_tables(void) {
    memset(hva(0x1000), 0, 0x3000);
    uint64_t *pml4 = hva(0x1000), *pdpt = hva(0x2000);
    pml4[0] = 0x2000 | 3;                          // P|RW
    for (uint64_t i = 0; i < (RAM_BYTES >> 30); i++)
        pdpt[i] = (i << 30) | 0x83;                // 1GiB page, P|RW
    // one extra 1GiB leaf so the MMIO doorbell GPA is guest-visible
    pdpt[RAM_BYTES >> 30] = (((uint64_t)(RAM_BYTES >> 30)) << 30) | 0x83;
    // gdt: null, code64, data64, TSS descriptor (16B) at 0x18
    uint64_t *gdt = hva(0x3000);
    gdt[0] = 0;
    gdt[1] = 0x00AF9A000000FFFFull;                // code64: L=1, D=0
    gdt[2] = 0x00CF92000000FFFFull;                // data64
    gdt[3] = 0x67 | (0x8000ull << 16) | (0x9ull << 40) | (1ull << 47)
           | ((0x8000ull >> 24) << 56);            // 64-bit TSS, base 0x8000
    gdt[4] = 0;
    memset(hva(0x8000), 0, 0x68);                  // tss body
}

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

// ------------------------------------------------------------------ elf load

static void load_elf(void *mem, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die(path);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *img = malloc(sz);
    if (fread(img, 1, sz, f) != (size_t)sz) die("read elf");
    fclose(f);
    if (sz < 0x40 || memcmp(img, "\x7f""ELF", 4) || img[4] != 2 || img[5] != 1)
        { fprintf(stderr, "vmm: %s not a 64-bit LE ELF\n", path); exit(2); }
    uint64_t entry = *(uint64_t *)(img + 24);
    uint64_t phoff = *(uint64_t *)(img + 32);
    uint16_t phentsize = *(uint16_t *)(img + 54);
    uint16_t phnum = *(uint16_t *)(img + 56);
    for (int i = 0; i < phnum; i++) {
        uint8_t *ph = img + phoff + i * phentsize;
        if (*(uint32_t *)ph != 1) continue;        // PT_LOAD
        uint64_t off = *(uint64_t *)(ph + 8);
        uint64_t va = *(uint64_t *)(ph + 16);
        uint64_t filesz = *(uint64_t *)(ph + 32);
        uint64_t memsz = *(uint64_t *)(ph + 40);
        memcpy((uint8_t *)mem + va, img + off, filesz);
        memset((uint8_t *)mem + va + filesz, 0, memsz - filesz);
    }
    g_entry = entry;
    free(img);
}

// ------------------------------------------------------------------ main

int main(int argc, char **argv) {
    const char *elf = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--elf")) elf = argv[++i];
        else if (!strcmp(argv[i], "--map")) snprintf(arg_map, sizeof arg_map, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--name-a")) snprintf(arg_name_a, sizeof arg_name_a, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--name-b")) snprintf(arg_name_b, sizeof arg_name_b, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--replay")) arg_replay_path = argv[++i];
        else if (!strcmp(argv[i], "--debug")) arg_debug = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seed"))
            { arg_seed = strtoull(argv[++i], NULL, 0); arg_seed_set = 1; }
        else if (!strcmp(argv[i], "--no-replay")) arg_no_replay = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) arg_verbose = 1;
        else fprintf(stderr, "vmm: unknown arg %s\n", argv[i]);
    }
    if (!elf || !*arg_map) {
        fprintf(stderr, "usage: vmm --elf GUEST --map MAP [opts]\n");
        return 2;
    }

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

    // map + bootinfo
    FILE *mf = fopen(arg_map, "rb");
    if (!mf) die(arg_map);
    fseek(mf, 0, SEEK_END);
    long msz = ftell(mf);
    fseek(mf, 0, SEEK_SET);
    if (msz > (long)MAP_MAX) { fprintf(stderr, "vmm: map too big\n"); return 2; }
    if (fread((uint8_t *)gmem + MAP_GPA, 1, msz, mf) != (size_t)msz) die("map");
    fclose(mf);
    struct bootinfo *bi = hva(BOOTINFO_GPA);
    bi->magic = BOOT_MAGIC;
    bi->map_gpa = MAP_GPA;
    bi->map_len = (uint64_t)msz;
    bi->ram_size = RAM_BYTES;
    bi->debug = arg_debug;
    bi->no_replay = arg_no_replay;
    bi->verbose = arg_verbose;
    bi->seed_set = arg_seed_set;
    bi->seed = arg_seed;
    snprintf(bi->name_a, sizeof bi->name_a, "%s", arg_name_a);
    snprintf(bi->name_b, sizeof bi->name_b, "%s", arg_name_b);

    // BSP: vcpu 0; HC_EXIT terminates the process
    int id = spawn_vcpu(g_entry, BSP_STACK_TOP, 0);
    if (id < 0) { fprintf(stderr, "vmm: failed to spawn BSP\n"); return 2; }
    for (;;) pause();
    return 0;
}
