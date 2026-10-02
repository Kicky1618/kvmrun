// vmm_common.h — platform-neutral VMM machinery shared by vmm.c (KVM,
// Linux) and vmm_whpx.c (WHPX, Windows).
//
// Hypercall dispatch and all guest-controlled pointer/length validation
// live ONLY here: keep the two backends in lockstep by never duplicating
// this file's logic.
//
// Each driver must provide, before including this header's users:
//   static void    *hva(uint64_t gpa);            // NULL if out of RAM
//   static uint8_t *gptr(uint64_t gpa, uint64_t n); // bounds-checked GPA
//   static int      spawn_vcpu(uint64_t entry, uint64_t stack_top,
//                              uint64_t arg);      // -> vcpu id or <0
// and must define `gmem` handling so that every GPA VMM writes through
// hva()/gptr() is host-committed (WHPX driver commits on demand).
//
// On Linux, drivers may include <linux/kvm.h> before this header to get
// the KVM-specific Vcpu fields.

#pragma once

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "abi.h"

// ------------------------------------------------------------------ helpers

// driver-provided hooks (defined later in each TU)
static void    *hva(uint64_t gpa);
static uint8_t *gptr(uint64_t gpa, uint64_t n);
static int      spawn_vcpu(uint64_t entry, uint64_t stack_top, uint64_t arg);

static void die(const char *m) { perror(m); exit(2); }

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

// ------------------------------------------------------------------ vcpus

#define MAX_VCPU (MBX_ARENA_BYTES / MBX_SIZE)

typedef struct Vcpu {
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
    uint64_t run_ns, disp_ns;   // backend RUN vs userspace dispatch time
    uint64_t nruns;             // total run returns (all exit reasons)
    uint64_t nexits[64];        // per-reason exit counts
    uint64_t woke_at;           // set by waker just before cond signal
    uint64_t wake_lat, nwake;   // signal→guest-resume latency sum/count
#ifdef __linux__
    int fd;
    struct kvm_run *run;
    size_t runsz;
#endif
} Vcpu;

static Vcpu *vcpus[MAX_VCPU];
static int nvcpu;                        // high-water mark of live slots
static int free_slots[MAX_VCPU], nfree;  // recyclable mailbox slots
static uint64_t stack_tops[MAX_VCPU];    // recycled guest thread stacks
static int nstacks;
static pthread_mutex_t vm_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile int vm_dead;
static uint64_t g_entry;

// ------------------------------------------------------------------ hcalls

static char arg_map[1024], arg_name_a[256], arg_name_b[256];
static int arg_no_replay, arg_debug = 15, arg_verbose, arg_seed_set;
static uint64_t arg_seed;
static const char *arg_replay_path;

static void stem_of(const char *arg, char *out) {
    const char *f = strrchr(arg, '/');
    const char *b2 = strrchr(arg, '\\');
    const char *b = f;
    if (b2 && (!b || b2 > b)) b = b2;
    b = b ? b + 1 : arg;
    if (*b && strcmp(b, ".") && strcmp(b, "..")) { snprintf(out, 128, "%s", b); return; }
    char cwd[1024];
    if (!getcwd(cwd, sizeof cwd)) { snprintf(out, 128, "bot"); return; }
    if (!strcmp(b, "..")) {
        char *d = strrchr(cwd, '/');
        if (d) *d = 0;
        d = strrchr(cwd, '\\');
        if (d) *d = 0;
    }
    const char *c = strrchr(cwd, '/');
    const char *c2 = strrchr(cwd, '\\');
    if (c2 && (!c || c2 > c)) c = c2;
    snprintf(out, 128, "%s", c ? c + 1 : cwd);
    if (!*out) snprintf(out, 128, "bot");
}

#define REPLAY_MAX (256ull << 20)   // replays are ~MBs; refuse absurd sizes
static void hc_replay(struct hcall *m) {
    if (m->b > REPLAY_MAX) {
        fprintf(stderr, "vmm: replay size %llu exceeds cap\n",
                (unsigned long long)m->b);
        m->ret = (uint64_t)-1;
        return;
    }
    uint8_t *blob = gptr(m->a, m->b);
    if (!blob) { m->ret = (uint64_t)-1; return; }
    char rpath[1024];
    if (arg_replay_path && arg_replay_path[0]) {
        snprintf(rpath, sizeof rpath, "%s", arg_replay_path);
    } else {
        const char *m_ = strrchr(arg_map, '/');
        const char *m2 = strrchr(arg_map, '\\');
        if (m2 && (!m_ || m2 > m_)) m_ = m2;
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
    char *sl2 = strrchr(rpath, '\\');
    if (sl2 && (!sl || sl2 > sl)) sl = sl2;
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
        // any non-zero return (timeout or error like EINVAL) ends the wait;
        // retrying on EINVAL would spin forever
        if (v->state != 1 || r != 0) break;
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

// hcall history ring for post-mortem debugging (KVMDBG)
static struct { int tid; uint32_t nr; uint64_t a, b; } hring[256];
static int hri;
static int g_dbg;

static void dispatch(Vcpu *v, uint64_t mbx_gpa) {
    // Mailboxes live in fixed places only: the BSP page and the arena slots.
    // Anything else means guest corruption — refuse before touching it.
    if (mbx_gpa != BSP_MBX_GPA &&
        (mbx_gpa < MBX_ARENA_GPA ||
         mbx_gpa >= MBX_ARENA_GPA + MBX_ARENA_BYTES ||
         (mbx_gpa & (MBX_SIZE - 1)))) {
        fprintf(stderr, "vmm: bad mbx gpa %llx\n", (unsigned long long)mbx_gpa);
        return;
    }
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
        // legit prints are kprint diagnostics — refuse multi-GiB floods
        if (m->c > (16ull << 20)) { m->ret = (uint64_t)-1; break; }
        uint8_t *b = gptr(m->b, m->c);
        if (b) fwrite(b, 1, m->c, m->a == 2 ? stderr : stdout);
        fflush(m->a == 2 ? stderr : stdout);
        m->ret = b ? m->c : (uint64_t)-1;
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
            if (!h) goto prof_done;
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
        // validate now: the histogram is dereferenced at HC_EXIT — a bad
        // GPA/len here must not turn exit-time stats into a NULL deref
        if (!m->b || (m->b & 7) || m->b > (8ull << 20) ||
            !gptr(m->a, m->b)) {
            m->ret = (uint64_t)-1;
            break;
        }
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

// ------------------------------------------------------------------ elf load

static void elf_bad(const char *path, const char *what) {
    fprintf(stderr, "vmm: %s: bad ELF (%s)\n", path, what);
    exit(2);
}

static void load_elf(void *mem, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die(path);
    if (fseek(f, 0, SEEK_END)) die("seek elf");
    long sz = ftell(f);
    if (sz <= 0) die("elf size");
    if (fseek(f, 0, SEEK_SET)) die("seek elf");
    uint8_t *img = malloc(sz);
    if (!img) die("elf malloc");
    if (fread(img, 1, sz, f) != (size_t)sz) die("read elf");
    fclose(f);
    if (sz < 0x40 || memcmp(img, "\x7f""ELF", 4) || img[4] != 2 || img[5] != 1)
        elf_bad(path, "not a 64-bit LE ELF");
    if (img[6] != 1) elf_bad(path, "version");
    uint64_t entry = *(uint64_t *)(img + 24);
    uint64_t phoff = *(uint64_t *)(img + 32);
    uint16_t phentsize = *(uint16_t *)(img + 54);
    uint16_t phnum = *(uint16_t *)(img + 56);
    if (entry >= RAM_BYTES) elf_bad(path, "entry out of range");
    if (phentsize < 56) elf_bad(path, "phentsize");
    if (phnum && (phoff >= (uint64_t)sz ||
                  phoff + (uint64_t)phnum * phentsize > (uint64_t)sz))
        elf_bad(path, "phdr table out of range");
    for (int i = 0; i < phnum; i++) {
        uint8_t *ph = img + phoff + i * phentsize;
        if (*(uint32_t *)ph != 1) continue;        // PT_LOAD
        uint64_t off = *(uint64_t *)(ph + 8);
        uint64_t va = *(uint64_t *)(ph + 16);
        uint64_t filesz = *(uint64_t *)(ph + 32);
        uint64_t memsz = *(uint64_t *)(ph + 40);
        if (filesz > memsz) elf_bad(path, "filesz > memsz");
        if (off > (uint64_t)sz || filesz > (uint64_t)sz - off)
            elf_bad(path, "segment data out of range");
        if (va >= RAM_BYTES || memsz > RAM_BYTES - va)
            elf_bad(path, "segment vaddr out of guest RAM");
        memcpy((uint8_t *)mem + va, img + off, filesz);
        memset((uint8_t *)mem + va + filesz, 0, memsz - filesz);
    }
    g_entry = entry;
    free(img);
}

// ------------------------------------------------------------------ args/map

// Load the map file into guest RAM at MAP_GPA and fill bootinfo.
static int load_map_and_bootinfo(const char *elf) {
    (void)elf;
    FILE *mf = fopen(arg_map, "rb");
    if (!mf) die(arg_map);
    fseek(mf, 0, SEEK_END);
    long msz = ftell(mf);
    fseek(mf, 0, SEEK_SET);
    if (msz > (long)MAP_MAX) { fprintf(stderr, "vmm: map too big\n"); return -1; }
    if (fread(hva(MAP_GPA), 1, msz, mf) != (size_t)msz) die("map");
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
    return 0;
}

static int parse_args(int argc, char **argv, const char **elf) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--elf")) *elf = argv[++i];
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
    if (!*elf || !*arg_map) {
        fprintf(stderr, "usage: vmm --elf GUEST --map MAP [opts]\n");
        return -1;
    }
    return 0;
}
