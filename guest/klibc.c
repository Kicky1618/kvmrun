// klibc.c — freestanding libc subset for the kvmrun guest.
// Single flat address space, identity-mapped, no paging faults expected.
#define KVMRUN_GUEST 1
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include "../abi.h"

// ---------------------------------------------------------------- hcalls

static inline struct hcall *mbx(void) {
    uint64_t m;
    __asm__ volatile("mov %%fs:8, %0" : "=r"(m));
    return (struct hcall *)m;
}

uint64_t hcall(uint32_t nr, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    struct hcall *m = mbx();
    m->nr = nr; m->a = a; m->b = b; m->c = c; m->d = d;
    __sync_synchronize();
    *(volatile uint64_t *)DOORBELL_GPA = (uint64_t)(uintptr_t)m;
    __sync_synchronize();
    return m->ret;
}

void kprint(int fd, const void *buf, uint64_t len) {
    hcall(HC_PRINT, fd, (uint64_t)(uintptr_t)buf, len, 0);
}

static void pflush(void);
_Noreturn void hcall_exit(int code) {
    pflush();
    hcall(HC_EXIT, (uint64_t)code, 0, 0, 0);
    for (;;) __asm__ volatile("hlt");
}

// ---------------------------------------------------------------- TLS image

extern char __tls_start[], __tdata_end[], __tbss_end[];

void tls_copy_to(uint64_t tp);
static void tls_copy(void) {           // x86-64 TLS: vars live at [tp-size, tp)
    uint64_t tp;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(tp));
    tls_copy_to(tp);
}
// fill a fresh TLS block for a cooperative thread: template in [tp-size,tp),
// self pointer at tp+0, shared BSP mailbox at tp+8 (hcall() reads fs:8)
void tls_copy_to(uint64_t tp) {
    uint64_t size = (uint64_t)__tbss_end - (uint64_t)__tls_start;
    uint8_t *d = (uint8_t *)(tp - size);
    for (char *s = __tls_start; s < __tdata_end; s++) *d++ = *s;
    while (d < (uint8_t *)tp) *d++ = 0;
    *(uint64_t *)tp = tp;
    *(uint64_t *)(tp + 8) = BSP_MBX_GPA;
}

// ---------------------------------------------------------------- sync

// tiny futex wrappers used by malloc's lock; full pthread api is in gthr.c
int g_futex_wait(uint32_t *addr, uint32_t expected, uint64_t deadline_ns);
int g_futex_wake(uint32_t *addr, uint32_t count);

// heap_lock is the only alock user; waiters lets unlock skip the wake
// hypercall when nobody is queued.
static volatile uint32_t alock_waiters;

static void alock(volatile uint32_t *l) {
    uint32_t exp = 0;
    for (;;) {
        for (int i = 0; i < 200; i++) {
            exp = 0;
            if (__atomic_compare_exchange_n(l, &exp, 1, true,
                                            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return;
            __asm__ volatile("pause");
        }
        __atomic_add_fetch(&alock_waiters, 1, __ATOMIC_ACQ_REL);
        g_futex_wait((uint32_t *)l, 1, 0);
        __atomic_sub_fetch(&alock_waiters, 1, __ATOMIC_ACQ_REL);
    }
}
static void aunlock(volatile uint32_t *l) {
    __atomic_store_n(l, 0, __ATOMIC_RELEASE);
    if (__atomic_load_n(&alock_waiters, __ATOMIC_ACQUIRE))
        g_futex_wake((uint32_t *)l, 1);
}

// ---------------------------------------------------------------- arena malloc

typedef struct Blk {
    uint64_t size;              // bytes including header
    struct Blk *next;           // free list link (when free)
    uint8_t free;
    uint8_t pristine;           // never written since boot: still all-zero
    uint64_t magic;             // Blk header sanity marker
} Blk;
#define BLK_H ((sizeof(Blk) + 15) & ~15ull)
#define BLK_MAGIC 0xB10CB10CB10CB10Cull

static volatile uint32_t heap_lock;
static Blk *heap_head;          // first block in address order
static uint64_t heap_next;      // bump pointer
static uint64_t heap_end;
static uint64_t heap_lo, heap_hi; // valid Blk* range
static uint64_t phys_next;      // page-pool cursor: heap cap shrinks as
                                // 4KiB frames are carved off the top

uint64_t hcall(uint32_t nr, uint64_t a, uint64_t b, uint64_t c, uint64_t d);

static void blk_check(Blk *b, uint64_t where, void *arg) {
    bool ok = (uint64_t)b >= heap_lo && (uint64_t)b < heap_hi &&
              b->magic == BLK_MAGIC;
    if (ok) {
        uint64_t bn = (uint64_t)b->next;
        ok = !b->next || (bn >= heap_lo && bn < heap_hi &&
                          b->next->magic == BLK_MAGIC);
    }
    if (ok) return;
    // report: a=99, b=bad block, c=site id, d=free() arg
    hcall(HC_GUESTFAULT, 99, (uint64_t)b, where, (uint64_t)arg);
    for (;;) __asm__ volatile("hlt");
}

static Blk *blk_new(uint64_t need) {
    uint64_t sz = (need + BLK_H + 15) & ~15ull;
    if (heap_next + sz > phys_next) return NULL;   // heap cap = phys pool
    Blk *b = (Blk *)heap_next;
    heap_next += sz;
    b->size = sz; b->free = 0; b->next = NULL; b->magic = BLK_MAGIC;
    b->pristine = 1;            // bump region has never been written
    // keep address order: append at list tail (bump alloc => always tail)
    if (!heap_head) heap_head = b;
    else {
        Blk *t = heap_head;
        while (t->next) t = t->next;
        t->next = b;
    }
    return b;
}

static Blk *free_hint;          // next-fit hint: a block recently freed

void *malloc(size_t n) {
    if (!n) n = 1;
    uint64_t need = (n + 15) & ~15ull;
    alock(&heap_lock);
    // next fit starting near a known-free block, then wrap once to head
    for (int pass = 0; pass < 2; pass++) {
        Blk *b = pass == 0 ? free_hint : heap_head;
        if (!b) continue;
        for (; b; b = b->next) {
            blk_check(b, 1, (void *)(uintptr_t)n);
            if (!b->free || b->size < need + BLK_H) continue;
            if (b->size >= need + BLK_H + 64) {
                Blk *r = (Blk *)((uint8_t *)b + BLK_H + need);
                r->size = b->size - BLK_H - need;
                r->free = 1; r->next = b->next;
                r->magic = BLK_MAGIC; r->pristine = 0;
                b->next = r; b->size = need + BLK_H;
            }
            b->free = 0;
            b->pristine = 0;    // recycled: contents are stale
            free_hint = b->next;
            aunlock(&heap_lock);
            return b + 1;
        }
        if (free_hint == heap_head) break;   // already scanned from head
    }
    Blk *b = blk_new(need);
    aunlock(&heap_lock);
    return b ? b + 1 : NULL;
}

void free(void *p) {
    if (!p) return;
    Blk *b = (Blk *)p - 1;
    alock(&heap_lock);
    blk_check(b, 2, p);
    b->free = 1;
    free_hint = b;
    // coalesce forward
    for (;;) {
        if (b->next) blk_check(b->next, 3, p);
        if (!b->next || !b->next->free ||
            (uint8_t *)b + b->size != (uint8_t *)b->next) break;
        if (free_hint == b->next) free_hint = b;
        b->size += b->next->size;
        b->next = b->next->next;
    }
    aunlock(&heap_lock);
}

void *calloc(size_t n, size_t sz) {
    uint64_t t = n * sz;
    if (sz && t / sz != n) return NULL;
    void *p = malloc(t ? t : 1);
    // fresh bump blocks sit on never-written, already-zero pages
    if (p && !((Blk *)p - 1)->pristine) memset(p, 0, t);
    return p;
}

void *realloc(void *p, size_t n) {
    if (!p) return malloc(n);
    Blk *b = (Blk *)p - 1;
    alock(&heap_lock);
    blk_check(b, 4, p);
    aunlock(&heap_lock);
    if (b->size - BLK_H >= n) return p;
    void *q = malloc(n);
    if (!q) return NULL;
    memcpy(q, p, b->size - BLK_H < n ? b->size - BLK_H : n);
    free(p);
    return q;
}

// ---------------------------------------------------------------- string.h

static uint64_t ms_bytes, mc_bytes, mm_bytes;   // bulk-op volume (debug 16)

void *memcpy(void *d, const void *s, size_t n) {
    mc_bytes += n;
    uint8_t *dd = d; const uint8_t *ss = s;
    if (n < 32) {
        while (((uintptr_t)dd & 7) && n) { *dd++ = *ss++; n--; }
        while (n >= 8) { uint64_t v; __builtin_memcpy(&v, ss, 8); __builtin_memcpy(dd, &v, 8); dd += 8; ss += 8; n -= 8; }
        while (n--) *dd++ = *ss++;
        return d;
    }
    if (n >= 4096) {                // rep movsb wins on big copies (FSRM)
        size_t cnt = n;
        __asm__ volatile("rep movsb"
                         : "+D"(dd), "+S"(ss), "+c"(cnt) :: "memory");
        return d;
    }
    // mid-size: AVX2 — head/tail 32B overlapping + 32B steps forward
    uintptr_t off = 32;
    __asm__ volatile(
        "vmovdqu (%[s]), %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[d])\n\t"
        "vmovdqu -32(%[s],%[n]), %%ymm1\n\t"
        "vmovdqu %%ymm1, -32(%[d],%[n])\n\t"
        "1:\n\t"
        "lea -32(%[n]), %%rax\n\t"
        "cmp %%rax, %[o]\n\t"
        "jae 2f\n\t"
        "vmovdqu (%[s],%[o]), %%ymm0\n\t"
        "vmovdqu %%ymm0, (%[d],%[o])\n\t"
        "add $32, %[o]\n\t"
        "jmp 1b\n\t"
        "2:\n\t"
        "vzeroupper\n\t"
        : [o]"+r"(off)
        : [s]"r"(ss), [d]"r"(dd), [n]"r"(n)
        : "rax", "ymm0", "ymm1", "memory");
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    mm_bytes += n;
    uint8_t *dd = d; const uint8_t *ss = s;
    if ((uintptr_t)d < (uintptr_t)s) {
        // forward direction: memcpy only when disjoint (its head/tail order
        // is unsafe when ranges overlap)
        if ((uintptr_t)dd + n <= (uintptr_t)ss) return memcpy(d, s, n);
        if (n >= 32) {              // rep movsb is strictly forward: safe
            size_t cnt = n;
            __asm__ volatile("rep movsb"
                             : "+D"(dd), "+S"(ss), "+c"(cnt) :: "memory");
            return d;
        }
        while (n--) *dd++ = *ss++;
        return d;
    }
    if (n >= 256) {                 // backward copy for overlap
        uint8_t *bd = dd + n - 1;
        const uint8_t *bs = ss + n - 1;
        size_t cnt = n;
        __asm__ volatile("std; rep movsb; cld"
                         : "+D"(bd), "+S"(bs), "+c"(cnt) :: "memory");
        return d;
    }
    dd += n; ss += n;
    while (n--) *--dd = *--ss;
    return d;
}
void *memset(void *d, int c, size_t n) {
    ms_bytes += n;
    if (n >= 256) {
        uint8_t *dd = d; size_t cnt = n;
        __asm__ volatile("rep stosb"
                         : "+D"(dd), "+c"(cnt) : "a"((uint8_t)c) : "memory");
        return d;
    }
    uint8_t *dd = d;
    while (((uintptr_t)dd & 7) && n) { *dd++ = (uint8_t)c; n--; }
    uint64_t v = 0x0101010101010101ull * (uint8_t)c;
    while (n >= 8) { *(uint64_t *)dd = v; dd += 8; n -= 8; }
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    while (n--) { if (*x != *y) return *x - *y; x++; y++; }
    return 0;
}
void *memchr(const void *s, int c, size_t n) {
    const uint8_t *p = s;
    while (n--) { if (*p == (uint8_t)c) return (void *)p; p++; }
    return NULL;
}
size_t strlen(const char *s) { const char *p = s; while (*p) p++; return p - s; }
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (uint8_t)*a - (uint8_t)*b;
}
int strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (uint8_t)*a - (uint8_t)*b : 0;
}
char *strchr(const char *s, int c) {
    for (; *s; s++) if (*s == c) return (char *)s;
    return c == 0 ? (char *)s : NULL;
}
char *strrchr(const char *s, int c) {
    const char *last = NULL;
    for (; *s; s++) if (*s == c) last = s;
    if (c == 0) return (char *)s;
    return (char *)last;
}
char *strstr(const char *h, const char *nd) {
    size_t n = strlen(nd);
    for (; *h; h++) if (!strncmp(h, nd, n)) return (char *)h;
    return NULL;
}
char *strcpy(char *d, const char *s) {
    char *o = d;
    while ((*d++ = *s++)) {}
    return o;
}
char *strncpy(char *d, const char *s, size_t n) {
    char *o = d;
    while (n && *s) { *d++ = *s++; n--; }
    while (n--) *d++ = 0;
    return o;
}
int atoi(const char *s) {
    while (*s == ' ' || (*s >= 9 && *s <= 13)) s++;
    int neg = *s == '-'; s += neg || *s == '+';
    int v = 0; while (*s >= '0' && *s <= '9') v = v * 10 + *s++ - '0';
    return neg ? -v : v;
}
int isprint(int c) { return c >= 0x20 && c < 0x7f; }
int toupper(int c) { return c >= 'a' && c <= 'z' ? c - 32 : c; }

// ---------------------------------------------------------------- mini printf

typedef void (*outfn)(void *ctx, const char *buf, size_t n);

static void fmt_u64(outfn fn, void *cx, uint64_t v, int base, int neg,
                    int width, char pad) {
    char tmp[32]; int i = 32;
    do { tmp[--i] = "0123456789abcdef"[v % base]; v /= base; } while (v);
    int len = 32 - i + neg;
    while (len++ < width) { char c = pad; fn(cx, &c, 1); }
    if (neg) fn(cx, "-", 1);
    fn(cx, tmp + i, 32 - i);
}

static void fmt_f64(outfn fn, void *cx, double v, int prec) {
    if (v != v) { fn(cx, "nan", 3); return; }
    if (v < 0) { fn(cx, "-", 1); v = -v; }
    uint64_t ip = (uint64_t)v;
    fmt_u64(fn, cx, ip, 10, 0, 0, ' ');
    if (prec <= 0) return;
    fn(cx, ".", 1);
    double f = v - ip;
    for (int i = 0; i < prec; i++) {
        f *= 10;
        int d = (int)f;
        fn(cx, &(char){'0' + (d > 9 ? 9 : d)}, 1);
        f -= d;
    }
}

static int kvfmt(outfn fn, void *cx, const char *fmt, va_list ap) {
    int total = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { fn(cx, p, 1); total++; continue; }
        p++;
        int width = 0, prec = -1; char pad = ' ';
        if (*p == '0') { pad = '0'; p++; }
        while (*p >= '0' && *p <= '9') width = width * 10 + *p++ - '0';
        if (*p == '.') { p++; prec = 0; while (*p >= '0' && *p <= '9') prec = prec * 10 + *p++ - '0'; }
        int lng = 0;
        while (*p == 'l' || *p == 'z' || *p == 'h') { if (*p == 'l') lng++; p++; }
        switch (*p) {
        case 's': { const char *s = va_arg(ap, const char *);
                    if (!s) s = "(null)";
                    size_t n = strlen(s); fn(cx, s, n); total += n; break; }
        case 'c': { char c = (char)va_arg(ap, int); fn(cx, &c, 1); total++; break; }
        case 'd': case 'i': {
            int64_t v = lng >= 2 ? va_arg(ap, long long)
                        : lng == 1 ? va_arg(ap, long) : va_arg(ap, int);
            fmt_u64(fn, cx, v < 0 ? -(uint64_t)v : (uint64_t)v, 10, v < 0, width, pad);
            break; }
        case 'u': case 'x': {
            uint64_t v = lng >= 2 ? va_arg(ap, unsigned long long)
                        : lng == 1 ? va_arg(ap, unsigned long) : va_arg(ap, unsigned);
            fmt_u64(fn, cx, v, *p == 'x' ? 16 : 10, 0, width, pad);
            break; }
        case 'p': { uint64_t v = (uintptr_t)va_arg(ap, void *);
                    fmt_u64(fn, cx, v, 16, 0, 0, ' '); break; }
        case 'f': { double v = va_arg(ap, double);
                    fmt_f64(fn, cx, v, prec < 0 ? 6 : prec); break; }
        case '%': fn(cx, "%", 1); total++; break;
        default: fn(cx, "%", 1); fn(cx, p, 1); total += 2; break;
        }
    }
    return total;
}

struct sctx { char *buf; size_t cap, len; };
static void sout(void *cx, const char *b, size_t n) {
    struct sctx *s = cx;
    if (s->len + n < s->cap) memcpy(s->buf + s->len, b, n);
    s->len += n;
}
static __thread char pbuf[1024];
static __thread int plen, pfd = -1;
static void pflush(void) {
    if (plen) { kprint(pfd, pbuf, plen); plen = 0; }
}
static void hout(void *cx, const char *b, size_t n) {
    int fd = (int)(intptr_t)cx;
    if (pfd != fd) { pflush(); pfd = fd; }
    for (size_t i = 0; i < n; i++) {
        pbuf[plen++] = b[i];
        if (b[i] == '\n' || plen == sizeof pbuf) pflush();
    }
}

int vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
    struct sctx s = {buf, cap, 0};
    int n = kvfmt(sout, &s, fmt, ap);
    if (cap) buf[s.len < cap ? s.len : cap - 1] = 0;
    return n;
}
int snprintf(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}
int sprintf(char *buf, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, 1 << 20, fmt, ap);
    va_end(ap);
    return n;
}
int vprintf(const char *fmt, va_list ap) { return kvfmt(hout, (void *)1, fmt, ap); }
int printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = kvfmt(hout, (void *)(intptr_t)1, fmt, ap);
    va_end(ap);
    return n;
}
int fprintf(FILE *f, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = kvfmt(hout, (void *)(intptr_t)f->fd, fmt, ap);
    va_end(ap);
    return n;
}
int vfprintf(FILE *f, const char *fmt, va_list ap) {
    return kvfmt(hout, (void *)(intptr_t)f->fd, fmt, ap);
}
int fputs(const char *s, FILE *f) { kprint(f->fd, s, strlen(s)); return 0; }
int puts(const char *s) { kprint(1, s, strlen(s)); kprint(1, "\n", 1); return 0; }
int putchar(int c) { char ch = c; kprint(1, &ch, 1); return c; }
int fflush(FILE *f) { (void)f; return 0; }
size_t fwrite(const void *p, size_t sz, size_t n, FILE *f) {
    kprint(f->fd, p, sz * n); return n;
}
void perror(const char *s) { kprint(2, s, strlen(s)); kprint(2, "\n", 1); }
FILE *fopen(const char *p, const char *m) { (void)p; (void)m; return NULL; }
size_t fread(void *a, size_t b, size_t c, FILE *f) { (void)a;(void)b;(void)c;(void)f; return 0; }
int fclose(FILE *f) { (void)f; return 0; }
int fseek(FILE *f, long o, int w) { (void)f; (void)o; (void)w; return -1; }
long ftell(FILE *f) { (void)f; return -1; }

// FILE stand-ins: first field is the fd
static FILE __sf_out = {1}, __sf_err = {2};
FILE *stdout = &__sf_out;
FILE *stderr = &__sf_err;

// ---------------------------------------------------------------- misc

// ------------------------------------------------------------------ IDT

struct idt_ent {
    uint16_t lo, sel;
    uint8_t ist, type;
    uint16_t mid;
    uint32_t hi, zero;
} __attribute__((packed));
_Static_assert(sizeof(struct idt_ent) == 16, "idt_ent");

static struct idt_ent g_idt[32] __attribute__((aligned(16)));
extern const uint64_t exc_stub_table[32];

// Dedicated exception stack via TSS IST1 (TSS descriptor lives at gdt 0x18,
// base 0x8000 — set up by the VMM). Demand-paged thread stacks can #PF on
// growth, so the handler itself must not run on the faulting stack.
static uint8_t exc_stk[16384] __attribute__((aligned(16)));

static void ist_init(void) {
    *(volatile uint64_t *)(0x8000 + 0x24) =        // tss.ist1
        (uint64_t)(exc_stk + sizeof exc_stk);
}

void idt_load(void) {                    // per-vCPU
    struct __attribute__((packed)) { uint16_t l; uint64_t b; } d =
        { sizeof g_idt - 1, (uint64_t)g_idt };
    __asm__ volatile("lidt %0" :: "m"(d));
}
static void idt_init(void) {
    ist_init();
    for (int i = 0; i < 32; i++) {
        uint64_t a = exc_stub_table[i];
        g_idt[i] = (struct idt_ent){
            .lo = a & 0xffff, .sel = 0x08,
            .ist = (i == 8 || i == 14) ? 1 : 0,   // #DF/#PF on exc_stk
            .type = 0x8e,
            .mid = (a >> 16) & 0xffff, .hi = (uint32_t)(a >> 32), .zero = 0};
    }
}

// ---------------------------------------------------- wasm memory arena
// wasm-rt guard-pages mode reserves 8GiB per wasm memory (4GiB usable +
// 4GiB guard). The identity map only spans guest RAM, so wasm memories live
// in a separate VA window starting at ARENA_VA, backed by 4KiB frames pulled
// from the phys pool (downward from the top of the heap region). Page tables
// are ours: pml4[8..23] -> a static pdpt pool at ARENA_PDPT_POOL, PDs/PTs
// allocated on demand from the phys pool. Unmapped addresses inside a
// reservation trap as WASM_RT_TRAP_OOB through the #PF path.

#define ARENA_VA        (4ull << 40)          // 4 TiB
#define ARENA_PML4_LO   8
#define ARENA_PML4_HI   24                    // 16 pdpts -> 8 TiB of arena
#define ARENA_PDPT_POOL 0x10000ull            // 64KiB of low RAM (free)
#define WREG_MAX        2048

typedef struct { uint64_t va, cap, committed; } WReg;
static WReg wreg[WREG_MAX];
static uint64_t arena_va_next;
static uint64_t va_free[WREG_MAX];      // recycled reservation bases
static size_t va_nfree;
static uint64_t phys_free[1 << 21];    // static: free_push runs in #PF ctx
static size_t phys_nfree;
static uint64_t phys2m_free[4096];     // 2MiB-aligned frames
static size_t phys2m_nfree;

void bad_phys(uint64_t pa);                 // fwd

static uint64_t phys_page(void) {
    if (!phys_nfree && phys2m_nfree) {
        // split a spare 2MiB frame into 512 single pages
        uint64_t base = phys2m_free[--phys2m_nfree];
        size_t cap = sizeof phys_free / sizeof *phys_free;
        for (int i = 0; i < 512 && phys_nfree < cap; i++)
            phys_free[phys_nfree++] = base + i * 4096;
    }
    if (phys_nfree) {
        uint64_t pa = phys_free[--phys_nfree];
        if (pa < heap_lo || pa >= heap_end) bad_phys(pa);
        memset((void *)pa, 0, 4096);               // recycled: must re-zero
        return pa;
    }
    if (phys_next - 4096 < heap_next) return 0;    // out of frames
    phys_next -= 4096;
    return phys_next;                              // untouched -> zeroed
}

void bad_phys(uint64_t pa) {
    char msg[128];
    int n = snprintf(msg, sizeof msg, "BAD-PHYS pa=%llx\n",
                     (unsigned long long)pa);
    kprint(2, msg, n);
    hcall(HC_GUESTFAULT, 98, pa, 0, 0);
    hcall_exit(4);
}

static void free_push(uint64_t pa) {
    if (pa < heap_lo || pa >= heap_end) bad_phys(pa);   // never a valid frame
    if (phys_nfree == sizeof phys_free / sizeof *phys_free)
        return;                                  // leak is better than crash
    phys_free[phys_nfree++] = pa;
}

static void free_push2m(uint64_t pa) {
    if (pa < heap_lo || pa >= heap_end) bad_phys(pa);
    if (phys2m_nfree == sizeof phys2m_free / sizeof *phys2m_free) {
        // overflow: return it as 512 loose pages instead of losing it
        for (int i = 0; i < 512; i++) free_push(pa + i * 4096);
        return;
    }
    phys2m_free[phys2m_nfree++] = pa;
}

// 2MiB-aligned frame for large mappings. Recycled frames first; a fresh carve
// aligns phys_next down, stranding < 2MiB which free_push() recovers below.
static uint64_t phys_page2m(void) {
    if (phys2m_nfree) {
        uint64_t pa = phys2m_free[--phys2m_nfree];
        memset((void *)pa, 0, 0x200000);
        return pa;
    }
    uint64_t base = (phys_next - 0x200000) & ~0x1fffffull;
    if (base < heap_next) return 0;
    // recover the alignment fragment instead of stranding it
    for (uint64_t a = base + 0x200000; a < phys_next; a += 4096)
        free_push(a);
    phys_next = base;
    memset((void *)base, 0, 0x200000);
    return base;
}

static uint64_t *arena_pd(uint64_t va, int create) {
    uint64_t i4 = (va >> 39) & 511, i3 = (va >> 30) & 511;
    uint64_t *pml4 = (uint64_t *)0x1000;
    if (!(pml4[i4] & 1)) {
        if (!create) return NULL;
        uint64_t pa = (i4 >= ARENA_PML4_LO && i4 < ARENA_PML4_HI)
            ? ARENA_PDPT_POOL + (i4 - ARENA_PML4_LO) * 4096
            : phys_page();                       // stack window et al.
        if (!pa) return NULL;
        pml4[i4] = pa | 3;
    }
    uint64_t *pdpt = (uint64_t *)(pml4[i4] & ~4095ull);
    if (!(pdpt[i3] & 1)) {
        if (!create) return NULL;
        uint64_t pa = phys_page();
        if (!pa) return NULL;
        pdpt[i3] = pa | 3;
    }
    return (uint64_t *)(pdpt[i3] & ~4095ull);
}

#define PTE_PS 0x80ull      // large page (2MiB at PD level)

static void arena_unmap_range(uint64_t va, uint64_t len) {
    uint64_t end = va + len;
    for (uint64_t slot = va & ~0x1fffffull; slot < end; slot += 0x200000) {
        uint64_t *pd = arena_pd(slot, 0);
        if (!pd) continue;
        uint64_t i2 = (slot >> 21) & 511;
        uint64_t e = pd[i2];
        if (!(e & 1)) continue;
        if (e & PTE_PS) {                          // whole 2MiB leaf
            pd[i2] = 0;
            __asm__ volatile("invlpg %0" :: "m"(*(volatile char *)slot)
                             : "memory");
            free_push2m(e & ~0x1fffffull);
            continue;
        }
        uint64_t *pt = (uint64_t *)(e & ~4095ull);
        bool empty = true;
        for (int i1 = 0; i1 < 512; i1++) {
            uint64_t a = slot + (uint64_t)i1 * 4096;
            if (!(pt[i1] & 1)) continue;
            if (a < va || a >= end) { empty = false; continue; }
            uint64_t pa = pt[i1] & ~4095ull;
            pt[i1] = 0;
            __asm__ volatile("invlpg %0" :: "m"(*(volatile char *)a)
                             : "memory");
            free_push(pa);
        }
        if (empty) {                               // all leaves gone
            pd[i2] = 0;
            __asm__ volatile("invlpg %0" :: "m"(*(volatile char *)slot)
                             : "memory");
            free_push((uint64_t)(uintptr_t)pt);
        }
    }
}

static WReg *wreg_find(uint64_t addr) {
    for (int i = 0; i < WREG_MAX; i++)
        if (wreg[i].cap && addr >= wreg[i].va && addr < wreg[i].va + wreg[i].cap)
            return &wreg[i];
    return NULL;
}

void *kvm_guest_mmap(size_t size) {                // reserve VA, all unmapped
    for (int i = 0; i < WREG_MAX; i++)
        if (!wreg[i].cap) {
            uint64_t va;
            if (va_nfree && size <= 0x200000000ull) {
                va = va_free[--va_nfree];          // recycled 8GiB slot
            } else {
                va = arena_va_next;
                arena_va_next += (size + 0x3fffffff) & ~0x3fffffffull;
                if (arena_va_next - ARENA_VA >= (8ull << 40)) return NULL;
            }
            wreg[i].va = va; wreg[i].cap = size; wreg[i].committed = 0;
            return (void *)va;
        }
    return NULL;
}

int kvm_guest_mprotect(void *addr, size_t len) {
    uint64_t a = (uint64_t)(uintptr_t)addr, end = a + len;
    WReg *r = wreg_find(a);
    if (!r) return -1;
    for (uint64_t p = a; p < end; ) {
        uint64_t i2 = (p >> 21) & 511;
        uint64_t *pd = arena_pd(p, 1);
        if (!pd) return -1;
        // fully-covered, aligned, still-empty 2MiB slot -> large page
        if (!(p & 0x1fffff) && p + 0x200000 <= end && !(pd[i2] & 1)) {
            uint64_t pa = phys_page2m();
            if (pa) { pd[i2] = pa | PTE_PS | 3; p += 0x200000; continue; }
            // fall through to 4KiB if the phys pool is out of 2MiB room
        }
        if (pd[i2] & PTE_PS) {                    // already inside a large page
            p = (p & ~0x1fffffull) + 0x200000;
            continue;
        }
        if (!(pd[i2] & 1)) {
            uint64_t pa = phys_page();
            if (!pa) return -1;
            pd[i2] = pa | 3;
        }
        uint64_t *pt = (uint64_t *)(pd[i2] & ~4095ull);
        uint64_t i1 = (p >> 12) & 511;
        if (!(pt[i1] & 1)) {
            uint64_t pa = phys_page();
            if (!pa) return -1;
            pt[i1] = pa | 3;
        }
        p += 4096;
    }
    uint64_t off = end - r->va;
    if (off > r->committed) r->committed = off;
    return 0;
}

int kvm_guest_munmap(void *addr, size_t len) {
    uint64_t a = (uint64_t)(uintptr_t)addr;
    WReg *r = wreg_find(a);
    if (!r) return -1;
    (void)len;
    arena_unmap_range(r->va, r->committed);
    if (r->cap >= 0x200000000ull && va_nfree < WREG_MAX)
        va_free[va_nfree++] = r->va;             // recycle the VA slot
    r->cap = r->va = r->committed = 0;
    return 0;
}

// true if cr2 sits in the guard/uncommitted part of a wasm reservation
static bool wasm_oob_fault(uint64_t cr2) {
    WReg *r = wreg_find(cr2);
    return r && cr2 >= r->va + r->committed;
}

// --------------------------------------------- demand-paged thread stacks
// Threads reserve 64MiB of VA each in a window at 16TiB; pages commit on #PF.
// The lowest 4KiB of each reservation stays unmapped as an overflow guard —
// running off the stack bottom faults fatally, same as a native SIGSEGV.

#define STK_VA_BASE   (16ull << 40)      // pml4 index 32, clear of the arena
#define STK_RSV       (64ull << 20)
#define STK_GUARD     4096
#define STK_MAX       8192               // 512 GiB window = one pdpt

static uint64_t stk_bmap[STK_MAX / 64];  // bit set = live reservation

uint64_t stk_rsv_bytes(void) { return STK_RSV; }

void heap_stats(void) {
    int live = 0, u = 0;
    for (int i = 0; i < STK_MAX / 64; i++) live += __builtin_popcountll(stk_bmap[i]);
    for (int i = 0; i < WREG_MAX; i++) if (wreg[i].cap) u++;
    char msg[192];
    int n = snprintf(msg, sizeof msg,
        "heap: next=%llx end=%llx phys_next=%llx nfree=%lu n2m=%lu livestk=%d "
        "va_nfree=%lu wreg=%d\n",
        (unsigned long long)heap_next, (unsigned long long)heap_end,
        (unsigned long long)phys_next, (unsigned long)phys_nfree,
        (unsigned long)phys2m_nfree, live, (unsigned long)va_nfree, u);
    kprint(2, msg, n);
}

uint64_t stk_alloc(void) {               // returns reservation BASE va, or 0
    for (int i = 0; i < STK_MAX / 64; i++)
        if (~stk_bmap[i])
            for (int b = 0; b < 64; b++)
                if (!(stk_bmap[i] & (1ull << b))) {
                    stk_bmap[i] |= 1ull << b;
                    return STK_VA_BASE + (uint64_t)(i * 64 + b) * STK_RSV;
                }
    return 0;
}

void stk_free(uint64_t base) {
    int idx = (int)((base - STK_VA_BASE) / STK_RSV);
    arena_unmap_range(base, STK_RSV);    // return committed frames
    stk_bmap[idx / 64] &= ~(1ull << (idx % 64));
}

// Commit the page containing cr2 if it lies inside a live stack reservation
// above the guard page. 1 = mapped (resume), 0 = not ours, -1 = stack overflow.
static int stk_fault_commit(uint64_t cr2) {
    if (cr2 < STK_VA_BASE || cr2 >= STK_VA_BASE + STK_MAX * STK_RSV)
        return 0;
    uint64_t idx = (cr2 - STK_VA_BASE) / STK_RSV;
    if (!(stk_bmap[idx / 64] & (1ull << (idx % 64)))) return 0;   // stale slot
    if (cr2 - (STK_VA_BASE + idx * STK_RSV) < STK_GUARD) return -1;
    uint64_t a = cr2 & ~4095ull;
    uint64_t *pd = arena_pd(a, 1);
    if (!pd) return -1;
    uint64_t i2 = (a >> 21) & 511;
    if (!(pd[i2] & 1)) {
        uint64_t pa = phys_page();
        if (!pa) return -1;
        pd[i2] = pa | 3;
    }
    uint64_t *pt = (uint64_t *)(pd[i2] & ~4095ull);
    uint64_t i1 = (a >> 12) & 511;
    if (!(pt[i1] & 1)) {
        uint64_t pa = phys_page();
        if (!pa) return -1;
        pt[i1] = pa | 3;
        __asm__ volatile("invlpg %0" :: "m"(*(volatile char *)a) : "memory");
    }
    return 1;
}

extern __thread char g_wasm_rt_jmp_buf[];    // wasm-rt: [0] == initialized (bool)
void wasm_rt_trap(int code);        // WASM_RT_TRAP_OOB == 1

void exc_report(uint64_t vec, uint64_t err, uint64_t rip, uint64_t cr2,
                uint64_t frame) {
    if (vec == 14) {
        // #PF on a live demand-paged stack reservation: commit and resume.
        if (stk_fault_commit(cr2) > 0) return;
        // #PF inside a wasm reservation's guard region == WASM OOB access:
        // deliver the same trap the native SIGSEGV handler would.
        if (wasm_oob_fault(cr2) && g_wasm_rt_jmp_buf[0])
            wasm_rt_trap(1);                // WASM_RT_TRAP_OOB
    }
    hcall(HC_GUESTFAULT, vec, rip, cr2, frame);
    printf("GUEST-EXC vec=%lu err=0x%lx rip=0x%lx cr2=0x%lx\n",
           (unsigned long)vec, (unsigned long)err,
           (unsigned long)rip, (unsigned long)cr2);
    hcall_exit(90 + (int)vec);
}
void abort(void) { kprint(2, "guest abort\n", 12); hcall_exit(134); }
void exit(int code) { hcall_exit(code); }
void _exit(int code) { hcall_exit(code); }
void __assert_fail(const char *e, const char *f, unsigned l, const char *fn) {
    printf("assert %s failed at %s:%u in %s\n", e, f, l, fn);
    abort();
}
char *getenv(const char *n) { (void)n; return NULL; }

int clock_gettime(int clk, struct timespec *ts) {
    uint64_t ns = hcall(HC_NOW, 0, 0, 0, 0);
    ts->tv_sec = ns / 1000000000ull;
    ts->tv_nsec = ns % 1000000000ull;
    return 0;
}

// qsort: insertion sort for tiny n, else simple quicksort
static void isort(uint8_t *b, size_t n, size_t sz,
                  int (*cmp)(const void *, const void *), uint8_t *tmp) {
    for (size_t i = 1; i < n; i++) {
        memcpy(tmp, b + i * sz, sz);
        size_t j = i;
        while (j > 0 && cmp(b + (j - 1) * sz, tmp) > 0) {
            memcpy(b + j * sz, b + (j - 1) * sz, sz);
            j--;
        }
        memcpy(b + j * sz, tmp, sz);
    }
}
static void rqsort(uint8_t *b, size_t n, size_t sz,
                   int (*cmp)(const void *, const void *), uint8_t *tmp) {
    if (n < 24) { isort(b, n, sz, cmp, tmp); return; }
    memcpy(tmp, b + (n / 2) * sz, sz);              // pivot
    size_t i = 0, j = n - 1;
    while (i <= j) {
        while (cmp(b + i * sz, tmp) < 0) i++;
        while (cmp(b + j * sz, tmp) > 0) j--;
        if (i <= j) {
            for (size_t k = 0; k < sz; k++) {
                uint8_t t = b[i * sz + k]; b[i * sz + k] = b[j * sz + k]; b[j * sz + k] = t;
            }
            i++; if (j) j--; else break;
        }
    }
    if (j) rqsort(b, j + 1, sz, cmp, tmp);
    if (i < n) rqsort(b + i * sz, n - i, sz, cmp, tmp);
}
void qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *)) {
    if (n < 2) return;
    uint8_t *tmp = malloc(sz);
    rqsort(base, n, sz, cmp, tmp);
    free(tmp);
}

// ---------------------------------------------------------------- libm

static inline double dabs(double x) { return x < 0 ? -x : x; }

double trunc(double x) {
    int e = (int)((__builtin_bit_cast(uint64_t, x) >> 52) & 0x7ff) - 1023;
    if (e < 0) return __builtin_copysign(0.0, x);
    if (e > 51) return x;
    uint64_t m = __builtin_bit_cast(uint64_t, x);
    m &= ~((1ull << (52 - e)) - 1);
    return __builtin_bit_cast(double, m);
}
float truncf(float x) {
    int e = (int)((__builtin_bit_cast(uint32_t, x) >> 23) & 0xff) - 127;
    if (e < 0) return __builtin_copysignf(0.0f, x);
    if (e > 22) return x;
    uint32_t m = __builtin_bit_cast(uint32_t, x);
    m &= ~((1u << (23 - e)) - 1);
    return __builtin_bit_cast(float, m);
}
double floor(double x) {
    double t = trunc(x);
    return (t > x) ? t - 1.0 : t;
}
float floorf(float x) {
    float t = truncf(x);
    return (t > x) ? t - 1.0f : t;
}
double ceil(double x) {
    double t = trunc(x);
    return (t < x) ? t + 1.0 : t;
}
float ceilf(float x) {
    float t = truncf(x);
    return (t < x) ? t + 1.0f : t;
}
double fabs(double x) { return dabs(x); }
float fabsf(float x) { return x < 0 ? -x : x; }
double fmin(double a, double b) { return a != a ? b : b != b ? a : a < b ? a : b; }
double fmax(double a, double b) { return a != a ? b : b != b ? a : a > b ? a : b; }
float fminf(float a, float b) { return a != a ? b : b != b ? a : a < b ? a : b; }
float fmaxf(float a, float b) { return a != a ? b : b != b ? a : a > b ? a : b; }
double sqrt(double x) { double r; __asm__("sqrtsd %1, %0" : "=x"(r) : "x"(x)); return r; }
float sqrtf(float x) { float r; __asm__("sqrtss %1, %0" : "=x"(r) : "x"(x)); return r; }
double copysign(double x, double y) { return __builtin_copysign(x, y); }
float copysignf(float x, float y) { return __builtin_copysignf(x, y); }
// round-half-even via the 2^52 add/sub trick
double rint(double x) {
    double c = __builtin_copysign(0x1p52, x);
    double r = (x + c) - c;
    return dabs(x) >= 0x1p52 ? x : r;
}
float rintf(float x) {
    float c = __builtin_copysignf(0x1p23f, x);
    float r = (x + c) - c;
    return (x < 0 ? -x : x) >= 0x1p23f ? x : r;
}
double nearbyint(double x) { return rint(x); }
float nearbyintf(float x) { return rintf(x); }
double round(double x) { double t = trunc(x); return dabs(x - t) >= 0.5 ? t + __builtin_copysign(1.0, x) : t; }
float roundf(float x) { float t = truncf(x); float d = x - t; return (d < 0 ? -d : d) >= 0.5f ? t + __builtin_copysignf(1.0f, x) : t; }
long lrint(double x) { return (long)rint(x); }
long lrintf(float x) { return (long)rintf(x); }
long long llrint(double x) { return (long long)rint(x); }
long long llrintf(float x) { return (long long)rintf(x); }
double fmod(double x, double y) { double q = trunc(x / y); return x - q * y; }
float fmodf(float x, float y) { float q = truncf(x / y); return x - q * y; }
double nan(const char *s) { (void)s; return __builtin_bit_cast(double, 0x7ff8000000000000ull); }

// ---------------------------------------------------------------- boot glue

extern char _end[];
static uint64_t _end_guest(void) { return (uint64_t)_end; }

struct bootinfo *const BOOT = (void *)BOOTINFO_GPA;
int kmain(void);


/* -finstrument-functions profiler: bucket histogram over guest text.
   Keep BSS total well under MBX_ARENA_GPA (64MiB) or we overlap mailboxes. */
#define PROF_BASE KERNEL_LINK
#define PROF_BITS 21
static uint64_t prof_hist[1 << PROF_BITS];
__attribute__((no_instrument_function, hot))
void __cyg_profile_func_enter(void *fn, void *caller) {
    (void)caller;
    uint64_t a = (uint64_t)(uintptr_t)fn - PROF_BASE;
    if (a < ((uint64_t)1 << (PROF_BITS + 4)))
        prof_hist[a >> 4]++;
}
__attribute__((no_instrument_function))
void __cyg_profile_func_exit(void *fn, void *caller) {
    (void)fn; (void)caller;
}

__attribute__((noinline)) static uint64_t bench_alu(uint64_t n) {
    uint64_t a = 0x9e3779b97f4a7c15ull;
    for (uint64_t i = 0; i < n; i++) {
        a ^= a >> 29; a *= 0xbf58476d1ce4e5b9ull; a += i;
    }
    return a;
}
__attribute__((noinline)) static uint64_t bench_mem(void *p, size_t n, int reps) {
    uint64_t t = 0;
    for (int i = 0; i < reps; i++) { memset(p, i, n); t += ((uint8_t *)p)[i]; }
    return t;
}
__attribute__((noinline)) static uint64_t bench_memcpy(void *d, const void *s,
                                                       size_t n, int reps) {
    uint64_t t = 0;
    for (int i = 0; i < reps; i++) { memcpy(d, s, n); t += ((uint8_t *)d)[i]; }
    return t;
}
/* random pointer chase: one dependent load per 4KB page -> TLB-walk bound */
__attribute__((noinline)) static uint64_t bench_chase(uint64_t *p, size_t pages,
                                                      uint64_t steps) {
    /* random permutation-ish stride chain: fill each page's first slot with
       the index of the next page to visit */
    uint64_t m = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < pages; i++) p[i * 512] = i;
    for (size_t i = pages - 1; i > 0; i--) {           /* shuffle */
        m ^= m >> 29; m *= 0xbf58476d1ce4e5b9ull;
        size_t j = m % (i + 1);
        uint64_t t = p[i * 512]; p[i * 512] = p[j * 512]; p[j * 512] = t;
    }
    /* p[i*512] now holds a permutation; chase follows random cycles */
    uint64_t cur = 0, acc = 0;
    for (uint64_t s = 0; s < steps; s++) {
        cur = p[cur * 512];
        acc += cur;
    }
    return acc;
}

void guest_boot(void) {
    idt_init();
    idt_load();
    tls_copy();
    heap_next = ((uint64_t)_end_guest() + 4095) & ~4095ull;
    heap_end = BOOT->ram_size - BSP_STACK_RESERVE;
    phys_next = heap_end;                 // phys pool takes from the top down
    heap_lo = heap_next; heap_hi = heap_end;
    arena_va_next = ARENA_VA;
    hcall(HC_PROF, (uint64_t)prof_hist, sizeof prof_hist, 0, 0);
    if (BOOT->debug == 998) {
        // mem function self-test inside the guest
        static uint8_t src[8192], dst[8192], ref[8192];
        int bad = -1, bn = -1, bj = -1;
        for (int i = 0; i < 8192; i++) src[i] = (uint8_t)(i * 37 + 11);
        for (int n = 0; n < 8192 && bad < 0; n++) {
            for (int j = 0; j < 8192; j++) { dst[j] = 0xAA; ref[j] = 0xAA; }
            memcpy(dst, src, n);                       // mine
            __builtin_memcpy(ref, src, n);             // compiler's
            for (int j = 0; j < 8192; j++)
                if (dst[j] != ref[j]) { bad = 1; bn = n; bj = j; break; }
            if (bad >= 0) break;
            for (int j = 0; j < 8192; j++) { dst[j] = 0xAA; ref[j] = 0xAA; }
            memset(dst, 0x5A, n);
            __builtin_memset(ref, 0x5A, n);
            for (int j = 0; j < 8192; j++)
                if (dst[j] != ref[j]) { bad = 2; bn = n; bj = j; break; }
        }
        // overlap memmove
        for (int off = 0; off < 1000 && bad < 0; off += 7) {
            for (int j = 0; j < 8192; j++) dst[j] = (uint8_t)j;
            memmove(dst + off, dst, 4000);
            for (int j = 0; j < 4000; j++)
                if (dst[off + j] != (uint8_t)j) { bad = 3; bn = off; bj = j; break; }
        }
        char msg[160];
        int k = snprintf(msg, sizeof msg,
                         "MEMTEST bad=%d n=%d j=%d d=%02x r=%02x srcj=%02x\n",
                         bad, bn, bj,
                         bj >= 0 && bj < 8192 ? dst[bj] : 0,
                         bj >= 0 && bj < 8192 ? ref[bj] : 0,
                         bj >= 0 && bj < 8192 ? src[bj] : 0);
        kprint(2, msg, k);
        hcall_exit(bad < 0 ? 0 : 3);
    }
    if (BOOT->debug == 999) {
        uint64_t t0 = hcall(HC_NOW, 0, 0, 0, 0);
        uint64_t r = bench_alu(300000000);
        uint64_t t1 = hcall(HC_NOW, 0, 0, 0, 0);
        void *buf = malloc(256 << 20);
        uint64_t t2 = hcall(HC_NOW, 0, 0, 0, 0);
        uint64_t r2 = bench_mem(buf, 64 << 20, 4);
        uint64_t t3 = hcall(HC_NOW, 0, 0, 0, 0);
        void *buf2 = malloc(64 << 20);
        uint64_t r3 = bench_memcpy(buf2, buf, 64 << 20, 8);
        uint64_t t4 = hcall(HC_NOW, 0, 0, 0, 0);
        uint64_t *chase = malloc(4ull << 30);
        uint64_t r4 = bench_chase(chase, (4ull << 30) / 4096, 8000000);
        uint64_t t5 = hcall(HC_NOW, 0, 0, 0, 0);
        char msg[192];
        int n = snprintf(msg, sizeof msg,
                         "BENCH alu=%lums mem=%lums copy=%lums (%llx %llx %llx)\n",
                         (unsigned long)(t1 - t0) / 1000000,
                         (unsigned long)(t3 - t2) / 1000000,
                         (unsigned long)(t4 - t3) / 1000000,
                         (unsigned long long)r, (unsigned long long)r2,
                         (unsigned long long)r3);
        kprint(2, msg, n);
        n = snprintf(msg, sizeof msg, "CHASE %lums (%llx)\n",
                     (unsigned long)(t5 - t4) / 1000000,
                     (unsigned long long)r4);
        kprint(2, msg, n);
        hcall_exit(0);
    }
    int rc = kmain();
    if (BOOT->debug == 16) {
        char msg[160];
        int n = snprintf(msg, sizeof msg,
                         "bulkops: memset=%lluMB memcpy=%lluMB memmove=%lluMB\n",
                         (unsigned long long)(ms_bytes >> 20),
                         (unsigned long long)(mc_bytes >> 20),
                         (unsigned long long)(mm_bytes >> 20));
        kprint(2, msg, n);
    }
    hcall_exit(rc);
}


