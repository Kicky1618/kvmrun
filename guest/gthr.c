// gthr.c — cooperative threads on the single BSP vCPU.
//
// The match engine <-> bot protocol is strictly serial: at any moment only
// one side can make progress, so real parallelism buys nothing. Running all
// threads as cooperative contexts on one vCPU replaces every
// hypercall+futex+VM-exit wake (~10-40us round trip) with an in-guest
// context switch (~50 cycles). Threads block only on mutex/cond/futex ops;
// when the run queue is empty the vCPU hcall-parks until the nearest
// timedwait deadline.
#define KVMRUN_GUEST 1
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include "../abi.h"

uint64_t hcall(uint32_t nr, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
void kprint(int fd, const void *buf, uint64_t len);
extern char __tls_start[], __tdata_end[], __tbss_end[];

void gctx_run(void);                     // first C frame on a new ctx
void gctx_switch(void *from, void *to);  // entry.S: ctx = {rsp, tp, ...}
void tls_copy_to(uint64_t tp);           // klibc.c
uint64_t stk_alloc(void);                // klibc.c: demand-paged VA stack
void stk_free(uint64_t base);
uint64_t stk_rsv_bytes(void);

#define TLS_RESERVE 16384                // TLS zone at top of stack

enum { BLK_MUTEX = 1, BLK_CV, BLK_FUTEX };

typedef struct gctx {
    uint64_t rsp;                        // 0: saved rsp (switch sw)
    uint64_t tp;                         // 8: TLS/self pointer
    struct gctx *next;                   // 16: queue link
    uint64_t deadline;                   // 24: abs ns, 0 = untimed
    int wake_rc;                         // 32: 0 ok, ETIMEDOUT/1 timeout
    int why;                             // 36: BLK_*
    volatile uint32_t *key;              // 40: wait word/queue owner
    uint8_t *stack;                      // 48: malloc base (NULL = BSP)
    void *(*fn)(void *);                 // 56
    void *arg;                           // 64
} gctx;

_Static_assert(__builtin_offsetof(gctx, rsp) == 0, "rsp off");
_Static_assert(__builtin_offsetof(gctx, tp) == 8, "tp off");

static gctx *cur;                        // running context
static gctx *rqh, *rqt;                  // runnable FIFO
static gctx *blocked;                    // all blocked ctx (any primitive)
static gctx *zombies;                    // exited, freed on next schedule
static gctx bsp_ctx;
static volatile uint32_t idle_word;      // never signaled; idle-park word

static void rq_put(gctx *t) {
    t->next = 0;
    if (rqt) rqt->next = t; else rqh = t;
    rqt = t;
}
static gctx *rq_get(void) {
    gctx *t = rqh;
    if (t) { rqh = t->next; if (!rqh) rqt = 0; }
    return t;
}
static void blk_put(gctx *t) {           // FIFO on the blocked list
    t->next = 0;
    if (!blocked) { blocked = t; return; }
    gctx *p = blocked;
    while (p->next) p = p->next;
    p->next = t;
}
static void blk_remove(gctx *t) {
    gctx **pp = &blocked;
    while (*pp) {
        if (*pp == t) { *pp = t->next; return; }
        pp = &(*pp)->next;
    }
}
static void blk_wake_one(volatile uint32_t *key, int why) {
    for (gctx *t = blocked; t; t = t->next)
        if (t->key == key && t->why == why) {
            blk_remove(t);
            t->wake_rc = 0; t->key = 0;
            rq_put(t);
            return;
        }
}
static int blk_wake_all(volatile uint32_t *key, int why, int count) {
    int n = 0;
    gctx *t = blocked;
    while (t) {
        gctx *nx = t->next;
        if (t->key == key && t->why == why) {
            blk_remove(t);
            t->wake_rc = 0; t->key = 0;
            rq_put(t);
            if (++n >= count) return n;
        }
        t = nx;
    }
    return n;
}

static void free_zombies(void) {
    while (zombies) {
        gctx *z = zombies;
        zombies = z->next;
        if (z->stack)
            stk_free((uint64_t)(uintptr_t)z->stack);
        free(z);
    }
}

static uint64_t vmm_now(void) { return hcall(HC_NOW, 0, 0, 0, 0); }

// pick next runnable ctx; parks the vCPU when nobody can run
static void schedule(void) {
    for (;;) {
        gctx *n = rq_get();
        if (n) {
            if (n == cur) return;        // only we are runnable
            gctx *from = cur;
            cur = n;
            gctx_switch(from, n);        // resumes here when re-scheduled
            free_zombies();              // safe now: we're the resumed ctx
            return;
        }
        // run queue empty: wake expired timed waiters, else park till the
        // earliest deadline (or forever — that would be a protocol deadlock)
        uint64_t now = vmm_now();
        uint64_t dl = 0;
        bool woke = false;
        for (gctx *t = blocked; t; t = t->next)
            if (t->deadline && t->deadline <= now) {
                t->wake_rc = 1; t->deadline = 0;
                woke = true;
            }
        if (woke) {
            gctx *t = blocked;
            while (t) {
                gctx *nx = t->next;
                if (t->wake_rc == 1) { blk_remove(t); t->key = 0; rq_put(t); }
                t = nx;
            }
            continue;
        }
        for (gctx *t = blocked; t; t = t->next)
            if (t->deadline && (!dl || t->deadline < dl)) dl = t->deadline;
        if (!dl) {
            kprint(2, "sched: deadlock (all threads blocked)\n", 38);
            hcall(HC_EXIT, 134, 0, 0, 0);
        }
        hcall(HC_FUTEX_WAIT, (uint64_t)(uintptr_t)&idle_word,
              idle_word, dl, 0);
    }
}

static void block_cur(int why, volatile uint32_t *key, uint64_t deadline) {
    cur->why = why; cur->key = key; cur->deadline = deadline;
    blk_put(cur);
    schedule();
    cur->why = 0; cur->deadline = 0;
}

void sched_init(void) {
    if (cur) return;
    memset(&bsp_ctx, 0, sizeof bsp_ctx);
    __asm__ volatile("mov %%fs:0, %0" : "=r"(bsp_ctx.tp));
    cur = &bsp_ctx;
}

// ---------------------------------------------------------------- threads

int pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *),
                   void *arg) {
    sched_init();
    (void)attr;
    gctx *g = malloc(sizeof *g);
    memset(g, 0, sizeof *g);
    uint64_t base = stk_alloc();
    if (!base) { free(g); return -1; }
    uint64_t top = (base + stk_rsv_bytes()) & ~63ull;
    uint64_t tp = top - 16;              // fs:0/fs:8 stay inside the block
    uint64_t tsize = (uint64_t)__tbss_end - (uint64_t)__tls_start;
    if (tsize + 16 > TLS_RESERVE) { stk_free(base); free(g); return -1; }
    tls_copy_to(tp);                     // fills [tp-tsize, tp+16)
    uint64_t sp = (tp - TLS_RESERVE) & ~15ull;   // ≡0 mod 16
    sp -= 16; *(uint64_t *)sp = (uint64_t)gctx_run;    // ret slot ≡0 mod 16
    sp -= 48; memset((void *)sp, 0, 48);               // r15..rbp image
    g->rsp = sp; g->tp = tp; g->stack = (uint8_t *)(uintptr_t)base;
    g->fn = fn; g->arg = arg;
    rq_put(g);
    if (t) *t = (pthread_t)(uintptr_t)g;
    return 0;
}

// entry.S lands here on a fresh ctx (cur == us); never returns
void gctx_run(void) {
    gctx *me = cur;
    me->fn(me->arg);
    me->next = zombies; zombies = me;    // freed after we switch away
    schedule();                          // switch out for good
    for (;;) __asm__ volatile("hlt");
}

int pthread_detach(pthread_t t) { (void)t; return 0; }
int pthread_join(pthread_t t, void **rc) { (void)t; (void)rc; return 0; }
pthread_t pthread_self(void) { return (pthread_t)(uintptr_t)cur; }

// ---------------------------------------------------------------- mutex

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    (void)a; m->v = 0; m->waiters = 0; return 0;
}
int pthread_mutex_lock(pthread_mutex_t *m) {
    sched_init();
    uint32_t exp = 0;
    while (!__atomic_compare_exchange_n(&m->v, &exp, true, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        block_cur(BLK_MUTEX, &m->v, 0);
        exp = 0;
    }
    return 0;
}
int pthread_mutex_unlock(pthread_mutex_t *m) {
    __atomic_store_n(&m->v, 0, __ATOMIC_RELEASE);
    blk_wake_one(&m->v, BLK_MUTEX);
    return 0;
}
int pthread_mutex_destroy(pthread_mutex_t *m) { (void)m; return 0; }

// ---------------------------------------------------------------- cond

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    (void)a; c->seq = 0; c->waiters = 0; return 0;
}
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    pthread_mutex_unlock(m);
    block_cur(BLK_CV, &c->seq, 0);
    pthread_mutex_lock(m);
    return 0;
}
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *dl) {
    pthread_mutex_unlock(m);
    block_cur(BLK_CV, &c->seq,
              (uint64_t)dl->tv_sec * 1000000000ull + dl->tv_nsec);
    int rc = cur->wake_rc == 1 ? ETIMEDOUT : 0;
    pthread_mutex_lock(m);
    return rc;
}
int pthread_cond_signal(pthread_cond_t *c) {
    __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELEASE);
    blk_wake_one(&c->seq, BLK_CV);
    return 0;
}
int pthread_cond_broadcast(pthread_cond_t *c) {
    __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELEASE);
    blk_wake_all(&c->seq, BLK_CV, 0x7fffffff);
    return 0;
}
int pthread_cond_destroy(pthread_cond_t *c) { (void)c; return 0; }
int sched_yield(void) { sched_init(); rq_put(cur); schedule(); return 0; }

// ---------------------------------------------------------------- futex
// Same ABI as before for klibc's alock; blocking goes through the coop
// scheduler instead of hypercalls. Single-CPU execution makes the
// check-then-block sequence atomic.

int g_futex_wait(uint32_t *addr, uint32_t expected, uint64_t dl_ns) {
    sched_init();
    if (__atomic_load_n(addr, __ATOMIC_ACQUIRE) != expected) return 2;
    block_cur(BLK_FUTEX, (volatile uint32_t *)addr, dl_ns);
    return cur->wake_rc == 1 ? 1 : 0;
}
int g_futex_wake(uint32_t *addr, uint32_t count) {
    return blk_wake_all((volatile uint32_t *)addr, BLK_FUTEX, count ? count : 0x7fffffff);
}

char *getcwd(char *b, size_t n) { if (n) b[0] = 0; return b; }
int errno;
