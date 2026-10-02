// gthr.c — cooperative threads on the single BSP vCPU.
//
// The match engine <-> bot protocol is strictly serial: at any moment only
// one side can make progress, so real parallelism buys nothing. Running all
// threads as cooperative contexts on one vCPU replaces every
// hypercall+futex+VM-exit wake (~10-40us round trip) with an in-guest
// context switch (~50 cycles). Threads block only on mutex/cond/futex ops;
// when the run queue is empty the vCPU hcall-parks until the nearest
// timedwait deadline.
//
// Waiters live on per-primitive queues (mutex->wq, cond->wq, or a futex
// hash bucket) so wake/block/timeout are O(1) — a global scan per op is
// quadratic once a map keeps thousands of dragon threads parked.
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
uint64_t guest_now(void);                 // klibc.c: rdtsc-based clock
extern char __tls_start[], __tdata_end[], __tbss_end[];

void gctx_run(void);                     // first C frame on a new ctx
void gctx_switch(void *from, void *to);  // entry.S: ctx = {rsp, tp, ...}
void tls_copy_to(uint64_t tp);           // klibc.c
uint64_t stk_alloc(void);                // klibc.c: demand-paged VA stack
void stk_free(uint64_t base);
uint64_t stk_rsv_bytes(void);

#define TLS_RESERVE 16384                // TLS zone at top of stack

enum { BLK_MUTEX = 1, BLK_CV, BLK_FUTEX, BLK_JOIN };

typedef struct gctx {
    uint64_t rsp;                        // 0: saved rsp (switch sw)
    uint64_t tp;                         // 8: TLS/self pointer
    struct gctx *next;                   // 16: run-queue link
    struct gctx *wnext;                  // 24: wait-queue link
    struct gctx **wprev;                 // 32: back-link into the wait queue
    struct gctx *tnext;                  // 40: timed-wait list link
    struct gctx **tprev;                 // 48: back-link into the timed list
    uint64_t deadline;                   // 56: abs ns, 0 = untimed
    int wake_rc;                         // 64: 0 ok, 1 timeout
    int why;                             // 68: BLK_*
    volatile uint32_t *key;              // 72: futex word (bucket disambig)
    uint8_t *stack;                      // 80: malloc base (NULL = BSP)
    void *(*fn)(void *);                 // 88
    void *arg;                           // 96
    void *retval;                        // 104: pthread_join result
    int done;                            // 112: 1=exited, 2=joined
    int in_z;                            // 116: still linked on zombies
    struct gctx *joinq;                  // 120: join waiters (wq)
} gctx;

_Static_assert(__builtin_offsetof(gctx, rsp) == 0, "rsp off");
_Static_assert(__builtin_offsetof(gctx, tp) == 8, "tp off");

static gctx *cur;                        // running context
static gctx *rqh, *rqt;                  // runnable FIFO
static gctx *timed;                      // contexts with a deadline set
static gctx *zombies;                    // exited; stacks freed on schedule
static gctx *gpool;                      // joined ctxs ready for reuse (wnext)
static gctx bsp_ctx;
static volatile uint32_t idle_word;      // never signaled; idle-park word

#define FHT 64                           // futex addr -> wait queue
static gctx *fhtab[FHT];

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

// intrusive FIFO wait queue: t->wprev points at the link naming us
// (the head pointer or the previous node's wnext)
static void wq_put(gctx **head, gctx *t) {
    t->wnext = 0;
    if (!*head) { *head = t; t->wprev = head; return; }
    gctx *p = *head;
    while (p->wnext) p = p->wnext;
    p->wnext = t; t->wprev = &p->wnext;
}
static gctx *wq_pop(gctx **head) {
    gctx *t = *head;
    if (!t) return 0;
    *head = t->wnext;
    if (t->wnext) t->wnext->wprev = head;
    t->wnext = 0; t->wprev = 0;
    return t;
}
static void wq_remove(gctx *t) {
    *t->wprev = t->wnext;
    if (t->wnext) t->wnext->wprev = t->wprev;
    t->wnext = 0; t->wprev = 0;
}

// timed list: intrusive singly-linked-out, link-pointer back — O(1) remove,
// required when thousands of timed waiters wake normally per turn
static void timed_put(gctx *t) {
    t->tnext = timed;
    if (timed) timed->tprev = &t->tnext;
    t->tprev = &timed;
    timed = t;
}
static void timed_remove(gctx *t) {
    *t->tprev = t->tnext;
    if (t->tnext) t->tnext->tprev = t->tprev;
    t->tnext = 0; t->tprev = 0;
}

// move a ctx from its wait queue back to the run queue; a runnable ctx must
// never keep a live deadline (schedule() would "expire" it mid-run)
static void wake_ctx(gctx *t) {
    if (t->deadline) { timed_remove(t); t->deadline = 0; }
    t->wake_rc = 0; t->key = 0;
    rq_put(t);
}

static void free_zombies(void) {
    while (zombies) {
        gctx *z = zombies;
        zombies = z->next;
        z->in_z = 0;
        if (z->stack)
            stk_free((uint64_t)(uintptr_t)z->stack);
        z->stack = 0;
        // already joined: nobody will touch it again -> recycle. Unjoined
        // ctxs stay allocated; a later pthread_join may still read retval.
        if (z->done == 2) { z->wnext = gpool; gpool = z; }
    }
}

static uint64_t vmm_now(void) { return guest_now(); }

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
        gctx *t = timed;
        while (t) {
            gctx *nx = t->tnext;
            if (t->deadline <= now) {
                timed_remove(t);
                t->deadline = 0;
                if (t->wprev) {              // still queued: it timed out
                    wq_remove(t);
                    t->wake_rc = 1; t->key = 0;
                    rq_put(t);
                }
            } else if (!dl || t->deadline < dl) {
                dl = t->deadline;
            }
            t = nx;
        }
        if (rqh) continue;                     // we woke someone
        if (!dl) {
            kprint(2, "sched: deadlock (all threads blocked)\n", 38);
            hcall(HC_EXIT, 134, 0, 0, 0);
        }
        hcall(HC_FUTEX_WAIT, (uint64_t)(uintptr_t)&idle_word,
              idle_word, dl, 0);
    }
}

static void block_cur(gctx **wq, volatile uint32_t *key, uint64_t deadline) {
    cur->why = key ? BLK_FUTEX : BLK_MUTEX;    // why is informational now
    cur->key = key;
    cur->wake_rc = 0;
    wq_put(wq, cur);
    cur->deadline = deadline;
    if (deadline) timed_put(cur);
    schedule();
    if (cur->deadline) { timed_remove(cur); cur->deadline = 0; }
    cur->key = 0;
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
    gctx *g = gpool;
    if (g) gpool = g->wnext;
    else g = malloc(sizeof *g);
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
    me->retval = me->fn(me->arg);
    me->done = 1;
    while (me->joinq) {                  // wake joiners before becoming zombie
        gctx *j = wq_pop(&me->joinq);
        wake_ctx(j);
    }
    me->next = zombies; zombies = me;    // stack freed after we switch away
    me->in_z = 1;
    schedule();                          // switch out for good
    for (;;) __asm__ volatile("hlt");
}

int pthread_detach(pthread_t t) { (void)t; return 0; }
int pthread_join(pthread_t t, void **rc) {
    sched_init();
    gctx *g = (gctx *)(uintptr_t)t;
    if (!g) return EINVAL;
    if (g == cur) return EDEADLK;
    if (g->done == 2) return EINVAL;     // already joined / stale handle
    if (!g->done)
        block_cur(&g->joinq, 0, 0);      // cooperative: no lost wake
    if (rc) *rc = g->retval;
    g->done = 2;
    if (g->stack) { stk_free((uint64_t)(uintptr_t)g->stack); g->stack = 0; }
    // if the zombie drain already ran we own disposal; otherwise
    // free_zombies() will recycle the ctx once it unlinks it
    if (!g->in_z) { g->wnext = gpool; gpool = g; }
    return 0;
}
pthread_t pthread_self(void) { return (pthread_t)(uintptr_t)cur; }

// ---------------------------------------------------------------- mutex

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    (void)a; m->v = 0; m->wq = 0; return 0;
}
int pthread_mutex_lock(pthread_mutex_t *m) {
    sched_init();
    uint32_t exp = 0;
    while (!__atomic_compare_exchange_n(&m->v, &exp, true, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        block_cur(&m->wq, 0, 0);
        exp = 0;
    }
    return 0;
}
int pthread_mutex_unlock(pthread_mutex_t *m) {
    __atomic_store_n(&m->v, 0, __ATOMIC_RELEASE);
    gctx *t = wq_pop(&m->wq);
    if (t) wake_ctx(t);
    return 0;
}
int pthread_mutex_destroy(pthread_mutex_t *m) { (void)m; return 0; }

// ---------------------------------------------------------------- cond

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    (void)a; c->seq = 0; c->wq = 0; return 0;
}
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    pthread_mutex_unlock(m);
    block_cur(&c->wq, 0, 0);
    pthread_mutex_lock(m);
    return 0;
}
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *dl) {
    pthread_mutex_unlock(m);
    block_cur(&c->wq, 0,
              (uint64_t)dl->tv_sec * 1000000000ull + dl->tv_nsec);
    int rc = cur->wake_rc == 1 ? ETIMEDOUT : 0;
    pthread_mutex_lock(m);
    return rc;
}
int pthread_cond_signal(pthread_cond_t *c) {
    __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELEASE);
    gctx *t = wq_pop(&c->wq);
    if (t) wake_ctx(t);
    return 0;
}
int pthread_cond_broadcast(pthread_cond_t *c) {
    __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELEASE);
    gctx *t;
    while ((t = wq_pop(&c->wq))) wake_ctx(t);
    return 0;
}
int pthread_cond_destroy(pthread_cond_t *c) { (void)c; return 0; }
int sched_yield(void) { sched_init(); rq_put(cur); schedule(); return 0; }

// ---------------------------------------------------------------- futex
// Same ABI as before for klibc's alock; blocking goes through the coop
// scheduler instead of hypercalls. Single-CPU execution makes the
// check-then-block sequence atomic.

static gctx **fut_bucket(volatile uint32_t *addr) {
    return &fhtab[((uintptr_t)addr >> 2) * 2654435761u % FHT];
}

int g_futex_wait(uint32_t *addr, uint32_t expected, uint64_t dl_ns) {
    sched_init();
    if (__atomic_load_n(addr, __ATOMIC_ACQUIRE) != expected) return 2;
    block_cur(fut_bucket((volatile uint32_t *)addr),
              (volatile uint32_t *)addr, dl_ns);
    return cur->wake_rc == 1 ? 1 : 0;
}
int g_futex_wake(uint32_t *addr, uint32_t count) {
    gctx **b = fut_bucket((volatile uint32_t *)addr);
    int n = 0;
    gctx *t = *b;
    while (t && (uint32_t)n < (count ? count : 0x7fffffff)) {
        gctx *nx = t->wnext;
        if (t->key == (volatile uint32_t *)addr) {
            wq_remove(t);
            wake_ctx(t);
            n++;
        }
        t = nx;
    }
    return n;
}

char *getcwd(char *b, size_t n) { if (n) b[0] = 0; return b; }
int errno;
