// host.c — runs one match: wasm2c-compiled engine + two bots, judge-faithful.
//
// Built once per (botA, botB) pair by kvmrun.py with module prefixes
// `engine`, `bota`, `botb`. Semantics mirror unswbc's sandbox.py/turn.py:
// pipes for stdin/stdout, ENDTURN/stdin-park/exit/10s turn end, CPU-point
// metering via the injected wasmer_metering_* globals, virtual clock,
// seeded xoshiro RNG, frozen gate between turns.
//
// KVMRUN_GUEST builds run freestanding inside the KVM guest (see guest/);
// otherwise this links as a normal Linux binary.
#ifdef KVMRUN_GUEST
#include "abi.h"
#else
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wasm-rt.h"
#include "wasm-rt-exceptions.h"
#include "wasm-rt-impl.h"
#include <ctype.h>

#include "engine.h"
#include "bota.h"
#include "botb.h"

#define NORETURN __attribute__((noreturn))

#define MAX_TURN_POINTS 100000000LL
#define MAX_MEMORY_PAGES 768
#define WRITE_SYSCALL_COST 2500000LL
#define WRITE_BYTE_COST 4000LL
#define READ_BYTE_COST 6LL
#define VIRTUAL_EPOCH_NS 1767225600000000000LL
#define INITIAL_POINTS ((int64_t)(((uint64_t)1 << 63) - 1))
#define BUFFER_LIMIT (10 * 1024)
#define WALL_LIMIT_S 10.0
#define MAX_IOV 4096                   // cap host-side iov walks (unmetered)
#define STDERR_CAP (1u << 20)          // bounded diagnostics buffer

// ---------------------------------------------------------------- rng

typedef struct { uint64_t s[4]; } Rng;

static uint64_t rng_next(Rng *r) {
    uint64_t *s = r->s;
    uint64_t x = s[1] * 5;
    x = (x << 7) | (x >> (64 - 7));
    uint64_t out = x * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t;
    s[3] = (s[3] << 45) | (s[3] >> (64 - 45));
    return out;
}

// sha256 — official seeds dragon RNGs with sha256(key "\0" proc)
static const uint32_t SHK[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static void sha256(const void *data_, size_t len, uint8_t out[32]) {
    const uint8_t *data = data_;
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[256];
    size_t bl = (len + 9 + 63) & ~63ull;
    memset(blk, 0, bl);
    memcpy(blk, data, len);
    blk[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blk[bl - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < bl; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)blk[off + 4*i] << 24 | (uint32_t)blk[off + 4*i + 1] << 16 |
                   (uint32_t)blk[off + 4*i + 2] << 8 | blk[off + 4*i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = (w[i-15] >> 7 | w[i-15] << 25) ^ (w[i-15] >> 18 | w[i-15] << 14) ^ (w[i-15] >> 3);
            uint32_t s1 = (w[i-2] >> 17 | w[i-2] << 15) ^ (w[i-2] >> 19 | w[i-2] << 13) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
                 e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
            uint32_t t1 = hh + S1 + ((e & f) ^ (~e & g)) + SHK[i] + w[i];
            uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
            uint32_t t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)(h[i] >> 24); out[4*i+1] = (uint8_t)(h[i] >> 16);
        out[4*i+2] = (uint8_t)(h[i] >> 8); out[4*i+3] = (uint8_t)h[i];
    }
}

// official: Rng(key, proc) = xoshiro256** over sha256(key + "\0" + proc),
// where key = "{seed:016x}-{team}" and proc = str(dragon_id).
static uint64_t g_seed;
static void rng_seed(Rng *r, const char *key, const char *proc) {
    uint8_t dig[32], buf[96];
    size_t kl = strlen(key), pl = strlen(proc);
    if (kl + 1 + pl > sizeof buf) return;         // never: key<=19, proc<=11
    memcpy(buf, key, kl);
    buf[kl] = 0;
    memcpy(buf + kl + 1, proc, pl);
    sha256(buf, kl + 1 + pl, dig);
    for (int i = 0; i < 4; i++) {
        const uint8_t *d = dig + 8 * i;
        r->s[i] = (uint64_t)d[0] | (uint64_t)d[1] << 8 | (uint64_t)d[2] << 16 |
                  (uint64_t)d[3] << 24 | (uint64_t)d[4] << 32 |
                  (uint64_t)d[5] << 40 | (uint64_t)d[6] << 48 | (uint64_t)d[7] << 56;
    }
}

static void rng_fill(Rng *r, uint8_t *dst, size_t n) {
    size_t off = 0;
    while (off < n) {
        uint64_t v = rng_next(r);
        size_t c = n - off < 8 ? n - off : 8;
        memcpy(dst + off, &v, c);
        off += c;
    }
}

// ---------------------------------------------------------------- pipes

typedef struct Pipe {
    uint8_t *buf;
    size_t len, cap;
    bool closed;
    int parks;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_cond_t *wake;            // also signaled on park (turn poller's cv)
    pthread_mutex_t *wake_mu;
    volatile uint64_t *wake_seq;     // ...and its seq counter (bot->out_seq)
} Pipe;

static void pipe_init(Pipe *p) {
    memset(p, 0, sizeof *p);
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
}

static void pipe_feed(Pipe *p, const uint8_t *d, size_t n) {
    pthread_mutex_lock(&p->mu);
    if (p->len + n > p->cap) {
        p->cap = (p->len + n) * 2 + 64;
        p->buf = realloc(p->buf, p->cap);
    }
    memcpy(p->buf + p->len, d, n);
    p->len += n;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

// forward: bump the poller-visible seq and broadcast (under out.mu)
struct Bot;
static void bot_kick(struct Bot *b);

static size_t pipe_read(Pipe *p, uint8_t *d, size_t n) {
    pthread_mutex_lock(&p->mu);
    bool parked = false;
    while (p->len == 0 && !p->closed) {
        if (!parked) {
            parked = true;
            p->parks++;
            pthread_cond_broadcast(&p->cv);   // wake the turn poller
            if (p->wake) {                    // == &bot->out.cv / &bot->out.mu
                pthread_mutex_t *wmu = p->wake_mu;
                pthread_mutex_lock(wmu);
                if (p->wake_seq) (*p->wake_seq)++;
                pthread_cond_broadcast(p->wake);
                pthread_mutex_unlock(wmu);
            }
        }
        pthread_cond_wait(&p->cv, &p->mu);
    }
    size_t c = p->len < n ? p->len : n;
    memcpy(d, p->buf, c);
    memmove(p->buf, p->buf + c, p->len - c);
    p->len -= c;
    pthread_mutex_unlock(&p->mu);
    return c;
}

static void pipe_close(Pipe *p) {
    pthread_mutex_lock(&p->mu);
    p->closed = true;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

// ---------------------------------------------------------------- framer

typedef struct Framer {
    bool armed, done;
    int64_t park_at;
    uint8_t out[BUFFER_LIMIT]; size_t out_len;
    uint8_t line[BUFFER_LIMIT]; size_t line_len;
    pthread_mutex_t mu;
} Framer;

static void framer_init(Framer *f) {
    memset(f, 0, sizeof *f);
    f->park_at = -1;
    pthread_mutex_init(&f->mu, NULL);
}

static void framer_arm(Framer *f) {
    pthread_mutex_lock(&f->mu);
    f->out_len = f->line_len = 0;
    f->armed = true; f->done = false; f->park_at = -1;
    pthread_mutex_unlock(&f->mu);
}

static const char READY[] = "READY";
static const char PARKMARK[] = "\x00UNSWBC PARK";

// bit0: ENDTURN arrived (turn ended).  bit1: a PARK line set park_at.
// Both are "wake the poller" events — writes that produce neither skip the
// broadcast entirely.
static int framer_feed(Framer *f, const uint8_t *d, size_t n) {
    pthread_mutex_lock(&f->mu);
    int flags = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = d[i];
        if (ch != '\n') {
            if (f->line_len < BUFFER_LIMIT) f->line[f->line_len++] = ch;
            continue;
        }
        size_t ln = f->line_len;
        if (ln && f->line[ln - 1] == '\r') ln--;
        f->line_len = 0;
        if (ln == sizeof(READY) - 1 && !memcmp(f->line, READY, ln)) continue;
        if (ln >= sizeof(PARKMARK) - 1 &&
            !memcmp(f->line, PARKMARK, sizeof(PARKMARK) - 1)) {
            size_t k = sizeof(PARKMARK) - 1;
            while (k < ln && (f->line[k] == ' ' || f->line[k] == '\t')) k++;
            int64_t v = 0; bool any = false, ok = true;
            while (k < ln && f->line[k] >= '0' && f->line[k] <= '9') {
                v = v * 10 + (f->line[k] - '0'); any = true; k++;
            }
            while (k < ln) { if (f->line[k] != ' ') ok = false; k++; }
            f->park_at = (any && ok) ? v : -1;
            if (f->park_at >= 0) flags |= 2;
            continue;
        }
        if (!f->armed) continue;
        if (ln == 7 && !memcmp(f->line, "ENDTURN", 7)) {
            f->armed = false; f->done = true;
            flags |= 1;
            break;
        }
        size_t room = BUFFER_LIMIT - f->out_len;
        if (room > 0) {
            size_t c = ln < room ? ln : room;
            memcpy(f->out + f->out_len, f->line, c);
            f->out_len += c;
            if (f->out_len < BUFFER_LIMIT) f->out[f->out_len++] = '\n';
        }
    }
    pthread_mutex_unlock(&f->mu);
    return flags;
}

static size_t framer_take(Framer *f, uint8_t *dst) {
    pthread_mutex_lock(&f->mu);
    if (!f->done) {
        size_t room = BUFFER_LIMIT - f->out_len;
        size_t c = f->line_len < room ? f->line_len : room;
        memcpy(f->out + f->out_len, f->line, c);
        f->out_len += c;
    }
    f->line_len = 0;
    size_t n = f->out_len;
    memcpy(dst, f->out, n);
    f->out_len = 0;
    pthread_mutex_unlock(&f->mu);
    return n;
}

// ---------------------------------------------------------------- contexts

typedef struct Bot Bot;
typedef struct Runner Runner;

struct w2c_wasi__snapshot__preview1 { Bot *bot; };
struct w2c_wasix__32v1 { Bot *bot; };
struct w2c_env { Bot *bot; wasm_rt_memory_t *mem; };
struct w2c_unswbc { Runner *r; };

// WASI errno values (preview1 numbering)
enum {
    WASI_OK = 0, WASI_E2BIG = 1, WASI_EACCES = 2, WASI_EBADF = 8,
    WASI_EEXIST = 20, WASI_EINVAL = 28, WASI_EISDIR = 31, WASI_ENOENT = 44,
    WASI_ENOSYS = 52, WASI_ENOTDIR = 54, WASI_ENOTSUP = 58, WASI_ENOTTY = 59,
    WASI_EPERM = 63, WASI_ERANGE = 68, WASI_ESPIPE = 70,
};

// ---------------------------------------------------------------- bot

struct Bot {
    int dragon;
    char team;
    const uint8_t *init; size_t init_len;
    bool is_new;

    w2c_bota *ia;
    w2c_botb *ib;
    wasm_rt_memory_t mem;
    struct w2c_env env_i;
    struct w2c_wasi__snapshot__preview1 wasi_i;
    struct w2c_wasix__32v1 wasix_i;

    Pipe in, out;
    Framer framer;
    uint8_t *stderr_buf; size_t stderr_len, stderr_cap;

    pthread_t th;
    volatile bool exited;
    volatile uint64_t out_seq;           // bumped on every poller-visible event
    int exit_code;
    char failure[160];

    int frozen;
    pthread_mutex_t fmu; pthread_cond_t fcv;

    // metering
    uint64_t *meter; uint32_t *exh;
    int64_t spent_acc, last, reported, turn;
    bool first, ended;
    int64_t slept_ns;
    int64_t budget;
    uint64_t live_pts, live_mem;
    uint64_t written;
    Rng rng;

    jmp_buf exit_jmp;
    volatile bool exit_armed;

    uint64_t t_gate, t_w1, t_wlast, t_r0; // profiling: wake & write stamps
    uint64_t c_r0, c_w1;                  // profiling: rdtsc stamps
    int n_w1, n_r;                        // profiling: syscall counts per ask
};

static NORETURN void bot_die(Bot *b, int code) {
    if (b->exit_armed) longjmp(b->exit_jmp, code + 1);
    abort();
}

static int64_t bot_spent(Bot *b) {
    if (!b->meter) return b->spent_acc;
    int64_t now = (int64_t)*b->meter;
    if (b->first) b->first = false;
    else b->spent_acc += b->last - now;
    b->last = now;
    return b->spent_acc;
}

static void bot_mark(Bot *b) {
    if (b->ended) return;
    b->reported = bot_spent(b);
    b->live_pts = (uint64_t)(b->reported - b->turn);
    b->live_mem = b->mem.size;
}

static void bot_refill(Bot *b, int64_t points) {
    if (!b->meter) return;
    int64_t gap = bot_spent(b) - b->reported;
    b->turn = b->reported;
    b->ended = false;
    int64_t left = points - gap;
    if (left < 0) left = 0;
    *b->meter = (uint64_t)left;
    b->last = left;
}

static void bot_charge(Bot *b, int64_t pts) {
    if (!b->meter) return;
    int64_t left = (int64_t)*b->meter - pts;
    *b->meter = (uint64_t)(left < 0 ? 0 : left);
}

static int64_t bot_now(Bot *b) { return bot_spent(b) + b->slept_ns; }

static NORETURN void bot_fail(Bot *b, const char *why, int code) {
    snprintf(b->failure, sizeof b->failure, "%s", why);
    bot_die(b, code);
}

static void bot_charge_write(Bot *b, int64_t total) {
    if (!b->meter) return;
    int64_t cost = WRITE_SYSCALL_COST + total * WRITE_BYTE_COST;
    int64_t left = (int64_t)*b->meter - cost;
    *b->meter = (uint64_t)left;
    if (!b->first) bot_mark(b);
    if (left < 0) {
        if (b->exh) *b->exh = 1;
        bot_fail(b, "exceeded CPU limit", 137);
    }
}

static uint64_t real_ns(void);      // fwd for profiling
static inline uint64_t rd_tsc(void);

static int prof_on;                     // --debug 17: per-ask instrumentation

// every non-exit syscall blocks between ENDTURN and the next turn's feed.
// fast path: frozen is a single atomic read; the mutex is only needed to
// park while actually frozen.
static void bot_gate(Bot *b) {
    bool waited = !__atomic_load_n(&b->frozen, __ATOMIC_ACQUIRE);
    if (waited) {
        pthread_mutex_lock(&b->fmu);
        while (!b->frozen) pthread_cond_wait(&b->fcv, &b->fmu);
        pthread_mutex_unlock(&b->fmu);
        if (prof_on) b->t_gate = real_ns();
    }
    if (!b->first) bot_mark(b);
}

static void bot_frozen_set(Bot *b, int v) {
    pthread_mutex_lock(&b->fmu);
    b->frozen = v;
    if (v) pthread_cond_broadcast(&b->fcv);
    pthread_mutex_unlock(&b->fmu);
}

// every poller-visible event funnels through here: seq bump (the predicate
// the poller actually waits on) + broadcast — always under out.mu so the
// poller's check-then-wait cannot miss a kick
static void bot_kick(struct Bot *b_) {
    Bot *b = b_;
    pthread_mutex_lock(&b->out.mu);
    b->out_seq++;
    pthread_cond_broadcast(&b->out.cv);
    pthread_mutex_unlock(&b->out.mu);
}

// memory helpers ----------------------------------------------------------

static void bounds(Bot *b, uint32_t ptr, uint64_t n) {
    if ((uint64_t)ptr + n > b->mem.size)
        bot_fail(b, "out of bounds memory access via import", 134);
}
static uint8_t rd8(Bot *b, uint32_t p) { bounds(b, p, 1); return b->mem.data[p]; }
static uint32_t rd32(Bot *b, uint32_t p) { bounds(b, p, 4); uint32_t v; memcpy(&v, b->mem.data + p, 4); return v; }
static uint64_t rd64(Bot *b, uint32_t p) { bounds(b, p, 8); uint64_t v; memcpy(&v, b->mem.data + p, 8); return v; }
static void wr8(Bot *b, uint32_t p, uint8_t v) { bounds(b, p, 1); b->mem.data[p] = v; }
static void wr32(Bot *b, uint32_t p, uint32_t v) { bounds(b, p, 4); memcpy(b->mem.data + p, &v, 4); }
static void wr64(Bot *b, uint32_t p, uint64_t v) { bounds(b, p, 8); memcpy(b->mem.data + p, &v, 8); }
static void wr(Bot *b, uint32_t p, const void *d, size_t n) { bounds(b, p, n); memcpy(b->mem.data + p, d, n); }

// engine side -------------------------------------------------------------

static wasm_rt_memory_t *eng_mem(void);
static void eng_w32(struct w2c_wasi__snapshot__preview1 *w, uint32_t p, uint32_t v);
static u32 eng_fd_write_impl(struct w2c_wasi__snapshot__preview1 *w, u32 fd,
                             u32 iovs, u32 n, u32 out);
static u32 eng_clock_impl(u32 clock_id, u64 prec, u32 out);

// ---------------------------------------------------------------- wasi (bot)

static int read_stdin(Bot *b, uint32_t iovs, uint32_t n, uint32_t out) {
    b->n_r++;                                  // profiling
    int64_t total = 0;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t ptr = rd32(b, iovs + 8 * k);
        uint32_t len = rd32(b, iovs + 8 * k + 4);
        bounds(b, ptr, len);
        size_t got = pipe_read(&b->in, b->mem.data + ptr, len);
        if (b->budget >= 0) {
            bot_refill(b, b->budget);
            b->budget = -1;
        }
        total += (int64_t)got;
        if (got < len) break;
    }
    bot_charge(b, total * READ_BYTE_COST);
    wr32(b, out, (uint32_t)total);
    if (prof_on && total > 0 && !b->t_r0) {    // profiling: data arrived
        b->t_r0 = real_ns();
        b->c_r0 = rd_tsc();
    }
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_fd_read(struct w2c_wasi__snapshot__preview1 *w,
                                         u32 fd, u32 iovs, u32 n, u32 out) {
    if (!w->bot) { eng_w32(w, out, 0); return WASI_OK; }   // engine: EOF
    Bot *b = w->bot;
    bot_gate(b);
    if (n > MAX_IOV) return WASI_EINVAL;
    if (fd == 0) return read_stdin(b, iovs, n, out);
    if (fd == 3 || fd == 4) return WASI_EISDIR;
    return WASI_EBADF;
}

u32 w2c_wasi__snapshot__preview1_fd_write(struct w2c_wasi__snapshot__preview1 *w,
                                          u32 fd, u32 iovs, u32 n, u32 out) {
    if (!w->bot) return eng_fd_write_impl(w, fd, iovs, n, out);
    Bot *b = w->bot;
    bot_gate(b);
    if (n > MAX_IOV) return WASI_EINVAL;
    int64_t total = 0;
    for (uint32_t k = 0; k < n; k++)
        total += (int64_t)rd32(b, iovs + 8 * k + 4);
    bot_charge_write(b, total);
    for (uint32_t k = 0; k < n; k++) {
        uint32_t ptr = rd32(b, iovs + 8 * k);
        uint32_t len = rd32(b, iovs + 8 * k + 4);
        bounds(b, ptr, len);
        if (fd == 1) {
            if (prof_on) {
                uint64_t nw = real_ns();
                if (!b->t_w1) { b->t_w1 = nw; b->c_w1 = rd_tsc(); }
                b->t_wlast = nw; b->n_w1++;
            }
            int ev = framer_feed(&b->framer, b->mem.data + ptr, len);
            if (ev & 1) {
                // ENDTURN: turn ends; the guest freezes at its next syscall
                pthread_mutex_lock(&b->fmu);
                b->frozen = 0;
                pthread_mutex_unlock(&b->fmu);
            }
            if (ev) bot_kick(b);
        } else if (fd == 2) {
            // bounded: a bot spamming stderr must not OOM the runner
            size_t room = STDERR_CAP - b->stderr_len;
            size_t keep = len < room ? len : room;
            if (keep) {
                if (b->stderr_len + keep > b->stderr_cap) {
                    b->stderr_cap = (b->stderr_len + keep) * 2 + 256;
                    if (b->stderr_cap > STDERR_CAP) b->stderr_cap = STDERR_CAP;
                    b->stderr_buf = realloc(b->stderr_buf, b->stderr_cap);
                }
                memcpy(b->stderr_buf + b->stderr_len, b->mem.data + ptr, keep);
                b->stderr_len += keep;
            }
        }
    }
    wr32(b, out, (uint32_t)total);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_environ_sizes_get(
    struct w2c_wasi__snapshot__preview1 *w, u32 a, u32 b_) {
    if (!w->bot) { eng_w32(w, a, 0); eng_w32(w, b_, 0); return WASI_OK; }
    Bot *b = w->bot;
    bot_gate(b);
    wr32(b, a, 1);
    wr32(b, b_, 10);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_environ_get(
    struct w2c_wasi__snapshot__preview1 *w, u32 vec, u32 buf) {
    if (!w->bot) return WASI_OK;
    Bot *b = w->bot;
    bot_gate(b);
    wr32(b, vec, buf);
    wr(b, buf, "TERM=dumb\0", 10);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_clock_time_get(
    struct w2c_wasi__snapshot__preview1 *w, u32 clock_id, u64 prec, u32 out) {
    if (!w->bot) return eng_clock_impl(clock_id, prec, out);
    Bot *b = w->bot;
    bot_gate(b);
    int64_t now = bot_now(b);
    wr64(b, out, (uint64_t)((clock_id == 0 ? VIRTUAL_EPOCH_NS : 0) + now));
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_random_get(
    struct w2c_wasi__snapshot__preview1 *w, u32 ptr, u32 len) {
    if (!w->bot) return WASI_OK;             // engine never imports this
    Bot *b = w->bot;
    bot_gate(b);
    bounds(b, ptr, len);
    rng_fill(&b->rng, b->mem.data + ptr, len);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_sched_yield(struct w2c_wasi__snapshot__preview1 *w) {
    if (w->bot) bot_gate(w->bot);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_fd_close(struct w2c_wasi__snapshot__preview1 *w, u32 fd) {
    if (w->bot) bot_gate(w->bot);
    return WASI_EBADF;
}

u32 w2c_wasi__snapshot__preview1_fd_seek(struct w2c_wasi__snapshot__preview1 *w,
                                         u32 fd, u64 off, u32 whence, u32 out) {
    if (!w->bot) return WASI_ESPIPE;
    Bot *b = w->bot;
    bot_gate(b);
    if (fd == 3 || fd == 4) { wr64(b, out, 0); return WASI_OK; }
    return WASI_EBADF;
}

u32 w2c_wasi__snapshot__preview1_fd_prestat_get(struct w2c_wasi__snapshot__preview1 *w,
                                              u32 fd, u32 out) {
    if (!w->bot) return WASI_EBADF;
    Bot *b = w->bot;
    bot_gate(b);
    if (fd == 3 || fd == 4) {
        uint8_t rec[8] = {0, 0, 0, 0, 1, 0, 0, 0};
        wr(b, out, rec, 8);
        return WASI_OK;
    }
    return WASI_EBADF;
}

u32 w2c_wasi__snapshot__preview1_fd_prestat_dir_name(
    struct w2c_wasi__snapshot__preview1 *w, u32 fd, u32 ptr, u32 n) {
    if (!w->bot) return WASI_EBADF;
    Bot *b = w->bot;
    bot_gate(b);
    if (fd == 3 || fd == 4) { wr(b, ptr, "/", n < 1 ? n : 1); return WASI_OK; }
    return WASI_EBADF;
}

u32 w2c_wasi__snapshot__preview1_fd_fdstat_get(struct w2c_wasi__snapshot__preview1 *w,
                                             u32 fd, u32 out) {
    if (!w->bot) return WASI_EBADF;
    Bot *b = w->bot;
    bot_gate(b);
    uint8_t kind;
    if (fd <= 2) kind = 2;               // character device
    else if (fd <= 4) kind = 3;          // directory
    else return WASI_EBADF;
    uint8_t rec[24] = {0};
    rec[0] = kind;
    memset(rec + 8, 0xFF, 16);
    wr(b, out, rec, 24);
    return WASI_OK;
}

u32 w2c_wasi__snapshot__preview1_fd_fdstat_set_flags(
    struct w2c_wasi__snapshot__preview1 *w, u32 fd, u32 flags) {
    if (w->bot) bot_gate(w->bot);
    return WASI_OK;
}

// engine-only extras
void w2c_wasi__snapshot__preview1_proc_exit(struct w2c_wasi__snapshot__preview1 *w,
                                            u32 code) {
    if (w->bot) bot_die(w->bot, (int)code);
    fprintf(stderr, "engine called proc_exit(%u)\n", code);
    _exit(90);
}

// ---------------------------------------------------------------- wasix

void w2c_wasix__32v1_callback_signal(struct w2c_wasix__32v1 *w, u32 a, u32 b_) {}

u32 w2c_wasix__32v1_thread_signal(struct w2c_wasix__32v1 *w, u32 a, u32 b_) {
    Bot *b = w->bot;
    bot_gate(b);
    return WASI_ENOTSUP;                 // DENIED
}

u32 w2c_wasix__32v1_fd_dup2(struct w2c_wasix__32v1 *w, u32 fd, u32 flags,
                            u32 newfd, u32 out) {
    Bot *b = w->bot;
    bot_gate(b);
    wr32(b, out, newfd);
    return WASI_OK;
}

u32 w2c_wasix__32v1_fd_fdflags_get(struct w2c_wasix__32v1 *w, u32 fd, u32 out) {
    Bot *b = w->bot;
    bot_gate(b);
    wr32(b, out, 0);
    return WASI_OK;
}

u32 w2c_wasix__32v1_fd_fdflags_set(struct w2c_wasix__32v1 *w, u32 fd, u32 flags) {
    Bot *b = w->bot;
    bot_gate(b);
    return WASI_OK;
}

u32 w2c_wasix__32v1_futex_wait(struct w2c_wasix__32v1 *w, u32 ptr, u32 expected,
                               u32 timeout_ptr, u32 woken) {
    Bot *b = w->bot;
    bot_gate(b);
    if (rd32(b, ptr) != expected) { wr8(b, woken, 1); return WASI_OK; }
    if (timeout_ptr && rd8(b, timeout_ptr)) { wr8(b, woken, 0); return WASI_OK; }
    bot_fail(b, "futex_wait would block forever", 134);
}

u32 w2c_wasix__32v1_futex_wake(struct w2c_wasix__32v1 *w, u32 ptr, u32 woken) {
    Bot *b = w->bot;
    bot_gate(b);
    wr8(b, woken, 0);
    return WASI_OK;
}

u32 w2c_wasix__32v1_futex_wake_all(struct w2c_wasix__32v1 *w, u32 ptr, u32 woken) {
    Bot *b = w->bot;
    bot_gate(b);
    wr8(b, woken, 0);
    return WASI_OK;
}

u32 w2c_wasix__32v1_getcwd(struct w2c_wasix__32v1 *w, u32 ptr, u32 lenptr) {
    Bot *b = w->bot;
    bot_gate(b);
    uint32_t maxlen = rd32(b, lenptr);
    wr32(b, lenptr, 1);
    if (1 > maxlen) return WASI_ERANGE;
    if (ptr == 0 || maxlen == 0) return WASI_EINVAL;
    wr(b, ptr, "/", maxlen >= 2 ? 2 : maxlen);
    return WASI_OK;
}

u32 w2c_wasix__32v1_path_open2(struct w2c_wasix__32v1 *w, u32 dirfd, u32 dirflags,
                               u32 ptr, u32 n, u32 oflags, u64 rights,
                               u64 inherit, u32 fdflags, u32 extra, u32 out) {
    Bot *b = w->bot;
    bot_gate(b);
    if (dirfd != 3 && dirfd != 4) return WASI_EBADF;
    if (oflags & 1 || oflags & 8) return WASI_EACCES;
    return WASI_ENOENT;
}

u32 w2c_wasix__32v1_proc_signals_sizes_get(struct w2c_wasix__32v1 *w, u32 out) {
    Bot *b = w->bot;
    bot_gate(b);
    wr32(b, out, 0);
    return WASI_OK;
}

u32 w2c_wasix__32v1_proc_signals_get(struct w2c_wasix__32v1 *w, u32 out) {
    Bot *b = w->bot;
    bot_gate(b);
    return WASI_OK;
}

void w2c_wasix__32v1_proc_exit2(struct w2c_wasix__32v1 *w, u32 code) {
    bot_die(w->bot, (int)code);          // EXITS: no gate
}

void w2c_wasix__32v1_thread_exit(struct w2c_wasix__32v1 *w, u32 code) {
    bot_die(w->bot, (int)code);          // EXITS: no gate
}

wasm_rt_memory_t *w2c_env_memory(struct w2c_env *e) { return e->mem; }

// ---------------------------------------------------------------- engine glue

struct Runner {
    w2c_engine eng;
    struct w2c_unswbc unswbc_i;
    struct w2c_wasi__snapshot__preview1 eng_wasi;
    Bot **live; int nliving, live_cap;   // every spawn ever (lookup by id)
    uint8_t *long_reply; size_t long_len;
    uint8_t *team_of; int team_cap;      // indexed by dragon id
    uint64_t *pts[2]; size_t npts[2];   // per-team per-turn points
    double t_start;
};

static Runner G;
static jmp_buf eng_exit_jmp;
static volatile bool eng_exit_armed;
static int u64cmpv(const void *pa, const void *pb);

static wasm_rt_memory_t *eng_mem(void) { return w2c_engine_memory(&G.eng); }

static void eng_wr(uint32_t p, const void *d, size_t n) {
    wasm_rt_memory_t *m = eng_mem();
    if ((uint64_t)p + n > m->size) { fprintf(stderr, "engine oob write\n"); abort(); }
    memcpy(m->data + p, d, n);
}
static void eng_rd(uint32_t p, void *d, size_t n) {
    wasm_rt_memory_t *m = eng_mem();
    if ((uint64_t)p + n > m->size) { fprintf(stderr, "engine oob read\n"); abort(); }
    memcpy(d, m->data + p, n);
}
static void eng_w32(struct w2c_wasi__snapshot__preview1 *w, uint32_t p, uint32_t v) {
    eng_wr(p, &v, 4);
}

static u32 eng_fd_write_impl(struct w2c_wasi__snapshot__preview1 *w, u32 fd,
                             u32 iovs, u32 n, u32 out) {
    uint32_t total = 0;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t ptr, len;
        eng_rd(iovs + 8 * k, &ptr, 4);
        eng_rd(iovs + 8 * k + 4, &len, 4);
        if (fd == 2 && len) {
            uint8_t *chunk = malloc(len);
            eng_rd(ptr, chunk, len);
            fwrite(chunk, 1, len, stderr);
            free(chunk);
        }
        total += len;
    }
    eng_wr(out, &total, 4);
    return WASI_OK;
}

static u32 eng_clock_impl(u32 clock_id, u64 prec, u32 out) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    eng_wr(out, &ns, 8);
    return WASI_OK;
}

// ---------------------------------------------------------------- bot spawn/turn

static void bot_spawn(int dragon, const uint8_t *init, size_t init_len);

void w2c_unswbc_bot_spawn(struct w2c_unswbc *u, u32 dragon, u32 ptr, u32 len) {
    uint8_t *init = malloc(len ? len : 1);
    eng_rd(ptr, init, len);
    bot_spawn((int)dragon, init, len);
}

static size_t bot_ask(Bot *b, const uint8_t *block, size_t n, uint8_t *dst);

u32 w2c_unswbc_bot_reply(struct w2c_unswbc *u, u32 dragon, u32 ptr, u32 len,
                         u32 out, u32 cap) {
    if (G.long_reply) {
        if (G.long_len > cap) return (u32)G.long_len;
        eng_wr(out, G.long_reply, G.long_len);
        size_t n = G.long_len;
        free(G.long_reply); G.long_reply = NULL; G.long_len = 0;
        return (u32)n;
    }
    uint8_t *block = malloc(len ? len : 1);
    eng_rd(ptr, block, len);
    Bot *b = NULL;
    for (int i = 0; i < G.nliving; i++)
        if (G.live[i]->dragon == (int)dragon) { b = G.live[i]; break; }
    if (!b) { free(block); return 0; }
    unsigned round = 0;
    if (len > 6 && !memcmp(block, "ROUND ", 6))
        for (size_t i = 6; i < len && block[i] >= '0' && block[i] <= '9'; i++)
            round = round * 10 + (block[i] - '0');
    uint8_t *reply = malloc(BUFFER_LIMIT + 64);
    size_t rl = bot_ask(b, block, len, reply);
    free(block);
    if (b->live_pts) {
        int ti = b->team == 'b';
        G.pts[ti] = realloc(G.pts[ti], (G.npts[ti] + 1) * sizeof(uint64_t));
        G.pts[ti][G.npts[ti]++] = b->live_pts;
    }
    if (b->failure[0])
        fprintf(stderr, "round %u: bot %u (team %c) %s\n",
                round, dragon, toupper(b->team), b->failure);
    if (rl > cap) {
        G.long_reply = reply; G.long_len = rl;
        return (u32)rl;
    }
    eng_wr(out, reply, rl);
    free(reply);
    return (u32)rl;
}

void w2c_unswbc_log(struct w2c_unswbc *u, u32 dragon, u32 round, u32 reason) {
    static const char *R[256];
    static bool init;
    if (!init) {
        R['W'] = "hit a wall"; R['S'] = "hit itself"; R['O'] = "hit another dragon";
        R['H'] = "lost a head-to-head"; R['A'] = "no valid action";
        init = true;
    }
    char r = isprint(reason) ? (char)reason : 0;
    fprintf(stderr, "round %u: bot %u (team %c) died: %s\n",
            round, dragon,
            toupper(dragon < G.team_cap ? G.team_of[dragon] : '?'),
            r && R[(uint8_t)r] ? R[(uint8_t)r] : "died");
    for (int i = 0; i < G.nliving; i++)
        if (G.live[i]->dragon == (int)dragon) {
            Bot *b = G.live[i];
            bot_frozen_set(b, 1);
            pipe_close(&b->in);
            pipe_close(&b->out);
        }
}

// ---------------------------------------------------------------- thread

static void *bot_main(void *arg) {
    Bot *b = arg;
    wasm_rt_init_thread();
    int exit_code = 0;
    int r = setjmp(b->exit_jmp);
    if (r) {
        exit_code = r - 1;                  // bot_die passed code + 1
    } else {
        b->exit_armed = true;
        wasm_rt_trap_t trap = wasm_rt_impl_try();
        if (trap == 0) {
            if (b->ia) w2c_bota_0x5Fstart(b->ia);
            else w2c_botb_0x5Fstart(b->ib);
        } else {
            if (b->exh && *b->exh)
                snprintf(b->failure, sizeof b->failure, "exceeded CPU limit");
            else if (!b->failure[0])
                snprintf(b->failure, sizeof b->failure, "sandbox error: %s",
                         wasm_rt_strerror(trap));
            exit_code = 128 + (int)trap;
        }
    }
    b->exit_armed = false;
    b->exited = true;                // exited bots are never asked again
    b->exit_code = exit_code;
    bot_kick(b);                     // the poller may be waiting on this bot
    wasm_rt_free_memory(&b->mem);    // mem.size stays valid for accounting
    pipe_close(&b->out);
    return NULL;
}

static void bot_spawn(int dragon, const uint8_t *init, size_t init_len) {
    // team from the "TEAM x" line of the init block
    char team = 'a';
    const uint8_t *s = init, *e = init + init_len;
    while (s < e) {
        const uint8_t *nl = memchr(s, '\n', e - s);
        size_t ln = nl ? (size_t)(nl - s) : (size_t)(e - s);
        if (ln > 5 && !memcmp(s, "TEAM ", 5)) {
            team = (char)(s[5] | 0x20);
            break;
        }
        if (!nl) break;
        s = nl + 1;
    }
    Bot *b = calloc(1, sizeof *b);
    if (!b) {
        fprintf(stderr, "bot_spawn: OOM (dragon %d)\n", dragon);
#ifdef KVMRUN_GUEST
        { void heap_stats(void); heap_stats(); }
#endif
        exit(12);
    }
    b->dragon = dragon;
    b->team = team;
    b->init = init; b->init_len = init_len;
    b->is_new = true;
    b->budget = -1;
    b->frozen = 1;
    b->first = true;
    b->last = INITIAL_POINTS;
    char name[16];
    snprintf(name, sizeof name, "%d", dragon);
    char key[24];                            // "{seed:016x}-{team}"
    snprintf(key, sizeof key, "%016llx-%c",
             (unsigned long long)g_seed, team);
    rng_seed(&b->rng, key, name);
    pipe_init(&b->in); pipe_init(&b->out);
    b->in.wake = &b->out.cv; b->in.wake_mu = &b->out.mu;
    b->in.wake_seq = &b->out_seq;
    framer_init(&b->framer);
    pthread_mutex_init(&b->fmu, NULL);
    pthread_cond_init(&b->fcv, NULL);

    // memory: module imports env.memory (min pages from generated const)
    b->env_i.bot = b;
    b->env_i.mem = &b->mem;
    b->wasi_i.bot = b;
    b->wasix_i.bot = b;

    if (team == 'a') {
        wasm_rt_allocate_memory(&b->mem,
                                wasm2c_bota_min_env_memory,
                                MAX_MEMORY_PAGES, false, 65536);
        b->ia = calloc(1, sizeof *b->ia);
        wasm2c_bota_instantiate(b->ia, &b->env_i, &b->wasi_i, &b->wasix_i);
        b->meter = w2c_bota_wasmer_metering_remaining_points(b->ia);
        b->exh = w2c_bota_wasmer_metering_points_exhausted(b->ia);
    } else {
        wasm_rt_allocate_memory(&b->mem,
                                wasm2c_botb_min_env_memory,
                                MAX_MEMORY_PAGES, false, 65536);
        b->ib = calloc(1, sizeof *b->ib);
        wasm2c_botb_instantiate(b->ib, &b->env_i, &b->wasi_i, &b->wasix_i);
        b->meter = w2c_botb_wasmer_metering_remaining_points(b->ib);
        b->exh = w2c_botb_wasmer_metering_points_exhausted(b->ib);
    }

    if ((int)dragon >= G.team_cap) {
        int nc = G.team_cap * 2 + 1024;
        while ((int)dragon >= nc) nc *= 2;
        G.team_of = realloc(G.team_of, nc);
        memset(G.team_of + G.team_cap, 0, nc - G.team_cap);
        G.team_cap = nc;
    }
    G.team_of[dragon] = team;
    if (G.nliving == G.live_cap) {
        G.live_cap = G.live_cap * 2 + 256;
        G.live = realloc(G.live, G.live_cap * sizeof(Bot *));
    }
    G.live[G.nliving++] = b;
#ifdef KVMRUN_GUEST
    pthread_create(&b->th, NULL, bot_main, b);
#else
    static pthread_attr_t bot_attr;
    static int bot_attr_init;
    if (!bot_attr_init) {
        pthread_attr_init(&bot_attr);
        pthread_attr_setstacksize(&bot_attr, 64u << 20);
        bot_attr_init = 1;
    }
    pthread_create(&b->th, &bot_attr, bot_main, b);
#endif
    pthread_detach(b->th);
}

// ---------------------------------------------------------------- ask

static uint64_t ask_wall_ns, ask_n, ask_wait_ns, ask_first_ns, ask_wake_n;
static uint64_t ask_gate_ns, ask_bot_ns, ask_wlast_ns, ask_tail_ns;
static uint64_t ask_w_n, ask_r_n, ask_cyc; // profiling
static uint64_t real_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}
static inline uint64_t rd_tsc(void) {      // profiling: raw cycle counter
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)hi << 32);
}

static size_t bot_ask(Bot *b, const uint8_t *block, size_t n, uint8_t *dst) {
    uint64_t t0 = prof_on ? real_ns() : 0;
    framer_arm(&b->framer);
    uint64_t parks0;
    pthread_mutex_lock(&b->in.mu);
    parks0 = (uint64_t)b->in.parks;
    pthread_mutex_unlock(&b->in.mu);

    size_t cap = n + b->init_len + 8;
    uint8_t *data = malloc(cap);
    size_t o = 0;
    if (b->is_new) { memcpy(data + o, b->init, b->init_len); o += b->init_len; }
    memcpy(data + o, block, n); o += n;
    if (!(o >= 2 && data[o - 2] == '\n' && data[o - 1] == '\n'))
        data[o++] = '\n';

    b->budget = MAX_TURN_POINTS;
    b->written += o;
    b->is_new = false;
    b->t_w1 = 0; b->t_r0 = 0; b->n_w1 = 0; b->n_r = 0;
    uint64_t twait = prof_on ? real_ns() : 0;
    pipe_feed(&b->in, data, o);    // feed while still frozen, like the judge
    bot_frozen_set(b, 1);          // only then may the guest read it
    free(data);
    uint64_t tfirst = 0;
    int wakes = 0;

    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += (time_t)WALL_LIMIT_S;
    pthread_mutex_lock(&b->out.mu);
    uint64_t seen = b->out_seq;
    pthread_mutex_unlock(&b->out.mu);
    for (;;) {
        pthread_mutex_lock(&b->framer.mu);
        bool done = b->framer.done;
        int64_t park_at = b->framer.park_at;
        if (prof_on && !tfirst && (b->framer.out_len || b->framer.line_len))
            tfirst = real_ns();
        pthread_mutex_unlock(&b->framer.mu);
        if (done) break;
        if (park_at >= 0 && (uint64_t)park_at == b->written) break;
        if (b->exited) break;
        pthread_mutex_lock(&b->in.mu);
        int parks = b->in.parks;
        pthread_mutex_unlock(&b->in.mu);
        if (parks > (int)parks0) break;
        // seq-gated wait: a kick that lands between the checks above and the
        // timedwait still flips out_seq under out.mu, so we see it before we
        // ever sleep. Writers kick only on real events (ENDTURN/PARK/exit/
        // first park), so mid-turn chunk writes no longer wake us.
        pthread_mutex_lock(&b->out.mu);
        struct timespec ts = dl;
        int r = 0;
        if (b->out_seq == seen)
            r = pthread_cond_timedwait(&b->out.cv, &b->out.mu, &ts);
        seen = b->out_seq;
        wakes++;
        pthread_mutex_unlock(&b->out.mu);
        if (r == ETIMEDOUT) {
            snprintf(b->failure, sizeof b->failure, "ran out of time");
            break;
        }
    }
    uint64_t tnow = prof_on ? real_ns() : twait;
    ask_wall_ns += tnow - t0;
    ask_wait_ns += tnow - twait;
    ask_first_ns += tfirst ? tfirst - twait : 0;
    ask_wake_n += wakes;
    if (b->t_gate > twait) ask_gate_ns += b->t_gate - twait;
    if (b->t_r0) ask_bot_ns += b->t_r0 - twait;          // feed->bot-read entry
    if (b->t_w1 && b->t_r0) ask_wlast_ns += b->t_w1 - b->t_r0; // read->first write
    if (b->t_wlast) ask_tail_ns += tnow - b->t_wlast;    // last write->done seen
    if (b->c_w1 && b->c_r0) ask_cyc += b->c_w1 - b->c_r0;
    ask_w_n += b->n_w1; ask_r_n += b->n_r;
    ask_n++;
    return framer_take(&b->framer, dst);
}

// ---------------------------------------------------------------- main

#ifndef KVMRUN_GUEST
static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1);
    if (fread(b, 1, n, f) != (size_t)n) { perror("read"); exit(2); }
    fclose(f);
    *len = n;
    return b;
}
#endif

#ifndef KVMRUN_GUEST
static void stem_of(const char *arg, char *out) {
    const char *b = strrchr(arg, '/');
    b = b ? b + 1 : arg;
    if (*b && strcmp(b, ".") && strcmp(b, "..")) {
        snprintf(out, 128, "%s", b);
        return;
    }
    char cwd[1024];
    if (!getcwd(cwd, sizeof cwd)) { snprintf(out, 128, "bot"); return; }
    if (!strcmp(b, "..")) {           // parent dir's name
        char *d = strrchr(cwd, '/');
        if (d) *d = 0;
    }
    const char *c = strrchr(cwd, '/');
    snprintf(out, 128, "%s", c ? c + 1 : cwd);
    if (!*out) snprintf(out, 128, "bot");
}
#endif

#ifdef KVMRUN_GUEST
uint64_t hcall(uint32_t nr, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
#endif

static int g_verbose;
static int g_seed_set;
#ifndef KVMRUN_GUEST
static const char *g_map_arg;
#endif

static uint64_t entropy64(void) {
#ifdef KVMRUN_GUEST
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return hcall(HC_NOW, 0, 0, 0, 0) ^ ((uint64_t)hi << 32 | lo) * 0x9e3779b97f4a7c15ull;
#else
    uint64_t v = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(&v, 1, 8, f) != 8) v = 0; fclose(f); }
    if (!v) {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        v = (uint64_t)ts.tv_nsec ^ (uint64_t)ts.tv_sec * 0x9e3779b97f4a7c15ull;
    }
    return v;
#endif
}

// The shared match core: takes map bytes + labels, runs engine, prints
// result, extracts the replay blob.
static int run_match(const uint8_t *map, size_t map_len, uint32_t debug,
                     const char *name_a, const char *name_b,
                     const char *replay_path) {
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    prof_on = (debug == 17);
    if (!g_seed_set) { g_seed = entropy64(); g_seed_set = 1; }
    printf("seed 0x%016llx\n", (unsigned long long)g_seed);

    wasm_rt_init();

    // engine instance
    G.unswbc_i.r = &G;
    G.eng_wasi.bot = NULL;
    {
        wasm_rt_trap_t trap = wasm_rt_impl_try();
        if (trap) { fprintf(stderr, "engine init trap: %s\n", wasm_rt_strerror(trap)); return 1; }
        wasm2c_engine_instantiate(&G.eng, &G.unswbc_i, &G.eng_wasi);
        w2c_engine_0x5Finitialize(&G.eng);
        uint32_t map_ptr = w2c_engine_ubc_alloc(&G.eng, (u32)map_len);
        eng_wr(map_ptr, map, map_len);
        uint32_t out_ptr = w2c_engine_ubc_alloc(&G.eng, 12 * 4);
        eng_exit_armed = true;
        uint32_t code = w2c_engine_ubc_run(&G.eng, map_ptr, (u32)map_len,
                                           debug, (u64)g_seed, out_ptr);
        eng_exit_armed = false;
        if (code != 0) {
            uint32_t ep = w2c_engine_ubc_error(&G.eng);
            char buf[4096]; uint32_t i = 0;
            while (i < sizeof buf - 1) {
                eng_rd(ep + i, buf + i, 1);
                if (!buf[i]) break;
                i++;
            }
            buf[i] = 0;
            fprintf(stderr, "engine error: %s\n", buf);
            return 1;
        }
        int32_t res[12];
        eng_rd(out_ptr, res, 48);
        static const char *END_R[2] = {"by elimination", "on length"};
        static const char *DRAW_R[2] = {"both teams eliminated", "equal length"};
        const char *who = res[1] == 1 ? "A" : res[1] == 2 ? "B" : NULL;
        struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
        double took = t1.tv_sec - t0.tv_sec + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        const char *rs = res[2] == 0 || res[2] == 1
            ? (who ? END_R[res[2]] : DRAW_R[res[2]]) : "over";
        if (who)
            printf("team %s wins after %d rounds (%s) (%.1fs)\n",
                   who, res[0] + 1, rs, took);
        else
            printf("draw after %d rounds (%s) (%.1fs)\n", res[0] + 1, rs, took);
        if (g_verbose)
            printf("a_dragons=%d b_dragons=%d a_length=%d b_length=%d events=%d\n"
                   "a_queen=%d b_queen=%d a_longest=%d b_longest=%d\n",
                   res[3], res[4], res[5], res[6], res[7],
                   res[8], res[9], res[10], res[11]);
        for (int ti = 0; ti < 2; ti++) {
            size_t n = G.npts[ti];
            if (!n) continue;
            uint64_t *a = G.pts[ti];
            qsort(a, n, sizeof(uint64_t), u64cmpv);
            uint64_t sum = 0;
            for (size_t i = 0; i < n; i++) sum += a[i];
            size_t p50 = (50 * n + 99) / 100 - 1;
            size_t p99 = (99 * n + 99) / 100 - 1;
            char ps[4][32];
            uint64_t vs[4] = {a[p50], a[p99], sum / n, a[n - 1]};
            for (int i = 0; i < 4; i++)
                if (vs[i] >= 100000) snprintf(ps[i], 32, "%.1fM", vs[i] / 1e6);
                else snprintf(ps[i], 32, "%" PRIu64, vs[i]);
            printf("team %c points per turn: p50 %s  p99 %s"
                   "  mean %s  max %s  (%zu turns)\n",
                   "AB"[ti], ps[0], ps[1], ps[2], ps[3], n);
        }
        if (prof_on) {
            fprintf(stderr, "ask: n=%llu wall=%llums wait=%llums first=%llums wakes=%llu gate=%llums bot=%llums wlast=%llums tail=%llums nw=%llu nr=%llu\n",
                    (unsigned long long)ask_n,
                    (unsigned long long)ask_wall_ns / 1000000,
                    (unsigned long long)ask_wait_ns / 1000000,
                    (unsigned long long)ask_first_ns / 1000000,
                    (unsigned long long)ask_wake_n,
                    (unsigned long long)ask_gate_ns / 1000000,
                    (unsigned long long)ask_bot_ns / 1000000,
                    (unsigned long long)ask_wlast_ns / 1000000,
                    (unsigned long long)ask_tail_ns / 1000000,
                    (unsigned long long)ask_w_n,
                    (unsigned long long)ask_r_n);
            fprintf(stderr, "askcyc: %lluM cycles (bot read->write)\n",
                    (unsigned long long)(ask_cyc / 1000000));
        }
        fflush(stdout);
        // replay
        if (name_a && name_b) {
            uint32_t na = w2c_engine_ubc_alloc(&G.eng, (u32)strlen(name_a));
            eng_wr(na, name_a, strlen(name_a));
            uint32_t nb = w2c_engine_ubc_alloc(&G.eng, (u32)strlen(name_b));
            eng_wr(nb, name_b, strlen(name_b));
            int32_t size = (int32_t)w2c_engine_ubc_replay(&G.eng,
                na, (u32)strlen(name_a), nb, (u32)strlen(name_b));
            w2c_engine_ubc_free(&G.eng, na);
            w2c_engine_ubc_free(&G.eng, nb);
            if (size >= 0) {
                uint32_t base = w2c_engine_ubc_replay_ptr(&G.eng);
                uint8_t *blob = malloc(size);
                eng_rd(base, blob, size);
#ifdef KVMRUN_GUEST
                (void)replay_path;
                hcall(HC_REPLAY, (uint64_t)blob, (uint64_t)size, 0, 0);
#else
                char rpath[1024];
                if (replay_path && replay_path[0]) {
                    snprintf(rpath, sizeof rpath, "%s", replay_path);
                } else {
                    const char *m = strrchr(g_map_arg, '/');
                    char map_stem[256];
                    snprintf(map_stem, sizeof map_stem, "%s", m ? m + 1 : g_map_arg);
                    char *dot = strrchr(map_stem, '.');
                    if (dot) *dot = 0;
                    char la[128], lb[128];
                    stem_of(name_a, la); stem_of(name_b, lb);
                    char stamp[64];
                    time_t tt = time(NULL);
                    strftime(stamp, sizeof stamp, "%Y-%m-%d-%H%M%S", localtime(&tt));
                    snprintf(rpath, sizeof rpath,
                             "replays/%s%s%s-on-%s-%s.replay",
                             la, !strcmp(la, lb) ? "-vs-itself" : "-vs-",
                             !strcmp(la, lb) ? "" : lb, map_stem, stamp);
                }
                char *sl = strrchr(rpath, '/');
                if (sl) { *sl = 0; mkdir(rpath, 0777); *sl = '/'; }
                FILE *rf = fopen(rpath, "wb");
                if (rf) {
                    fwrite(blob, 1, size, rf); fclose(rf);
                    printf("wrote replay: %s\n", rpath);
                } else {
                    fprintf(stderr, "cannot write the replay to %s\n", rpath);
                }
#endif
                free(blob);
            }
        }
    }
    return 0;
}

#ifndef KVMRUN_GUEST
struct run_args {
    uint8_t *map; size_t map_len; uint32_t debug;
    const char *name_a, *name_b, *replay_path;
};
static void *run_match_th(void *p) {
    struct run_args *a = p;
    return (void *)(intptr_t)run_match(a->map, a->map_len, a->debug,
                                       a->name_a, a->name_b, a->replay_path);
}

int main(int argc, char **argv) {
    // usage: host MAP [--debug N] [--no-replay] [--replay FILE] [--name-a S] [--name-b S]
    const char *name_a = NULL, *name_b = NULL;
    const char *replay_path = NULL;
    uint32_t debug = 15;
    int no_replay = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--debug") && i + 1 < argc) debug = (u32)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-replay")) no_replay = 1;
        else if (!strcmp(argv[i], "--replay") && i + 1 < argc) replay_path = argv[++i];
        else if (!strcmp(argv[i], "--name-a") && i + 1 < argc) name_a = argv[++i];
        else if (!strcmp(argv[i], "--name-b") && i + 1 < argc) name_b = argv[++i];
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc)
            { g_seed = strtoull(argv[++i], NULL, 0); g_seed_set = 1; }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) g_verbose = 1;
        else if (!g_map_arg) g_map_arg = argv[i];
    }
    if (!g_map_arg) { fprintf(stderr, "usage: host MAP [opts]\n"); return 2; }
    if (no_replay) name_a = name_b = NULL;
    if (getenv("KVMRUN_VERBOSE")) g_verbose = 1;
    size_t map_len;
    uint8_t *map = (uint8_t *)slurp(g_map_arg, &map_len);
    // the engine recurses ~O(map tiles) deep on large maps; run the match on a
    // thread with a stack big enough for any plausible depth.
    struct run_args ra = {map, map_len, debug, name_a, name_b, replay_path};
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 512u << 20);
    pthread_t th;
    void *rc = NULL;
    if (pthread_create(&th, &at, run_match_th, &ra) != 0)
        return run_match(map, map_len, debug, name_a, name_b, replay_path);
    pthread_join(th, &rc);
    return (int)(intptr_t)rc;
}
#else
int kmain(void) {
    struct bootinfo *b = (struct bootinfo *)BOOTINFO_GPA;
    g_verbose = b->verbose;
    if (b->seed_set) { g_seed = b->seed; g_seed_set = 1; }
    const char *na = b->no_replay ? NULL : (b->name_a[0] ? b->name_a : NULL);
    const char *nb = b->no_replay ? NULL : (b->name_b[0] ? b->name_b : NULL);
    return run_match((const uint8_t *)b->map_gpa, (size_t)b->map_len,
                     b->debug, na, nb, NULL);
}
#endif

static int u64cmpv(const void *pa, const void *pb) {
    uint64_t a = *(const uint64_t *)pa, b = *(const uint64_t *)pb;
    return a < b ? -1 : a > b;
}
