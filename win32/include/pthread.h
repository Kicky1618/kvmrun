/* Minimal pthreads -> Win32 shim for the kvmrun native backend.
 * Only included on Windows builds (-Iwin32/include); guest builds use
 * guest/include/pthread.h instead.
 *
 * Covers exactly what host.c uses: mutexes, condition variables
 * (incl. timedwait), threads with detach/join, and attr stack size.
 * Also provides clock_gettime (MSVCRT lacks CLOCK_MONOTONIC on older SDKs).
 */
#ifndef KVMRUN_WIN32_PTHREAD_H
#define KVMRUN_WIN32_PTHREAD_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <process.h>

#ifndef ETIMEDOUT
#define ETIMEDOUT 138
#endif
#ifndef EIO
#define EIO 5
#endif
#ifndef EAGAIN
#define EAGAIN 11
#endif

/* ---- clock_gettime --------------------------------------------------
 * mingw keeps clock_gettime in libwinpthread — linking it adds a runtime
 * dependency on libwinpthread-1.dll. Provide our own under a macro rename
 * (declared in <time.h>, calls rewritten to this TU-local definition), so
 * runner.exe stays free of the pthread DLL entirely. */
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#define clock_gettime kvmrun_win_clock_gettime
static __inline int kvmrun_win_clock_gettime(int id, struct timespec *ts) {
    if (id == CLOCK_MONOTONIC) {
        static volatile LONG qpf_done;
        static LARGE_INTEGER qpf;
        if (!qpf_done) {
            LARGE_INTEGER f;
            QueryPerformanceFrequency(&f);
            qpf = f;
            InterlockedExchange(&qpf_done, 1);
        }
        LARGE_INTEGER c;
        QueryPerformanceCounter(&c);
        ts->tv_sec = (time_t)(c.QuadPart / qpf.QuadPart);
        ts->tv_nsec = (long)((c.QuadPart % qpf.QuadPart)
                             * 1000000000LL / qpf.QuadPart);
        return 0;
    }
    /* CLOCK_REALTIME and anything else: FILETIME is 100 ns ticks since
     * 1601; the unix epoch is 11644473600 s after that. */
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime)
                 - 116444736000000000ull;
    ts->tv_sec = (time_t)(t / 10000000ull);
    ts->tv_nsec = (long)(t % 10000000ull) * 100;
    return 0;
}

/* ---- mutexes --------------------------------------------------------- */

typedef CRITICAL_SECTION pthread_mutex_t;
typedef void *pthread_mutexattr_t;

static __inline int pthread_mutex_init(pthread_mutex_t *m,
                                       const pthread_mutexattr_t *a) {
    (void)a;
    InitializeCriticalSection(m);
    return 0;
}
static __inline int pthread_mutex_lock(pthread_mutex_t *m) {
    EnterCriticalSection(m);
    return 0;
}
static __inline int pthread_mutex_unlock(pthread_mutex_t *m) {
    LeaveCriticalSection(m);
    return 0;
}
static __inline int pthread_mutex_destroy(pthread_mutex_t *m) {
    DeleteCriticalSection(m);
    return 0;
}

/* ---- condition variables ---------------------------------------------- */

typedef CONDITION_VARIABLE pthread_cond_t;
typedef void *pthread_condattr_t;

static __inline int pthread_cond_init(pthread_cond_t *c,
                                      const pthread_condattr_t *a) {
    (void)a;
    InitializeConditionVariable(c);
    return 0;
}
static __inline int pthread_cond_wait(pthread_cond_t *c,
                                      pthread_mutex_t *m) {
    return SleepConditionVariableCS(c, m, INFINITE) ? 0 : EIO;
}
static __inline int pthread_cond_broadcast(pthread_cond_t *c) {
    WakeAllConditionVariable(c);
    return 0;
}
/* pthread_cond_timedwait takes an ABSOLUTE CLOCK_REALTIME deadline;
 * SleepConditionVariableCS takes a relative timeout — convert. */
static __inline int pthread_cond_timedwait(pthread_cond_t *c,
                                           pthread_mutex_t *m,
                                           const struct timespec *ab) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int64_t ms = (int64_t)(ab->tv_sec - now.tv_sec) * 1000 +
                 (ab->tv_nsec - now.tv_nsec) / 1000000;
    if (ms < 0)
        return ETIMEDOUT;
    if (ms > (int64_t)INFINITE - 1)
        ms = INFINITE - 1;
    if (SleepConditionVariableCS(c, m, (DWORD)ms))
        return 0;
    return GetLastError() == ERROR_TIMEOUT ? ETIMEDOUT : EIO;
}
static __inline int pthread_cond_destroy(pthread_cond_t *c) {
    (void)c;
    return 0;
}

/* ---- threads -----------------------------------------------------------
 * pthread_t is a heap block holding the handle + return slot + detached
 * state. detach/join free it; a detached thread frees itself on exit.
 *   state: 0 running-attached, 1 detached, 2 exited
 */
typedef struct kvmrun_win_th {
    HANDLE h;
    void *(*fn)(void *);
    void *arg;
    void *ret;
    volatile LONG state;
} kvmrun_win_th_t;
typedef kvmrun_win_th_t *pthread_t;

typedef struct {
    size_t stacksize;
} pthread_attr_t;

static __inline int pthread_attr_init(pthread_attr_t *a) {
    a->stacksize = 0;
    return 0;
}
static __inline int pthread_attr_setstacksize(pthread_attr_t *a, size_t s) {
    a->stacksize = s;
    return 0;
}
static __inline int pthread_attr_destroy(pthread_attr_t *a) {
    (void)a;
    return 0;
}

static DWORD WINAPI kvmrun_th_tramp(void *p) {
    kvmrun_win_th_t *t = (kvmrun_win_th_t *)p;
    t->ret = t->fn(t->arg);
    if (InterlockedCompareExchange(&t->state, 2, 0) == 1) { /* was detached */
        CloseHandle(t->h);
        free(t);
    }
    return 0;
}

static __inline int pthread_create(pthread_t *pt, const pthread_attr_t *a,
                                   void *(*fn)(void *), void *arg) {
    kvmrun_win_th_t *t = (kvmrun_win_th_t *)malloc(sizeof *t);
    if (!t)
        return EAGAIN;
    t->fn = fn;
    t->arg = arg;
    t->ret = NULL;
    t->state = 0;
    /* CreateThread + RESERVATION: bot stacks must be reserve-only
     * (64-512MiB); _beginthreadex would commit them up front. Under UCRT
     * (VS2015+/mingw-w64 recent) CRT TLS is FLS-managed, so CreateThread
     * is safe — the old leak caveat is pre-UCRT MSVCRT. */
    t->h = CreateThread(NULL,
                        a && a->stacksize ? a->stacksize : 0,
                        kvmrun_th_tramp, t,
                        STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!t->h) {
        free(t);
        return EAGAIN;
    }
    *pt = t;
    return 0;
}

static __inline int pthread_detach(pthread_t t) {
    if (InterlockedCompareExchange(&t->state, 1, 0) == 2) { /* already exited */
        CloseHandle(t->h);
        free(t);
    }
    return 0;
}

static __inline int pthread_join(pthread_t t, void **rc) {
    WaitForSingleObject(t->h, INFINITE);
    if (rc)
        *rc = t->ret;
    CloseHandle(t->h);
    free(t);
    return 0;
}

#endif /* KVMRUN_WIN32_PTHREAD_H */
