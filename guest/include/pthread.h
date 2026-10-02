#ifndef G_PTHREAD_H
#define G_PTHREAD_H
#include <stdint.h>
#include <time.h>

typedef uint64_t pthread_t;
typedef struct { volatile uint32_t v; volatile uint32_t waiters; } pthread_mutex_t;
typedef struct { volatile uint32_t seq; volatile uint32_t waiters; } pthread_cond_t;
typedef void pthread_mutexattr_t;
typedef void pthread_condattr_t;
typedef void pthread_attr_t;

#define PTHREAD_MUTEX_INITIALIZER {0}
#define PTHREAD_COND_INITIALIZER {0}

int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int pthread_detach(pthread_t);
int pthread_join(pthread_t, void **);
pthread_t pthread_self(void);
int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int pthread_mutex_lock(pthread_mutex_t *);
int pthread_mutex_unlock(pthread_mutex_t *);
int pthread_mutex_destroy(pthread_mutex_t *);
int pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *,
                           const struct timespec *);
int pthread_cond_signal(pthread_cond_t *);
int pthread_cond_broadcast(pthread_cond_t *);
int pthread_cond_destroy(pthread_cond_t *);
int sched_yield(void);
#endif
