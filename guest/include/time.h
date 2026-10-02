#ifndef G_TIME_H
#define G_TIME_H
#include <stdint.h>
typedef int64_t time_t;
struct timespec { int64_t tv_sec; int64_t tv_nsec; };
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
int clock_gettime(int, struct timespec *);
time_t time(time_t *);
#endif
