#ifndef G_UNISTD_H
#define G_UNISTD_H
#include <stddef.h>
typedef int ssize_t;
char *getcwd(char *, size_t);
int sched_yield(void);
void _exit(int) __attribute__((noreturn));
static inline int usleep(unsigned int usec) { (void)usec; return 0; }
#endif
