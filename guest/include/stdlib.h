#ifndef G_STDLIB_H
#define G_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void free(void *);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
int atoi(const char *);
long atol(const char *);
char *getenv(const char *);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
#endif
