#ifndef G_STDIO_H
#define G_STDIO_H
#include <stdarg.h>
#include <stddef.h>
typedef struct { int fd; } FILE;
extern FILE *stdout, *stderr;
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int sprintf(char *, const char *, ...);
int vsnprintf(char *, size_t, const char *, va_list);
int vprintf(const char *, va_list);
int vfprintf(FILE *, const char *, va_list);
int fputs(const char *, FILE *);
int puts(const char *);
int putchar(int);
int fflush(FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
void perror(const char *);
FILE *fopen(const char *, const char *);
size_t fread(void *, size_t, size_t, FILE *);
int fclose(FILE *);
int fseek(FILE *, long, int);
long ftell(FILE *);
#define SEEK_SET 0
#define SEEK_END 2
#endif
