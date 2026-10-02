#ifndef G_SETJMP_H
#define G_SETJMP_H
#include <stdint.h>
#ifdef __aarch64__
// {x19-x28, fp, lr, sp, d8-d15}
typedef uint64_t jmp_buf[24];
#else
typedef uint64_t jmp_buf[8];       // {rbx rbp r12 r13 r14 r15 rsp rip}
#endif
typedef jmp_buf sigjmp_buf;
int __sigsetjmp(jmp_buf, int);
int setjmp(jmp_buf);
int _setjmp(jmp_buf);
void siglongjmp(jmp_buf, int) __attribute__((noreturn));
void longjmp(jmp_buf, int) __attribute__((noreturn));
void _longjmp(jmp_buf, int) __attribute__((noreturn));
#define sigsetjmp(b, s) __sigsetjmp(b, s)
#endif
