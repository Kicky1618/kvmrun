#ifndef G_SETJMP_H
#define G_SETJMP_H
#include <stdint.h>
typedef uint64_t jmp_buf[8];       // {rbx rbp r12 r13 r14 r15 rsp rip}
typedef jmp_buf sigjmp_buf;
int __sigsetjmp(jmp_buf, int);
int setjmp(jmp_buf);
int _setjmp(jmp_buf);
void siglongjmp(jmp_buf, int) __attribute__((noreturn));
void longjmp(jmp_buf, int) __attribute__((noreturn));
void _longjmp(jmp_buf, int) __attribute__((noreturn));
#define sigsetjmp(b, s) __sigsetjmp(b, s)
#endif
