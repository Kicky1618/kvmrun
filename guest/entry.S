// entry.S — guest entry points, TLS init, setjmp/longjmp.
    .text

    // rdi = tp (TLS self pointer), rsi = mailbox GPA
    .globl tls_init
tls_init:
    mov  $0xC0000100, %ecx          // MSR_FS_BASE
    mov  %rdi, %rax
    mov  %rdi, %rdx
    shr  $32, %rdx
    wrmsr
    mov  %rdi, %fs:0
    mov  %rsi, %fs:8                // hcall() reads mbx from fs:8
    ret

    .globl _start
_start:
    // VMM: rip=_start, rsp=BSP_STACK_TOP, rsi=mailbox GPA
    fninit
    lea  __bsp_tls(%rip), %rdi
    add  $0x800, %rdi               // tp; TLS image lands below
    call tls_init
    xor  %ebp, %ebp
    call guest_boot
    hlt

    // cooperative ctx switch: rdi=from gctx, rsi=to gctx
    // gctx layout: +0 saved rsp, +8 tp (fs base)
    .globl gctx_switch
gctx_switch:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    mov  %rsp, 0(%rdi)
    mov  0(%rsi), %rsp
    mov  8(%rsi), %rdi              // to->tp
    mov  $0xC0000100, %ecx          // MSR_FS_BASE
    mov  %rdi, %rax
    mov  %rdi, %rdx
    shr  $32, %rdx
    wrmsr
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

    // setjmp family: buf = {rbx rbp r12 r13 r14 r15 rsp rip}
    .globl __sigsetjmp
    .globl setjmp
    .globl _setjmp
__sigsetjmp:
setjmp:
_setjmp:
    mov  %rbx,  0(%rdi)
    mov  %rbp,  8(%rdi)
    mov  %r12, 16(%rdi)
    mov  %r13, 24(%rdi)
    mov  %r14, 32(%rdi)
    mov  %r15, 40(%rdi)
    lea  8(%rsp), %rdx
    mov  %rdx, 48(%rdi)
    mov  (%rsp), %rdx
    mov  %rdx, 56(%rdi)
    xor  %eax, %eax
    ret

    .globl siglongjmp
    .globl longjmp
    .globl _longjmp
siglongjmp:
longjmp:
_longjmp:
    mov  0(%rdi), %rbx
    mov  8(%rdi), %rbp
    mov  16(%rdi), %r12
    mov  24(%rdi), %r13
    mov  32(%rdi), %r14
    mov  40(%rdi), %r15
    mov  48(%rdi), %rsp
    mov  56(%rdi), %rdx
    mov  %esi, %eax
    test %esi, %esi
    jnz  1f
    mov  $1, %eax
1:  jmp  *%rdx

    .section .bss
    .balign 64
__bsp_tls:
    .zero 4096

// ------------------------------------------------------------------ IDT
// Exception stubs: normalize stack to [vec][err][rip][cs][rflags] then call
// exc_report(vec, err, rip, cr2) in klibc.c. CPU err-code vectors:
// 8,10,11,12,13,14,17,21,29,30.
    .text
// exc_report may resume the faulting context (stack demand-paging), so save
// all GPRs and iretq if it returns. Layout after pushes:
//   rsp+0..112 saved regs, +120 vec, +128 err, +136 rip, +144 cs, +152 rflags
exc_common:
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    push %rbp
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rbx
    push %rax
    mov  %cr2, %rcx
    mov  120(%rsp), %rdi
    mov  128(%rsp), %rsi
    mov  136(%rsp), %rdx
    lea  120(%rsp), %r8           // frame base for post-mortem stack walk
    mov  %rsp, %rbp
    and  $-16, %rsp
    call exc_report
    mov  %rbp, %rsp
    pop  %rax
    pop  %rbx
    pop  %rcx
    pop  %rdx
    pop  %rsi
    pop  %rdi
    pop  %rbp
    pop  %r8
    pop  %r9
    pop  %r10
    pop  %r11
    pop  %r12
    pop  %r13
    pop  %r14
    pop  %r15
    add  $16, %rsp                // drop vec+err
    iretq

.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
exc_\n:
    .if \n != 8 && \n != 10 && \n != 11 && \n != 12 && \n != 13 && \n != 14 && \n != 17 && \n != 21 && \n != 29 && \n != 30
    pushq $0
    .endif
    pushq $\n
    jmp  exc_common
.endr

    .section .rodata
    .balign 8
    .globl exc_stub_table
exc_stub_table:
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .quad exc_\n
.endr
