// entry_arm64.S — aarch64 guest entry, TLS init, ctx switch, setjmp,
// EL1 exception vectors for the Hypervisor.framework backend.
//
// Boot contract (set by vmm_hv.c via hv_vcpu_set_sys_reg):
//   pc = _start, SP_EL0 = BSP_STACK_TOP, CPSR = EL1t (SP0), DAIF masked
//   x1 = mailbox GPA (BSP_MBX_GPA)
//   MMU/sysregs preconfigured by the VMM: TTBR0_EL1/TCR_EL1/MAIR_EL1/SCTLR_EL1
//   VBAR_EL1 and SP_EL1 are guest-owned — set here at boot.
//
// TLS model (mirrors x86 fs:0/fs:8): tp = per-context pointer,
//   [tp+0] = tp (self), [tp+8] = hcall mailbox GPA.
//   Both TPIDR_EL0 (compiler TLS codegen) and TPIDR_EL1 (arch.h reads) get it.
    .text

    // x0 = tp (TLS self pointer), x1 = mailbox GPA
    .globl tls_init
tls_init:
    msr  tpidr_el1, x0
    msr  tpidr_el0, x0          // __thread codegen reads TPIDR_EL0
    isb
    str  x0, [x0]               // [tp] = tp   (fs:0 equivalent)
    str  x1, [x0, #8]           // [tp+8] = mbx (fs:8 equivalent)
    ret

    .globl _start
_start:
    ldr  x9, =vectors_el1
    msr  vbar_el1, x9
    ldr  x9, =__exc_stk_top
    msr  sp_el1, x9             // exceptions always take SP_EL1
    isb
    ldr  x0, =__bsp_tls + 0x800 // tp; TLS image lands below
    // x1 = mailbox GPA, still live from VMM boot regs
    bl   tls_init
    mov  x29, xzr
    mov  x30, xzr
    bl   guest_boot
1:  wfi
    b    1b

    // cooperative ctx switch: x0=from gctx, x1=to gctx
    // gctx layout: +0 saved sp, +8 tp (+128 gs unused here)
    // frame: x19-x30 @0..87, d8-d15 @96..159 — d8-d15 are callee-saved
    // on aarch64 (unlike x86 XMMs) so a switch must carry them.
    .globl gctx_switch
gctx_switch:
    sub  sp, sp, #160
    stp  x19, x20, [sp, #0]
    stp  x21, x22, [sp, #16]
    stp  x23, x24, [sp, #32]
    stp  x25, x26, [sp, #48]
    stp  x27, x28, [sp, #64]
    stp  x29, x30, [sp, #80]
    stp  d8,  d9,  [sp, #96]
    stp  d10, d11, [sp, #112]
    stp  d12, d13, [sp, #128]
    stp  d14, d15, [sp, #144]
    mov  x9, sp
    str  x9, [x0]               // from->rsp
    ldr  x9, [x1]               // to->rsp
    mov  sp, x9
    ldr  x9, [x1, #8]           // to->tp
    msr  tpidr_el1, x9
    msr  tpidr_el0, x9
    isb
    ldp  x19, x20, [sp, #0]
    ldp  x21, x22, [sp, #16]
    ldp  x23, x24, [sp, #32]
    ldp  x25, x26, [sp, #48]
    ldp  x27, x28, [sp, #64]
    ldp  x29, x30, [sp, #80]
    ldp  d8,  d9,  [sp, #96]
    ldp  d10, d11, [sp, #112]
    ldp  d12, d13, [sp, #128]
    ldp  d14, d15, [sp, #144]
    add  sp, sp, #160
    ret                         // jumps to restored x30

    // setjmp family. buf: x19-x28 @0..79, fp @80, lr @88, sp @96,
    // d8-d15 @104..167 -> 21 slots (jmp_buf[24]).
    .globl __sigsetjmp
    .globl setjmp
    .globl _setjmp
__sigsetjmp:
setjmp:
_setjmp:
    stp  x19, x20, [x0, #0]
    stp  x21, x22, [x0, #16]
    stp  x23, x24, [x0, #32]
    stp  x25, x26, [x0, #48]
    stp  x27, x28, [x0, #64]
    stp  x29, x30, [x0, #80]
    mov  x9, sp
    str  x9, [x0, #96]
    stp  d8,  d9,  [x0, #104]
    stp  d10, d11, [x0, #120]
    stp  d12, d13, [x0, #136]
    stp  d14, d15, [x0, #152]
    mov  w0, #0
    ret

    .globl siglongjmp
    .globl longjmp
    .globl _longjmp
siglongjmp:
longjmp:
_longjmp:
    ldp  x19, x20, [x0, #0]
    ldp  x21, x22, [x0, #16]
    ldp  x23, x24, [x0, #32]
    ldp  x25, x26, [x0, #48]
    ldp  x27, x28, [x0, #64]
    ldp  x29, x30, [x0, #80]
    ldr  x9, [x0, #96]
    mov  sp, x9
    ldp  d8,  d9,  [x0, #104]
    ldp  d10, d11, [x0, #120]
    ldp  d12, d13, [x0, #136]
    ldp  d14, d15, [x0, #152]
    mov  w0, w1
    cbnz w1, 1f
    mov  w0, #1
1:  ret

    .section .bss
    .balign 64
__bsp_tls:
    .zero 4096

    // dedicated exception stack — SP_EL1 always, so demand-paged thread
    // stacks faulting mid-growth never run the handler on the faulting sp
    .balign 16
__exc_stk:
    .zero 16384
__exc_stk_top:

// ---------------------------------------------------- exception vectors
// VBAR_EL1: 16 slots x 0x80. Only "sync from EL1t" (offset 0x000) ever
// fires — all code runs at EL1 on SP_EL0; everything else hangs.
    .text
    .balign 0x800
    .globl vectors_el1
vectors_el1:
    .balign 0x80
    b    sync_el1t              // 0x000 sync, EL1t (SP0): the live one
    .balign 0x80
    b    exc_hang               // 0x080 irq EL1t
    .balign 0x80
    b    exc_hang               // 0x100 fiq EL1t
    .balign 0x80
    b    exc_hang               // 0x180 serror EL1t
    .balign 0x80
    b    exc_hang               // 0x200 sync EL1h — unreachable (spsel=0)
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang               // 0x400+ lower EL — guest is EL1-only
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang
    .balign 0x80
    b    exc_hang

exc_hang:
    wfi
    b    exc_hang

// sync exception (EL1t): data/instruction abort == guest page fault.
// exc_report(vec=EC, err=ESR, rip=ELR, far=FAR, frame) in klibc.c decides:
//   demand-page stack commit / wasm OOB trap -> return + eret
//   anything else -> report + hcall_exit (noreturn)
// Stack frame on SP_EL1 (288 bytes, 16-aligned):
//   +0..247  x0-x30      +256 elr_el1   +264 spsr_el1
//   +272     esr_el1     +280 far_el1
sync_el1t:
    sub  sp, sp, #288
    stp  x0,  x1,  [sp, #0]
    stp  x2,  x3,  [sp, #16]
    stp  x4,  x5,  [sp, #32]
    stp  x6,  x7,  [sp, #48]
    stp  x8,  x9,  [sp, #64]
    stp  x10, x11, [sp, #80]
    stp  x12, x13, [sp, #96]
    stp  x14, x15, [sp, #112]
    stp  x16, x17, [sp, #128]
    stp  x18, x19, [sp, #144]
    stp  x20, x21, [sp, #160]
    stp  x22, x23, [sp, #176]
    stp  x24, x25, [sp, #192]
    stp  x26, x27, [sp, #208]
    stp  x28, x29, [sp, #224]
    str  x30, [sp, #240]
    mrs  x9,  elr_el1
    mrs  x10, spsr_el1
    mrs  x11, esr_el1
    mrs  x12, far_el1
    stp  x9,  x10, [sp, #256]
    stp  x11, x12, [sp, #272]
    lsr  x0, x11, #26
    and  x0, x0, #0x3f          // vec = EC (0x24 data abort, 0x20 insn abort)
    mov  x1, x11                // err = full ESR (ISS in low bits)
    mov  x2, x9                 // rip = ELR
    mov  x3, x12                // cr2-equiv = FAR
    mov  x4, sp                 // frame base for post-mortem walk
    bl   exc_report
    ldr  x9,  [sp, #256]
    msr  elr_el1, x9
    ldr  x10, [sp, #264]
    msr  spsr_el1, x10
    ldp  x0,  x1,  [sp, #0]
    ldp  x2,  x3,  [sp, #16]
    ldp  x4,  x5,  [sp, #32]
    ldp  x6,  x7,  [sp, #48]
    ldp  x8,  x9,  [sp, #64]
    ldp  x10, x11, [sp, #80]
    ldp  x12, x13, [sp, #96]
    ldp  x14, x15, [sp, #112]
    ldp  x16, x17, [sp, #128]
    ldp  x18, x19, [sp, #144]
    ldp  x20, x21, [sp, #160]
    ldp  x22, x23, [sp, #176]
    ldp  x24, x25, [sp, #192]
    ldp  x26, x27, [sp, #208]
    ldp  x28, x29, [sp, #224]
    ldr  x30, [sp, #240]
    add  sp, sp, #288
    eret
