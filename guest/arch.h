// arch.h — ISA glue shared by klibc.c / gthr.c so the guest can build for
// x86-64 (KVM, WHPX) or aarch64 (Hypervisor.framework).
//
// TLS model is identical on both ISAs: a per-context thread pointer `tp`
// where [tp+0] = tp (self) and [tp+8] = hcall mailbox GPA.
//   x86-64:  tp lives in FS base (fs:0/fs:8)
//   aarch64: tp lives in TPIDR_EL1
#pragma once
#include <stdint.h>

#ifdef __aarch64__

static inline uint64_t guest_tp(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(v));
    return v;
}
static inline void guest_set_tp(uint64_t tp) {
    __asm__ volatile("msr tpidr_el1, %0" :: "r"(tp) : "memory");
}
static inline void cpu_relax(void) { __asm__ volatile("yield"); }
static inline void cpu_halt(void)  { __asm__ volatile("wfi"); }
// drain all stores before the MMIO doorbell write traps to the VMM
static inline void mmio_fence(void) {
    __asm__ volatile("dsb sy" ::: "memory");
}
static inline uint64_t rd_cycles(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
// guest page tables: invalidate a single VA after a PTE change
static inline void tlb_inval_page(uint64_t va) {
    __asm__ volatile("dsb ishst\n\t"
                     "tlbi vaae1, %0\n\t"
                     "dsb ish\n\t"
                     "isb"
                     :: "r"(va >> 12) : "memory");
}
// invalidate whole guest TLB (table changes / new mappings)
static inline void tlb_inval_all(void) {
    __asm__ volatile("dsb ishst\n\ttlbi vmalle1\n\tdsb ish\n\tisb"
                     ::: "memory");
}

#else /* x86-64 */

static inline uint64_t guest_tp(void) {
    uint64_t v;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(v));
    return v;
}
static inline void guest_set_tp(uint64_t tp) {   // via FS-base MSR
    uint32_t lo = (uint32_t)tp, hi = (uint32_t)(tp >> 32);
    __asm__ volatile("wrmsr" :: "c"(0xC0000100u), "a"(lo), "d"(hi));
}
static inline void cpu_relax(void) { __asm__ volatile("pause"); }
static inline void cpu_halt(void)  { __asm__ volatile("hlt"); }
static inline void mmio_fence(void) { __sync_synchronize(); }
static inline uint64_t rd_cycles(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | ((uint64_t)hi << 32);
}
static inline void tlb_inval_page(uint64_t va) {
    __asm__ volatile("invlpg %0" :: "m"(*(volatile char *)va) : "memory");
}
static inline void tlb_inval_all(void) { }

#endif

// Guest page-table descriptor encodings. VA index split is identical on
// both ISAs (4x9 bits @39/30/21/12, 4KiB granule); only the descriptor
// format differs.
//   x86-64:  table/leaf = pa|3; 2MiB leaf sets PS(bit7). Valid = bit0.
//   aarch64: table = pa|0b11; leaf = pa|desc + AF|SH_INNER; 2MiB block
//            has bits[1:0]=01 (vs table 0b11). Valid = bit0.
#ifdef __aarch64__
#define PT_TBL      0x3ull                                    // table desc
#define PT_LEAF     (0x3ull | (1ull << 10) | (3ull << 8))     // AF|inner-sh
#define PT_LEAF2M   (0x1ull | (1ull << 10) | (3ull << 8))     // L2 block
#define PTE_IS_2M(e)  (!((e) & 0x2ull))
#else
#define PT_TBL      3ull
#define PT_LEAF     3ull
#define PT_LEAF2M   (3ull | 0x80ull)                          // PS bit
#define PTE_IS_2M(e)  ((e) & 0x80ull)
#endif
