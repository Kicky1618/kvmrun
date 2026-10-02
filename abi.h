// abi.h — guest <-> VMM contract for kvmrun.
//
// A guest thread == a KVM vCPU. All threads share identity-mapped flat memory.
// Threads synchronise with futex hypercalls; everything else uses a per-thread
// mailbox + MMIO doorbell:
//
//   guest fills `struct hcall` in its mailbox page, then stores the mailbox GPA
//   into the DOORBELL MMIO slot -> KVM_EXIT_MMIO gives the VMM the mailbox GPA.
//
// Memory map (GPA):
//   0x1000  PML4          0x2000  PDPT (1GiB entries)
//   0x3000  GDT
//   0x6000  BSP mailbox   0x7000  bootinfo
//   0x800000              MAP_GPA: map bytes, preloaded by the VMM (8MiB)
//   0x1000000             payload ELF (linked at KERNEL_LINK)
//   0x4000000..0x4800000  per-thread mailbox arena (4KiB slots, 2048)
//   [_end, RAM_BYTES - BSP_STACK_RESERVE)   guest heap
//   top 256MiB of RAM     BSP stack (grows down from BSP_STACK_TOP)
//   DOORBELL_GPA          MMIO doorbell (just above RAM)
//
#ifndef KVMRUN_ABI_H
#define KVMRUN_ABI_H

#include <stdint.h>

#define RAM_BYTES      (32ull << 30)      /* 32 GiB */
#define KERNEL_LINK    0x1000000ull
#define BSP_STACK_TOP  RAM_BYTES          /* grows down; top of guest RAM */
#define BSP_STACK_RESERVE (256ull << 20)  /* heap stays below this ceiling */
#define BSP_MBX_GPA    0x6000ull
#define BOOTINFO_GPA   0x7000ull
#define MBX_ARENA_GPA  0x4000000ull       /* 4KiB slots -> 2048 threads */
#define MBX_SIZE       0x1000ull
#define MBX_ARENA_BYTES (8ull << 20)
#define MAP_GPA        0x800000ull        /* 8 MiB of map space */
#define MAP_MAX        (8ull << 20)
#define DOORBELL_GPA   (RAM_BYTES + 0x100000ull)

#define BOOT_MAGIC     0x4B564D52554E21ull /* "KVMRUN!" */

struct bootinfo {
    uint64_t magic;
    uint64_t map_gpa, map_len;
    uint64_t ram_size;
    uint32_t debug;
    uint32_t no_replay;
    uint32_t verbose;
    uint32_t seed_set;
    uint64_t seed;                      /* valid when seed_set */
    char name_a[256], name_b[256];
};

struct hcall {
    uint32_t nr;
    uint32_t _pad;
    uint64_t a, b, c, d;
    uint64_t ret;
};

enum {
    HC_NOP = 0,
    HC_PRINT,          // a=fd b=buf_gpa c=len      -> ret=len
    HC_EXIT,           // a=code                    -> VM exits
    HC_NOW,            //                           -> ret = host MONOTONIC ns
    HC_SPAWN,          // a=entry b=stacktop c=arg  -> ret = tid (<0 err)
    HC_EXIT_THREAD,    //                           -> parks this vCPU for good
    HC_FUTEX_WAIT,     // a=addr b=expected c=dl_ns -> ret 0=wake 1=tmo 2=mismatch
    HC_FUTEX_WAKE,     // a=addr b=count            -> ret = woken count
    HC_REPLAY,         // a=buf b=len               -> ret 0/-1
    HC_GUESTFAULT,     // a=vec b=rip c=cr2         -> diagnostic, ret unused
    HC_PROF,           // a=hist_gpa b=bytes        -> registers prof histogram
};

#endif
