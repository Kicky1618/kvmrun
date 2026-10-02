/* guest_arm64.ld — flat 64-bit aarch64 payload linked at 0x1000000 */
OUTPUT_FORMAT("elf64-littleaarch64")
ENTRY(_start)

SECTIONS {
    . = 0x1000000;
    .text : {
        *(.text.start)
        *(.text)
        *(.text.*)
    }
    . = ALIGN(4096);
    .rodata : {
        *(.rodata)
        *(.rodata.*)
        *(.rodata1)
    }
    . = ALIGN(4096);
    .data : {
        *(.data)
        *(.data.*)
        *(.data1)
    }
    . = ALIGN(64);
    __tls_start = .;
    .tdata : { *(.tdata) *(.tdata.*) }
    __tdata_end = .;
    .tbss : { *(.tbss) *(.tbss.*) __tbss_end = .; }
    . = ALIGN(4096);
    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
    . = ALIGN(4096);
    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.gnu.hash)
        *(.hash)
        *(.dynsym)
        *(.dynstr)
        *(.got.plt)
    }
}
