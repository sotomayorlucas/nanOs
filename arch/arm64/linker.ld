/*
 * NanOS ARM64 Linker Script
 * For QEMU virt machine (-M virt -cpu cortex-a72)
 *
 * Memory layout:
 *   0x40000000 - RAM start (QEMU virt default)
 *   0x40080000 - Kernel load address
 */

ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 64M
}

SECTIONS
{
    . = 0x40080000;

    /* Code section - must be first for boot */
    .text : {
        KEEP(*(.text.boot))     /* Boot code first */
        *(.text*)               /* Rest of code */
    } > RAM

    /* Read-only data */
    .rodata : ALIGN(4K) {
        *(.rodata*)
    } > RAM

    /* Initialized data */
    .data : ALIGN(4K) {
        *(.data*)
    } > RAM

    /* Uninitialized data */
    _bss_start = .;
    .bss : ALIGN(4K) {
        *(.bss*)
        *(COMMON)
    } > RAM
    _bss_end = .;

    /* Stack at end of used memory */
    . = ALIGN(16);
    _stack_bottom = .;
    . += 16K;
    _stack_top = .;

    /* Heap after stack */
    _heap_start = .;
    _heap_end = ORIGIN(RAM) + LENGTH(RAM);

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
