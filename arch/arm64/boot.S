/*
 * NanOS - ARM64 Boot Code
 * Entry point for AArch64 systems (QEMU virt, Raspberry Pi 4)
 *
 * Boot protocol: Kernel loaded at 0x40080000 by QEMU -kernel
 * DTB passed in x0, kernel entry in x1 (or 0)
 */

.section .text.boot
.global _start

/* ==========================================================================
 * Entry Point - CPU starts here in EL1 or EL2
 * ========================================================================== */
_start:
    /* Save DTB pointer (passed in x0 by bootloader) */
    ldr     x9, =_dtb_ptr
    str     x0, [x9]

    /* Get current exception level */
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.eq    drop_to_el1
    cmp     x0, #1
    b.eq    setup_el1
    /* If EL3, we need more setup - not supported for now */
    b       halt

/* ==========================================================================
 * Drop from EL2 to EL1 (hypervisor to kernel mode)
 * ========================================================================== */
drop_to_el1:
    /* Configure EL2 to drop to EL1 */
    mov     x0, #(1 << 31)      /* EL1 uses AArch64 */
    orr     x0, x0, #(1 << 1)   /* SWIO hardwired */
    msr     hcr_el2, x0

    /* Set up SPSR for EL1h (SP_EL1, interrupts masked) */
    mov     x0, #0x3c5          /* D=1, A=1, I=1, F=1, M=EL1h */
    msr     spsr_el2, x0

    /* Set return address to EL1 setup */
    adr     x0, setup_el1
    msr     elr_el2, x0

    /* Return to EL1 */
    eret

/* ==========================================================================
 * EL1 Setup - Configure MMU, caches, and stack
 * ========================================================================== */
setup_el1:
    /* Disable MMU and caches initially for simple flat mapping */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)   /* M: MMU off */
    bic     x0, x0, #(1 << 2)   /* C: Data cache off */
    bic     x0, x0, #(1 << 12)  /* I: Instruction cache off */
    msr     sctlr_el1, x0
    isb

    /* Set up stack pointer (16KB stack at end of reserved memory) */
    ldr     x0, =_stack_top
    mov     sp, x0

    /* Clear BSS section */
    ldr     x0, =_bss_start
    ldr     x1, =_bss_end
    mov     x2, #0
1:  cmp     x0, x1
    b.ge    2f
    str     x2, [x0], #8
    b       1b
2:

    /* Enable instruction cache for performance */
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 12)  /* I: Instruction cache on */
    msr     sctlr_el1, x0
    isb

    /* Initialize vector table */
    ldr     x0, =exception_vectors
    msr     vbar_el1, x0
    isb

    /* Enable FPU/SIMD (for memcpy etc) */
    mov     x0, #(3 << 20)      /* FPEN = 11 (no trap) */
    msr     cpacr_el1, x0
    isb

    /* Jump to C code */
    bl      kernel_main

    /* If kernel_main returns, halt */
halt:
    wfi
    b       halt

/* ==========================================================================
 * Exception Vector Table (must be 2KB aligned)
 * ========================================================================== */
.balign 0x800
exception_vectors:
    /* Current EL with SP0 */
    .balign 0x80
    b       sync_handler        /* Synchronous */
    .balign 0x80
    b       irq_handler         /* IRQ */
    .balign 0x80
    b       fiq_handler         /* FIQ */
    .balign 0x80
    b       serror_handler      /* SError */

    /* Current EL with SPx */
    .balign 0x80
    b       sync_handler
    .balign 0x80
    b       irq_handler
    .balign 0x80
    b       fiq_handler
    .balign 0x80
    b       serror_handler

    /* Lower EL using AArch64 */
    .balign 0x80
    b       sync_handler
    .balign 0x80
    b       irq_handler
    .balign 0x80
    b       fiq_handler
    .balign 0x80
    b       serror_handler

    /* Lower EL using AArch32 */
    .balign 0x80
    b       sync_handler
    .balign 0x80
    b       irq_handler
    .balign 0x80
    b       fiq_handler
    .balign 0x80
    b       serror_handler

/* ==========================================================================
 * Exception Handlers
 * ========================================================================== */
sync_handler:
    /* Save context */
    stp     x29, x30, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!
    stp     x17, x18, [sp, #-16]!
    stp     x15, x16, [sp, #-16]!
    stp     x13, x14, [sp, #-16]!
    stp     x11, x12, [sp, #-16]!
    stp     x9, x10, [sp, #-16]!
    stp     x7, x8, [sp, #-16]!
    stp     x5, x6, [sp, #-16]!
    stp     x3, x4, [sp, #-16]!
    stp     x1, x2, [sp, #-16]!
    str     x0, [sp, #-8]!

    /* Call C handler */
    bl      arm64_sync_exception

    /* Restore and return */
    ldr     x0, [sp], #8
    ldp     x1, x2, [sp], #16
    ldp     x3, x4, [sp], #16
    ldp     x5, x6, [sp], #16
    ldp     x7, x8, [sp], #16
    ldp     x9, x10, [sp], #16
    ldp     x11, x12, [sp], #16
    ldp     x13, x14, [sp], #16
    ldp     x15, x16, [sp], #16
    ldp     x17, x18, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x29, x30, [sp], #16
    eret

irq_handler:
    stp     x29, x30, [sp, #-16]!
    stp     x0, x1, [sp, #-16]!

    /* Call C IRQ handler */
    bl      arm64_irq_handler

    ldp     x0, x1, [sp], #16
    ldp     x29, x30, [sp], #16
    eret

fiq_handler:
    b       halt

serror_handler:
    b       halt

/* ==========================================================================
 * CPU Control Functions (called from C)
 * ========================================================================== */
.global arm64_wfi
arm64_wfi:
    wfi
    ret

.global arm64_wfe
arm64_wfe:
    wfe
    ret

.global arm64_irq_enable
arm64_irq_enable:
    msr     daifclr, #2         /* Clear I bit */
    ret

.global arm64_irq_disable
arm64_irq_disable:
    mrs     x0, daif
    msr     daifset, #2         /* Set I bit */
    ret

.global arm64_get_timer
arm64_get_timer:
    mrs     x0, cntpct_el0      /* Physical timer count */
    ret

.global arm64_get_timer_freq
arm64_get_timer_freq:
    mrs     x0, cntfrq_el0      /* Timer frequency */
    ret

/* ==========================================================================
 * Data Section
 * ========================================================================== */
.section .data
.global _dtb_ptr
_dtb_ptr:
    .quad   0

/* ==========================================================================
 * BSS Section
 * ========================================================================== */
.section .bss
.balign 16
_stack_bottom:
    .skip   16384               /* 16KB stack */
_stack_top:
