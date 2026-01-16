/*
 * NanOS - ARM64 HAL Implementation
 * Hardware abstraction for AArch64 platforms (QEMU virt, RPi4)
 */

#include "../../include/hal.h"
#include "../../include/nanos.h"

/* ==========================================================================
 * ARM64 Specific Definitions
 * ========================================================================== */

/* QEMU virt machine memory map */
#define VIRT_UART_BASE      0x09000000  /* PL011 UART */
#define VIRT_RTC_BASE       0x09010000  /* PL031 RTC */
#define VIRT_GIC_DIST       0x08000000  /* GIC Distributor */
#define VIRT_GIC_CPU        0x08010000  /* GIC CPU Interface (GICv2) */
#define VIRT_GIC_REDIST     0x080A0000  /* GIC Redistributor (GICv3) */
#define VIRT_VIRTIO_BASE    0x0A000000  /* VirtIO MMIO base */
#define VIRT_VIRTIO_SIZE    0x200       /* Size per device */
#define VIRT_VIRTIO_IRQ     48          /* First VirtIO IRQ */

/* PL011 UART Registers */
#define UART_DR             0x00        /* Data Register */
#define UART_FR             0x18        /* Flag Register */
#define UART_IBRD           0x24        /* Integer Baud Rate */
#define UART_FBRD           0x28        /* Fractional Baud Rate */
#define UART_LCR_H          0x2C        /* Line Control */
#define UART_CR             0x30        /* Control Register */
#define UART_IMSC           0x38        /* Interrupt Mask */
#define UART_ICR            0x44        /* Interrupt Clear */

#define UART_FR_TXFF        (1 << 5)    /* TX FIFO Full */
#define UART_FR_RXFE        (1 << 4)    /* RX FIFO Empty */

/* GICv2 Registers */
#define GICD_CTLR           0x000
#define GICD_ISENABLER      0x100
#define GICD_ICENABLER      0x180
#define GICD_ICPENDR        0x280
#define GICD_ITARGETSR      0x800
#define GICC_CTLR           0x000
#define GICC_PMR            0x004
#define GICC_IAR            0x00C
#define GICC_EOIR           0x010

/* ARM Generic Timer */
#define TIMER_IRQ           30          /* Non-secure EL1 physical timer */

/* ==========================================================================
 * External Assembly Functions
 * ========================================================================== */
extern void arm64_wfi(void);
extern void arm64_wfe(void);
extern void arm64_irq_enable(void);
extern uint32_t arm64_irq_disable(void);
extern uint64_t arm64_get_timer(void);
extern uint64_t arm64_get_timer_freq(void);

/* ==========================================================================
 * State
 * ========================================================================== */
static volatile uint32_t timer_ticks = 0;
static uint32_t timer_interval = 0;
static uint64_t timer_freq = 0;

/* IRQ handlers table */
#define MAX_IRQS 256
static irq_handler_t irq_handlers[MAX_IRQS];

/* ==========================================================================
 * UART Console (PL011)
 * ========================================================================== */
void hal_console_init(void) {
    /* Disable UART */
    mmio_write32(VIRT_UART_BASE + UART_CR, 0);

    /* Clear pending interrupts */
    mmio_write32(VIRT_UART_BASE + UART_ICR, 0x7FF);

    /* Set baud rate (115200 @ 24MHz clock) */
    mmio_write32(VIRT_UART_BASE + UART_IBRD, 13);
    mmio_write32(VIRT_UART_BASE + UART_FBRD, 1);

    /* 8N1, enable FIFOs */
    mmio_write32(VIRT_UART_BASE + UART_LCR_H, (3 << 5) | (1 << 4));

    /* Enable UART, TX, RX */
    mmio_write32(VIRT_UART_BASE + UART_CR, (1 << 0) | (1 << 8) | (1 << 9));
}

void hal_console_putc(char c) {
    /* Wait for TX FIFO not full */
    while (mmio_read32(VIRT_UART_BASE + UART_FR) & UART_FR_TXFF);
    mmio_write32(VIRT_UART_BASE + UART_DR, c);
}

void hal_console_puts(const char* str) {
    while (*str) {
        if (*str == '\n') hal_console_putc('\r');
        hal_console_putc(*str++);
    }
}

void hal_console_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    hal_console_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        hal_console_putc(hex[(value >> i) & 0xF]);
    }
}

void hal_console_put_dec(uint32_t value) {
    char buf[12];
    int i = 0;
    if (value == 0) {
        hal_console_putc('0');
        return;
    }
    while (value > 0) {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i > 0) hal_console_putc(buf[--i]);
}

void hal_console_set_color(uint8_t color) {
    /* ANSI escape codes for serial terminal */
    hal_console_puts("\033[");
    switch (color & 0x0F) {
        case 0x0A: hal_console_puts("32"); break;  /* Green */
        case 0x0B: hal_console_puts("36"); break;  /* Cyan */
        case 0x0C: hal_console_puts("31"); break;  /* Red */
        case 0x0D: hal_console_puts("35"); break;  /* Magenta */
        case 0x0E: hal_console_puts("33"); break;  /* Yellow */
        default:   hal_console_puts("37"); break;  /* White */
    }
    hal_console_putc('m');
}

void hal_console_clear(void) {
    hal_console_puts("\033[2J\033[H");  /* Clear screen, home cursor */
}

/* ==========================================================================
 * GIC (Generic Interrupt Controller) v2
 * ========================================================================== */
void hal_irq_init(void) {
    /* Clear handlers */
    for (int i = 0; i < MAX_IRQS; i++) {
        irq_handlers[i] = (irq_handler_t)0;
    }

    /* Enable GIC Distributor */
    mmio_write32(VIRT_GIC_DIST + GICD_CTLR, 1);

    /* Enable GIC CPU Interface */
    mmio_write32(VIRT_GIC_CPU + GICC_CTLR, 1);

    /* Set priority mask to allow all priorities */
    mmio_write32(VIRT_GIC_CPU + GICC_PMR, 0xFF);
}

void hal_irq_register(uint32_t irq_num, irq_handler_t handler) {
    if (irq_num < MAX_IRQS) {
        irq_handlers[irq_num] = handler;
    }
}

void hal_irq_unmask(uint32_t irq_num) {
    uint32_t reg = irq_num / 32;
    uint32_t bit = irq_num % 32;

    /* Enable the interrupt */
    mmio_write32(VIRT_GIC_DIST + GICD_ISENABLER + reg * 4, 1 << bit);

    /* Route to CPU 0 */
    if (irq_num >= 32) {
        uint32_t target_reg = VIRT_GIC_DIST + GICD_ITARGETSR + irq_num;
        mmio_write8(target_reg, 0x01);
    }
}

void hal_irq_mask(uint32_t irq_num) {
    uint32_t reg = irq_num / 32;
    uint32_t bit = irq_num % 32;
    mmio_write32(VIRT_GIC_DIST + GICD_ICENABLER + reg * 4, 1 << bit);
}

void hal_irq_ack(uint32_t irq_num) {
    mmio_write32(VIRT_GIC_CPU + GICC_EOIR, irq_num);
}

/* ==========================================================================
 * Timer (ARM Generic Timer)
 * ========================================================================== */
static void timer_handler(void) {
    timer_ticks++;

    /* Acknowledge timer interrupt by writing to CNTV_TVAL */
    __asm__ volatile(
        "msr cntv_tval_el0, %0"
        :
        : "r"(timer_interval)
    );
}

void hal_timer_init(uint32_t frequency) {
    /* Get timer frequency */
    timer_freq = arm64_get_timer_freq();
    timer_interval = timer_freq / frequency;

    /* Register timer IRQ handler */
    hal_irq_register(TIMER_IRQ, timer_handler);
    hal_irq_unmask(TIMER_IRQ);

    /* Set timer value and enable */
    __asm__ volatile(
        "msr cntv_tval_el0, %0\n"
        "mov x0, #1\n"
        "msr cntv_ctl_el0, x0"
        :
        : "r"(timer_interval)
        : "x0"
    );
}

uint32_t hal_timer_ticks(void) {
    return timer_ticks;
}

void hal_delay_us(uint32_t us) {
    uint64_t start = arm64_get_timer();
    uint64_t ticks = (timer_freq * us) / 1000000;
    while (arm64_get_timer() - start < ticks);
}

void hal_delay_ms(uint32_t ms) {
    hal_delay_us(ms * 1000);
}

/* ==========================================================================
 * CPU Control
 * ========================================================================== */
void hal_cpu_idle(void) {
    arm64_wfi();
}

uint32_t hal_irq_disable(void) {
    return arm64_irq_disable();
}

void hal_irq_enable(void) {
    arm64_irq_enable();
}

void hal_irq_restore(uint32_t state) {
    if (!(state & (1 << 7))) {  /* Check if IRQ was enabled */
        arm64_irq_enable();
    }
}

void hal_cpu_halt(void) {
    for (;;) arm64_wfi();
}

void hal_cpu_reset(void) {
    /* QEMU virt: write to PSCI or just halt */
    hal_cpu_halt();
}

/* ==========================================================================
 * Power Management
 * ========================================================================== */
static power_mode_t current_power_mode = POWER_MODE_RUN;

void hal_power_set_mode(power_mode_t mode) {
    current_power_mode = mode;
}

power_mode_t hal_power_get_mode(void) {
    return current_power_mode;
}

void hal_power_idle(void) {
    arm64_wfi();  /* Wait For Interrupt - low power state */
}

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */
static uint32_t sw_rng_state = 0xDEADBEEF;

void hal_rng_init(void) {
    /* Seed from timer */
    sw_rng_state = (uint32_t)arm64_get_timer();
    if (sw_rng_state == 0) sw_rng_state = 0xDEADBEEF;
}

void hal_rng_seed(uint32_t seed) {
    sw_rng_state = seed;
    if (sw_rng_state == 0) sw_rng_state = 0xDEADBEEF;
}

uint32_t hal_rng_get(void) {
    /* Xorshift32 */
    sw_rng_state ^= sw_rng_state << 13;
    sw_rng_state ^= sw_rng_state >> 17;
    sw_rng_state ^= sw_rng_state << 5;
    return sw_rng_state;
}

/* ==========================================================================
 * Cache Operations
 * ========================================================================== */
void hal_cache_flush(void* addr, size_t size) {
    uintptr_t start = (uintptr_t)addr & ~63;  /* 64-byte cache line */
    uintptr_t end = ((uintptr_t)addr + size + 63) & ~63;

    for (uintptr_t p = start; p < end; p += 64) {
        __asm__ volatile("dc civac, %0" : : "r"(p) : "memory");
    }
    dsb();
}

void hal_cache_invalidate(void* addr, size_t size) {
    uintptr_t start = (uintptr_t)addr & ~63;
    uintptr_t end = ((uintptr_t)addr + size + 63) & ~63;

    for (uintptr_t p = start; p < end; p += 64) {
        __asm__ volatile("dc ivac, %0" : : "r"(p) : "memory");
    }
    dsb();
}

/* ==========================================================================
 * Platform Initialization
 * ========================================================================== */
void hal_early_init(void) {
    /* Called before BSS is cleared, be careful */
}

void hal_platform_init(void) {
    hal_console_init();
    hal_irq_init();
    hal_rng_init();
}

const char* hal_platform_info(void) {
    return "ARM64 QEMU virt";
}

/* ==========================================================================
 * IRQ Handler (called from assembly)
 * ========================================================================== */
void arm64_irq_handler(void) {
    /* Read interrupt ID from GIC */
    uint32_t iar = mmio_read32(VIRT_GIC_CPU + GICC_IAR);
    uint32_t irq = iar & 0x3FF;

    if (irq < 1020) {  /* Valid interrupt */
        if (irq_handlers[irq]) {
            irq_handlers[irq]();
        }
        hal_irq_ack(irq);
    }
}

void arm64_sync_exception(void) {
    hal_console_puts("\n!!! Synchronous Exception !!!\n");
    hal_cpu_halt();
}
