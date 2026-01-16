/*
 * NanOS - Hardware Abstraction Layer
 * Portable interface for multi-architecture support
 *
 * Supported architectures:
 *   - x86 (i386/i686)
 *   - ARM64 (AArch64)
 *   - ARM32 (Cortex-M for low-power MCUs)
 */

#ifndef HAL_H
#define HAL_H

#include "nanos.h"  /* For freestanding types */

/* ==========================================================================
 * Architecture Detection
 * ========================================================================== */
#if defined(__x86_64__) || defined(__i386__) || defined(__i686__)
    #ifndef ARCH_X86
        #define ARCH_X86
    #endif
    #define ARCH_NAME "x86"
#elif defined(__aarch64__)
    #define ARCH_ARM64
    #define ARCH_NAME "ARM64"
#elif defined(__arm__)
    #define ARCH_ARM32
    #define ARCH_NAME "ARM32"
#else
    #error "Unsupported architecture"
#endif

/* ==========================================================================
 * Platform Detection
 * ========================================================================== */
#if defined(PLATFORM_QEMU_X86)
    #define PLATFORM_NAME "QEMU-x86"
#elif defined(PLATFORM_QEMU_ARM64)
    #define PLATFORM_NAME "QEMU-virt"
#elif defined(PLATFORM_RPI4)
    #define PLATFORM_NAME "RPi4"
#elif defined(PLATFORM_STM32)
    #define PLATFORM_NAME "STM32"
#else
    #define PLATFORM_NAME "generic"
#endif

/* ==========================================================================
 * Memory-Mapped I/O (Architecture-independent)
 * ========================================================================== */
static inline void mmio_write32(uintptr_t addr, uint32_t value) {
    *(volatile uint32_t*)addr = value;
}

static inline uint32_t mmio_read32(uintptr_t addr) {
    return *(volatile uint32_t*)addr;
}

static inline void mmio_write16(uintptr_t addr, uint16_t value) {
    *(volatile uint16_t*)addr = value;
}

static inline uint16_t mmio_read16(uintptr_t addr) {
    return *(volatile uint16_t*)addr;
}

static inline void mmio_write8(uintptr_t addr, uint8_t value) {
    *(volatile uint8_t*)addr = value;
}

static inline uint8_t mmio_read8(uintptr_t addr) {
    return *(volatile uint8_t*)addr;
}

/* ==========================================================================
 * Memory Barriers (Critical for multi-core and DMA)
 * ========================================================================== */
#ifdef ARCH_X86
    #define dmb()   __asm__ volatile("mfence" ::: "memory")
    #define dsb()   __asm__ volatile("mfence" ::: "memory")
    #define isb()   __asm__ volatile("" ::: "memory")
#elif defined(ARCH_ARM64)
    #define dmb()   __asm__ volatile("dmb sy" ::: "memory")
    #define dsb()   __asm__ volatile("dsb sy" ::: "memory")
    #define isb()   __asm__ volatile("isb" ::: "memory")
#elif defined(ARCH_ARM32)
    #define dmb()   __asm__ volatile("dmb" ::: "memory")
    #define dsb()   __asm__ volatile("dsb" ::: "memory")
    #define isb()   __asm__ volatile("isb" ::: "memory")
#endif

/* ==========================================================================
 * CPU Control - Architecture-specific implementations
 * ========================================================================== */

/* Sleep until interrupt (low power) */
void hal_cpu_idle(void);

/* Disable interrupts, return previous state */
uint32_t hal_irq_disable(void);

/* Enable interrupts */
void hal_irq_enable(void);

/* Restore interrupt state */
void hal_irq_restore(uint32_t state);

/* Full system halt */
void hal_cpu_halt(void) __attribute__((noreturn));

/* Reset the system */
void hal_cpu_reset(void) __attribute__((noreturn));

/* ==========================================================================
 * Timer Interface
 * ========================================================================== */

/* Initialize system timer at given frequency (Hz) */
void hal_timer_init(uint32_t frequency);

/* Get current tick count */
uint32_t hal_timer_ticks(void);

/* Microsecond delay (blocking) */
void hal_delay_us(uint32_t us);

/* Millisecond delay (blocking) */
void hal_delay_ms(uint32_t ms);

/* ==========================================================================
 * Console Output (Debug)
 * ========================================================================== */

/* Initialize console output */
void hal_console_init(void);

/* Write a character */
void hal_console_putc(char c);

/* Write a string */
void hal_console_puts(const char* str);

/* Write hex value */
void hal_console_put_hex(uint32_t value);

/* Write decimal value */
void hal_console_put_dec(uint32_t value);

/* Set console color (if supported) */
void hal_console_set_color(uint8_t color);

/* Clear console */
void hal_console_clear(void);

/* ==========================================================================
 * Network Interface (Abstract)
 * ========================================================================== */

/* Network driver type */
typedef enum {
    NET_DRIVER_NONE = 0,
    NET_DRIVER_E1000,       /* Intel e1000 (x86 QEMU) */
    NET_DRIVER_VIRTIO,      /* VirtIO-net (ARM QEMU) */
    NET_DRIVER_BCM_GENET,   /* BCM54213PE (RPi4) */
    NET_DRIVER_ENC28J60,    /* SPI Ethernet (MCU) */
    NET_DRIVER_W5500,       /* WIZnet W5500 (MCU) */
} net_driver_t;

/* Initialize network interface */
int hal_net_init(void);

/* Get MAC address */
void hal_net_get_mac(uint8_t* mac);

/* Send packet (non-blocking, returns 0 on success) */
int hal_net_send(void* data, uint16_t length);

/* Receive packet (returns length, -1 if none) */
int hal_net_receive(void* buffer, uint16_t max_length);

/* Check if packet is available */
bool hal_net_has_packet(void);

/* Drain TX queue (call from main loop) */
void hal_net_tx_drain(void);

/* Get TX queue depth */
uint8_t hal_net_tx_queue_depth(void);

/* Get driver type in use */
net_driver_t hal_net_get_driver(void);

/* ==========================================================================
 * Power Management
 * ========================================================================== */

typedef enum {
    POWER_MODE_RUN,         /* Full speed */
    POWER_MODE_IDLE,        /* CPU idle, peripherals on */
    POWER_MODE_SLEEP,       /* Low power, wake on interrupt */
    POWER_MODE_DEEP_SLEEP,  /* Very low power, limited wake sources */
} power_mode_t;

/* Set power mode */
void hal_power_set_mode(power_mode_t mode);

/* Get current power mode */
power_mode_t hal_power_get_mode(void);

/* Enter low-power idle (returns on interrupt) */
void hal_power_idle(void);

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */

/* Initialize RNG (use hardware if available) */
void hal_rng_init(void);

/* Get random 32-bit value */
uint32_t hal_rng_get(void);

/* Seed software RNG (if hardware unavailable) */
void hal_rng_seed(uint32_t seed);

/* ==========================================================================
 * Platform Initialization
 * ========================================================================== */

/* Early hardware init (before kernel_main) */
void hal_early_init(void);

/* Full platform init (called from kernel_main) */
void hal_platform_init(void);

/* Get platform info string */
const char* hal_platform_info(void);

/* ==========================================================================
 * Cache Operations (for DMA)
 * ========================================================================== */

/* Flush data cache for address range */
void hal_cache_flush(void* addr, size_t size);

/* Invalidate data cache for address range */
void hal_cache_invalidate(void* addr, size_t size);

/* ==========================================================================
 * Interrupt Controller
 * ========================================================================== */

/* Initialize interrupt controller */
void hal_irq_init(void);

/* Register interrupt handler */
typedef void (*irq_handler_t)(void);
void hal_irq_register(uint32_t irq_num, irq_handler_t handler);

/* Enable specific IRQ */
void hal_irq_unmask(uint32_t irq_num);

/* Disable specific IRQ */
void hal_irq_mask(uint32_t irq_num);

/* Acknowledge/clear IRQ */
void hal_irq_ack(uint32_t irq_num);

#endif /* HAL_H */
