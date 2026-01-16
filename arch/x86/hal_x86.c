/*
 * NanOS - x86 HAL Implementation
 * Wrapper that connects HAL interface to existing x86 drivers
 */

#include "../../include/hal.h"
#include "../../include/io.h"
#include "../../include/e1000.h"
#include "../../include/nanos.h"

#ifdef ARCH_X86

/* ==========================================================================
 * External Functions from kernel.c
 * ========================================================================== */
extern void vga_clear(void);
extern void vga_puts(const char* str);
extern void vga_putchar(char c);
extern void vga_put_hex(uint32_t value);
extern void vga_put_dec(uint32_t value);
extern void vga_set_color(uint8_t color);
extern void pit_init(uint32_t frequency);
extern uint32_t get_ticks(void);
extern void gdt_load(void);
extern void idt_load(void* ptr);
extern void cpu_halt(void);
extern void interrupts_enable(void);
extern void interrupts_disable(void);

/* Forward declarations for internal init */
void pic_init_internal(void);
void idt_init_internal(void);

/* ==========================================================================
 * Console Functions (redirect to VGA)
 * ========================================================================== */
void hal_console_init(void) {
    vga_clear();
}

void hal_console_putc(char c) {
    vga_putchar(c);
}

void hal_console_puts(const char* str) {
    vga_puts(str);
}

void hal_console_put_hex(uint32_t value) {
    vga_put_hex(value);
}

void hal_console_put_dec(uint32_t value) {
    vga_put_dec(value);
}

void hal_console_set_color(uint8_t color) {
    vga_set_color(color);
}

void hal_console_clear(void) {
    vga_clear();
}

/* ==========================================================================
 * CPU Control
 * ========================================================================== */
void hal_cpu_idle(void) {
    __asm__ volatile("hlt");
}

uint32_t hal_irq_disable(void) {
    uint32_t flags;
    __asm__ volatile(
        "pushfl\n"
        "pop %0\n"
        "cli"
        : "=r"(flags)
    );
    return flags;
}

void hal_irq_enable(void) {
    __asm__ volatile("sti");
}

void hal_irq_restore(uint32_t state) {
    if (state & (1 << 9)) {  /* IF bit */
        hal_irq_enable();
    }
}

void hal_cpu_halt(void) {
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

void hal_cpu_reset(void) {
    /* Triple fault to reset */
    uint8_t null_idt[6] = {0};
    __asm__ volatile("lidt %0" : : "m"(null_idt));
    __asm__ volatile("int $0");
    hal_cpu_halt();
}

/* ==========================================================================
 * Timer Functions
 * ========================================================================== */
void hal_timer_init(uint32_t frequency) {
    pit_init(frequency);
}

uint32_t hal_timer_ticks(void) {
    return get_ticks();
}

void hal_delay_us(uint32_t us) {
    /* Approximate delay using PIT */
    uint32_t start = get_ticks();
    uint32_t ticks_needed = (us * 100) / 1000000;  /* Assuming 100Hz */
    if (ticks_needed == 0) ticks_needed = 1;
    while (get_ticks() - start < ticks_needed);
}

void hal_delay_ms(uint32_t ms) {
    uint32_t start = get_ticks();
    uint32_t ticks_needed = (ms * 100) / 1000;
    if (ticks_needed == 0) ticks_needed = 1;
    while (get_ticks() - start < ticks_needed);
}

/* ==========================================================================
 * Network Functions (redirect to e1000)
 * ========================================================================== */
static net_driver_t x86_driver = NET_DRIVER_NONE;

int hal_net_init(void) {
    int ret = e1000_init();
    if (ret == 0) {
        x86_driver = NET_DRIVER_E1000;
    }
    return ret;
}

void hal_net_get_mac(uint8_t* mac) {
    e1000_get_mac(mac);
}

int hal_net_send(void* data, uint16_t length) {
    return e1000_send(data, length);
}

int hal_net_receive(void* buffer, uint16_t max_length) {
    return e1000_receive(buffer, max_length);
}

bool hal_net_has_packet(void) {
    return e1000_has_packet();
}

void hal_net_tx_drain(void) {
    e1000_tx_drain();
}

uint8_t hal_net_tx_queue_depth(void) {
    return e1000_tx_queue_depth();
}

net_driver_t hal_net_get_driver(void) {
    return x86_driver;
}

/* ==========================================================================
 * Power Management
 * ========================================================================== */
static power_mode_t x86_power_mode = POWER_MODE_RUN;

void hal_power_set_mode(power_mode_t mode) {
    x86_power_mode = mode;
}

power_mode_t hal_power_get_mode(void) {
    return x86_power_mode;
}

void hal_power_idle(void) {
    __asm__ volatile("hlt");
}

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */
static uint32_t x86_rng_state = 0xDEADBEEF;

void hal_rng_init(void) {
    /* Try RDTSC for entropy */
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    x86_rng_state = lo ^ hi;
    if (x86_rng_state == 0) x86_rng_state = 0xDEADBEEF;
}

void hal_rng_seed(uint32_t seed) {
    x86_rng_state = seed;
    if (x86_rng_state == 0) x86_rng_state = 0xDEADBEEF;
}

uint32_t hal_rng_get(void) {
    x86_rng_state ^= x86_rng_state << 13;
    x86_rng_state ^= x86_rng_state >> 17;
    x86_rng_state ^= x86_rng_state << 5;
    return x86_rng_state;
}

/* ==========================================================================
 * Cache Operations (x86 is cache-coherent for most purposes)
 * ========================================================================== */
void hal_cache_flush(void* addr, size_t size) {
    (void)addr;
    (void)size;
    __asm__ volatile("wbinvd");  /* Write-back and invalidate all caches */
}

void hal_cache_invalidate(void* addr, size_t size) {
    (void)addr;
    (void)size;
    /* x86 caches are coherent for normal memory */
}

/* ==========================================================================
 * IRQ Functions (minimal implementation)
 * ========================================================================== */
void hal_irq_init(void) {
    /* PIC and IDT init is done in kernel_main for x86 */
}

void hal_irq_register(uint32_t irq_num, irq_handler_t handler) {
    (void)irq_num;
    (void)handler;
    /* x86 uses static IDT setup */
}

void hal_irq_unmask(uint32_t irq_num) {
    if (irq_num < 8) {
        uint8_t mask = inb(0x21);
        mask &= ~(1 << irq_num);
        outb(0x21, mask);
    } else if (irq_num < 16) {
        uint8_t mask = inb(0xA1);
        mask &= ~(1 << (irq_num - 8));
        outb(0xA1, mask);
    }
}

void hal_irq_mask(uint32_t irq_num) {
    if (irq_num < 8) {
        uint8_t mask = inb(0x21);
        mask |= (1 << irq_num);
        outb(0x21, mask);
    } else if (irq_num < 16) {
        uint8_t mask = inb(0xA1);
        mask |= (1 << (irq_num - 8));
        outb(0xA1, mask);
    }
}

void hal_irq_ack(uint32_t irq_num) {
    if (irq_num >= 8) {
        outb(0xA0, 0x20);  /* EOI to slave */
    }
    outb(0x20, 0x20);  /* EOI to master */
}

/* ==========================================================================
 * Platform Init
 * ========================================================================== */
void hal_early_init(void) {
    /* Nothing for x86 */
}

void hal_platform_init(void) {
    /* x86 init is done in kernel_main */
}

const char* hal_platform_info(void) {
    return "x86 QEMU";
}

#endif /* ARCH_X86 */
