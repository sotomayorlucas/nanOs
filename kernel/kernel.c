/*
 * NanOS - The Hive Mind Kernel
 * A reactive unikernel that lives to sense and respond
 */

#include "../include/nanos.h"
#include "../include/io.h"
#include "../include/e1000.h"

/* ==========================================================================
 * Global State - The cell's memory (one instance, no malloc)
 * ========================================================================== */
struct nanos_state g_state;

/* ==========================================================================
 * Bump Allocator - Memory that grows but never shrinks
 * Like biological tissue, once allocated it's part of us forever
 * ========================================================================== */
static uint8_t heap[65536];  /* 64KB heap - plenty for a cell */
static size_t heap_ptr = 0;

void* bump_alloc(size_t size) {
    /* Align to 16 bytes for performance */
    size = (size + 15) & ~15;

    if (heap_ptr + size > sizeof(heap)) {
        /* Out of memory - cell dies */
        return (void*)0;
    }

    void* ptr = &heap[heap_ptr];
    heap_ptr += size;
    return ptr;
}

/* ==========================================================================
 * VGA Text Mode - Primitive output for debugging
 * Address: 0xB8000, 80x25 characters, attribute byte per char
 * ========================================================================== */
#define VGA_ADDR    0xB8000
#define VGA_WIDTH   80
#define VGA_HEIGHT  25
#define VGA_COLOR   0x0A    /* Bright green on black - the swarm color */

static uint16_t* const vga_buffer = (uint16_t*)VGA_ADDR;
static int vga_row = 0;
static int vga_col = 0;

void vga_clear(void) {
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = (VGA_COLOR << 8) | ' ';
    }
    vga_row = 0;
    vga_col = 0;
}

void vga_putchar(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
    } else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = (VGA_COLOR << 8) | c;
        vga_col++;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row++;
        }
    }

    /* Scroll if needed */
    if (vga_row >= VGA_HEIGHT) {
        for (int i = 0; i < VGA_WIDTH * (VGA_HEIGHT - 1); i++) {
            vga_buffer[i] = vga_buffer[i + VGA_WIDTH];
        }
        for (int i = 0; i < VGA_WIDTH; i++) {
            vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + i] = (VGA_COLOR << 8) | ' ';
        }
        vga_row = VGA_HEIGHT - 1;
    }
}

void vga_puts(const char* str) {
    while (*str) {
        vga_putchar(*str++);
    }
}

void vga_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    vga_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        vga_putchar(hex[(value >> i) & 0xF]);
    }
}

/* ==========================================================================
 * PIT (Programmable Interval Timer) - Our heartbeat source
 * ========================================================================== */
#define PIT_CH0_DATA    0x40
#define PIT_CMD         0x43
#define PIT_FREQUENCY   1193182  /* Base frequency in Hz */

static volatile uint32_t ticks = 0;

void pit_init(uint32_t frequency) {
    uint32_t divisor = PIT_FREQUENCY / frequency;

    /* Channel 0, lobyte/hibyte, rate generator */
    outb(PIT_CMD, 0x36);
    outb(PIT_CH0_DATA, divisor & 0xFF);
    outb(PIT_CH0_DATA, (divisor >> 8) & 0xFF);
}

uint32_t get_ticks(void) {
    return ticks;
}

/* PIT interrupt handler - called from IDT */
void pit_handler(void) {
    ticks++;
    /* Send EOI to PIC */
    outb(0x20, 0x20);
}

/* ==========================================================================
 * IDT (Interrupt Descriptor Table) - How we react to hardware events
 * ========================================================================== */
struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  zero;
    uint8_t  type_attr;
    uint16_t offset_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr   idtp;

/* Assembly stub for timer interrupt */
extern void isr_timer_stub(void);

__asm__(
    ".globl isr_timer_stub\n"
    "isr_timer_stub:\n"
    "    pusha\n"
    "    call pit_handler\n"
    "    popa\n"
    "    iret\n"
);

static void idt_set_entry(uint8_t num, uint32_t handler) {
    idt[num].offset_low  = handler & 0xFFFF;
    idt[num].selector    = 0x08;  /* Kernel code segment */
    idt[num].zero        = 0;
    idt[num].type_attr   = 0x8E;  /* Present, ring 0, 32-bit interrupt gate */
    idt[num].offset_high = (handler >> 16) & 0xFFFF;
}

static void idt_init(void) {
    idtp.limit = sizeof(idt) - 1;
    idtp.base  = (uint32_t)&idt;

    /* Clear all entries */
    for (int i = 0; i < 256; i++) {
        idt_set_entry(i, 0);
    }

    /* Set up timer interrupt (IRQ0 = INT 32) */
    idt_set_entry(32, (uint32_t)isr_timer_stub);

    idt_load(&idtp);
}

/* ==========================================================================
 * PIC (Programmable Interrupt Controller) - Route hardware interrupts
 * ========================================================================== */
#define PIC1_CMD    0x20
#define PIC1_DATA   0x21
#define PIC2_CMD    0xA0
#define PIC2_DATA   0xA1

static void pic_init(void) {
    /* ICW1: Start initialization sequence */
    outb(PIC1_CMD, 0x11);
    outb(PIC2_CMD, 0x11);
    io_wait();

    /* ICW2: Interrupt vector offsets (32 for master, 40 for slave) */
    outb(PIC1_DATA, 32);
    outb(PIC2_DATA, 40);
    io_wait();

    /* ICW3: Master/slave wiring */
    outb(PIC1_DATA, 4);   /* Slave at IRQ2 */
    outb(PIC2_DATA, 2);   /* Cascade identity */
    io_wait();

    /* ICW4: 8086 mode */
    outb(PIC1_DATA, 0x01);
    outb(PIC2_DATA, 0x01);
    io_wait();

    /* Mask all interrupts except IRQ0 (timer) */
    outb(PIC1_DATA, 0xFE);  /* Enable only IRQ0 */
    outb(PIC2_DATA, 0xFF);  /* Mask all slave IRQs */
}

/* ==========================================================================
 * Pseudo-Random Number Generator - For node ID
 * Uses a simple LFSR (Linear Feedback Shift Register)
 * ========================================================================== */
static uint32_t rng_state = 0xDEADBEEF;

static uint32_t random(void) {
    /* Xorshift32 - fast and good enough for chaos */
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static void seed_random(void) {
    /* Use timer ticks + status register for entropy */
    rng_state = ticks;
    rng_state ^= inb(0x40);  /* PIT counter value */
    rng_state ^= inb(0x40) << 8;
    if (rng_state == 0) rng_state = 0xDEADBEEF;
}

/* ==========================================================================
 * Pheromone Processing - React to swarm signals
 * ========================================================================== */
static uint8_t compute_checksum(struct nanos_pheromone* pkt) {
    uint8_t* data = (uint8_t*)pkt;
    uint8_t checksum = 0;

    /* XOR all bytes except checksum field itself */
    for (size_t i = 0; i < sizeof(*pkt); i++) {
        if (i != offsetof(struct nanos_pheromone, checksum)) {
            checksum ^= data[i];
        }
    }
    return checksum;
}

void process_pheromone(struct nanos_pheromone* pkt) {
    /* Validate magic */
    if (pkt->magic != NANOS_MAGIC) {
        return;  /* Not our protocol, ignore */
    }

    /* Validate checksum */
    if (compute_checksum(pkt) != pkt->checksum) {
        return;  /* Corrupted, ignore */
    }

    /* Don't process our own messages */
    if (pkt->node_id == g_state.node_id) {
        return;
    }

    g_state.packets_rx++;

    /* React based on pheromone type */
    switch (pkt->type) {
        case PHEROMONE_HELLO:
            /* Another cell says hi - we could track neighbors here */
            g_state.neighbors_seen++;
            vga_puts("< HELLO from ");
            vga_put_hex(pkt->node_id);
            vga_puts("\n");
            break;

        case PHEROMONE_DATA:
            /* Data payload - print it */
            vga_puts("< DATA: ");
            pkt->payload[51] = '\0';  /* Ensure null termination */
            vga_puts((char*)pkt->payload);
            vga_puts("\n");
            break;

        case PHEROMONE_ALARM:
            /* Danger! Propagate if TTL > 0 */
            vga_puts("! ALARM from ");
            vga_put_hex(pkt->node_id);
            vga_puts("\n");
            if (pkt->ttl > 0) {
                pkt->ttl--;
                pkt->checksum = compute_checksum(pkt);
                e1000_send(pkt, sizeof(*pkt));
            }
            break;

        case PHEROMONE_DIE:
            /* Graceful shutdown requested */
            vga_puts("X DIE command received - halting\n");
            for (;;) cpu_halt();
            break;

        default:
            /* Unknown pheromone type - ignore */
            break;
    }
}

/* ==========================================================================
 * Heartbeat Emission - "I exist"
 * ========================================================================== */
#define HEARTBEAT_INTERVAL  100  /* Ticks between heartbeats (~1 second at 100Hz) */

void emit_heartbeat(void) {
    struct nanos_pheromone pkt;

    pkt.magic   = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type    = PHEROMONE_HELLO;
    pkt.ttl     = 1;  /* Don't propagate heartbeats */
    pkt.flags   = 0;

    /* Put some stats in payload */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.packets_rx;  p += 4;
    *(uint32_t*)p = g_state.packets_tx;  p += 4;
    *(uint32_t*)p = ticks;               p += 4;

    pkt.checksum = compute_checksum(&pkt);

    if (e1000_send(&pkt, sizeof(pkt)) == 0) {
        g_state.packets_tx++;
    }

    g_state.last_heartbeat = ticks;
}

/* ==========================================================================
 * Main Reactive Loop - The cell's life cycle
 * ========================================================================== */
void nanos_loop(void) {
    static uint8_t rx_buffer[2048];

    for (;;) {
        /* Check for incoming pheromones */
        if (e1000_has_packet()) {
            int len = e1000_receive(rx_buffer, sizeof(rx_buffer));
            if (len >= (int)(sizeof(struct eth_header) + sizeof(struct nanos_pheromone))) {
                /* Skip Ethernet header, process pheromone */
                struct nanos_pheromone* pkt = (struct nanos_pheromone*)(rx_buffer + sizeof(struct eth_header));
                process_pheromone(pkt);
            }
        }

        /* Emit heartbeat periodically */
        if (ticks - g_state.last_heartbeat >= HEARTBEAT_INTERVAL) {
            emit_heartbeat();
        }

        /* Sleep until next interrupt - conserve energy */
        cpu_halt();
    }
}

/* ==========================================================================
 * Kernel Entry Point - The cell awakens
 * ========================================================================== */
void kernel_main(uint32_t magic, void* mb_info) {
    (void)mb_info;  /* Not used for now */

    /* Clear screen first */
    vga_clear();

    /* Verify we were loaded by a Multiboot2 bootloader */
    if (magic != MULTIBOOT2_MAGIC) {
        vga_puts("ERROR: Not loaded by Multiboot2 bootloader!\n");
        vga_puts("Expected: ");
        vga_put_hex(MULTIBOOT2_MAGIC);
        vga_puts(" Got: ");
        vga_put_hex(magic);
        vga_puts("\n");
        for (;;) cpu_halt();
    }

    /* Banner */
    vga_puts("========================================\n");
    vga_puts("  NanOS v0.1 - The Hive Mind Awakens\n");
    vga_puts("========================================\n\n");

    /* Initialize GDT */
    vga_puts("[*] Loading GDT...\n");
    gdt_load();

    /* Initialize IDT and PIC */
    vga_puts("[*] Initializing interrupts...\n");
    pic_init();
    idt_init();

    /* Initialize timer (100 Hz) */
    vga_puts("[*] Starting heartbeat timer (100 Hz)...\n");
    pit_init(100);

    /* Enable interrupts */
    interrupts_enable();

    /* Wait a bit for entropy, then seed RNG */
    while (ticks < 10) cpu_halt();
    seed_random();

    /* Generate our unique node ID */
    g_state.node_id = random();
    vga_puts("[*] Node ID: ");
    vga_put_hex(g_state.node_id);
    vga_puts("\n");

    /* Initialize network */
    vga_puts("[*] Initializing e1000 NIC...\n");
    if (e1000_init() != 0) {
        vga_puts("ERROR: Failed to initialize network!\n");
        vga_puts("       Running in isolated mode.\n");
    } else {
        uint8_t mac[6];
        e1000_get_mac(mac);
        vga_puts("[*] MAC: ");
        for (int i = 0; i < 6; i++) {
            const char* hex = "0123456789ABCDEF";
            vga_putchar(hex[mac[i] >> 4]);
            vga_putchar(hex[mac[i] & 0xF]);
            if (i < 5) vga_putchar(':');
        }
        vga_puts("\n");
    }

    /* Initialize state */
    g_state.boot_time = ticks;
    g_state.last_heartbeat = 0;
    g_state.packets_rx = 0;
    g_state.packets_tx = 0;
    g_state.neighbors_seen = 0;

    vga_puts("\n[*] Cell is alive. Entering reactive loop.\n");
    vga_puts("    Listening for pheromones...\n\n");

    /* Enter the main reactive loop */
    nanos_loop();
}
