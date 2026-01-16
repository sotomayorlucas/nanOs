/*
 * NanOS - The Hive Mind Kernel v0.3
 * A reactive unikernel with collective intelligence:
 * - Quorum sensing (neighbor tracking)
 * - Queen elections
 * - Gradient-based routing
 */

#include "../include/nanos.h"
#include "../include/io.h"
#include "../include/e1000.h"

/* ==========================================================================
 * Global State - The cell's memory
 * ========================================================================== */
struct nanos_state g_state;

/* ==========================================================================
 * Bump Allocator with Apoptosis Support
 * ========================================================================== */
#define HEAP_SIZE 65536
static uint8_t heap[HEAP_SIZE];
static size_t heap_ptr = 0;

void* bump_alloc(size_t size) {
    size = (size + 15) & ~15;  /* 16-byte align */

    if (heap_ptr + size > HEAP_SIZE) {
        return (void*)0;  /* Trigger apoptosis check */
    }

    void* ptr = &heap[heap_ptr];
    heap_ptr += size;
    g_state.heap_used = heap_ptr;
    return ptr;
}

size_t heap_usage_percent(void) {
    return (heap_ptr * 100) / HEAP_SIZE;
}

void heap_reset(void) {
    heap_ptr = 0;
    g_state.heap_used = 0;
}

/* ==========================================================================
 * VGA Console
 * ========================================================================== */
#define VGA_ADDR    0xB8000
#define VGA_WIDTH   80
#define VGA_HEIGHT  25

static uint16_t* const vga_buffer = (uint16_t*)VGA_ADDR;
static int vga_row = 0;
static int vga_col = 0;
static uint8_t vga_color = 0x0A;  /* Default: bright green */

void vga_set_color(uint8_t color) {
    vga_color = color;
}

void vga_clear(void) {
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = (vga_color << 8) | ' ';
    }
    vga_row = 0;
    vga_col = 0;
}

void vga_putchar(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
    } else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = (vga_color << 8) | c;
        vga_col++;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row++;
        }
    }

    if (vga_row >= VGA_HEIGHT) {
        for (int i = 0; i < VGA_WIDTH * (VGA_HEIGHT - 1); i++) {
            vga_buffer[i] = vga_buffer[i + VGA_WIDTH];
        }
        for (int i = 0; i < VGA_WIDTH; i++) {
            vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + i] = (vga_color << 8) | ' ';
        }
        vga_row = VGA_HEIGHT - 1;
    }
}

void vga_puts(const char* str) {
    while (*str) vga_putchar(*str++);
}

void vga_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    vga_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        vga_putchar(hex[(value >> i) & 0xF]);
    }
}

void vga_put_dec(uint32_t value) {
    char buf[12];
    int i = 0;
    if (value == 0) {
        vga_putchar('0');
        return;
    }
    while (value > 0) {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i > 0) vga_putchar(buf[--i]);
}

/* ==========================================================================
 * Timer (PIT)
 * ========================================================================== */
#define PIT_CH0_DATA    0x40
#define PIT_CMD         0x43
#define PIT_FREQUENCY   1193182

static volatile uint32_t ticks = 0;

void pit_init(uint32_t frequency) {
    uint32_t divisor = PIT_FREQUENCY / frequency;
    outb(PIT_CMD, 0x36);
    outb(PIT_CH0_DATA, divisor & 0xFF);
    outb(PIT_CH0_DATA, (divisor >> 8) & 0xFF);
}

uint32_t get_ticks(void) {
    return ticks;
}

void pit_handler(void) {
    ticks++;
    outb(0x20, 0x20);  /* EOI */
}

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */
static uint32_t rng_state = 0xDEADBEEF;

uint32_t random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

void seed_random(void) {
    rng_state = ticks;
    rng_state ^= inb(0x40);
    rng_state ^= inb(0x40) << 8;
    rng_state ^= inb(0x40) << 16;
    if (rng_state == 0) rng_state = 0xDEADBEEF;
}

/* ==========================================================================
 * IDT Setup
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
static struct idt_ptr idtp;

extern void isr_timer_stub(void);
__asm__(
    ".globl isr_timer_stub\n"
    "isr_timer_stub:\n"
    "    pusha\n"
    "    call pit_handler\n"
    "    popa\n"
    "    iret\n"
);

/* ==========================================================================
 * Keyboard Input Handler
 * ========================================================================== */
#define KB_DATA_PORT    0x60
#define KB_STATUS_PORT  0x64

static volatile char kb_buffer[16];
static volatile uint8_t kb_head = 0;
static volatile uint8_t kb_tail = 0;

/* Simple scancode to ASCII (US layout, lowercase only) */
static const char scancode_to_ascii[128] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','=','\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',
    0, 'a','s','d','f','g','h','j','k','l',';','\'','`',
    0, '\\','z','x','c','v','b','n','m',',','.','/', 0,
    '*', 0, ' '
};

void keyboard_handler(void) {
    uint8_t scancode = inb(KB_DATA_PORT);

    /* Only process key press (not release) */
    if (scancode < 128) {
        char c = scancode_to_ascii[scancode];
        if (c != 0) {
            uint8_t next = (kb_head + 1) % 16;
            if (next != kb_tail) {
                kb_buffer[kb_head] = c;
                kb_head = next;
            }
        }
    }

    outb(0x20, 0x20);  /* EOI */
}

static char kb_getchar(void) {
    if (kb_head == kb_tail) return 0;
    char c = kb_buffer[kb_tail];
    kb_tail = (kb_tail + 1) % 16;
    return c;
}

extern void isr_keyboard_stub(void);
__asm__(
    ".globl isr_keyboard_stub\n"
    "isr_keyboard_stub:\n"
    "    pusha\n"
    "    call keyboard_handler\n"
    "    popa\n"
    "    iret\n"
);

/* ==========================================================================
 * Serial Port (COM1) for Logging
 * ========================================================================== */
#define COM1_PORT       0x3F8

static void serial_init(void) {
    outb(COM1_PORT + 1, 0x00);  /* Disable interrupts */
    outb(COM1_PORT + 3, 0x80);  /* Enable DLAB */
    outb(COM1_PORT + 0, 0x03);  /* 38400 baud (low byte) */
    outb(COM1_PORT + 1, 0x00);  /* (high byte) */
    outb(COM1_PORT + 3, 0x03);  /* 8 bits, no parity, 1 stop */
    outb(COM1_PORT + 2, 0xC7);  /* Enable FIFO */
    outb(COM1_PORT + 4, 0x0B);  /* IRQs enabled, RTS/DSR set */
}

static void serial_putchar(char c) {
    while ((inb(COM1_PORT + 5) & 0x20) == 0);
    outb(COM1_PORT, c);
}

static void serial_puts(const char* str) {
    while (*str) serial_putchar(*str++);
}

static void serial_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    serial_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        serial_putchar(hex[(value >> i) & 0xF]);
    }
}

static void serial_put_dec(uint32_t value) {
    char buf[12];
    int i = 0;
    if (value == 0) { serial_putchar('0'); return; }
    while (value > 0) {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i > 0) serial_putchar(buf[--i]);
}

static void idt_set_entry(uint8_t num, uint32_t handler) {
    idt[num].offset_low  = handler & 0xFFFF;
    idt[num].selector    = 0x08;
    idt[num].zero        = 0;
    idt[num].type_attr   = 0x8E;
    idt[num].offset_high = (handler >> 16) & 0xFFFF;
}

static void idt_init(void) {
    idtp.limit = sizeof(idt) - 1;
    idtp.base  = (uint32_t)&idt;
    for (int i = 0; i < 256; i++) idt_set_entry(i, 0);
    idt_set_entry(32, (uint32_t)isr_timer_stub);
    idt_set_entry(33, (uint32_t)isr_keyboard_stub);  /* IRQ1 = keyboard */
    idt_load(&idtp);
}

/* ==========================================================================
 * PIC Setup
 * ========================================================================== */
static void pic_init(void) {
    outb(0x20, 0x11); outb(0xA0, 0x11); io_wait();
    outb(0x21, 32);   outb(0xA1, 40);   io_wait();
    outb(0x21, 4);    outb(0xA1, 2);    io_wait();
    outb(0x21, 0x01); outb(0xA1, 0x01); io_wait();
    outb(0x21, 0xFC); outb(0xA1, 0xFF);  /* Enable IRQ0 (timer) and IRQ1 (keyboard) */
}

/* ==========================================================================
 * HMAC-like Authentication (SipHash-inspired, simplified)
 * ========================================================================== */
static uint32_t swarm_secret[4] = {
    SWARM_SECRET_0, SWARM_SECRET_1, SWARM_SECRET_2, SWARM_SECRET_3
};

static uint32_t siphash_round(uint32_t v0, uint32_t v1, uint32_t v2, uint32_t v3) {
    v0 += v1; v1 = (v1 << 5) | (v1 >> 27); v1 ^= v0;
    v2 += v3; v3 = (v3 << 8) | (v3 >> 24); v3 ^= v2;
    v0 += v3; v3 = (v3 << 7) | (v3 >> 25); v3 ^= v0;
    v2 += v1; v1 = (v1 << 13) | (v1 >> 19); v1 ^= v2;
    return v0 ^ v1 ^ v2 ^ v3;
}

void compute_hmac(struct nanos_pheromone* pkt) {
    uint32_t v0 = swarm_secret[0] ^ pkt->magic;
    uint32_t v1 = swarm_secret[1] ^ pkt->node_id;
    uint32_t v2 = swarm_secret[2] ^ (pkt->type | (pkt->ttl << 8));
    uint32_t v3 = swarm_secret[3] ^ pkt->seq;

    uint32_t hash = siphash_round(v0, v1, v2, v3);
    hash = siphash_round(hash, v1, v2, v3);  /* Second round */

    /* Store truncated HMAC */
    pkt->hmac[0] = (hash >> 0) & 0xFF;
    pkt->hmac[1] = (hash >> 8) & 0xFF;
    pkt->hmac[2] = (hash >> 16) & 0xFF;
    pkt->hmac[3] = (hash >> 24) & 0xFF;
    hash = siphash_round(hash, v0, v2, v1);
    pkt->hmac[4] = (hash >> 0) & 0xFF;
    pkt->hmac[5] = (hash >> 8) & 0xFF;
    pkt->hmac[6] = (hash >> 16) & 0xFF;
    pkt->hmac[7] = (hash >> 24) & 0xFF;

    pkt->flags |= FLAG_AUTHENTICATED;
}

bool verify_hmac(struct nanos_pheromone* pkt) {
    uint8_t saved_hmac[HMAC_TAG_SIZE];
    for (int i = 0; i < HMAC_TAG_SIZE; i++) {
        saved_hmac[i] = pkt->hmac[i];
    }

    compute_hmac(pkt);

    for (int i = 0; i < HMAC_TAG_SIZE; i++) {
        if (pkt->hmac[i] != saved_hmac[i]) {
            return false;
        }
    }
    return true;
}

bool is_authenticated_type(uint8_t type) {
    return type == PHEROMONE_DIE ||
           type == PHEROMONE_QUEEN_CMD ||
           type == PHEROMONE_REBIRTH;
}

/* ==========================================================================
 * Gossip Protocol - Prevent Broadcast Storms
 * ========================================================================== */
uint32_t gossip_hash(struct nanos_pheromone* pkt) {
    /* Simple hash of identifying fields */
    uint32_t h = pkt->node_id;
    h = h * 31 + pkt->seq;
    h = h * 31 + pkt->type;
    h = h * 31 + (pkt->payload[0] | (pkt->payload[1] << 8));
    return h;
}

void gossip_record(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);

    /* Check if already in cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        if (g_state.gossip_cache[i].hash == hash) {
            g_state.gossip_cache[i].count++;
            return;
        }
    }

    /* Add to cache (circular) */
    struct gossip_entry* entry = &g_state.gossip_cache[g_state.gossip_index];
    entry->hash = hash;
    entry->timestamp = ticks;
    entry->count = 1;
    entry->relayed = 0;

    g_state.gossip_index = (g_state.gossip_index + 1) % GOSSIP_CACHE_SIZE;
}

bool gossip_should_relay(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);

    /* Look up in cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        struct gossip_entry* entry = &g_state.gossip_cache[i];

        if (entry->hash == hash) {
            /* Message still fresh? */
            if (ticks - entry->timestamp > (GOSSIP_IMMUNITY_MS / 10)) {
                entry->count = 1;  /* Reset - old message */
                entry->timestamp = ticks;
            }

            /* Already relayed? */
            if (entry->relayed) {
                return false;
            }

            /* Too many copies seen? */
            if (entry->count >= ALARM_MAX_ECHOES) {
                g_state.packets_dropped++;
                return false;
            }

            /* Probabilistic relay - decay with each copy seen */
            uint32_t prob = GOSSIP_PROB_BASE;
            for (uint8_t j = 1; j < entry->count && prob > 0; j++) {
                prob = (prob * (100 - GOSSIP_PROB_DECAY)) / 100;
            }

            if ((random() % 100) < prob) {
                entry->relayed = 1;
                return true;
            }

            return false;
        }
    }

    /* Not in cache - first time seeing it, relay */
    return true;
}

/* ==========================================================================
 * Cell Role Management
 * ========================================================================== */
static const char* role_name(uint8_t role) {
    switch (role) {
        case ROLE_WORKER:    return "WORKER";
        case ROLE_EXPLORER:  return "EXPLORER";
        case ROLE_SENTINEL:  return "SENTINEL";
        case ROLE_QUEEN:     return "QUEEN";
        case ROLE_CANDIDATE: return "CANDIDATE";
        default:             return "UNKNOWN";
    }
}

static uint8_t determine_role(void) {
    uint32_t r = random();

    /* Queen: 1 in 256 */
    if ((r & 0xFF) == 0) {
        return ROLE_QUEEN;
    }

    /* Explorer: 1 in 8 */
    if ((r & 0x07) == 1) {
        return ROLE_EXPLORER;
    }

    /* Sentinel: 1 in 8 */
    if ((r & 0x07) == 2) {
        return ROLE_SENTINEL;
    }

    /* Default: Worker */
    return ROLE_WORKER;
}

static uint32_t heartbeat_interval(void) {
    switch (g_state.role) {
        case ROLE_EXPLORER: return 50;   /* Fast: every 0.5s */
        case ROLE_SENTINEL: return 200;  /* Slow: every 2s */
        case ROLE_QUEEN:    return 300;  /* Very slow: every 3s */
        default:            return 100;  /* Normal: every 1s */
    }
}

/* ==========================================================================
 * Interactive Commands
 * ========================================================================== */

/* Show swarm status */
static void cmd_show_status(void) {
    vga_set_color(0x0B);  /* Cyan */
    vga_puts("\n========== SWARM STATUS ==========\n");
    vga_set_color(0x0A);

    /* Node identity */
    vga_puts("Node ID: ");
    vga_put_hex(g_state.node_id);
    vga_puts("  Role: ");
    vga_set_color(g_state.role == ROLE_QUEEN ? 0x0D : 0x0E);
    vga_puts(role_name(g_state.role));
    vga_set_color(0x0A);
    vga_puts("  Gen: ");
    vga_put_dec(g_state.generation);
    vga_puts("\n");

    /* Network stats */
    vga_puts("Packets: RX=");
    vga_put_dec(g_state.packets_rx);
    vga_puts(" TX=");
    vga_put_dec(g_state.packets_tx);
    vga_puts(" Dropped=");
    vga_put_dec(g_state.packets_dropped);
    vga_puts(" Routed=");
    vga_put_dec(g_state.packets_routed);
    vga_puts("\n");

    /* Queen info */
    vga_puts("Queen: ");
    if (g_state.known_queen_id != 0) {
        vga_put_hex(g_state.known_queen_id);
        vga_puts(" (distance=");
        vga_put_dec(g_state.distance_to_queen);
        vga_puts(")\n");
    } else {
        vga_puts("NONE\n");
    }

    /* Neighbor table */
    vga_puts("Neighbors: ");
    vga_put_dec(g_state.neighbor_count);
    vga_puts("/");
    vga_put_dec(NEIGHBOR_TABLE_SIZE);
    vga_puts("\n");

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id != 0) {
            vga_puts("  ");
            vga_put_hex(g_state.neighbors[i].node_id);
            vga_puts(" [");
            vga_puts(role_name(g_state.neighbors[i].role));
            vga_puts("] d=");
            vga_put_dec(g_state.neighbors[i].distance);
            vga_puts(" pkts=");
            vga_put_dec(g_state.neighbors[i].packets);
            vga_puts("\n");
        }
    }

    /* Role distribution */
    vga_puts("Roles: W=");
    vga_put_dec(g_state.role_counts[ROLE_WORKER]);
    vga_puts(" E=");
    vga_put_dec(g_state.role_counts[ROLE_EXPLORER]);
    vga_puts(" S=");
    vga_put_dec(g_state.role_counts[ROLE_SENTINEL]);
    vga_puts(" Q=");
    vga_put_dec(g_state.role_counts[ROLE_QUEEN]);
    vga_puts("\n");

    /* Memory */
    vga_puts("Heap: ");
    vga_put_dec(heap_usage_percent());
    vga_puts("% (");
    vga_put_dec(heap_ptr);
    vga_puts("/");
    vga_put_dec(HEAP_SIZE);
    vga_puts(")\n");

    /* Uptime */
    vga_puts("Uptime: ");
    vga_put_dec((ticks - g_state.boot_time) / 100);
    vga_puts("s\n");

    vga_set_color(0x0B);
    vga_puts("==================================\n\n");
    vga_set_color(0x0A);

    /* Also log to serial */
    serial_puts("[STATUS] Node=");
    serial_put_hex(g_state.node_id);
    serial_puts(" Role=");
    serial_puts(role_name(g_state.role));
    serial_puts(" Neighbors=");
    serial_put_dec(g_state.neighbor_count);
    serial_puts(" RX=");
    serial_put_dec(g_state.packets_rx);
    serial_puts(" TX=");
    serial_put_dec(g_state.packets_tx);
    serial_puts("\n");
}

/* Send DATA message to swarm */
static void cmd_send_data(void) {
    static uint32_t data_counter = 0;

    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_DATA;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;

    PKT_SET_ROLE(&pkt, g_state.role);

    /* Create message */
    char* msg = (char*)pkt.payload;
    const char* prefix = "Hello from ";
    int i = 0;
    while (*prefix && i < 20) msg[i++] = *prefix++;

    /* Add node ID (hex, short) */
    const char* hex = "0123456789ABCDEF";
    uint32_t id = g_state.node_id;
    msg[i++] = hex[(id >> 28) & 0xF];
    msg[i++] = hex[(id >> 24) & 0xF];
    msg[i++] = hex[(id >> 20) & 0xF];
    msg[i++] = hex[(id >> 16) & 0xF];
    msg[i++] = ' ';
    msg[i++] = '#';

    /* Add counter */
    uint32_t c = data_counter++;
    char num[8];
    int j = 0;
    if (c == 0) num[j++] = '0';
    while (c > 0 && j < 8) { num[j++] = '0' + (c % 10); c /= 10; }
    while (j > 0 && i < 31) msg[i++] = num[--j];
    msg[i] = '\0';

    for (int k = 0; k < HMAC_TAG_SIZE; k++) pkt.hmac[k] = 0;

    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0E);
    vga_puts("> DATA: ");
    vga_puts((char*)pkt.payload);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[TX] DATA: ");
    serial_puts((char*)pkt.payload);
    serial_puts("\n");
}

/* Trigger ALARM propagation */
static void cmd_send_alarm(void) {
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_ALARM;
    pkt.ttl = 5;  /* Will propagate up to 5 hops */
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;

    PKT_SET_ROLE(&pkt, g_state.role);

    /* Alarm payload */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = ticks;  /* Timestamp */
    p += 4;
    *(uint32_t*)p = g_state.node_id;  /* Source */

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;

    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0C);
    vga_puts("!!! ALARM TRIGGERED !!!\n");
    vga_set_color(0x0A);

    serial_puts("[ALARM] Triggered from ");
    serial_put_hex(g_state.node_id);
    serial_puts("\n");
}

/* Send Queen command (only if queen) */
static void cmd_queen_command(void) {
    if (g_state.role != ROLE_QUEEN) {
        vga_set_color(0x0C);
        vga_puts("! Only QUEEN can send commands\n");
        vga_set_color(0x0A);
        return;
    }

    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_QUEEN_CMD;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = 0;
    pkt.hop_count = 0;

    PKT_SET_ROLE(&pkt, ROLE_QUEEN);

    /* Command message */
    const char* cmd = "QUEEN ORDERS: Report!";
    int i = 0;
    while (*cmd && i < 31) pkt.payload[i++] = *cmd++;
    pkt.payload[i] = '\0';

    compute_hmac(&pkt);  /* Queen commands must be authenticated */

    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0D);
    vga_puts(">> QUEEN COMMAND SENT: ");
    vga_puts((char*)pkt.payload);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[QUEEN] Command sent\n");
}

/* Force election start */
static void cmd_force_election(void) {
    vga_set_color(0x0E);
    vga_puts("~ Forcing queen election...\n");
    vga_set_color(0x0A);

    /* Reset queen tracking to force election */
    g_state.known_queen_id = 0;
    g_state.last_queen_seen = 0;
    g_state.distance_to_queen = GRADIENT_INFINITY;

    election_start();

    serial_puts("[ELECTION] Forced start\n");
}

/* Show help */
static void cmd_show_help(void) {
    vga_set_color(0x0B);
    vga_puts("\n=== NanOS Interactive Commands ===\n");
    vga_set_color(0x0A);
    vga_puts("  s - Show swarm status\n");
    vga_puts("  d - Send DATA message\n");
    vga_puts("  a - Trigger ALARM\n");
    vga_puts("  q - Send QUEEN command (queens only)\n");
    vga_puts("  e - Force queen election\n");
    vga_puts("  h - Show this help\n");
    vga_puts("  r - Force apoptosis (rebirth)\n");
    vga_set_color(0x0E);
    vga_puts("--- Workloads ---\n");
    vga_set_color(0x0A);
    vga_puts("  k - KV store demo (set/replicate)\n");
    vga_puts("  t - Task distribution (queens only)\n");
    vga_puts("  w - Show workload stats\n");
    vga_set_color(0x0E);
    vga_puts("--- Global Compute ---\n");
    vga_set_color(0x0A);
    vga_puts("  j - Start compute job (queens only)\n");
    vga_puts("      Cycles: prime search, pi, sum\n");
    vga_set_color(0x0B);
    vga_puts("==================================\n\n");
    vga_set_color(0x0A);
}

/* ==========================================================================
 * Workload: Key-Value Store
 * ========================================================================== */
static int kv_find(const uint8_t* key) {
    for (int i = 0; i < KV_STORE_SIZE; i++) {
        if (g_state.kv_store[i].valid) {
            int match = 1;
            for (int j = 0; j < KV_KEY_SIZE && key[j]; j++) {
                if (g_state.kv_store[i].key[j] != key[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) return i;
        }
    }
    return -1;
}

static void kv_set(const uint8_t* key, const uint8_t* value, int replicate) {
    int idx = kv_find(key);
    if (idx < 0) {
        /* Find empty slot */
        for (int i = 0; i < KV_STORE_SIZE; i++) {
            if (!g_state.kv_store[i].valid) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) idx = 0;  /* Overwrite first if full */

    /* Copy key and value */
    for (int i = 0; i < KV_KEY_SIZE; i++)
        g_state.kv_store[idx].key[i] = (i < KV_KEY_SIZE && key[i]) ? key[i] : 0;
    for (int i = 0; i < KV_VALUE_SIZE; i++)
        g_state.kv_store[idx].value[i] = (i < KV_VALUE_SIZE && value[i]) ? value[i] : 0;
    g_state.kv_store[idx].valid = 1;

    serial_puts("[KV] SET ");
    serial_puts((const char*)key);
    serial_puts("=");
    serial_puts((const char*)value);
    serial_puts("\n");

    /* Replicate to neighbors */
    if (replicate && g_state.neighbor_count > 0) {
        struct nanos_pheromone pkt;
        pkt.magic = NANOS_MAGIC;
        pkt.node_id = g_state.node_id;
        pkt.type = PHEROMONE_KV_SET;
        pkt.ttl = KV_REPLICATION;
        pkt.flags = 0;
        pkt.version = NANOS_VERSION;
        pkt.seq = g_state.seq_counter++;
        pkt.dest_id = 0;
        pkt.distance = g_state.distance_to_queen;
        pkt.hop_count = 0;
        PKT_SET_ROLE(&pkt, g_state.role);

        /* Payload: key (8) + value (16) */
        for (int i = 0; i < KV_KEY_SIZE; i++) pkt.payload[i] = key[i] ? key[i] : 0;
        for (int i = 0; i < KV_VALUE_SIZE; i++) pkt.payload[KV_KEY_SIZE + i] = value[i] ? value[i] : 0;

        for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
        e1000_send(&pkt, sizeof(pkt));
        g_state.packets_tx++;
    }
}

static void process_kv_set(struct nanos_pheromone* pkt) {
    uint8_t key[KV_KEY_SIZE + 1];
    uint8_t value[KV_VALUE_SIZE + 1];
    for (int i = 0; i < KV_KEY_SIZE; i++) key[i] = pkt->payload[i];
    key[KV_KEY_SIZE] = 0;
    for (int i = 0; i < KV_VALUE_SIZE; i++) value[i] = pkt->payload[KV_KEY_SIZE + i];
    value[KV_VALUE_SIZE] = 0;

    kv_set(key, value, 0);  /* Don't re-replicate */

    /* Forward if TTL > 0 */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* ==========================================================================
 * Workload: Task Distribution
 * ========================================================================== */
static uint32_t is_prime(uint32_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (uint32_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

static uint32_t factorial(uint32_t n) {
    uint32_t result = 1;
    for (uint32_t i = 2; i <= n && i < 13; i++) {  /* Limit to avoid overflow */
        result *= i;
    }
    return result;
}

static uint32_t fibonacci(uint32_t n) {
    if (n <= 1) return n;
    uint32_t a = 0, b = 1;
    for (uint32_t i = 2; i <= n && i < 47; i++) {  /* Limit to avoid overflow */
        uint32_t c = a + b;
        a = b;
        b = c;
    }
    return b;
}

static void task_execute(uint8_t task_type, uint32_t input, uint32_t task_id, uint32_t requester) {
    uint32_t result = 0;

    switch (task_type) {
        case TASK_PRIME_CHECK:
            result = is_prime(input);
            vga_puts("[TASK] Prime(");
            vga_put_dec(input);
            vga_puts(") = ");
            vga_puts(result ? "YES" : "NO");
            vga_puts("\n");
            break;
        case TASK_FACTORIAL:
            result = factorial(input);
            vga_puts("[TASK] Factorial(");
            vga_put_dec(input);
            vga_puts(") = ");
            vga_put_dec(result);
            vga_puts("\n");
            break;
        case TASK_FIBONACCI:
            result = fibonacci(input);
            vga_puts("[TASK] Fibonacci(");
            vga_put_dec(input);
            vga_puts(") = ");
            vga_put_dec(result);
            vga_puts("\n");
            break;
    }

    /* Send result back */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_RESULT;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = FLAG_ROUTED;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = requester;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    uint8_t* p = pkt.payload;
    *(uint32_t*)p = task_id; p += 4;
    *(uint32_t*)p = result; p += 4;
    *p = task_type;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    serial_puts("[TASK] Completed task ");
    serial_put_dec(task_id);
    serial_puts(" result=");
    serial_put_dec(result);
    serial_puts("\n");
}

static void task_distribute(uint8_t task_type, uint32_t input) {
    if (g_state.role != ROLE_QUEEN) {
        vga_puts("! Only QUEEN can distribute tasks\n");
        return;
    }

    /* Find a worker neighbor */
    uint32_t target = 0;
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id != 0 &&
            g_state.neighbors[i].role == ROLE_WORKER) {
            target = g_state.neighbors[i].node_id;
            break;
        }
    }
    if (target == 0 && g_state.neighbor_count > 0) {
        /* No worker found, pick any neighbor */
        for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
            if (g_state.neighbors[i].node_id != 0) {
                target = g_state.neighbors[i].node_id;
                break;
            }
        }
    }

    uint32_t task_id = g_state.tasks_sent++;

    /* Record pending task */
    int slot = task_id % MAX_PENDING_TASKS;
    g_state.pending_tasks[slot].task_id = task_id;
    g_state.pending_tasks[slot].task_type = task_type;
    g_state.pending_tasks[slot].input = input;
    g_state.pending_tasks[slot].assigned_to = target;
    g_state.pending_tasks[slot].sent_at = ticks;
    g_state.pending_tasks[slot].completed = 0;

    /* Send task */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_TASK;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = target ? FLAG_ROUTED : 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = target;
    pkt.distance = 0;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, ROLE_QUEEN);

    uint8_t* p = pkt.payload;
    *(uint32_t*)p = task_id; p += 4;
    *(uint32_t*)p = input; p += 4;
    *p = task_type;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0D);
    vga_puts(">> TASK #");
    vga_put_dec(task_id);
    vga_puts(" sent to ");
    vga_put_hex(target);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[QUEEN] Task ");
    serial_put_dec(task_id);
    serial_puts(" type=");
    serial_put_dec(task_type);
    serial_puts(" input=");
    serial_put_dec(input);
    serial_puts(" -> ");
    serial_put_hex(target);
    serial_puts("\n");
}

static void process_task(struct nanos_pheromone* pkt) {
    uint32_t task_id = *(uint32_t*)(pkt->payload);
    uint32_t input = *(uint32_t*)(pkt->payload + 4);
    uint8_t task_type = pkt->payload[8];

    task_execute(task_type, input, task_id, pkt->node_id);
}

static void process_result(struct nanos_pheromone* pkt) {
    uint32_t task_id = *(uint32_t*)(pkt->payload);
    uint32_t result = *(uint32_t*)(pkt->payload + 4);

    /* Find pending task */
    int slot = task_id % MAX_PENDING_TASKS;
    if (g_state.pending_tasks[slot].task_id == task_id) {
        g_state.pending_tasks[slot].completed = 1;
        g_state.pending_tasks[slot].result = result;
        g_state.tasks_completed++;
    }

    vga_set_color(0x0B);
    vga_puts("<< RESULT #");
    vga_put_dec(task_id);
    vga_puts(" = ");
    vga_put_dec(result);
    vga_puts(" from ");
    vga_put_hex(pkt->node_id);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[QUEEN] Result task=");
    serial_put_dec(task_id);
    serial_puts(" result=");
    serial_put_dec(result);
    serial_puts("\n");
}

/* ==========================================================================
 * Workload: Sensor Network
 * ========================================================================== */
static void sensor_generate(void) {
    /* Generate simulated sensor readings */
    g_state.sensors[0].value = 200 + (random() % 100);  /* Temp: 20.0-30.0 C (x10) */
    g_state.sensors[1].value = 400 + (random() % 400);  /* Humidity: 40-80% (x10) */
    g_state.sensors[2].value = 10100 + (random() % 200) - 100;  /* Pressure: 1000-1020 hPa (x10) */

    /* Update local aggregates */
    for (int i = 0; i < SENSOR_TYPES; i++) {
        g_state.sensors[i].sum += g_state.sensors[i].value;
        g_state.sensors[i].count++;
        if (g_state.sensors[i].value < g_state.sensors[i].min || g_state.sensors[i].min == 0)
            g_state.sensors[i].min = g_state.sensors[i].value;
        if (g_state.sensors[i].value > g_state.sensors[i].max)
            g_state.sensors[i].max = g_state.sensors[i].value;
    }

    /* Send sensor data */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_SENSOR;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    uint8_t* p = pkt.payload;
    for (int i = 0; i < SENSOR_TYPES; i++) {
        *(int32_t*)p = g_state.sensors[i].value; p += 4;
    }

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    serial_puts("[SENSOR] T=");
    serial_put_dec(g_state.sensors[0].value / 10);
    serial_puts(".");
    serial_put_dec(g_state.sensors[0].value % 10);
    serial_puts("C H=");
    serial_put_dec(g_state.sensors[1].value / 10);
    serial_puts("% P=");
    serial_put_dec(g_state.sensors[2].value / 10);
    serial_puts("hPa\n");

    g_state.last_sensor_reading = ticks;
}

static void process_sensor(struct nanos_pheromone* pkt) {
    /* Aggregate received sensor data */
    int32_t* values = (int32_t*)pkt->payload;
    for (int i = 0; i < SENSOR_TYPES; i++) {
        g_state.sensors[i].sum += values[i];
        g_state.sensors[i].count++;
        if (values[i] < g_state.sensors[i].min || g_state.sensors[i].min == 0)
            g_state.sensors[i].min = values[i];
        if (values[i] > g_state.sensors[i].max)
            g_state.sensors[i].max = values[i];
    }
}

static void sensor_aggregate(void) {
    if (g_state.role != ROLE_QUEEN) return;
    if (g_state.sensors[0].count == 0) return;

    vga_set_color(0x0B);
    vga_puts("[AGGREGATE] n=");
    vga_put_dec(g_state.sensors[0].count);
    vga_puts(" Temp: avg=");
    vga_put_dec((g_state.sensors[0].sum / g_state.sensors[0].count) / 10);
    vga_puts(".");
    vga_put_dec((g_state.sensors[0].sum / g_state.sensors[0].count) % 10);
    vga_puts(" min=");
    vga_put_dec(g_state.sensors[0].min / 10);
    vga_puts(" max=");
    vga_put_dec(g_state.sensors[0].max / 10);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[AGGREGATE] count=");
    serial_put_dec(g_state.sensors[0].count);
    serial_puts(" temp_avg=");
    serial_put_dec(g_state.sensors[0].sum / g_state.sensors[0].count);
    serial_puts(" hum_avg=");
    serial_put_dec(g_state.sensors[1].sum / g_state.sensors[1].count);
    serial_puts(" pres_avg=");
    serial_put_dec(g_state.sensors[2].sum / g_state.sensors[2].count);
    serial_puts("\n");

    /* Reset for next period */
    for (int i = 0; i < SENSOR_TYPES; i++) {
        g_state.sensors[i].sum = 0;
        g_state.sensors[i].count = 0;
        g_state.sensors[i].min = 0;
        g_state.sensors[i].max = 0;
    }

    g_state.last_aggregate = ticks;
}

/* ==========================================================================
 * Global Compute - MapReduce Style Distributed Computing
 * ========================================================================== */

/* Count primes in a range (for prime search job) */
static uint32_t count_primes_in_range(uint32_t start, uint32_t end) {
    uint32_t count = 0;
    for (uint32_t n = start; n <= end; n++) {
        if (is_prime(n)) count++;
    }
    return count;
}

/* Monte Carlo Pi estimation - random points in unit square */
static uint32_t monte_carlo_pi_samples(uint32_t samples) {
    uint32_t inside = 0;
    for (uint32_t i = 0; i < samples; i++) {
        /* Generate random point in [0,1000) x [0,1000) */
        uint32_t x = random() % 1000;
        uint32_t y = random() % 1000;
        /* Check if inside quarter circle: x^2 + y^2 < 1000^2 */
        if (x * x + y * y < 1000000) {
            inside++;
        }
    }
    return inside;  /* Pi ~= 4 * inside / samples */
}

/* Sum numbers in a range (for parallel sum job) */
static uint64_t sum_range(uint32_t start, uint32_t end) {
    uint64_t sum = 0;
    for (uint32_t n = start; n <= end; n++) {
        sum += n;
    }
    return sum;
}

/* Process a job chunk */
static void job_process_chunk(void) {
    if (!g_state.current_chunk.processing) return;

    uint32_t job_id = g_state.current_chunk.job_id;
    uint8_t job_type = g_state.current_chunk.job_type;
    uint32_t start = g_state.current_chunk.range_start;
    uint32_t end = g_state.current_chunk.range_end;
    uint64_t result = 0;

    vga_set_color(0x0E);
    vga_puts("[JOB] Processing chunk ");
    vga_put_dec(g_state.current_chunk.chunk_id);
    vga_puts(" (");
    vga_put_dec(start);
    vga_puts("-");
    vga_put_dec(end);
    vga_puts(")\n");
    vga_set_color(0x0A);

    switch (job_type) {
        case JOB_PRIME_SEARCH:
            result = count_primes_in_range(start, end);
            break;
        case JOB_MONTE_CARLO_PI:
            result = monte_carlo_pi_samples(end - start);
            break;
        case JOB_REDUCE_SUM:
            result = sum_range(start, end);
            break;
        default:
            result = 0;
    }

    /* Send result back */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_JOB_DONE;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast to queen */
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    /* Payload: job_id(4) + chunk_id(4) + result_lo(4) + result_hi(4) */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = job_id; p += 4;
    *(uint32_t*)p = g_state.current_chunk.chunk_id; p += 4;
    *(uint32_t*)p = (uint32_t)(result & 0xFFFFFFFF); p += 4;
    *(uint32_t*)p = (uint32_t)(result >> 32); p += 4;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0B);
    vga_puts("[JOB] Chunk ");
    vga_put_dec(g_state.current_chunk.chunk_id);
    vga_puts(" done: result=");
    vga_put_dec((uint32_t)result);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[JOB] Chunk ");
    serial_put_dec(g_state.current_chunk.chunk_id);
    serial_puts(" done: ");
    serial_put_dec((uint32_t)result);
    serial_puts("\n");

    g_state.current_chunk.processing = 0;
    g_state.chunks_processed++;
}

/* Handle JOB_START pheromone */
static void process_job_start(struct nanos_pheromone* pkt) {
    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint8_t job_type = pkt->payload[4];
    uint32_t param1 = *(uint32_t*)(pkt->payload + 5);
    uint32_t param2 = *(uint32_t*)(pkt->payload + 9);
    uint32_t num_chunks = *(uint32_t*)(pkt->payload + 13);

    /* Check if we're already processing this job (deduplication) */
    int slot = job_id % MAX_ACTIVE_JOBS;
    if (g_state.active_jobs[slot].job_id == job_id && g_state.active_jobs[slot].active) {
        /* Already processing - just relay if needed */
        if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
            pkt->ttl--;
            e1000_send(pkt, sizeof(*pkt));
        }
        return;
    }

    /* Also check if we're currently processing a chunk from this job */
    if (g_state.current_chunk.job_id == job_id && g_state.current_chunk.processing) {
        if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
            pkt->ttl--;
            e1000_send(pkt, sizeof(*pkt));
        }
        return;
    }

    /* New job - display it */
    vga_set_color(0x0D);
    vga_puts(">> JOB #");
    vga_put_dec(job_id);
    vga_puts(" type=");
    vga_put_dec(job_type);
    vga_puts(" range=");
    vga_put_dec(param1);
    vga_puts("-");
    vga_put_dec(param2);
    vga_puts(" chunks=");
    vga_put_dec(num_chunks);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[JOB] Received job ");
    serial_put_dec(job_id);
    serial_puts(" type=");
    serial_put_dec(job_type);
    serial_puts("\n");

    /* Calculate which chunk this node should process based on node_id */
    uint32_t my_chunk = g_state.node_id % num_chunks;
    uint32_t range_size = (param2 - param1) / num_chunks;
    uint32_t chunk_start = param1 + (my_chunk * range_size);
    uint32_t chunk_end = (my_chunk == num_chunks - 1) ? param2 : chunk_start + range_size - 1;

    /* Record the job */
    g_state.active_jobs[slot].job_id = job_id;
    g_state.active_jobs[slot].job_type = job_type;
    g_state.active_jobs[slot].active = 1;
    g_state.active_jobs[slot].param1 = param1;
    g_state.active_jobs[slot].param2 = param2;
    g_state.active_jobs[slot].chunks_total = num_chunks;
    g_state.active_jobs[slot].chunks_done = 0;
    g_state.active_jobs[slot].result = 0;
    g_state.active_jobs[slot].started_at = ticks;
    g_state.active_jobs[slot].coordinator_id = pkt->node_id;  /* Sender aggregates results */

    /* Set current chunk to process */
    g_state.current_chunk.job_id = job_id;
    g_state.current_chunk.job_type = job_type;
    g_state.current_chunk.chunk_id = my_chunk;
    g_state.current_chunk.range_start = chunk_start;
    g_state.current_chunk.range_end = chunk_end;
    g_state.current_chunk.processing = 1;

    /* Relay the job announcement (gossip) */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Handle JOB_DONE pheromone (chunk result from worker) */
static void process_job_done(struct nanos_pheromone* pkt) {
    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint32_t chunk_id = *(uint32_t*)(pkt->payload + 4);
    uint32_t result_lo = *(uint32_t*)(pkt->payload + 8);
    uint32_t result_hi = *(uint32_t*)(pkt->payload + 12);
    uint64_t result = ((uint64_t)result_hi << 32) | result_lo;

    int slot = job_id % MAX_ACTIVE_JOBS;

    /* Check if we should aggregate results */
    int should_aggregate = 0;

    if (g_state.role == ROLE_QUEEN) {
        /* Queens always aggregate */
        should_aggregate = 1;
    } else if (g_state.active_jobs[slot].coordinator_id == g_state.node_id) {
        /* We are the designated coordinator */
        should_aggregate = 1;
    } else if (g_state.current_chunk.chunk_id == 0 &&
               g_state.current_chunk.job_id == job_id) {
        /* Fallback: node processing chunk 0 aggregates (for external coordinators like dashboard) */
        should_aggregate = 1;
    }

    if (should_aggregate) {
        if (g_state.active_jobs[slot].job_id == job_id && g_state.active_jobs[slot].active) {
            g_state.active_jobs[slot].result += result;
            g_state.active_jobs[slot].chunks_done++;

            vga_set_color(0x0B);
            vga_puts("<< CHUNK ");
            vga_put_dec(chunk_id);
            vga_puts(" result=");
            vga_put_dec((uint32_t)result);
            vga_puts(" (");
            vga_put_dec(g_state.active_jobs[slot].chunks_done);
            vga_puts("/");
            vga_put_dec(g_state.active_jobs[slot].chunks_total);
            vga_puts(")\n");
            vga_set_color(0x0A);

            /* Check if job is complete */
            if (g_state.active_jobs[slot].chunks_done >= g_state.active_jobs[slot].chunks_total) {
                vga_set_color(0x0D);
                vga_puts(">> JOB #");
                vga_put_dec(job_id);
                vga_puts(" COMPLETE! Total result: ");
                vga_put_dec((uint32_t)g_state.active_jobs[slot].result);
                vga_puts("\n");
                vga_set_color(0x0A);

                serial_puts("[JOB] Job ");
                serial_put_dec(job_id);
                serial_puts(" complete: result=");
                serial_put_dec((uint32_t)g_state.active_jobs[slot].result);
                serial_puts("\n");

                g_state.active_jobs[slot].active = 0;
                g_state.jobs_completed++;

                /* Broadcast final result */
                struct nanos_pheromone result_pkt;
                result_pkt.magic = NANOS_MAGIC;
                result_pkt.node_id = g_state.node_id;
                result_pkt.type = PHEROMONE_JOB_RESULT;
                result_pkt.ttl = GRADIENT_MAX_HOPS;
                result_pkt.flags = 0;
                result_pkt.version = NANOS_VERSION;
                result_pkt.seq = g_state.seq_counter++;
                result_pkt.dest_id = 0;
                result_pkt.distance = 0;
                result_pkt.hop_count = 0;
                PKT_SET_ROLE(&result_pkt, ROLE_QUEEN);

                uint8_t* p = result_pkt.payload;
                *(uint32_t*)p = job_id; p += 4;
                *(uint32_t*)p = (uint32_t)(g_state.active_jobs[slot].result & 0xFFFFFFFF); p += 4;
                *(uint32_t*)p = (uint32_t)(g_state.active_jobs[slot].result >> 32);

                for (int i = 0; i < HMAC_TAG_SIZE; i++) result_pkt.hmac[i] = 0;
                e1000_send(&result_pkt, sizeof(result_pkt));
                g_state.packets_tx++;
            }
        }
    }

    /* Relay result (gossip toward queen) */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Handle JOB_RESULT pheromone (final result broadcast) */
static void process_job_result(struct nanos_pheromone* pkt) {
    /* Deduplicate using gossip cache */
    if (!gossip_should_relay(pkt)) {
        return;  /* Already seen this result */
    }

    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint32_t result_lo = *(uint32_t*)(pkt->payload + 4);
    uint32_t result_hi = *(uint32_t*)(pkt->payload + 8);
    uint64_t result = ((uint64_t)result_hi << 32) | result_lo;

    vga_set_color(0x0D);
    vga_puts(">> FINAL RESULT Job #");
    vga_put_dec(job_id);
    vga_puts(": ");
    vga_put_dec((uint32_t)result);
    vga_puts("\n");
    vga_set_color(0x0A);

    /* Clear our active job state for this job */
    int slot = job_id % MAX_ACTIVE_JOBS;
    if (g_state.active_jobs[slot].job_id == job_id) {
        g_state.active_jobs[slot].active = 0;
    }

    /* Relay the result */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Command to start a global compute job (queen only) */
static void cmd_start_job(void) {
    if (g_state.role != ROLE_QUEEN) {
        vga_puts("! Only QUEEN can start global jobs\n");
        return;
    }

    static uint32_t job_counter = 0;
    uint32_t job_id = job_counter++;

    /* Create a prime search job */
    uint32_t range_start = 1 + (random() % 1000);
    uint32_t range_end = range_start + 1000 + (random() % 5000);
    uint32_t num_chunks = g_state.neighbor_count > 0 ? g_state.neighbor_count + 1 : 1;
    if (num_chunks > MAX_JOB_CHUNKS) num_chunks = MAX_JOB_CHUNKS;

    vga_set_color(0x0D);
    vga_puts(">> Starting PRIME SEARCH job #");
    vga_put_dec(job_id);
    vga_puts("\n   Range: ");
    vga_put_dec(range_start);
    vga_puts(" - ");
    vga_put_dec(range_end);
    vga_puts("\n   Chunks: ");
    vga_put_dec(num_chunks);
    vga_puts("\n");
    vga_set_color(0x0A);

    /* Build and send JOB_START */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_JOB_START;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = 0;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, ROLE_QUEEN);

    /* Payload: job_id(4) + job_type(1) + param1(4) + param2(4) + num_chunks(4) */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = job_id; p += 4;
    *p++ = JOB_PRIME_SEARCH;
    *(uint32_t*)p = range_start; p += 4;
    *(uint32_t*)p = range_end; p += 4;
    *(uint32_t*)p = num_chunks;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;

    /* Record the job locally */
    int slot = job_id % MAX_ACTIVE_JOBS;
    g_state.active_jobs[slot].job_id = job_id;
    g_state.active_jobs[slot].job_type = JOB_PRIME_SEARCH;
    g_state.active_jobs[slot].active = 1;
    g_state.active_jobs[slot].param1 = range_start;
    g_state.active_jobs[slot].param2 = range_end;
    g_state.active_jobs[slot].chunks_total = num_chunks;
    g_state.active_jobs[slot].chunks_done = 0;
    g_state.active_jobs[slot].result = 0;
    g_state.active_jobs[slot].started_at = ticks;
    g_state.active_jobs[slot].coordinator_id = g_state.node_id;  /* We are coordinator */

    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    /* Also process our own chunk */
    process_job_start(&pkt);

    serial_puts("[JOB] Started global job ");
    serial_put_dec(job_id);
    serial_puts("\n");
}

/* ==========================================================================
 * Workload Commands
 * ========================================================================== */
static void cmd_kv_demo(void) {
    static int demo = 0;
    uint8_t key[16], value[16];

    /* Generate demo key/value */
    key[0] = 'k'; key[1] = 'e'; key[2] = 'y';
    key[3] = '0' + (demo % 10); key[4] = 0;

    value[0] = 'v'; value[1] = 'a'; value[2] = 'l';
    value[3] = '0' + (demo % 10); value[4] = 0;

    demo++;

    kv_set(key, value, 1);
    vga_puts("[KV] Stored and replicated: ");
    vga_puts((char*)key);
    vga_puts("=");
    vga_puts((char*)value);
    vga_puts("\n");
}

static void cmd_task_demo(void) {
    if (g_state.role != ROLE_QUEEN) {
        vga_puts("! Only QUEEN can distribute tasks\n");
        return;
    }

    /* Send a random task */
    uint8_t task_type = (random() % 3) + 1;
    uint32_t input = (random() % 100) + 1;

    task_distribute(task_type, input);
}

static void cmd_show_workloads(void) {
    vga_set_color(0x0B);
    vga_puts("\n========= WORKLOAD STATUS =========\n");
    vga_set_color(0x0A);

    /* KV Store */
    vga_puts("KV Store: ");
    int kv_used = 0;
    for (int i = 0; i < KV_STORE_SIZE; i++) {
        if (g_state.kv_store[i].valid) kv_used++;
    }
    vga_put_dec(kv_used);
    vga_puts("/");
    vga_put_dec(KV_STORE_SIZE);
    vga_puts(" slots used\n");
    for (int i = 0; i < KV_STORE_SIZE; i++) {
        if (g_state.kv_store[i].valid) {
            vga_puts("  ");
            vga_puts((char*)g_state.kv_store[i].key);
            vga_puts(" = ");
            vga_puts((char*)g_state.kv_store[i].value);
            vga_puts("\n");
        }
    }

    /* Tasks */
    vga_puts("Tasks: sent=");
    vga_put_dec(g_state.tasks_sent);
    vga_puts(" completed=");
    vga_put_dec(g_state.tasks_completed);
    vga_puts("\n");

    /* Sensors */
    vga_puts("Sensors: readings=");
    vga_put_dec(g_state.sensors[0].count);
    if (g_state.sensors[0].count > 0) {
        vga_puts(" T=");
        vga_put_dec(g_state.sensors[0].value / 10);
        vga_puts("C H=");
        vga_put_dec(g_state.sensors[1].value / 10);
        vga_puts("% P=");
        vga_put_dec(g_state.sensors[2].value / 10);
        vga_puts("hPa");
    }
    vga_puts("\n");

    /* Global Compute Jobs */
    vga_set_color(0x0E);
    vga_puts("--- Global Compute ---\n");
    vga_set_color(0x0A);
    vga_puts("Jobs completed: ");
    vga_put_dec(g_state.jobs_completed);
    vga_puts(" | Chunks processed: ");
    vga_put_dec(g_state.chunks_processed);
    vga_puts("\n");

    /* Show active jobs */
    for (int i = 0; i < MAX_ACTIVE_JOBS; i++) {
        if (g_state.active_jobs[i].active) {
            vga_puts("  Job ");
            vga_put_hex(g_state.active_jobs[i].job_id);
            vga_puts(": type=");
            switch (g_state.active_jobs[i].job_type) {
                case JOB_PRIME_SEARCH: vga_puts("PRIME"); break;
                case JOB_MONTE_CARLO_PI: vga_puts("PI"); break;
                case JOB_REDUCE_SUM: vga_puts("SUM"); break;
                default: vga_puts("?"); break;
            }
            vga_puts(" progress=");
            vga_put_dec(g_state.active_jobs[i].chunks_done);
            vga_puts("/");
            vga_put_dec(g_state.active_jobs[i].chunks_total);
            vga_puts("\n");
        }
    }

    /* Show current chunk if processing */
    if (g_state.current_chunk.processing) {
        vga_puts("  Processing chunk ");
        vga_put_dec(g_state.current_chunk.chunk_id);
        vga_puts(" [");
        vga_put_dec(g_state.current_chunk.range_start);
        vga_puts("-");
        vga_put_dec(g_state.current_chunk.range_end);
        vga_puts("]\n");
    }

    vga_set_color(0x0B);
    vga_puts("===================================\n\n");
    vga_set_color(0x0A);
}

/* Process keyboard command */
static void process_command(char c) {
    switch (c) {
        case 's': cmd_show_status(); break;
        case 'd': cmd_send_data(); break;
        case 'a': cmd_send_alarm(); break;
        case 'q': cmd_queen_command(); break;
        case 'e': cmd_force_election(); break;
        case 'h': cmd_show_help(); break;
        case 'r':
            vga_puts("~ Manual rebirth requested...\n");
            cell_apoptosis();
            break;
        /* Workload commands */
        case 'k': cmd_kv_demo(); break;      /* KV store demo */
        case 't': cmd_task_demo(); break;    /* Task distribution demo */
        case 'w': cmd_show_workloads(); break; /* Show workload status */
        case 'j': cmd_start_job(); break;    /* Start global compute job */
        default:
            break;
    }
}

/* ==========================================================================
 * Apoptosis - Programmed Cell Death and Rebirth
 * ========================================================================== */
void cell_apoptosis(void) {
    vga_set_color(0x0C);  /* Red */
    vga_puts("\n!!! APOPTOSIS TRIGGERED !!!\n");
    vga_puts("    Reason: ");

    if (heap_usage_percent() >= HEAP_CRITICAL_PCT) {
        vga_puts("Memory exhaustion (");
        vga_put_dec(heap_usage_percent());
        vga_puts("%)\n");
    } else if (ticks - g_state.boot_time > MAX_CELL_LIFETIME) {
        vga_puts("Maximum lifetime reached\n");
    } else {
        vga_puts("Unknown\n");
    }

    /* Emit farewell pheromone */
    struct nanos_pheromone pkt;
    pkt.magic   = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type    = PHEROMONE_REBIRTH;
    pkt.ttl     = 2;
    pkt.flags   = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq     = g_state.seq_counter++;

    /* Payload: our stats before death */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.packets_rx; p += 4;
    *(uint32_t*)p = g_state.packets_tx; p += 4;
    *(uint32_t*)p = g_state.generation; p += 4;

    compute_hmac(&pkt);
    e1000_send(&pkt, sizeof(pkt));

    /* Wait for TX to complete */
    for (volatile int i = 0; i < 100000; i++);

    /* REBIRTH */
    vga_puts("    Rebirthing...\n");

    /* Save generation and increment */
    uint32_t old_gen = g_state.generation;

    /* Reset heap */
    heap_reset();

    /* Clear gossip cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        g_state.gossip_cache[i].hash = 0;
        g_state.gossip_cache[i].count = 0;
    }

    /* Generate new identity */
    seed_random();
    g_state.node_id = random();
    g_state.role = determine_role();
    g_state.generation = old_gen + 1;
    g_state.boot_time = ticks;
    g_state.last_heartbeat = ticks;
    g_state.seq_counter = 0;
    g_state.packets_rx = 0;
    g_state.packets_tx = 0;
    g_state.packets_dropped = 0;
    g_state.packets_routed = 0;
    g_state.alarms_relayed = 0;
    g_state.neighbor_count = 0;
    g_state.distance_to_queen = (g_state.role == ROLE_QUEEN) ? 0 : GRADIENT_INFINITY;
    g_state.gradient_via = 0;
    g_state.known_queen_id = 0;
    g_state.last_queen_seen = 0;
    g_state.election.participating = 0;

    /* Clear neighbor and route tables */
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        g_state.neighbors[i].node_id = 0;
    }
    for (int i = 0; i < ROUTE_CACHE_SIZE; i++) {
        g_state.routes[i].valid = 0;
    }

    vga_set_color(0x0A);  /* Back to green */
    vga_puts("    New Node ID: ");
    vga_put_hex(g_state.node_id);
    vga_puts("\n    New Role: ");
    vga_puts(role_name(g_state.role));
    vga_puts("\n    Generation: ");
    vga_put_dec(g_state.generation);
    vga_puts("\n\n");
}

/* ==========================================================================
 * Pheromone Processing
 * ========================================================================== */
void process_pheromone(struct nanos_pheromone* pkt) {
    /* Validate magic and version */
    if (pkt->magic != NANOS_MAGIC) return;
    if (pkt->version != NANOS_VERSION && pkt->version != 0) {
        /* Incompatible version - quarantine */
        return;
    }

    /* Don't process our own messages */
    if (pkt->node_id == g_state.node_id) return;

    /* Security check for critical messages */
    if (is_authenticated_type(pkt->type)) {
        if (!(pkt->flags & FLAG_AUTHENTICATED)) {
            vga_set_color(0x0E);  /* Yellow warning */
            vga_puts("! Rejected unauthenticated ");
            vga_put_hex(pkt->type);
            vga_puts(" from ");
            vga_put_hex(pkt->node_id);
            vga_puts("\n");
            vga_set_color(0x0A);
            return;
        }

        if (!verify_hmac(pkt)) {
            vga_set_color(0x0C);  /* Red alert */
            vga_puts("!! INVALID HMAC from ");
            vga_put_hex(pkt->node_id);
            vga_puts(" - possible attack!\n");
            vga_set_color(0x0A);
            return;
        }
    }

    /* Record in gossip cache */
    gossip_record(pkt);

    g_state.packets_rx++;

    /* Update collective intelligence (all packet types) */
    neighbor_update(pkt);
    gradient_update(pkt);

    /* Handle routed packets */
    if (pkt->flags & FLAG_ROUTED) {
        if (pkt->dest_id != 0 && pkt->dest_id != g_state.node_id) {
            route_forward(pkt);
            return;  /* Don't process, just forward */
        }
    }

    /* Process by type */
    switch (pkt->type) {
        case PHEROMONE_HELLO:
            if (g_state.role == ROLE_SENTINEL) {
                /* Sentinels log all contacts */
                vga_puts("< [");
                vga_puts(role_name(PKT_GET_ROLE(pkt)));
                vga_puts("] ");
                vga_put_hex(pkt->node_id);
                vga_puts(" d=");
                vga_put_dec(pkt->distance);
                vga_puts("\n");
            }
            break;

        case PHEROMONE_DATA:
            vga_puts("< DATA: ");
            pkt->payload[31] = '\0';
            vga_puts((char*)pkt->payload);
            vga_puts("\n");
            break;

        case PHEROMONE_ALARM:
            vga_set_color(0x0C);  /* Red */
            vga_puts("! ALARM from ");
            vga_put_hex(pkt->node_id);
            vga_puts(" TTL=");
            vga_put_dec(pkt->ttl);
            vga_puts("\n");
            vga_set_color(0x0A);

            /* Relay using gossip protocol */
            if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
                pkt->ttl--;
                pkt->seq = g_state.seq_counter++;  /* Our seq for dedup */
                e1000_send(pkt, sizeof(*pkt));
                g_state.alarms_relayed++;
            }
            break;

        case PHEROMONE_QUEEN_CMD:
            if (PKT_GET_ROLE(pkt) != ROLE_QUEEN) {
                vga_puts("! Non-queen sent QUEEN_CMD - ignoring\n");
                break;
            }
            vga_set_color(0x0D);  /* Magenta - queen commands */
            vga_puts(">> QUEEN COMMAND: ");
            pkt->payload[31] = '\0';
            vga_puts((char*)pkt->payload);
            vga_puts("\n");
            vga_set_color(0x0A);
            break;

        case PHEROMONE_REBIRTH:
            vga_set_color(0x0E);  /* Yellow */
            vga_puts("~ Cell ");
            vga_put_hex(pkt->node_id);
            vga_puts(" died (gen ");
            vga_put_dec(*(uint32_t*)(pkt->payload + 8));
            vga_puts(")\n");
            vga_set_color(0x0A);
            break;

        case PHEROMONE_DIE:
            /* Authenticated DIE command - only queens can send */
            if (PKT_GET_ROLE(pkt) == ROLE_QUEEN) {
                vga_set_color(0x0C);
                vga_puts("X DIE from Queen - halting\n");
                for (;;) cpu_halt();
            }
            break;

        case PHEROMONE_ELECTION:
            /* Queen election in progress */
            election_process(pkt);
            break;

        case PHEROMONE_CORONATION:
            /* New queen announced */
            if (verify_hmac(pkt)) {
                g_state.known_queen_id = pkt->node_id;
                g_state.last_queen_seen = ticks;
                g_state.distance_to_queen = pkt->hop_count + 1;
                g_state.gradient_via = pkt->node_id;

                /* Cancel any ongoing election */
                g_state.election.participating = 0;
                if (g_state.role == ROLE_CANDIDATE) {
                    g_state.role = g_state.previous_role;
                }

                vga_set_color(0x0D);
                vga_puts(">> NEW QUEEN: ");
                vga_put_hex(pkt->node_id);
                vga_puts("\n");
                vga_set_color(0x0A);

                /* Relay coronation */
                if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
                    pkt->ttl--;
                    pkt->hop_count++;
                    e1000_send(pkt, sizeof(*pkt));
                }
            }
            break;

        /* ==========================================================================
         * Workload Pheromones
         * ========================================================================== */
        case PHEROMONE_KV_SET:
            process_kv_set(pkt);
            break;

        case PHEROMONE_KV_GET:
            /* Handle GET request - send back value if we have it */
            {
                uint8_t* key = pkt->payload;
                int idx = kv_find(key);
                if (idx >= 0) {
                    /* We have this key - send reply */
                    struct nanos_pheromone reply;
                    reply.magic = NANOS_MAGIC;
                    reply.node_id = g_state.node_id;
                    reply.type = PHEROMONE_KV_REPLY;
                    reply.ttl = GRADIENT_MAX_HOPS;
                    reply.flags = FLAG_ROUTED;
                    reply.version = NANOS_VERSION;
                    reply.seq = g_state.seq_counter++;
                    reply.dest_id = pkt->node_id;  /* Reply to sender */
                    reply.distance = g_state.distance_to_queen;
                    reply.hop_count = 0;

                    /* Copy key and value to payload */
                    for (int i = 0; i < KV_KEY_SIZE; i++)
                        reply.payload[i] = key[i];
                    for (int i = 0; i < KV_VALUE_SIZE; i++)
                        reply.payload[KV_KEY_SIZE + i] = g_state.kv_store[idx].value[i];

                    for (int i = 0; i < HMAC_TAG_SIZE; i++) reply.hmac[i] = 0;
                    e1000_send(&reply, sizeof(reply));
                    g_state.packets_tx++;
                }
            }
            break;

        case PHEROMONE_KV_REPLY:
            /* Got a KV reply */
            vga_set_color(0x0E);
            vga_puts("< KV REPLY: ");
            pkt->payload[KV_KEY_SIZE - 1] = '\0';
            vga_puts((char*)pkt->payload);
            vga_puts(" = ");
            pkt->payload[KV_KEY_SIZE + KV_VALUE_SIZE - 1] = '\0';
            vga_puts((char*)(pkt->payload + KV_KEY_SIZE));
            vga_puts("\n");
            vga_set_color(0x0A);
            break;

        case PHEROMONE_TASK:
            process_task(pkt);
            break;

        case PHEROMONE_RESULT:
            process_result(pkt);
            break;

        case PHEROMONE_SENSOR:
            process_sensor(pkt);
            break;

        case PHEROMONE_AGGREGATE:
            /* Display aggregate stats from other nodes */
            vga_set_color(0x0B);
            vga_puts("< AGGREGATE from ");
            vga_put_hex(pkt->node_id);
            vga_puts(": T=");
            vga_put_dec(*(int32_t*)(pkt->payload));
            vga_puts(" H=");
            vga_put_dec(*(int32_t*)(pkt->payload + 4));
            vga_puts(" P=");
            vga_put_dec(*(int32_t*)(pkt->payload + 8));
            vga_puts("\n");
            vga_set_color(0x0A);
            break;

        /* Global Compute - MapReduce job handling */
        case PHEROMONE_JOB_START:
            process_job_start(pkt);
            break;

        case PHEROMONE_JOB_DONE:
            process_job_done(pkt);
            break;

        case PHEROMONE_JOB_RESULT:
            process_job_result(pkt);
            break;

        default:
            break;
    }
}

/* ==========================================================================
 * Heartbeat Emission
 * ========================================================================== */
void emit_heartbeat(void) {
    struct nanos_pheromone pkt;

    pkt.magic   = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type    = PHEROMONE_HELLO;
    pkt.ttl     = 1;
    pkt.flags   = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq     = g_state.seq_counter++;

    PKT_SET_ROLE(&pkt, g_state.role);

    /* Routing fields - propagate gradient */
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    pkt.via_node_lo = g_state.gradient_via & 0xFF;
    pkt.via_node_hi = (g_state.gradient_via >> 8) & 0xFF;

    /* Stats in payload */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.packets_rx; p += 4;
    *(uint32_t*)p = g_state.packets_tx; p += 4;
    *(uint32_t*)p = ticks;              p += 4;
    *(uint32_t*)p = g_state.generation; p += 4;
    *p++ = heap_usage_percent();
    *p++ = g_state.role;
    *p++ = e1000_tx_queue_depth();
    *p++ = g_state.neighbor_count;

    /* Zero HMAC for non-critical message */
    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;

    /* Propagate gradient before sending */
    gradient_propagate();

    if (e1000_send(&pkt, sizeof(pkt)) == 0) {
        g_state.packets_tx++;
    }

    g_state.last_heartbeat = ticks;
}

/* ==========================================================================
 * Main Reactive Loop
 * ========================================================================== */
void nanos_loop(void) {
    static uint8_t rx_buffer[2048];
    static uint32_t last_maintenance = 0;
    static uint32_t last_metrics = 0;

    for (;;) {
        /* Check for apoptosis conditions */
        if (heap_usage_percent() >= HEAP_CRITICAL_PCT ||
            ticks - g_state.boot_time > MAX_CELL_LIFETIME) {
            cell_apoptosis();
        }

        /* Process keyboard input */
        char c = kb_getchar();
        if (c != 0) {
            process_command(c);
        }

        /* Drain TX queue (non-blocking) */
        e1000_tx_drain();

        /* Process incoming packets */
        while (e1000_has_packet()) {
            int len = e1000_receive(rx_buffer, sizeof(rx_buffer));
            if (len >= (int)(sizeof(struct eth_header) + sizeof(struct nanos_pheromone))) {
                struct nanos_pheromone* pkt =
                    (struct nanos_pheromone*)(rx_buffer + sizeof(struct eth_header));
                process_pheromone(pkt);
            }
        }

        /* Periodic metrics logging to serial (every 10 seconds) */
        if (ticks - last_metrics >= 1000) {
            serial_puts("[METRICS] t=");
            serial_put_dec((ticks - g_state.boot_time) / 100);
            serial_puts("s node=");
            serial_put_hex(g_state.node_id);
            serial_puts(" role=");
            serial_puts(role_name(g_state.role));
            serial_puts(" neighbors=");
            serial_put_dec(g_state.neighbor_count);
            serial_puts(" rx=");
            serial_put_dec(g_state.packets_rx);
            serial_puts(" tx=");
            serial_put_dec(g_state.packets_tx);
            serial_puts(" queen=");
            serial_put_hex(g_state.known_queen_id);
            serial_puts(" dist=");
            serial_put_dec(g_state.distance_to_queen);
            serial_puts("\n");
            last_metrics = ticks;
        }

        /* Periodic collective intelligence maintenance (every ~1 second) */
        if (ticks - last_maintenance >= 100) {
            neighbor_expire();      /* Remove stale neighbors */
            quorum_evaluate();      /* Adapt role based on neighborhood */
            election_check_timeout(); /* Check for election completion */
            last_maintenance = ticks;
        }

        /* Emit heartbeat based on role */
        if (ticks - g_state.last_heartbeat >= heartbeat_interval()) {
            emit_heartbeat();
        }

        /* Sensor network - generate readings periodically */
        if (ticks - g_state.last_sensor_reading >= SENSOR_INTERVAL) {
            sensor_generate();
        }

        /* Queens aggregate sensor data periodically */
        if (g_state.role == ROLE_QUEEN &&
            ticks - g_state.last_aggregate >= AGGREGATE_INTERVAL) {
            sensor_aggregate();
        }

        /* Process any pending compute job chunks */
        job_process_chunk();

        /* Sleep until next interrupt */
        cpu_halt();
    }
}

/* ==========================================================================
 * Kernel Entry Point
 * ========================================================================== */
void kernel_main(uint32_t magic, void* mb_info) {
    (void)mb_info;

    vga_clear();

    if (magic != MULTIBOOT2_MAGIC) {
        vga_puts("ERROR: Not Multiboot2!\n");
        for (;;) cpu_halt();
    }

    /* Banner */
    vga_set_color(0x0B);  /* Cyan */
    vga_puts("========================================\n");
    vga_puts("  NanOS v0.3 - Collective Intelligence\n");
    vga_puts("========================================\n\n");
    vga_set_color(0x0A);

    /* Initialize hardware */
    vga_puts("[*] Loading GDT...\n");
    gdt_load();

    vga_puts("[*] Initializing serial (COM1)...\n");
    serial_init();
    serial_puts("\n=== NanOS v0.3 Boot ===\n");

    vga_puts("[*] Initializing interrupts...\n");
    pic_init();
    idt_init();

    vga_puts("[*] Starting timer (100 Hz)...\n");
    pit_init(100);
    interrupts_enable();

    /* Wait for entropy */
    while (ticks < 10) cpu_halt();
    seed_random();

    /* Generate identity */
    g_state.node_id = random();
    g_state.role = determine_role();
    g_state.generation = 0;
    g_state.heap_size = HEAP_SIZE;

    vga_puts("[*] Node ID: ");
    vga_put_hex(g_state.node_id);
    vga_puts("\n[*] Role: ");
    vga_set_color(g_state.role == ROLE_QUEEN ? 0x0D : 0x0A);
    vga_puts(role_name(g_state.role));
    vga_set_color(0x0A);
    vga_puts("\n");

    /* Initialize network */
    vga_puts("[*] Initializing e1000 NIC...\n");
    if (e1000_init() != 0) {
        vga_puts("ERROR: Network init failed!\n");
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
    g_state.seq_counter = 0;
    g_state.packets_rx = 0;
    g_state.packets_tx = 0;
    g_state.packets_dropped = 0;
    g_state.packets_routed = 0;
    g_state.alarms_relayed = 0;
    g_state.gossip_index = 0;
    g_state.last_role_check = 0;

    /* Initialize collective intelligence state */
    g_state.neighbor_count = 0;
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        g_state.neighbors[i].node_id = 0;
    }
    for (int i = 0; i < 8; i++) {
        g_state.role_counts[i] = 0;
    }
    g_state.last_queen_seen = 0;
    g_state.known_queen_id = 0;
    g_state.distance_to_queen = (g_state.role == ROLE_QUEEN) ? 0 : GRADIENT_INFINITY;
    g_state.gradient_via = 0;
    for (int i = 0; i < ROUTE_CACHE_SIZE; i++) {
        g_state.routes[i].valid = 0;
    }
    g_state.election.participating = 0;
    g_state.election.phase = ELECTION_PHASE_NONE;

    /* Clear gossip cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        g_state.gossip_cache[i].hash = 0;
    }

    vga_puts("\n[*] Cell alive. Features:\n");
    vga_puts("    - Quorum sensing\n");
    vga_puts("    - Queen elections\n");
    vga_puts("    - Gradient routing\n");
    vga_puts("    - HMAC authentication\n");
    vga_puts("    - Apoptosis at ");
    vga_put_dec(HEAP_CRITICAL_PCT);
    vga_puts("% heap or ");
    vga_put_dec(MAX_CELL_LIFETIME / 100);
    vga_puts("s\n\n");

    vga_set_color(0x0E);
    vga_puts("Commands: [s]tatus [d]ata [a]larm [q]ueen [e]lection [h]elp\n\n");
    vga_set_color(0x0A);

    vga_puts("Listening for pheromones...\n\n");

    /* Log boot complete to serial */
    serial_puts("[BOOT] Node=");
    serial_put_hex(g_state.node_id);
    serial_puts(" Role=");
    serial_puts(role_name(g_state.role));
    serial_puts(" ready\n");

    nanos_loop();
}
