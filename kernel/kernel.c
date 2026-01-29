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
#include "../include/nanos/bloom.h"
#include "../include/nanos/gossip.h"
#include "../include/nanos/hmac.h"
#include "../include/nanos/allocator.h"
#include "../include/nanos/serial.h"
#include "../include/nanos/task_handler.h"

/* NERT Protocol Integration */
#include <nert.h>
#include "../lib/nert/hal/hal_adapter.h"
#include "../lib/nert/nert_phy_if.h"

/* ==========================================================================
 * Global State - The cell's memory
 * ========================================================================== */
struct nanos_state g_state;

/* ==========================================================================
 * VGA Console (implementation in arch/x86/console_vga.c)
 * ========================================================================== */
/* Functions declared in nanos.h, implemented in arch/x86/console_vga.c */

/* ==========================================================================
 * Timer (PIT) - x86 specific
 * ========================================================================== */
#define PIT_CH0_DATA    0x40
#define PIT_CMD         0x43
#define PIT_FREQUENCY   1193182

volatile uint32_t ticks = 0;  /* Global tick counter, used by protocol modules */

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
 * NERT Protocol Integration
 * ========================================================================== */

/* NERT enabled flag */
static uint8_t g_nert_enabled = 0;

/* NERT PHY interface for e1000 */
static int nert_phy_send(const void *data, uint16_t len, void *ctx) {
    (void)ctx;
    return e1000_send((void*)data, len);  /* Cast away const - e1000_send doesn't modify data */
}

static int nert_phy_receive(void *buffer, uint16_t max_len, void *ctx) {
    (void)ctx;
    if (!e1000_has_packet()) return 0;
    return e1000_receive(buffer, max_len);
}

static uint32_t nert_phy_get_ticks(void *ctx) {
    (void)ctx;
    return ticks;
}

static uint32_t nert_phy_random(void *ctx) {
    (void)ctx;
    return random();
}

static struct nert_phy_interface g_nert_phy = {
    .send = nert_phy_send,
    .receive = nert_phy_receive,
    .get_ticks = nert_phy_get_ticks,
    .random = nert_phy_random,
    .context = NULL
};

/* NERT message handler - dispatches pheromones to appropriate handlers */
static void nert_message_handler(uint16_t sender_id, uint8_t msg_type,
                                  const void *data, uint8_t len) {
    (void)len;

    /* Increment RX counter for received NERT packets */
    g_state.packets_rx++;

    switch (msg_type) {
        case 0xA0:  /* PHEROMONE_TASK_ASSIGN */
            task_handler_process_pheromone((const struct task_payload*)data);
            break;

        case 0x14:  /* PHEROMONE_CONFIG_UPDATE - Genetic config from Queen */
            /* TODO: Handle genetic configuration updates */
            serial_puts("[NERT] Config update from ");
            serial_put_hex(sender_id);
            serial_puts("\n");
            break;

        case 0x13:  /* PHEROMONE_DIE - Apoptosis trigger */
            serial_puts("[NERT] DIE command from Queen!\n");
            cell_apoptosis();
            break;

        case 0x01:  /* PHEROMONE_ANNOUNCE - Queen announcement */
            /* Update Queen tracking */
            if (data && len >= 2) {
                const uint8_t *d = (const uint8_t*)data;
                uint16_t queen_id = d[0] | (d[1] << 8);
                if (queen_id != 0) {
                    g_state.known_queen_id = queen_id;
                    g_state.last_queen_seen = ticks;
                    g_state.distance_to_queen = 1;  /* Direct from Queen */
                }
            }
            break;

        default:
            /* Unknown pheromone - log for debugging */
            serial_puts("[NERT] Unknown type 0x");
            serial_put_hex(msg_type);
            serial_puts(" from ");
            serial_put_hex(sender_id);
            serial_puts("\n");
            break;
    }
}

/* ==========================================================================
 * IDT Setup - x86 specific
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

/* Serial Port functions in arch/x86/serial_com.c */

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
    vga_put_dec(heap_used_bytes());
    vga_puts("/");
    vga_put_dec(heap_total_bytes());
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
 * Workload: Sensor Network (DISABLED - too spammy)
 * ========================================================================== */
#if 0
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
#endif /* sensor_generate disabled */

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

#if 0 /* sensor_aggregate disabled - too spammy */
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
#endif /* Sensor network disabled */

/* Tactical Intelligence module moved to kernel/tactical/intelligence.c */
#include "../include/nanos/intelligence.h"

/* Maze module moved to kernel/tactical/maze.c */
#include "../include/nanos/maze.h"

/* Terrain module moved to kernel/tactical/terrain.c */
#include "../include/nanos/terrain.h"

/* v0.5: Distributed Black Box - forensic evidence preservation */
#include "../include/nanos/blackbox.h"

/* Global Compute module moved to kernel/workloads/global_compute.c */
#include "../include/nanos/global_compute.h"

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

    /* v0.5: Determine death reason for Black Box */
    uint8_t death_reason = DEATH_UNKNOWN;

    if (heap_usage_percent() >= HEAP_CRITICAL_PCT) {
        vga_puts("Memory exhaustion (");
        vga_put_dec(heap_usage_percent());
        vga_puts("%)\n");
        death_reason = DEATH_HEAP_EXHAUSTED;
    } else if (ticks - g_state.boot_time > MAX_CELL_LIFETIME) {
        vga_puts("Maximum lifetime reached\n");
        death_reason = DEATH_NATURAL;
    } else if (g_state.neighbor_count == 0 &&
               ticks - g_state.boot_time > 60000) {
        vga_puts("Isolation\n");
        death_reason = DEATH_ISOLATION;
    } else {
        vga_puts("Unknown\n");
    }

    /* v0.5: Emit Last Will to trusted neighbors before dying
     * "The dead speak through the living" */
    blackbox_emit_last_will(death_reason);

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
    g_state.election.last_ended = 0;

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
    /* DEBUG: Show all packets entering process_pheromone */
    if (pkt->type == 0xA0) {  /* PHEROMONE_TASK_ASSIGN */
        vga_set_color(0x0E);  /* Yellow */
        vga_puts("[DEBUG] TASK pkt: magic=0x");
        vga_put_hex(pkt->magic);
        vga_puts(" ver=");
        vga_put_dec(pkt->version);
        vga_puts(" from=0x");
        vga_put_hex(pkt->node_id);
        vga_puts("\n");
        vga_set_color(0x0A);
    }

    /* Validate magic and version */
    if (pkt->magic != NANOS_MAGIC) {
        if (pkt->type == 0xA0) {
            vga_puts("[DEBUG] TASK dropped: bad magic\n");
        }
        return;
    }
    if (pkt->version != (NANOS_VERSION & 0xFF) && pkt->version != 0) {
        /* Incompatible version - quarantine */
        if (pkt->type == 0xA0) {
            vga_puts("[DEBUG] TASK dropped: bad version (");
            vga_put_dec(pkt->version);
            vga_puts(" vs ");
            vga_put_dec(NANOS_VERSION & 0xFF);
            vga_puts(")\n");
        }
        return;
    }

    /* Don't process our own messages */
    if (pkt->node_id == g_state.node_id) {
        if (pkt->type == 0xA0) {
            vga_puts("[DEBUG] TASK dropped: own message\n");
        }
        return;
    }

    /* Bloom filter deduplication - O(1) check */
    /* SKIP bloom filter for TASK packets to ensure they get processed */
    if (pkt->type != 0xA0) {
        if (!bloom_check_and_add(pkt)) {
            /* Already seen this packet - skip processing */
            g_state.packets_dropped++;
            return;
        }
    } else {
        vga_puts("[DEBUG] TASK skipping bloom filter\n");
    }

    if (pkt->type == 0xA0) {
        vga_puts("[DEBUG] TASK passed all checks, entering switch\n");
    }

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

                /* Cancel any ongoing election and start cooldown */
                g_state.election.participating = 0;
                g_state.election.last_ended = ticks;  /* Cooldown to prevent immediate re-election */
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

        /* Task distribution from micrOS Queen (uses task_handler) */
        case PHEROMONE_TASK_ASSIGN:
            /* pkt->payload contains the task_payload struct */
            serial_puts("[TASK] Received TASK_ASSIGN from 0x");
            serial_put_hex(pkt->node_id);
            serial_puts("\n");
            vga_set_color(0x0D);  /* Magenta */
            vga_puts(">> TASK from Queen\n");
            vga_set_color(0x0A);
            task_handler_process_pheromone((const struct task_payload*)pkt->payload);
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

        /* Tactical Intelligence pheromones */
        case PHEROMONE_DETECT:
            tactical_process_detection(pkt);
            if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
                pkt->ttl--;
                e1000_send(pkt, sizeof(*pkt));
            }
            break;

        /* Maze Exploration pheromones */
        case PHEROMONE_MAZE_INIT:
            maze_process_init(pkt);
            break;

        case PHEROMONE_MAZE_DISCOVER:
            maze_process_discover(pkt);
            break;

        case PHEROMONE_MAZE_MOVE:
            maze_process_move(pkt);
            break;

        case PHEROMONE_MAZE_SOLVED:
            maze_process_solved(pkt);
            break;

        /* Terrain Exploration pheromones */
        case PHEROMONE_TERRAIN_INIT:
            terrain_process_init(pkt);
            break;

        case PHEROMONE_TERRAIN_REPORT:
            terrain_process_report(pkt);
            break;

        case PHEROMONE_TERRAIN_MOVE:
            terrain_process_move(pkt);
            break;

        case PHEROMONE_TERRAIN_THREAT:
            terrain_process_threat(pkt);
            break;

        case PHEROMONE_TERRAIN_STRATEGY:
            terrain_process_strategy(pkt);
            break;

        /* v0.5 Stigmergia: Digital pheromone broadcast */
        case PHEROMONE_STIGMERGIA:
            terrain_process_stigmergia(pkt);
            break;

        /* v0.5 Black Box: Dying node's testament */
        case PHEROMONE_LAST_WILL:
            blackbox_process_last_will(pkt);
            break;

        default:
            break;
    }
}

/* ==========================================================================
 * Heartbeat Emission
 * ========================================================================== */

/* Ethernet constants for heartbeat - must match micrOS */
#define HB_ETH_ALEN         6
#define HB_NERT_ETH_TYPE    0x4F4E

/* NERT multicast MAC address - must match micrOS */
static const uint8_t HB_MULTICAST_MAC[HB_ETH_ALEN] = {
    0x01, 0x00, 0x5E, 0x4E, 0x45, 0x52
};

void emit_heartbeat(void) {
    /* Ethernet frame: 14 byte header + 64 byte pheromone */
    uint8_t frame[14 + sizeof(struct nanos_pheromone)];
    struct nanos_pheromone *pkt = (struct nanos_pheromone *)(frame + 14);

    /* Build Ethernet header */
    for (int i = 0; i < HB_ETH_ALEN; i++) {
        frame[i] = HB_MULTICAST_MAC[i];  /* Destination: multicast */
    }
    e1000_get_mac(frame + HB_ETH_ALEN);  /* Source: our MAC */
    frame[12] = (HB_NERT_ETH_TYPE >> 8) & 0xFF;  /* EtherType high byte */
    frame[13] = HB_NERT_ETH_TYPE & 0xFF;         /* EtherType low byte */

    /* Build pheromone */
    pkt->magic   = NANOS_MAGIC;
    pkt->node_id = g_state.node_id;
    pkt->type    = PHEROMONE_HELLO;
    pkt->ttl     = 1;
    pkt->flags   = 0;
    pkt->version = NANOS_VERSION;
    pkt->seq     = g_state.seq_counter++;

    PKT_SET_ROLE(pkt, g_state.role);

    /* Routing fields - propagate gradient */
    pkt->dest_id = 0;  /* Broadcast */
    pkt->distance = g_state.distance_to_queen;
    pkt->hop_count = 0;
    pkt->via_node_lo = g_state.gradient_via & 0xFF;
    pkt->via_node_hi = (g_state.gradient_via >> 8) & 0xFF;

    /* Stats in payload */
    uint8_t* p = pkt->payload;
    *(uint32_t*)p = g_state.packets_rx; p += 4;
    *(uint32_t*)p = g_state.packets_tx; p += 4;
    *(uint32_t*)p = ticks;              p += 4;
    *(uint32_t*)p = g_state.generation; p += 4;
    *p++ = heap_usage_percent();
    *p++ = g_state.role;
    *p++ = e1000_tx_queue_depth();
    *p++ = g_state.neighbor_count;

    /* Zero HMAC for non-critical message */
    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt->hmac[i] = 0;

    /* Propagate gradient before sending */
    gradient_propagate();

    /* Send complete Ethernet frame */
    if (e1000_send(frame, sizeof(frame)) == 0) {
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

        /* Process incoming packets (legacy raw pheromones) FIRST
         * Must be before NERT processing because nert_process_incoming()
         * consumes packets from e1000 queue and discards non-NERT packets.
         * micrOS sends raw pheromones, not encrypted NERT packets. */
        while (e1000_has_packet()) {
            int len = e1000_receive(rx_buffer, sizeof(rx_buffer));

            /* DEBUG: Show ALL received packets on VGA */
            vga_set_color(0x0B);  /* Cyan */
            vga_puts("[RX] len=");
            vga_put_dec(len);

            if (len >= (int)(sizeof(struct eth_header) + sizeof(struct nanos_pheromone))) {
                struct nanos_pheromone* pkt =
                    (struct nanos_pheromone*)(rx_buffer + sizeof(struct eth_header));

                vga_puts(" type=0x");
                vga_put_hex(pkt->type);
                vga_puts(" from=0x");
                vga_put_hex(pkt->node_id);
                vga_puts("\n");
                vga_set_color(0x0A);

                /* Also to serial */
                serial_puts("[RX] len=");
                serial_put_dec(len);
                serial_puts(" type=0x");
                serial_put_hex(pkt->type);
                serial_puts(" from=0x");
                serial_put_hex(pkt->node_id);
                serial_puts("\n");

                process_pheromone(pkt);
            } else {
                vga_puts(" (too small)\n");
                vga_set_color(0x0A);
            }
        }

        /* NERT Protocol Processing (if enabled) */
        if (g_nert_enabled) {
            nert_hal_update_ticks();
            /* NOTE: nert_process_incoming() disabled - it consumes packets
             * and discards raw pheromones. micrOS uses raw format. */
            /* nert_process_incoming(); */
            nert_timer_tick();
            nert_check_key_rotation();

            /* Task handler periodic tick */
            task_handler_tick();
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

        /* Sensor network - DISABLED (spams logs)
        if (ticks - g_state.last_sensor_reading >= SENSOR_INTERVAL) {
            sensor_generate();
        }
        if (g_state.role == ROLE_QUEEN &&
            ticks - g_state.last_aggregate >= AGGREGATE_INTERVAL) {
            sensor_aggregate();
        }
        */

        /* Tactical intelligence - DISABLED (spams logs)
        if (g_state.role == ROLE_SENTINEL) {
            tactical_simulate();
        }
        tactical_maintenance();
        */

        /* Maze exploration - move and share discoveries */
        maze_move();
        maze_share_discoveries();

        /* Terrain exploration - move and share discoveries */
        terrain_move();
        terrain_share_discoveries();
        terrain_integrate_detections();

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
    vga_puts("  NanOS v0.4 - Swarm Exploration\n");
    vga_puts("========================================\n\n");
    vga_set_color(0x0A);

    /* Initialize hardware */
    vga_puts("[*] Loading GDT...\n");
    gdt_load();

    vga_puts("[*] Initializing serial (COM1)...\n");
    serial_init();
    serial_puts("\n=== NanOS v0.4 Boot ===\n");

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
    g_state.heap_size = heap_total_bytes();

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

        /* Initialize NERT Protocol Stack */
        vga_puts("[*] Initializing NERT protocol...\n");
        nert_hal_adapter_init(&g_nert_phy, (uint16_t)(g_state.node_id & 0xFFFF));
        nert_init();

        /* Master key must match micrOS Queen */
        static const uint8_t master_key[32] = {
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x8B, 0xAD, 0xF0, 0x0D, 0xFE, 0xED, 0xFA, 0xCE,
            0x13, 0x37, 0xC0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01,
            0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0
        };
        nert_set_master_key(master_key);
        nert_set_receive_callback(nert_message_handler);

        /* Initialize Task Handler */
        task_handler_init((uint16_t)(g_state.node_id & 0xFFFF));

        g_nert_enabled = 1;
        vga_puts("[*] NERT protocol ready\n");
        serial_puts("[NERT] Initialized with node_id=");
        serial_put_hex(g_state.node_id);
        serial_puts("\n");
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
    g_state.election.last_ended = 0;

    /* Clear gossip cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        g_state.gossip_cache[i].hash = 0;
    }

    /* Initialize bloom filter for O(1) deduplication */
    bloom_init();

    /* Initialize tactical intelligence system */
    tactical_init();

    /* Initialize maze exploration */
    maze_init();

    /* Initialize terrain exploration */
    terrain_init();

    /* v0.5: Initialize distributed black box (forensics) */
    blackbox_init();

    vga_puts("\n[*] Cell alive. Features:\n");
    vga_puts("    - Quorum sensing\n");
    vga_puts("    - Queen elections\n");
    vga_puts("    - Gradient routing\n");
    vga_puts("    - HMAC authentication\n");
    vga_puts("    - Bloom filter dedup\n");
    vga_puts("    - Tactical correlation\n");
    vga_puts("    - Maze exploration\n");
    vga_puts("    - Terrain exploration\n");
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
