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
    outb(0x21, 0xFE); outb(0xA1, 0xFF);
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
            pkt->payload[39] = '\0';
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
            pkt->payload[39] = '\0';
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

    for (;;) {
        /* Check for apoptosis conditions */
        if (heap_usage_percent() >= HEAP_CRITICAL_PCT ||
            ticks - g_state.boot_time > MAX_CELL_LIFETIME) {
            cell_apoptosis();
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

    vga_puts("Listening for pheromones...\n\n");

    nanos_loop();
}
