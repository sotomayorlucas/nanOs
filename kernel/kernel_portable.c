/*
 * NanOS - Portable Kernel v0.3
 * Architecture-independent with collective intelligence:
 * - Quorum sensing (neighbor tracking)
 * - Queen elections
 * - Gradient-based routing
 *
 * This is the main kernel for ARM64 and other non-x86 platforms
 */

#include "../include/hal.h"
#include "../include/nanos.h"

/* ==========================================================================
 * Global State
 * ========================================================================== */
struct nanos_state g_state;

/* ==========================================================================
 * Bump Allocator with Apoptosis Support
 * ========================================================================== */
#define HEAP_SIZE 65536
static uint8_t heap[HEAP_SIZE];
static size_t heap_ptr = 0;

void* bump_alloc(size_t size) {
    size = (size + 15) & ~15;
    if (heap_ptr + size > HEAP_SIZE) {
        return (void*)0;
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
 * HMAC-like Authentication (SipHash-inspired)
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
    hash = siphash_round(hash, v1, v2, v3);

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
 * Gossip Protocol
 * ========================================================================== */
uint32_t gossip_hash(struct nanos_pheromone* pkt) {
    uint32_t h = pkt->node_id;
    h = h * 31 + pkt->seq;
    h = h * 31 + pkt->type;
    h = h * 31 + (pkt->payload[0] | (pkt->payload[1] << 8));
    return h;
}

void gossip_record(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);

    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        if (g_state.gossip_cache[i].hash == hash) {
            g_state.gossip_cache[i].count++;
            return;
        }
    }

    struct gossip_entry* entry = &g_state.gossip_cache[g_state.gossip_index];
    entry->hash = hash;
    entry->timestamp = hal_timer_ticks();
    entry->count = 1;
    entry->relayed = 0;

    g_state.gossip_index = (g_state.gossip_index + 1) % GOSSIP_CACHE_SIZE;
}

bool gossip_should_relay(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);
    uint32_t ticks = hal_timer_ticks();

    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        struct gossip_entry* entry = &g_state.gossip_cache[i];

        if (entry->hash == hash) {
            if (ticks - entry->timestamp > (GOSSIP_IMMUNITY_MS / 10)) {
                entry->count = 1;
                entry->timestamp = ticks;
            }

            if (entry->relayed) {
                return false;
            }

            if (entry->count >= ALARM_MAX_ECHOES) {
                g_state.packets_dropped++;
                return false;
            }

            uint32_t prob = GOSSIP_PROB_BASE;
            for (uint8_t j = 1; j < entry->count && prob > 0; j++) {
                prob = (prob * (100 - GOSSIP_PROB_DECAY)) / 100;
            }

            if ((hal_rng_get() % 100) < prob) {
                entry->relayed = 1;
                return true;
            }

            return false;
        }
    }

    return true;
}

/* ==========================================================================
 * Cell Roles
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
    uint32_t r = hal_rng_get();

    if ((r & 0xFF) == 0) return ROLE_QUEEN;
    if ((r & 0x07) == 1) return ROLE_EXPLORER;
    if ((r & 0x07) == 2) return ROLE_SENTINEL;
    return ROLE_WORKER;
}

static uint32_t heartbeat_interval(void) {
    switch (g_state.role) {
        case ROLE_EXPLORER: return 50;
        case ROLE_SENTINEL: return 200;
        case ROLE_QUEEN:    return 300;
        default:            return 100;
    }
}

/* ==========================================================================
 * Apoptosis
 * ========================================================================== */
void cell_apoptosis(void) {
    hal_console_set_color(0x0C);
    hal_console_puts("\n!!! APOPTOSIS TRIGGERED !!!\n");
    hal_console_puts("    Reason: ");

    if (heap_usage_percent() >= HEAP_CRITICAL_PCT) {
        hal_console_puts("Memory exhaustion (");
        hal_console_put_dec(heap_usage_percent());
        hal_console_puts("%)\n");
    } else {
        hal_console_puts("Maximum lifetime\n");
    }

    /* Emit farewell */
    struct nanos_pheromone pkt;
    pkt.magic   = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type    = PHEROMONE_REBIRTH;
    pkt.ttl     = 2;
    pkt.flags   = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq     = g_state.seq_counter++;

    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.packets_rx; p += 4;
    *(uint32_t*)p = g_state.packets_tx; p += 4;
    *(uint32_t*)p = g_state.generation; p += 4;

    compute_hmac(&pkt);
    hal_net_send(&pkt, sizeof(pkt));

    hal_delay_ms(100);

    /* Rebirth */
    hal_console_puts("    Rebirthing...\n");

    uint32_t old_gen = g_state.generation;
    heap_reset();

    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        g_state.gossip_cache[i].hash = 0;
        g_state.gossip_cache[i].count = 0;
    }

    hal_rng_seed(hal_timer_ticks());
    g_state.node_id = hal_rng_get();
    g_state.role = determine_role();
    g_state.generation = old_gen + 1;
    g_state.boot_time = hal_timer_ticks();
    g_state.last_heartbeat = hal_timer_ticks();
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

    hal_console_set_color(0x0A);
    hal_console_puts("    New Node ID: ");
    hal_console_put_hex(g_state.node_id);
    hal_console_puts("\n    New Role: ");
    hal_console_puts(role_name(g_state.role));
    hal_console_puts("\n    Generation: ");
    hal_console_put_dec(g_state.generation);
    hal_console_puts("\n\n");
}

/* ==========================================================================
 * Pheromone Processing
 * ========================================================================== */
void process_pheromone(struct nanos_pheromone* pkt) {
    if (pkt->magic != NANOS_MAGIC) return;
    if (pkt->version != NANOS_VERSION && pkt->version != 0) return;
    if (pkt->node_id == g_state.node_id) return;

    if (is_authenticated_type(pkt->type)) {
        if (!(pkt->flags & FLAG_AUTHENTICATED)) {
            hal_console_set_color(0x0E);
            hal_console_puts("! Rejected unauthenticated msg\n");
            hal_console_set_color(0x0A);
            return;
        }

        if (!verify_hmac(pkt)) {
            hal_console_set_color(0x0C);
            hal_console_puts("!! INVALID HMAC - attack?\n");
            hal_console_set_color(0x0A);
            return;
        }
    }

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

    switch (pkt->type) {
        case PHEROMONE_HELLO:
            if (g_state.role == ROLE_SENTINEL) {
                hal_console_puts("< [");
                hal_console_puts(role_name(PKT_GET_ROLE(pkt)));
                hal_console_puts("] ");
                hal_console_put_hex(pkt->node_id);
                hal_console_puts(" d=");
                hal_console_put_dec(pkt->distance);
                hal_console_puts("\n");
            }
            break;

        case PHEROMONE_DATA:
            hal_console_puts("< DATA: ");
            pkt->payload[39] = '\0';
            hal_console_puts((char*)pkt->payload);
            hal_console_puts("\n");
            break;

        case PHEROMONE_ALARM:
            hal_console_set_color(0x0C);
            hal_console_puts("! ALARM from ");
            hal_console_put_hex(pkt->node_id);
            hal_console_puts("\n");
            hal_console_set_color(0x0A);

            if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
                pkt->ttl--;
                pkt->seq = g_state.seq_counter++;
                hal_net_send(pkt, sizeof(*pkt));
                g_state.alarms_relayed++;
            }
            break;

        case PHEROMONE_QUEEN_CMD:
            if (PKT_GET_ROLE(pkt) == ROLE_QUEEN) {
                hal_console_set_color(0x0D);
                hal_console_puts(">> QUEEN CMD\n");
                hal_console_set_color(0x0A);
            }
            break;

        case PHEROMONE_REBIRTH:
            hal_console_set_color(0x0E);
            hal_console_puts("~ Cell died: ");
            hal_console_put_hex(pkt->node_id);
            hal_console_puts("\n");
            hal_console_set_color(0x0A);
            break;

        case PHEROMONE_DIE:
            if (PKT_GET_ROLE(pkt) == ROLE_QUEEN) {
                hal_console_puts("X DIE from Queen\n");
                hal_cpu_halt();
            }
            break;

        case PHEROMONE_ELECTION:
            /* Queen election in progress */
            election_process(pkt);
            break;

        case PHEROMONE_CORONATION:
            /* New queen announced */
            if (verify_hmac(pkt)) {
                uint32_t ticks = hal_timer_ticks();
                g_state.known_queen_id = pkt->node_id;
                g_state.last_queen_seen = ticks;
                g_state.distance_to_queen = pkt->hop_count + 1;
                g_state.gradient_via = pkt->node_id;

                /* Cancel any ongoing election */
                g_state.election.participating = 0;
                if (g_state.role == ROLE_CANDIDATE) {
                    g_state.role = g_state.previous_role;
                }

                hal_console_set_color(0x0D);
                hal_console_puts(">> NEW QUEEN: ");
                hal_console_put_hex(pkt->node_id);
                hal_console_puts("\n");
                hal_console_set_color(0x0A);

                /* Relay coronation */
                if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
                    pkt->ttl--;
                    pkt->hop_count++;
                    hal_net_send(pkt, sizeof(*pkt));
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

    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.packets_rx; p += 4;
    *(uint32_t*)p = g_state.packets_tx; p += 4;
    *(uint32_t*)p = hal_timer_ticks();  p += 4;
    *(uint32_t*)p = g_state.generation; p += 4;
    *p++ = heap_usage_percent();
    *p++ = g_state.role;
    *p++ = hal_net_tx_queue_depth();
    *p++ = g_state.neighbor_count;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;

    /* Propagate gradient before sending */
    gradient_propagate();

    if (hal_net_send(&pkt, sizeof(pkt)) == 0) {
        g_state.packets_tx++;
    }

    g_state.last_heartbeat = hal_timer_ticks();
}

/* ==========================================================================
 * Main Reactive Loop
 * ========================================================================== */
void nanos_loop(void) {
    static uint8_t rx_buffer[2048];
    static uint32_t last_maintenance = 0;

    for (;;) {
        uint32_t ticks = hal_timer_ticks();

        /* Apoptosis check */
        if (heap_usage_percent() >= HEAP_CRITICAL_PCT ||
            ticks - g_state.boot_time > MAX_CELL_LIFETIME) {
            cell_apoptosis();
        }

        /* Drain TX queue */
        hal_net_tx_drain();

        /* Process packets */
        while (hal_net_has_packet()) {
            int len = hal_net_receive(rx_buffer, sizeof(rx_buffer));
            /* VirtIO doesn't have Ethernet header in our setup */
            if (len >= (int)sizeof(struct nanos_pheromone)) {
                struct nanos_pheromone* pkt = (struct nanos_pheromone*)rx_buffer;
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

        /* Heartbeat */
        if (ticks - g_state.last_heartbeat >= heartbeat_interval()) {
            emit_heartbeat();
        }

        /* Low power idle */
        hal_power_idle();
    }
}

/* ==========================================================================
 * Kernel Entry Point (Portable)
 * ========================================================================== */
void kernel_main(void) {
    /* Initialize platform */
    hal_platform_init();
    hal_console_clear();

    /* Banner */
    hal_console_set_color(0x0B);
    hal_console_puts("========================================\n");
    hal_console_puts("  NanOS v0.3 - ");
    hal_console_puts(ARCH_NAME);
    hal_console_puts(" Port\n");
    hal_console_puts("========================================\n\n");
    hal_console_set_color(0x0A);

    hal_console_puts("[*] Platform: ");
    hal_console_puts(hal_platform_info());
    hal_console_puts("\n");

    /* Initialize timer */
    hal_console_puts("[*] Starting timer (100 Hz)...\n");
    hal_timer_init(100);
    hal_irq_enable();

    /* Wait for entropy */
    while (hal_timer_ticks() < 10) hal_power_idle();
    hal_rng_init();

    /* Generate identity */
    g_state.node_id = hal_rng_get();
    g_state.role = determine_role();
    g_state.generation = 0;
    g_state.heap_size = HEAP_SIZE;

    hal_console_puts("[*] Node ID: ");
    hal_console_put_hex(g_state.node_id);
    hal_console_puts("\n[*] Role: ");
    hal_console_set_color(g_state.role == ROLE_QUEEN ? 0x0D : 0x0A);
    hal_console_puts(role_name(g_state.role));
    hal_console_set_color(0x0A);
    hal_console_puts("\n");

    /* Initialize network */
    hal_console_puts("[*] Initializing network...\n");
    if (hal_net_init() != 0) {
        hal_console_puts("ERROR: Network init failed!\n");
    } else {
        uint8_t mac[6];
        hal_net_get_mac(mac);
        hal_console_puts("[*] MAC: ");
        for (int i = 0; i < 6; i++) {
            const char* hex = "0123456789ABCDEF";
            hal_console_putc(hex[mac[i] >> 4]);
            hal_console_putc(hex[mac[i] & 0xF]);
            if (i < 5) hal_console_putc(':');
        }
        hal_console_puts("\n");

        hal_console_puts("[*] Driver: ");
        switch (hal_net_get_driver()) {
            case NET_DRIVER_E1000:  hal_console_puts("Intel e1000"); break;
            case NET_DRIVER_VIRTIO: hal_console_puts("VirtIO-net"); break;
            default:                hal_console_puts("Unknown"); break;
        }
        hal_console_puts("\n");
    }

    /* Initialize state */
    g_state.boot_time = hal_timer_ticks();
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

    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        g_state.gossip_cache[i].hash = 0;
    }

    hal_console_puts("\n[*] Cell alive. Features:\n");
    hal_console_puts("    - Quorum sensing\n");
    hal_console_puts("    - Queen elections\n");
    hal_console_puts("    - Gradient routing\n");
    hal_console_puts("    - HMAC authentication\n");
    hal_console_puts("    - Low-power idle (WFI)\n\n");

    hal_console_puts("Listening for pheromones...\n\n");

    nanos_loop();
}
