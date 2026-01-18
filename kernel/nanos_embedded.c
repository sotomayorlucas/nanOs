/*
 * NanOS Embedded Core
 * Portable implementation for microcontrollers (ESP32, RP2040, STM32, etc.)
 *
 * This file provides the main loop and state management for embedded platforms.
 * Compile with appropriate NANOS_PLATFORM_* define.
 */

#include "nanos_config.h"

/* Only compile for embedded platforms */
#if !defined(NANOS_PLATFORM_X86)

#include "hal_portable.h"
#include <string.h>

/* Include compact packet support if enabled */
#ifdef NANOS_COMPACT_PACKETS
#include "nanos/packet_compact.h"
#endif

/* ==========================================================================
 * Type Definitions (embedded-optimized)
 * ========================================================================== */

/* Pheromone types - same as x86 */
#define PHEROMONE_HEARTBEAT     0x01
#define PHEROMONE_DATA          0x02
#define PHEROMONE_ALARM         0x03
#define PHEROMONE_QUEEN_CMD     0x04
#define PHEROMONE_ELECTION      0x05
#define PHEROMONE_REBIRTH       0x06
#define PHEROMONE_HELLO         0x07
#define PHEROMONE_KV_SET        0x10
#define PHEROMONE_KV_GET        0x11
#define PHEROMONE_TASK_ASSIGN   0x12
#define PHEROMONE_TASK_RESULT   0x13
#define PHEROMONE_DETECT        0x20
#define PHEROMONE_SENSOR        0x30

/* Roles */
#define ROLE_WORKER             0
#define ROLE_EXPLORER           1
#define ROLE_SENTINEL           2
#define ROLE_QUEEN              3

/* Magic and version */
#define NANOS_MAGIC             0xDEAD
#define NANOS_VERSION           1

/* Gradient routing */
#define GRADIENT_MAX_HOPS       15
#define GRADIENT_INFINITY       0xFF

/* ==========================================================================
 * Packet Structure
 * ========================================================================== */

#ifdef NANOS_COMPACT_PACKETS
typedef struct nanos_pheromone_compact nanos_packet_t;
#define PKT_MAGIC               COMPACT_MAGIC
#define PKT_SIZE                COMPACT_PKT_SIZE
#define PKT_PAYLOAD_SIZE        COMPACT_PAYLOAD_SIZE
#else
/* Standard packet format */
struct nanos_pheromone_std {
    uint16_t magic;
    uint32_t node_id;
    uint8_t  type;
    uint8_t  ttl;
    uint8_t  flags;
    uint8_t  version;
    uint32_t seq;
    uint32_t dest_id;
    uint8_t  distance;
    uint8_t  hop_count;
    uint8_t  payload[NANOS_PKT_PAYLOAD_SIZE];
    uint8_t  hmac[NANOS_HMAC_SIZE];
} __attribute__((packed));
typedef struct nanos_pheromone_std nanos_packet_t;
#define PKT_MAGIC               NANOS_MAGIC
#define PKT_SIZE                sizeof(nanos_packet_t)
#define PKT_PAYLOAD_SIZE        NANOS_PKT_PAYLOAD_SIZE
#endif

/* ==========================================================================
 * State Structures (size-optimized)
 * ========================================================================== */

/* Neighbor entry */
struct neighbor_entry {
    uint16_t node_id;           /* 16-bit on embedded */
    uint8_t  role;
    uint8_t  distance;
    uint32_t last_seen;
    uint16_t packets;
};

/* KV store entry */
#if NANOS_FEATURE_KV
struct kv_entry {
    uint8_t key[KV_KEY_SIZE];
    uint8_t value[KV_VALUE_SIZE];
    uint8_t valid;
};
#endif

/* Gossip cache entry */
struct gossip_entry {
    uint32_t hash;
    uint8_t  count;
};

/* Global state */
struct nanos_embedded_state {
    /* Identity */
    uint32_t node_id;
    uint8_t  role;
    uint8_t  generation;

    /* Network */
    uint32_t packets_rx;
    uint32_t packets_tx;
    uint16_t packets_dropped;
    uint16_t seq_counter;

    /* Timing */
    uint32_t boot_time;
    uint32_t last_heartbeat;
    uint32_t last_hello;

    /* Queen tracking */
    uint16_t known_queen_id;
    uint32_t last_queen_seen;
    uint8_t  distance_to_queen;

    /* Neighbors */
    struct neighbor_entry neighbors[NEIGHBOR_TABLE_SIZE];
    uint8_t  neighbor_count;

    /* Gossip dedup */
    struct gossip_entry gossip_cache[GOSSIP_CACHE_SIZE];
    uint8_t  gossip_idx;

#if NANOS_FEATURE_KV
    /* KV store */
    struct kv_entry kv_store[KV_STORE_SIZE];
#endif

    /* Sensors */
#if NANOS_MAX_SENSORS > 0
    struct {
        uint8_t  type;
        int32_t  value;
        uint32_t last_read;
    } sensors[NANOS_MAX_SENSORS];
#endif

#ifdef NANOS_DEEP_SLEEP
    /* Power management */
    uint32_t last_activity;
    uint8_t  sleep_mode;
#endif
};

/* Global state instance */
static struct nanos_embedded_state g_state;

/* ==========================================================================
 * Role Names
 * ========================================================================== */

static const char* role_name(uint8_t role) {
    switch (role) {
        case ROLE_WORKER:   return "WORKER";
        case ROLE_EXPLORER: return "EXPLORER";
        case ROLE_SENTINEL: return "SENTINEL";
        case ROLE_QUEEN:    return "QUEEN";
        default:            return "?";
    }
}

/* ==========================================================================
 * Gossip Deduplication
 * ========================================================================== */

static uint32_t packet_hash(const nanos_packet_t* pkt) {
    /* Simple FNV-1a hash */
    uint32_t hash = 0x811c9dc5;
    const uint8_t* data = (const uint8_t*)pkt;
    for (uint16_t i = 0; i < PKT_SIZE; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

static int gossip_is_duplicate(const nanos_packet_t* pkt) {
    uint32_t hash = packet_hash(pkt);

    for (uint8_t i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        if (g_state.gossip_cache[i].hash == hash) {
            g_state.gossip_cache[i].count++;
            return 1;  /* Duplicate */
        }
    }

    /* Not found - add to cache */
    g_state.gossip_cache[g_state.gossip_idx].hash = hash;
    g_state.gossip_cache[g_state.gossip_idx].count = 1;
    g_state.gossip_idx = (g_state.gossip_idx + 1) % GOSSIP_CACHE_SIZE;

    return 0;  /* Not duplicate */
}

/* ==========================================================================
 * Neighbor Management
 * ========================================================================== */

static void update_neighbor(uint16_t node_id, uint8_t role, uint8_t distance) {
    uint32_t now = hal_get_ticks();

    /* Find existing or empty slot */
    int idx = -1;
    int oldest_idx = 0;
    uint32_t oldest_time = now;

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id == node_id) {
            idx = i;
            break;
        }
        if (g_state.neighbors[i].node_id == 0) {
            idx = i;
            break;
        }
        if (g_state.neighbors[i].last_seen < oldest_time) {
            oldest_time = g_state.neighbors[i].last_seen;
            oldest_idx = i;
        }
    }

    if (idx < 0) {
        idx = oldest_idx;  /* Evict oldest */
    }

    g_state.neighbors[idx].node_id = node_id;
    g_state.neighbors[idx].role = role;
    g_state.neighbors[idx].distance = distance;
    g_state.neighbors[idx].last_seen = now;
    g_state.neighbors[idx].packets++;

    /* Recount neighbors */
    g_state.neighbor_count = 0;
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id != 0 &&
            (now - g_state.neighbors[i].last_seen) < NEIGHBOR_TIMEOUT_MS) {
            g_state.neighbor_count++;
        }
    }
}

/* ==========================================================================
 * Heartbeat
 * ========================================================================== */

static void send_heartbeat(void) {
    nanos_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

#ifdef NANOS_COMPACT_PACKETS
    pkt.magic = COMPACT_MAGIC;
    pkt.node_id = (uint16_t)(g_state.node_id & 0xFFFF);
    pkt.type = PHEROMONE_HEARTBEAT;
    pkt.ttl_flags = COMPACT_SET_TTL_FLAGS(GRADIENT_MAX_HOPS, 0);
    pkt.seq = (uint8_t)(g_state.seq_counter++ & 0xFF);
    pkt.dist_hop = COMPACT_SET_DIST_HOP(g_state.distance_to_queen, 0);

    /* Compact heartbeat payload */
    struct compact_heartbeat* hb = (struct compact_heartbeat*)pkt.payload;
    hb->role = g_state.role;
    hb->neighbors = g_state.neighbor_count;
#ifdef NANOS_DEEP_SLEEP
    hb->battery = hal_battery_level();
#else
    hb->battery = 100;
#endif
    hb->uptime_min = (uint16_t)((hal_get_ticks() - g_state.boot_time) / 60000);
#else
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_HEARTBEAT;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;

    /* Standard heartbeat payload */
    pkt.payload[0] = g_state.role;
    pkt.payload[1] = g_state.neighbor_count;
    pkt.payload[2] = (uint8_t)((g_state.packets_rx >> 8) & 0xFF);
    pkt.payload[3] = (uint8_t)(g_state.packets_rx & 0xFF);
#endif

    hal_net_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;
    g_state.last_heartbeat = hal_get_ticks();
}

/* ==========================================================================
 * Packet Processing
 * ========================================================================== */

static void process_heartbeat(nanos_packet_t* pkt) {
#ifdef NANOS_COMPACT_PACKETS
    uint16_t node_id = pkt->node_id;
    struct compact_heartbeat* hb = (struct compact_heartbeat*)pkt->payload;
    uint8_t role = hb->role;
    uint8_t distance = COMPACT_GET_DISTANCE(pkt);
#else
    uint16_t node_id = (uint16_t)(pkt->node_id & 0xFFFF);
    uint8_t role = pkt->payload[0];
    uint8_t distance = pkt->distance;
#endif

    update_neighbor(node_id, role, distance);

    /* Track queen */
    if (role == ROLE_QUEEN) {
        if (distance < g_state.distance_to_queen || g_state.known_queen_id == 0) {
            g_state.known_queen_id = node_id;
            g_state.distance_to_queen = distance + 1;
            g_state.last_queen_seen = hal_get_ticks();
        }
    }
}

static void process_packet(nanos_packet_t* pkt) {
    /* Duplicate check */
    if (gossip_is_duplicate(pkt)) {
        g_state.packets_dropped++;
        return;
    }

    g_state.packets_rx++;

#ifdef NANOS_DEEP_SLEEP
    g_state.last_activity = hal_get_ticks();
#endif

#ifdef NANOS_COMPACT_PACKETS
    uint8_t type = pkt->type;
#else
    uint8_t type = pkt->type;
#endif

    switch (type) {
        case PHEROMONE_HEARTBEAT:
            process_heartbeat(pkt);
            break;

        case PHEROMONE_ALARM:
            /* Flash LED on alarm */
#ifdef NANOS_HAS_LED
            hal_led_blink(LED_ERROR, 100, 100);
#endif
            hal_set_color(0x0C);
            hal_print("[ALARM] Received!\n");
            hal_set_color(0x0A);
            break;

        case PHEROMONE_DETECT:
#if NANOS_FEATURE_TACTICAL
            /* Process tactical detection */
            hal_print("[DETECT] Event\n");
#endif
            break;

        default:
            break;
    }
}

/* ==========================================================================
 * Main Tick Function
 * ========================================================================== */

void nanos_tick(void) {
    uint32_t now = hal_get_ticks();

    /* Receive packets */
    nanos_packet_t rx_pkt;
    while (hal_net_available()) {
        uint16_t len = hal_net_recv(&rx_pkt, sizeof(rx_pkt));
        if (len >= sizeof(rx_pkt)) {
#ifdef NANOS_COMPACT_PACKETS
            if (rx_pkt.magic == COMPACT_MAGIC) {
                process_packet(&rx_pkt);
            }
#else
            if (rx_pkt.magic == NANOS_MAGIC) {
                process_packet(&rx_pkt);
            }
#endif
        }
    }

    /* Periodic heartbeat */
    if ((now - g_state.last_heartbeat) >= HEARTBEAT_INTERVAL_MS) {
        send_heartbeat();

#ifdef NANOS_HAS_LED
        hal_led_toggle(LED_NETWORK);
#endif
    }

    /* Queen timeout - become candidate */
    if (g_state.role != ROLE_QUEEN &&
        g_state.known_queen_id != 0 &&
        (now - g_state.last_queen_seen) > QUEEN_TIMEOUT_MS) {

        hal_print("[ELECTION] Queen timeout, becoming candidate\n");
        g_state.known_queen_id = 0;
        g_state.distance_to_queen = GRADIENT_INFINITY;

        /* Simple election: highest node_id wins */
        g_state.role = ROLE_QUEEN;
        hal_set_color(0x0D);
        hal_print(">> Promoted to QUEEN\n");
        hal_set_color(0x0A);
    }

    /* Feed watchdog */
#ifdef NANOS_HAS_WATCHDOG
    hal_watchdog_feed();
#endif
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

static uint8_t determine_role(void) {
    /* Role based on chip ID bits */
    uint32_t id = hal_get_chip_id();
    uint8_t role_bits = (id >> 4) & 0x03;

    switch (role_bits) {
        case 0:  return ROLE_WORKER;
        case 1:  return ROLE_EXPLORER;
        case 2:  return ROLE_SENTINEL;
        case 3:  return ROLE_QUEEN;
        default: return ROLE_WORKER;
    }
}

void nanos_init(void) {
    /* Clear state */
    memset(&g_state, 0, sizeof(g_state));

    /* Initialize HAL */
    hal_init();

    /* Generate node ID from chip ID */
    g_state.node_id = hal_get_chip_id();
    g_state.role = determine_role();
    g_state.generation = 1;
    g_state.boot_time = hal_get_ticks();
    g_state.distance_to_queen = (g_state.role == ROLE_QUEEN) ? 0 : GRADIENT_INFINITY;

    /* Initialize network */
    hal_net_init();

    /* Print banner */
    hal_set_color(0x0B);
    hal_print("\n========================================\n");
    hal_print("  NanOS Embedded - The Swarm Awakens\n");
    hal_print("========================================\n");
    hal_set_color(0x0A);

    hal_print("Node ID: ");
    hal_print_hex(g_state.node_id);
    hal_print("\nRole: ");
    hal_print(role_name(g_state.role));
    hal_print("\nFree heap: ");
    hal_print_dec(hal_get_free_heap());
    hal_print(" bytes\n\n");

#ifdef NANOS_HAS_LED
    hal_led_init();
    hal_led_set(LED_STATUS, true);
#endif

#ifdef NANOS_HAS_WATCHDOG
    hal_watchdog_init(5000);  /* 5 second watchdog */
#endif
}

/* ==========================================================================
 * Main Loop (for standalone builds)
 * ========================================================================== */

#ifndef NANOS_NO_MAIN

void app_main(void) {    /* ESP-IDF entry point */
    nanos_init();

    while (1) {
        nanos_tick();
        hal_delay_ms(NANOS_TICK_MS);
    }
}

/* Alternative main for other platforms */
int main(void) {
    nanos_init();

    while (1) {
        nanos_tick();
        hal_delay_ms(NANOS_TICK_MS);
    }

    return 0;
}

#endif /* NANOS_NO_MAIN */

#endif /* !NANOS_PLATFORM_X86 */
