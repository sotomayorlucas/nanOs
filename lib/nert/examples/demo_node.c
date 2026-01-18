/*
 * NERT Framework Demo - Secure Node Example
 * Demonstrates the v0.4 framework API with full NERT protocol
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "../nert_phy_if.h"
#include "../nert_config.h"
#include "../nert_security.h"
#include "../hal/hal_adapter.h"
#include "../../include/nert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define SWARM_PORT          5555
#define SWARM_MULTICAST     "239.255.0.1"

/* Demo master key (shared across swarm) */
static const uint8_t demo_master_key[32] = {
    0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x4D, 0x65,
    0x73, 0x68, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72,
    0x6B, 0x69, 0x6E, 0x67, 0x46, 0x72, 0x61, 0x6D,
    0x65, 0x77, 0x6F, 0x72, 0x6B, 0x76, 0x30, 0x34
};

/* Global state */
static volatile int running = 1;
static uint16_t my_node_id;

/* ============================================================================
 * Message Handlers (Pub/Sub Pattern)
 * ============================================================================ */

static void handle_echo(uint16_t sender_id, uint8_t msg_type,
                       const void *data, uint8_t len, void *user_ctx) {
    (void)msg_type;
    (void)user_ctx;

    printf("[Node %04X] Echo from %04X: ", my_node_id, sender_id);
    if (len > 0) {
        printf("%.*s\n", len, (const char *)data);
    } else {
        printf("<empty>\n");
    }
}

static void handle_alarm(uint16_t sender_id, uint8_t msg_type,
                        const void *data, uint8_t len, void *user_ctx) {
    (void)msg_type;
    (void)user_ctx;

    printf("[Node %04X] ALARM from %04X: ", my_node_id, sender_id);
    if (len >= 4) {
        uint32_t alarm_code;
        memcpy(&alarm_code, data, sizeof(alarm_code));
        printf("Code=0x%08X\n", alarm_code);
    } else {
        printf("Malformed\n");
    }
}

static void handle_data(uint16_t sender_id, uint8_t msg_type,
                       const void *data, uint8_t len, void *user_ctx) {
    (void)msg_type;
    (void)user_ctx;

    printf("[Node %04X] Data from %04X (%d bytes): ", my_node_id, sender_id, len);
    for (uint8_t i = 0; i < len && i < 16; i++) {
        printf("%02X ", ((const uint8_t *)data)[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}

/* ============================================================================
 * Connection & Security Callbacks
 * ============================================================================ */

static void on_connection_state(int conn_id, uint16_t peer_id,
                               uint8_t new_state, void *user_ctx) {
    (void)user_ctx;

    const char *state_name[] = {
        "CLOSED", "SYN_SENT", "ESTABLISHED", "FIN_SENT", "CLOSE_WAIT", "TIME_WAIT"
    };

    if (new_state < 6) {
        printf("[Node %04X] Connection %d with %04X: %s\n",
               my_node_id, conn_id, peer_id, state_name[new_state]);
    }
}

static void on_security_event(uint8_t event_type, uint16_t peer_id,
                              const char *details, void *user_ctx) {
    (void)user_ctx;

    const char *event_name[] = {
        "UNKNOWN", "BAD_MAC", "REPLAY_BLOCKED", "KEY_ROTATED", "INVALID_PAYLOAD"
    };

    if (event_type <= NERT_SEC_EVENT_INVALID_PAYLOAD) {
        printf("[Node %04X] Security Event: %s from %04X (%s)\n",
               my_node_id, event_name[event_type], peer_id,
               details ? details : "");
    }
}

/* ============================================================================
 * Signal Handler
 * ============================================================================ */

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\nShutting down gracefully...\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char **argv) {
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║   NERT Framework v0.4 - Secure Mesh Demo      ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    /* Parse command line */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <node_id_hex>\n", argv[0]);
        fprintf(stderr, "Example: %s 1234\n", argv[0]);
        return 1;
    }

    my_node_id = (uint16_t)strtoul(argv[1], NULL, 16);
    printf("[Node %04X] Initializing...\n", my_node_id);

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create virtual PHY (UDP multicast) */
    printf("[Node %04X] Creating virtual PHY on %s:%d\n",
           my_node_id, SWARM_MULTICAST, SWARM_PORT);

    struct nert_phy_interface *phy = nert_phy_virtual_create(SWARM_PORT, SWARM_MULTICAST);
    if (!phy) {
        fprintf(stderr, "Failed to create virtual PHY\n");
        return 1;
    }

    /* Initialize NERT configuration */
    struct nert_config config;
    nert_config_init(&config, my_node_id, demo_master_key, phy);

    /* Register message handlers */
    printf("[Node %04X] Registering message handlers...\n", my_node_id);
    nert_config_add_handler(&config, PHEROMONE_ECHO, handle_echo, NULL);
    nert_config_add_handler(&config, PHEROMONE_ALARM, handle_alarm, NULL);
    nert_config_add_handler(&config, PHEROMONE_DATA, handle_data, NULL);

    /* Register callbacks */
    config.connection_callback = on_connection_state;
    config.security_callback = on_security_event;

    /* Enable security features */
    config.security.enable_replay_protection = 1;
    config.security.enable_key_rotation = 1;

    /* Initialize HAL adapter - bridges PHY with NERT protocol */
    printf("[Node %04X] Initializing HAL adapter...\n", my_node_id);
    nert_hal_adapter_init(phy, my_node_id);

    /* Initialize NERT protocol stack */
    printf("[Node %04X] Initializing NERT stack...\n", my_node_id);
    nert_init();
    nert_set_master_key(demo_master_key);

    /* Register payload constraints for custom messages */
    nert_security_register_constraints(PHEROMONE_ALARM, 4, 32, 0);

    printf("[Node %04X] READY - Using NERT protocol over UDP multicast\n", my_node_id);
    printf("[Node %04X] All traffic encrypted with ChaCha8+Poly1305\n\n", my_node_id);

    /* Main loop */
    uint32_t last_announce = 0;
    uint32_t announce_interval = 5000;  /* 5 seconds */

    while (running) {
        /* Update HAL tick counter (for gossip/bloom filters) */
        nert_hal_update_ticks();

        /* Process incoming NERT packets */
        nert_process_incoming();

        /* Timer tick for retransmissions */
        nert_timer_tick();

        /* Check key rotation */
        nert_check_key_rotation();

        /* Periodic announce using NERT protocol */
        uint32_t now = nert_hal_get_ticks();
        if (now - last_announce > announce_interval) {
            printf("[Node %04X] Sending NERT announce (encrypted)...\n", my_node_id);

            uint8_t announce_data[8];
            memcpy(announce_data, &my_node_id, 2);
            memcpy(announce_data + 2, &now, 4);

            /* Send via NERT protocol (will be encrypted automatically) */
            nert_send_unreliable(0, PHEROMONE_ANNOUNCE, announce_data, 6);
            last_announce = now;
        }

        /* Small delay to prevent CPU spin */
        usleep(10000);  /* 10ms */
    }

    /* Cleanup */
    printf("[Node %04X] Wiping security keys...\n", my_node_id);
    nert_security_wipe_keys();

    printf("[Node %04X] Destroying PHY...\n", my_node_id);
    nert_phy_virtual_destroy(phy);

    /* Print statistics */
    const struct nert_stats *stats = nert_get_stats();
    printf("\n[Node %04X] Final Statistics:\n", my_node_id);
    printf("  TX: %u packets, %u bytes, %u retransmits\n",
           stats->tx_packets, stats->tx_bytes, stats->tx_retransmits);
    printf("  RX: %u packets, %u bytes, %u duplicates\n",
           stats->rx_packets, stats->rx_bytes, stats->rx_duplicates);
    printf("  Security: %u bad MACs, %u replays blocked\n",
           stats->rx_bad_mac, stats->rx_replay_blocked);

    printf("\n[Node %04X] Shutdown complete.\n", my_node_id);
    return 0;
}
