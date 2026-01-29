/*
 * NERT HAL Adapter for Framework
 * Bridges nert_phy_interface with nert_hal_* functions
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "../nert_phy_if.h"
#include "../../include/nert.h"
#include <string.h>

/* ============================================================================
 * Global State
 * ============================================================================ */

static struct nert_phy_interface *g_phy = NULL;
static uint16_t g_node_id = 0;

/* ============================================================================
 * HAL Adapter API
 * ============================================================================ */

/**
 * Initialize HAL adapter with PHY interface and node ID
 * Must be called before using NERT functions
 */
void nert_hal_adapter_init(struct nert_phy_interface *phy, uint16_t node_id) {
    g_phy = phy;
    g_node_id = node_id;
}

/**
 * Get current PHY interface
 */
struct nert_phy_interface* nert_hal_adapter_get_phy(void) {
    return g_phy;
}

/* ============================================================================
 * NERT HAL Implementation (required by nert.c)
 * ============================================================================ */

/**
 * Send packet over network
 * Called by NERT protocol to transmit packets
 */
int nert_hal_send(const void *data, uint16_t len) {
    if (!g_phy || !g_phy->send) {
        return -1;
    }

    return g_phy->send(data, len, g_phy->context);
}

/**
 * Receive packet from network (non-blocking)
 * Called by NERT protocol to check for incoming packets
 */
int nert_hal_receive(void *buffer, uint16_t max_len) {
    if (!g_phy || !g_phy->receive) {
        return -1;
    }

    return g_phy->receive(buffer, max_len, g_phy->context);
}

/**
 * Get monotonic tick count in milliseconds
 * Used for timeouts, retransmissions, and key rotation
 */
uint32_t nert_hal_get_ticks(void) {
    if (!g_phy || !g_phy->get_ticks) {
        return 0;
    }

    return g_phy->get_ticks(g_phy->context);
}

/**
 * Get random number for nonces and initialization
 * Used for sequence numbers, nonce generation, etc.
 */
uint32_t nert_hal_random(void) {
    if (!g_phy || !g_phy->random) {
        return 0;
    }

    return g_phy->random(g_phy->context);
}

/**
 * Get this node's identifier
 * Used in packet headers and crypto nonces
 */
uint16_t nert_hal_get_node_id(void) {
    return g_node_id;
}

/* ============================================================================
 * Additional HAL stubs (for NERT multipath routing)
 * ============================================================================ */

/* Neighbor entry for multipath routing (internal NERT struct) */
struct nert_neighbor_entry {
    uint32_t node_id;
    uint8_t  distance;
    uint16_t packets;
    uint8_t  synaptic_weight;
};

/* Neighbor table for NERT routing (micrOS doesn't have one, so we provide stub) */
uint8_t neighbor_count = 0;
struct nert_neighbor_entry neighbors[16];

/* RNG state for this module */
static uint32_t adapter_g_state[4] = {0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210};

/**
 * Update global tick counter
 * Should be called periodically (e.g., every timer tick)
 */
void nert_hal_update_ticks(void) {
    /* Note: In kernel mode, ticks is already updated by the timer interrupt */
    /* This function is called to keep adapter_g_state entropy pool mixed */
    uint32_t t = nert_hal_get_ticks();

    /* Update RNG state */
    adapter_g_state[0] ^= t;
    adapter_g_state[1] = (adapter_g_state[1] << 7) ^ adapter_g_state[0];
    adapter_g_state[2] = (adapter_g_state[2] >> 3) ^ adapter_g_state[1];
    adapter_g_state[3] += adapter_g_state[2];
}
