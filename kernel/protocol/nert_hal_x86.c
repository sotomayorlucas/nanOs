/*
 * NERT HAL Implementation for x86 (QEMU e1000)
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include "e1000.h"
#include "nanos.h"
#include <string.h>

/* External state from kernel */
extern volatile uint32_t ticks;
extern struct nanos_state g_state;  /* For neighbor table */

/* Local state */
static uint16_t local_node_id = 0;
static uint32_t rng_state = 0x12345678;

/* Neighbor table for NERT multipath routing (references kernel's neighbor table) */
uint8_t neighbor_count = 0;  /* Updated in nert_hal_update_ticks */
struct neighbor_entry neighbors[NEIGHBOR_TABLE_SIZE];

/* ============================================================================
 * Ethernet Frame Structure
 * ============================================================================ */

#define ETH_ALEN            6
#define ETH_TYPE_NERT       0x4F4E  /* Must match micrOS NERT_ETH_TYPE */

struct eth_frame {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
    uint8_t  payload[];
} __attribute__((packed));

/* Multicast address for NERT broadcast */
static const uint8_t NERT_MULTICAST_MAC[ETH_ALEN] = {
    0x01, 0x00, 0x5E, 0x4E, 0x45, 0x52  /* NERT multicast group */
};

/* ============================================================================
 * Simple PRNG (xorshift32)
 * ============================================================================ */

static uint32_t xorshift32(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

/* ============================================================================
 * HAL Implementation
 * ============================================================================ */

int nert_hal_send(const void *data, uint16_t len) {
    uint8_t frame[ETH_ALEN * 2 + 2 + 300]; /* Max NERT packet */
    struct eth_frame *eth = (struct eth_frame*)frame;

    if (len > 280) return -1; /* Too large */

    /* Build Ethernet frame */
    memcpy(eth->dst, NERT_MULTICAST_MAC, ETH_ALEN);
    e1000_get_mac(eth->src);
    eth->ethertype = __builtin_bswap16(ETH_TYPE_NERT);

    /* Copy NERT packet as payload */
    memcpy(eth->payload, data, len);

    /* Send via e1000 driver */
    return e1000_send(frame, ETH_ALEN * 2 + 2 + len);
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
    uint8_t frame[ETH_ALEN * 2 + 2 + 300];
    int frame_len;

    frame_len = e1000_receive(frame, sizeof(frame));
    if (frame_len <= 0) return 0;

    struct eth_frame *eth = (struct eth_frame*)frame;

    /* Check for NERT protocol */
    if (__builtin_bswap16(eth->ethertype) != ETH_TYPE_NERT) {
        return 0; /* Not a NERT packet */
    }

    /* Skip packets from ourselves */
    uint8_t our_mac[6];
    e1000_get_mac(our_mac);
    if (memcmp(eth->src, our_mac, ETH_ALEN) == 0) {
        return 0;
    }

    /* Extract NERT payload */
    int payload_len = frame_len - (ETH_ALEN * 2 + 2);
    if (payload_len > max_len) payload_len = max_len;
    if (payload_len <= 0) return 0;

    memcpy(buffer, eth->payload, payload_len);
    return payload_len;
}

uint32_t nert_hal_get_ticks(void) {
    return ticks;
}

uint32_t nert_hal_random(void) {
    /* Mix in hardware entropy if available */
    rng_state ^= ticks;
    rng_state ^= (uint32_t)(uintptr_t)&rng_state; /* ASLR entropy */
    return xorshift32();
}

uint16_t nert_hal_get_node_id(void) {
    if (local_node_id == 0) {
        /* Generate from MAC address */
        uint8_t mac[6];
        e1000_get_mac(mac);

        local_node_id = (mac[4] << 8) | mac[5];

        /* Ensure non-zero */
        if (local_node_id == 0) {
            local_node_id = (uint16_t)nert_hal_random();
        }
    }
    return local_node_id;
}

/* ============================================================================
 * Initialization Helper
 * ============================================================================ */

void nert_hal_init(void) {
    /* Seed PRNG with entropy */
    rng_state = ticks ^ 0xDEADBEEF;
    xorshift32(); /* Warm up */
    xorshift32();
    xorshift32();

    /* Pre-compute node ID */
    nert_hal_get_node_id();
}

/* ============================================================================
 * HAL Adapter Interface (for compatibility with hal_adapter.h)
 * ============================================================================ */

/* PHY interface pointer (not used in x86 direct HAL, but needed for API) */
static void *g_phy_interface = NULL;

void nert_hal_adapter_init(void *phy, uint16_t node_id) {
    g_phy_interface = phy;
    local_node_id = node_id;
    nert_hal_init();
}

void nert_hal_update_ticks(void) {
    /* Sync neighbor table from kernel state for NERT multipath routing */
    neighbor_count = g_state.neighbor_count;
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE && i < 16; i++) {
        neighbors[i] = g_state.neighbors[i];
    }
}
