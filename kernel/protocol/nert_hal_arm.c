/*
 * NERT HAL Implementation for ARM Cortex-M3 (QEMU Stellaris)
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>

#if defined(__arm__) && !defined(ESP_PLATFORM)

/* ============================================================================
 * Stellaris LM3S6965 Hardware Registers
 * ============================================================================ */

/* System tick timer */
#define SYSTICK_BASE        0xE000E010
#define SYSTICK_CTRL        (*(volatile uint32_t*)(SYSTICK_BASE + 0x00))
#define SYSTICK_LOAD        (*(volatile uint32_t*)(SYSTICK_BASE + 0x04))
#define SYSTICK_VAL         (*(volatile uint32_t*)(SYSTICK_BASE + 0x08))

/* Ethernet MAC registers */
#define ETH_BASE            0x40048000
#define MAC_RIS             (*(volatile uint32_t*)(ETH_BASE + 0x00))
#define MAC_IACK            (*(volatile uint32_t*)(ETH_BASE + 0x00))
#define MAC_IM              (*(volatile uint32_t*)(ETH_BASE + 0x04))
#define MAC_RCTL            (*(volatile uint32_t*)(ETH_BASE + 0x08))
#define MAC_TCTL            (*(volatile uint32_t*)(ETH_BASE + 0x0C))
#define MAC_DATA            (*(volatile uint32_t*)(ETH_BASE + 0x10))
#define MAC_IA0             (*(volatile uint32_t*)(ETH_BASE + 0x14))
#define MAC_IA1             (*(volatile uint32_t*)(ETH_BASE + 0x18))
#define MAC_NP              (*(volatile uint32_t*)(ETH_BASE + 0x34))

/* RCTL bits */
#define RCTL_RXEN           0x01
#define RCTL_AMUL           0x02
#define RCTL_PRMS           0x04
#define RCTL_RSTFIFO        0x10

/* TCTL bits */
#define TCTL_TXEN           0x01
#define TCTL_PADEN          0x02
#define TCTL_CRC            0x04

/* RIS bits */
#define RIS_RXINT           0x01
#define RIS_TXER            0x02
#define RIS_TXEMP           0x04
#define RIS_FOV             0x08
#define RIS_RXER            0x10

/* ============================================================================
 * Local State
 * ============================================================================ */

static volatile uint32_t systick_counter = 0;
static uint16_t local_node_id = 0;
static uint32_t rng_state = 0xCAFEBABE;
static uint8_t local_mac[6] = {0x52, 0x54, 0x00, 0x00, 0x00, 0x00};

/* ============================================================================
 * Interrupt Handlers
 * ============================================================================ */

void SysTick_Handler(void) {
    systick_counter++;
}

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
 * Ethernet Functions
 * ============================================================================ */

static void eth_init(void) {
    /* Reset RX FIFO */
    MAC_RCTL = RCTL_RSTFIFO;

    /* Read MAC address from hardware */
    uint32_t ia0 = MAC_IA0;
    uint32_t ia1 = MAC_IA1;

    local_mac[0] = (ia0 >> 0) & 0xFF;
    local_mac[1] = (ia0 >> 8) & 0xFF;
    local_mac[2] = (ia0 >> 16) & 0xFF;
    local_mac[3] = (ia0 >> 24) & 0xFF;
    local_mac[4] = (ia1 >> 0) & 0xFF;
    local_mac[5] = (ia1 >> 8) & 0xFF;

    /* Enable RX with multicast */
    MAC_RCTL = RCTL_RXEN | RCTL_AMUL;

    /* Enable TX with padding and CRC */
    MAC_TCTL = TCTL_TXEN | TCTL_PADEN | TCTL_CRC;
}

static int eth_send(const void *data, uint16_t len) {
    const uint8_t *ptr = (const uint8_t*)data;
    uint32_t word;

    /* Wait for TX ready */
    int timeout = 10000;
    while (!(MAC_RIS & RIS_TXEMP) && --timeout > 0);
    if (timeout == 0) return -1;

    /* First word: length in bytes 0-1 */
    word = len | (ptr[0] << 16) | (ptr[1] << 24);
    MAC_DATA = word;

    /* Remaining data */
    for (int i = 2; i < len; i += 4) {
        word = 0;
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            word |= ptr[i + j] << (j * 8);
        }
        MAC_DATA = word;
    }

    return 0;
}

static int eth_receive(void *buffer, uint16_t max_len) {
    uint8_t *ptr = (uint8_t*)buffer;

    /* Check for pending frame */
    if (MAC_NP == 0) return 0;

    /* Read first word (contains length) */
    uint32_t word = MAC_DATA;
    uint16_t len = word & 0xFFFF;

    if (len > max_len) {
        /* Discard oversized frame */
        int words = (len + 3) / 4;
        for (int i = 0; i < words; i++) {
            (void)MAC_DATA;
        }
        return 0;
    }

    /* First two data bytes in high bytes of first word */
    ptr[0] = (word >> 16) & 0xFF;
    ptr[1] = (word >> 24) & 0xFF;

    /* Read remaining words */
    for (int i = 2; i < len; i += 4) {
        word = MAC_DATA;
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            ptr[i + j] = (word >> (j * 8)) & 0xFF;
        }
    }

    return len;
}

/* ============================================================================
 * HAL Implementation
 * ============================================================================ */

/* Compact Ethernet header for ARM */
#define ETH_ALEN        6
#define ETH_TYPE_NERT   0x4E52

struct eth_header_compact {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
} __attribute__((packed));

static const uint8_t NERT_BROADCAST_MAC[ETH_ALEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

int nert_hal_send(const void *data, uint16_t len) {
    uint8_t frame[14 + 100]; /* Compact frame buffer */
    struct eth_header_compact *eth = (struct eth_header_compact*)frame;

    if (len > 80) return -1; /* Compact mode limit */

    /* Build frame */
    memcpy(eth->dst, NERT_BROADCAST_MAC, ETH_ALEN);
    memcpy(eth->src, local_mac, ETH_ALEN);
    eth->ethertype = __builtin_bswap16(ETH_TYPE_NERT);

    /* Copy payload */
    memcpy(frame + 14, data, len);

    return eth_send(frame, 14 + len);
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
    uint8_t frame[14 + 100];
    struct eth_header_compact *eth = (struct eth_header_compact*)frame;

    int frame_len = eth_receive(frame, sizeof(frame));
    if (frame_len < 14) return 0;

    /* Check ethertype */
    if (__builtin_bswap16(eth->ethertype) != ETH_TYPE_NERT) {
        return 0;
    }

    /* Skip own packets */
    if (memcmp(eth->src, local_mac, ETH_ALEN) == 0) {
        return 0;
    }

    /* Extract payload */
    int payload_len = frame_len - 14;
    if (payload_len > max_len) payload_len = max_len;
    if (payload_len <= 0) return 0;

    memcpy(buffer, frame + 14, payload_len);
    return payload_len;
}

uint32_t nert_hal_get_ticks(void) {
    return systick_counter;
}

uint32_t nert_hal_random(void) {
    rng_state ^= systick_counter;
    rng_state ^= SYSTICK_VAL;
    return xorshift32();
}

uint16_t nert_hal_get_node_id(void) {
    if (local_node_id == 0) {
        local_node_id = (local_mac[4] << 8) | local_mac[5];
        if (local_node_id == 0) {
            local_node_id = (uint16_t)nert_hal_random();
        }
    }
    return local_node_id;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void nert_hal_init(void) {
    /* Configure SysTick for 1ms ticks (assuming 50MHz clock) */
    SYSTICK_LOAD = 50000 - 1;
    SYSTICK_VAL = 0;
    SYSTICK_CTRL = 0x07; /* Enable, interrupt, processor clock */

    /* Initialize Ethernet */
    eth_init();

    /* Seed PRNG */
    rng_state ^= SYSTICK_VAL ^ MAC_IA0 ^ MAC_IA1;
    xorshift32();
    xorshift32();

    /* Pre-compute node ID */
    nert_hal_get_node_id();
}

#endif /* __arm__ && !ESP_PLATFORM */
