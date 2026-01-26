/*
 * NERT LoRa HAL Implementation (Stub)
 *
 * Stub implementation for LoRa-based NERT transport.
 * To be completed with actual hardware driver integration.
 *
 * Target hardware: SX1276/SX1278 or similar
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "../nert_phy_if.h"
#include <string.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* LoRa-specific defaults */
#define LORA_DEFAULT_CHANNEL        0
#define LORA_DEFAULT_SF             7       /* Spreading factor */
#define LORA_DEFAULT_BW             125000  /* Bandwidth: 125kHz */
#define LORA_DEFAULT_CR             5       /* Coding rate: 4/5 */
#define LORA_DEFAULT_POWER          14      /* TX power: 14 dBm */
#define LORA_MTU                    255     /* LoRa max payload */
#define LORA_CHANNELS               64      /* Available channels */

/* ============================================================================
 * Internal State
 * ============================================================================ */

static struct nert_phy_caps lora_caps = {
    .mtu = LORA_MTU,
    .phy_type = NERT_PHY_TYPE_LORA,
    .capabilities = NERT_PHY_CAP_BROADCAST |
                    NERT_PHY_CAP_SLEEP |
                    NERT_PHY_CAP_CHANNEL |
                    NERT_PHY_CAP_RSSI |
                    NERT_PHY_CAP_TX_POWER,
    .channels = LORA_CHANNELS,
    .tx_power_levels = 15,
    .min_rssi = -130,
    .max_rssi = -20
};

static struct nert_phy_stats lora_stats;

static uint8_t current_channel = LORA_DEFAULT_CHANNEL;
static uint8_t power_mode = NERT_PHY_POWER_OFF;
static int8_t last_rssi = -127;
static uint8_t initialized = 0;

/* ============================================================================
 * HAL Implementation (Stubs)
 * ============================================================================ */

static int lora_init(void *config) {
    (void)config;

    /* TODO: Initialize SPI interface to LoRa chip */
    /* TODO: Configure LoRa parameters (SF, BW, CR, etc.) */
    /* TODO: Set frequency based on region */

    memset(&lora_stats, 0, sizeof(lora_stats));
    current_channel = LORA_DEFAULT_CHANNEL;
    power_mode = NERT_PHY_POWER_ACTIVE;
    initialized = 1;

    return 0;
}

static void lora_destroy(void) {
    /* TODO: Put chip in sleep mode */
    /* TODO: Release SPI resources */

    power_mode = NERT_PHY_POWER_OFF;
    initialized = 0;
}

static int lora_send(const uint8_t *data, uint16_t len) {
    if (!initialized || power_mode != NERT_PHY_POWER_ACTIVE) {
        return -1;
    }

    if (len > LORA_MTU) {
        return -1;
    }

    /* TODO: Write data to FIFO */
    /* TODO: Set to TX mode */
    /* TODO: Wait for TX complete or timeout */
    /* TODO: Return to RX mode */

    lora_stats.tx_packets++;
    lora_stats.tx_bytes += len;

    return 0;
}

static int lora_receive(uint8_t *buf, uint16_t max_len) {
    if (!initialized || power_mode != NERT_PHY_POWER_ACTIVE) {
        return -1;
    }

    /* TODO: Check for RX done interrupt/flag */
    /* TODO: Read RSSI of received packet */
    /* TODO: Read data from FIFO */
    /* TODO: Check CRC validity */

    /* Stub: No data available */
    (void)buf;
    (void)max_len;

    return 0;
}

static int lora_get_mtu(void) {
    return LORA_MTU;
}

static int lora_set_channel(uint8_t channel) {
    if (!initialized) {
        return -1;
    }

    if (channel >= LORA_CHANNELS) {
        return -1;
    }

    /* TODO: Calculate frequency from channel number */
    /* TODO: Set frequency register */

    current_channel = channel;
    lora_stats.current_channel = channel;

    return 0;
}

static int lora_get_rssi(void) {
    if (!initialized) {
        return -127;
    }

    /* TODO: Read RSSI register */
    /* For packet RSSI, this was captured during receive */

    return last_rssi;
}

static int lora_sleep(uint32_t duration_ms) {
    if (!initialized) {
        return -1;
    }

    /* TODO: Set chip to sleep mode */
    (void)duration_ms;

    power_mode = NERT_PHY_POWER_SLEEP;
    lora_stats.power_mode = NERT_PHY_POWER_SLEEP;

    return 0;
}

static int lora_wake(void) {
    if (!initialized) {
        return -1;
    }

    /* TODO: Wake chip from sleep */
    /* TODO: Restore configuration */
    /* TODO: Set to RX mode */

    power_mode = NERT_PHY_POWER_ACTIVE;
    lora_stats.power_mode = NERT_PHY_POWER_ACTIVE;

    return 0;
}

static const struct nert_phy_caps* lora_get_caps(void) {
    return &lora_caps;
}

static const struct nert_phy_stats* lora_get_stats(void) {
    return &lora_stats;
}

/* ============================================================================
 * PHY Operations Structure
 * ============================================================================ */

static const struct nert_phy_ops lora_ops = {
    .init = lora_init,
    .destroy = lora_destroy,
    .send = lora_send,
    .receive = lora_receive,
    .get_mtu = lora_get_mtu,
    .set_channel = lora_set_channel,
    .get_rssi = lora_get_rssi,
    .sleep = lora_sleep,
    .wake = lora_wake,
    .get_caps = lora_get_caps,
    .get_stats = lora_get_stats
};

/* ============================================================================
 * Public API
 * ============================================================================ */

const struct nert_phy_ops* nert_phy_lora_get(void) {
    return &lora_ops;
}
