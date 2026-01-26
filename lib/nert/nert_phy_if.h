/*
 * NERT Physical Layer Interface
 * Hardware abstraction for NERT framework
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_PHY_IF_H
#define NERT_PHY_IF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* PHY type identifiers */
#define NERT_PHY_TYPE_UNKNOWN       0x00
#define NERT_PHY_TYPE_ETHERNET      0x01
#define NERT_PHY_TYPE_WIFI          0x02
#define NERT_PHY_TYPE_ESPNOW        0x03
#define NERT_PHY_TYPE_LORA          0x04
#define NERT_PHY_TYPE_BLE           0x05
#define NERT_PHY_TYPE_ZIGBEE        0x06
#define NERT_PHY_TYPE_VIRTUAL       0xFF

/* PHY capability flags */
#define NERT_PHY_CAP_BROADCAST      0x01    /* Supports broadcast */
#define NERT_PHY_CAP_MULTICAST      0x02    /* Supports multicast */
#define NERT_PHY_CAP_SLEEP          0x04    /* Supports sleep mode */
#define NERT_PHY_CAP_CHANNEL        0x08    /* Supports channel selection */
#define NERT_PHY_CAP_RSSI           0x10    /* Can read RSSI */
#define NERT_PHY_CAP_TX_POWER       0x20    /* Adjustable TX power */
#define NERT_PHY_CAP_ACK            0x40    /* Hardware ACK support */
#define NERT_PHY_CAP_ENCRYPTION     0x80    /* Hardware encryption */

/* PHY power modes */
#define NERT_PHY_POWER_OFF          0
#define NERT_PHY_POWER_SLEEP        1
#define NERT_PHY_POWER_STANDBY      2
#define NERT_PHY_POWER_ACTIVE       3

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * PHY capabilities structure
 * Describes the capabilities of a physical layer implementation
 */
struct nert_phy_caps {
    uint16_t mtu;                   /* Maximum transmission unit */
    uint8_t  phy_type;              /* NERT_PHY_TYPE_* */
    uint8_t  capabilities;          /* NERT_PHY_CAP_* bitmask */
    uint8_t  channels;              /* Number of channels (0 = N/A) */
    uint8_t  tx_power_levels;       /* TX power levels (0 = N/A) */
    int8_t   min_rssi;              /* Minimum readable RSSI (dBm) */
    int8_t   max_rssi;              /* Maximum readable RSSI (dBm) */
};

/**
 * PHY statistics structure
 */
struct nert_phy_stats {
    uint32_t tx_packets;            /* Packets transmitted */
    uint32_t tx_bytes;              /* Bytes transmitted */
    uint32_t tx_errors;             /* TX errors */
    uint32_t rx_packets;            /* Packets received */
    uint32_t rx_bytes;              /* Bytes received */
    uint32_t rx_errors;             /* RX errors (CRC, etc.) */
    uint32_t rx_dropped;            /* Packets dropped (buffer full) */
    int8_t   last_rssi;             /* RSSI of last received packet */
    uint8_t  current_channel;       /* Current channel */
    uint8_t  power_mode;            /* Current power mode */
    uint8_t  _reserved;
};

/**
 * PHY Operations Structure (Enhanced - v0.5)
 * Platform-specific implementations populate this structure
 */
struct nert_phy_ops {
    /**
     * Initialize the PHY
     * @param config  Platform-specific configuration
     * @return 0 on success, -1 on error
     */
    int (*init)(void *config);

    /**
     * Destroy/cleanup the PHY
     */
    void (*destroy)(void);

    /**
     * Send raw packet over network
     * @param data  Packet data
     * @param len   Data length
     * @return 0 on success, -1 on error
     */
    int (*send)(const uint8_t *data, uint16_t len);

    /**
     * Receive packet from network (non-blocking)
     * @param buffer   Receive buffer
     * @param max_len  Buffer size
     * @return Bytes received, 0 if no packet, -1 on error
     */
    int (*receive)(uint8_t *buf, uint16_t max_len);

    /**
     * Get MTU (Maximum Transmission Unit)
     * @return MTU in bytes
     */
    int (*get_mtu)(void);

    /**
     * Set radio channel
     * @param channel  Channel number
     * @return 0 on success, -1 on error or not supported
     */
    int (*set_channel)(uint8_t channel);

    /**
     * Get current RSSI (Received Signal Strength Indicator)
     * @return RSSI in dBm, or INT8_MIN if not available
     */
    int (*get_rssi)(void);

    /**
     * Enter sleep/low-power mode
     * @param duration_ms  Sleep duration (0 = indefinite until wake)
     * @return 0 on success, -1 on error or not supported
     */
    int (*sleep)(uint32_t duration_ms);

    /**
     * Wake from sleep mode
     * @return 0 on success, -1 on error
     */
    int (*wake)(void);

    /**
     * Get PHY capabilities
     * @return Pointer to capabilities structure
     */
    const struct nert_phy_caps* (*get_caps)(void);

    /**
     * Get PHY statistics
     * @return Pointer to statistics structure
     */
    const struct nert_phy_stats* (*get_stats)(void);
};

/* ============================================================================
 * Legacy PHY Interface (backwards compatibility)
 * ============================================================================ */

/**
 * PHY Interface Structure (Legacy)
 * Platform-specific implementations populate this structure
 */
struct nert_phy_interface {
    int (*send)(const void *data, uint16_t len, void *ctx);
    int (*receive)(void *buffer, uint16_t max_len, void *ctx);
    uint32_t (*get_ticks)(void *ctx);
    uint32_t (*random)(void *ctx);
    void *context;
};

/* ============================================================================
 * PHY Registration and Management
 * ============================================================================ */

/**
 * Register a PHY implementation
 * @param ops   PHY operations structure
 * @param name  Human-readable name (for debugging)
 * @return 0 on success, -1 on error
 */
int nert_phy_register(const struct nert_phy_ops *ops, const char *name);

/**
 * Get the currently active PHY
 * @return Pointer to active PHY ops, or NULL if none
 */
const struct nert_phy_ops* nert_phy_get_active(void);

/**
 * Get PHY capabilities
 * @return Pointer to capabilities structure
 */
const struct nert_phy_caps* nert_phy_get_caps(void);

/**
 * Get PHY statistics
 * @return Pointer to statistics structure
 */
const struct nert_phy_stats* nert_phy_get_stats(void);

/* ============================================================================
 * Pre-defined Platform Implementations
 * ============================================================================ */

/**
 * Get x86 PHY implementation (E1000 ethernet)
 * @return Pointer to x86 PHY interface
 */
struct nert_phy_interface* nert_phy_x86_get(void);

/**
 * Get ARM PHY implementation (platform-specific ethernet)
 * @return Pointer to ARM PHY interface
 */
struct nert_phy_interface* nert_phy_arm_get(void);

/**
 * Get ESP32 PHY implementation (ESP-NOW)
 * @return Pointer to ESP32 PHY interface
 */
struct nert_phy_interface* nert_phy_esp32_get(void);

/**
 * Get LoRa PHY implementation
 * @return Pointer to LoRa PHY ops
 */
const struct nert_phy_ops* nert_phy_lora_get(void);

/**
 * Get BLE Mesh PHY implementation
 * @return Pointer to BLE PHY ops
 */
const struct nert_phy_ops* nert_phy_ble_get(void);

/**
 * Get virtual PHY implementation (UDP sockets for testing)
 * @param port  UDP port to bind
 * @param multicast_group  Multicast group address (e.g., "239.255.0.1")
 * @return Pointer to virtual PHY interface
 */
struct nert_phy_interface* nert_phy_virtual_create(uint16_t port, const char *multicast_group);

/**
 * Destroy virtual PHY instance
 * @param phy  PHY interface to destroy
 */
void nert_phy_virtual_destroy(struct nert_phy_interface *phy);

#ifdef __cplusplus
}
#endif

#endif /* NERT_PHY_IF_H */
