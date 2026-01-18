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
 * Physical Layer Interface
 *
 * This interface must be implemented by each platform (x86, ARM, ESP32, etc.)
 * NERT protocol is agnostic to the underlying transport mechanism.
 * ============================================================================ */

/**
 * PHY Interface Structure
 * Platform-specific implementations populate this structure
 */
struct nert_phy_interface {
    /**
     * Send raw packet over network
     * @param data  Packet data
     * @param len  Data length
     * @param ctx  Platform-specific context
     * @return 0 on success, -1 on error
     */
    int (*send)(const void *data, uint16_t len, void *ctx);

    /**
     * Receive packet from network (non-blocking)
     * @param buffer  Receive buffer
     * @param max_len  Buffer size
     * @param ctx  Platform-specific context
     * @return Bytes received, 0 if no packet, -1 on error
     */
    int (*receive)(void *buffer, uint16_t max_len, void *ctx);

    /**
     * Get current tick count in milliseconds
     * @param ctx  Platform-specific context
     * @return Tick count
     */
    uint32_t (*get_ticks)(void *ctx);

    /**
     * Get random number
     * @param ctx  Platform-specific context
     * @return 32-bit random value
     */
    uint32_t (*random)(void *ctx);

    /**
     * Platform-specific context (optional)
     * Can hold socket descriptors, device handles, etc.
     */
    void *context;
};

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
