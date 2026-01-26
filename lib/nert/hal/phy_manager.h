/*
 * NERT PHY Manager - Header
 *
 * Provides runtime PHY selection and management for NERT.
 * Allows registering multiple PHY backends and switching between them.
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_PHY_MANAGER_H
#define NERT_PHY_MANAGER_H

#include "../nert_phy_if.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define PHY_MANAGER_MAX_PHYS    4   /* Maximum registered PHY backends */

/* ============================================================================
 * Error Codes
 * ============================================================================ */

#define PHY_MGR_OK              0
#define PHY_MGR_ERR_INVALID     -1
#define PHY_MGR_ERR_FULL        -2
#define PHY_MGR_ERR_NOT_FOUND   -3
#define PHY_MGR_ERR_INIT_FAIL   -4
#define PHY_MGR_ERR_NO_ACTIVE   -5

/* ============================================================================
 * PHY Manager API
 * ============================================================================ */

/**
 * Initialize PHY manager
 * Must be called before any other PHY manager functions
 */
void phy_manager_init(void);

/**
 * Register a PHY backend
 *
 * @param phy_type  PHY type identifier (NERT_PHY_TYPE_*)
 * @param ops       PHY operations structure
 * @return PHY_MGR_OK on success, error code on failure
 */
int phy_manager_register(uint8_t phy_type, const struct nert_phy_ops *ops);

/**
 * Unregister a PHY backend
 *
 * @param phy_type  PHY type to unregister
 * @return PHY_MGR_OK on success, error code on failure
 */
int phy_manager_unregister(uint8_t phy_type);

/**
 * Select and activate a PHY backend
 *
 * @param phy_type  PHY type to activate
 * @param config    Configuration to pass to PHY init (can be NULL)
 * @return PHY_MGR_OK on success, error code on failure
 */
int phy_manager_select(uint8_t phy_type, void *config);

/**
 * Get the currently active PHY operations
 *
 * @return Pointer to active PHY ops, or NULL if none active
 */
const struct nert_phy_ops* phy_manager_get_active(void);

/**
 * Get the currently active PHY type
 *
 * @return Active PHY type, or 0 if none active
 */
uint8_t phy_manager_get_active_type(void);

/**
 * Get PHY capabilities for a specific type
 *
 * @param phy_type  PHY type to query
 * @return Pointer to capabilities, or NULL if not found
 */
const struct nert_phy_caps* phy_manager_get_caps(uint8_t phy_type);

/**
 * Check if a PHY type is registered
 *
 * @param phy_type  PHY type to check
 * @return 1 if registered, 0 if not
 */
int phy_manager_is_registered(uint8_t phy_type);

/**
 * Deactivate current PHY (calls destroy)
 *
 * @return PHY_MGR_OK on success
 */
int phy_manager_deactivate(void);

/**
 * Get list of registered PHY types
 *
 * @param types     Output array for PHY types
 * @param max_count Maximum number of types to return
 * @return Number of registered PHY types
 */
int phy_manager_list(uint8_t *types, int max_count);

/* ============================================================================
 * Convenience Wrappers (use active PHY)
 * ============================================================================ */

/**
 * Send data via active PHY
 */
int phy_manager_send(const uint8_t *data, uint16_t len);

/**
 * Receive data via active PHY
 */
int phy_manager_receive(uint8_t *buf, uint16_t max_len);

/**
 * Get MTU of active PHY
 */
int phy_manager_get_mtu(void);

/**
 * Set channel on active PHY
 */
int phy_manager_set_channel(uint8_t channel);

/**
 * Get RSSI from active PHY
 */
int phy_manager_get_rssi(void);

/**
 * Put active PHY to sleep
 */
int phy_manager_sleep(uint32_t duration_ms);

/**
 * Wake active PHY from sleep
 */
int phy_manager_wake(void);

/* ============================================================================
 * Built-in PHY Getters (defined in HAL implementations)
 * ============================================================================ */

/* LoRa PHY */
extern const struct nert_phy_ops* nert_phy_lora_get(void);

/* BLE Mesh PHY */
extern const struct nert_phy_ops* nert_phy_ble_get(void);

/* ============================================================================
 * Auto-Registration Macro
 * ============================================================================ */

/**
 * Register all built-in PHY backends
 * Call after phy_manager_init()
 */
#define PHY_MANAGER_REGISTER_BUILTIN() do { \
    phy_manager_register(NERT_PHY_TYPE_LORA, nert_phy_lora_get()); \
    phy_manager_register(NERT_PHY_TYPE_BLE, nert_phy_ble_get()); \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* NERT_PHY_MANAGER_H */
