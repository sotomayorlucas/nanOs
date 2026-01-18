/*
 * NERT HAL Adapter for Framework
 * Bridges nert_phy_interface with nert_hal_* functions
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef HAL_ADAPTER_H
#define HAL_ADAPTER_H

#include "../nert_phy_if.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize HAL adapter with PHY interface and node ID
 * Must be called before using NERT functions
 *
 * @param phy  Physical layer interface (e.g., virtual, x86, ARM)
 * @param node_id  This node's unique identifier
 */
void nert_hal_adapter_init(struct nert_phy_interface *phy, uint16_t node_id);

/**
 * Get current PHY interface
 * @return Pointer to current PHY, or NULL if not initialized
 */
struct nert_phy_interface* nert_hal_adapter_get_phy(void);

/**
 * Update global tick counter
 * Should be called periodically in main loop
 */
void nert_hal_update_ticks(void);

#ifdef __cplusplus
}
#endif

#endif /* HAL_ADAPTER_H */
