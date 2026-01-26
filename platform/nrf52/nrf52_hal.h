/*
 * NERT HAL for nRF52840 - Header
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_NRF52_HAL_H
#define NERT_NRF52_HAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Configuration
 * ============================================================================ */

/* Transport selection */
#ifndef NERT_NRF_USE_BLE
#define NERT_NRF_USE_BLE        1   /* Use BLE advertising/GATT */
#endif

#ifndef NERT_NRF_USE_MESH
#define NERT_NRF_USE_MESH       0   /* Use BLE Mesh (requires mesh SDK) */
#endif

#ifndef NERT_NRF_USE_THREAD
#define NERT_NRF_USE_THREAD     0   /* Use Thread (requires OpenThread) */
#endif

/* ============================================================================
 * BLE Configuration
 * ============================================================================ */

/* NERT Service UUID: 4E455254-xxxx-1000-8000-00805F9B34FB */
#define NERT_SERVICE_UUID           0x4E52      /* "NR" */
#define NERT_CHAR_TX_UUID           0x4E54      /* "NT" - TX to swarm */
#define NERT_CHAR_RX_UUID           0x4E52      /* "NR" - RX from swarm */

/* Advertising parameters */
#define ADV_INTERVAL_MIN_MS         100
#define ADV_INTERVAL_MAX_MS         200
#define SCAN_INTERVAL_MS            100
#define SCAN_WINDOW_MS              50

/* Manufacturer ID for advertising data */
#define NERT_MANUFACTURER_ID        0xFFFF      /* Development ID */

/* ============================================================================
 * Thread Configuration (if enabled)
 * ============================================================================ */

#define NERT_THREAD_CHANNEL         15
#define NERT_THREAD_PANID           0x4E52      /* "NR" */
#define NERT_THREAD_UDP_PORT        0x4E52

/* ============================================================================
 * Power Targets
 * ============================================================================ */

/*
 * Power consumption targets:
 * - Active TX:     ~8 mA @ 0 dBm
 * - Active RX:     ~5 mA
 * - System ON:     ~1.5 uA (RAM retained)
 * - System OFF:    ~0.3 uA
 *
 * With duty cycling and System ON sleep:
 * - Target: <10 uA average for 30+ day battery life on CR2032
 */

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize nRF52 HAL
 * Call this before nert_init()
 */
void nert_hal_init(void);

/**
 * Get PHY interface for NERT
 * @return Pointer to PHY interface structure
 */
struct nert_phy_interface* nert_phy_nrf52_get(void);

/**
 * Enter System OFF mode (lowest power)
 * Only wakes on reset, GPIO, or NFC field
 */
void nert_hal_enter_system_off(void);

/**
 * Enter low power mode (System ON with sleep)
 * @param duration_ms  Sleep duration (0 = until event)
 */
void nert_hal_enter_low_power(uint32_t duration_ms);

/**
 * Set BLE TX power
 * @param power_dbm  Power in dBm (-40 to +4)
 */
void nert_hal_set_tx_power(int8_t power_dbm);

/**
 * Get RSSI of last received packet
 * @return RSSI in dBm
 */
int8_t nert_hal_get_last_rssi(void);

/**
 * Check if BLE is connected
 * @return 1 if connected, 0 otherwise
 */
uint8_t nert_hal_is_connected(void);

/**
 * Disconnect current BLE connection
 */
void nert_hal_disconnect(void);

/**
 * Enable/disable scanning
 * @param enable  1 to enable, 0 to disable
 */
void nert_hal_set_scanning(uint8_t enable);

/**
 * Enable/disable advertising
 * @param enable  1 to enable, 0 to disable
 */
void nert_hal_set_advertising(uint8_t enable);

/* ============================================================================
 * Thread-specific API (if NERT_NRF_USE_THREAD)
 * ============================================================================ */

#if NERT_NRF_USE_THREAD

/**
 * Get Thread device role
 * @return OpenThread device role
 */
uint8_t nert_hal_thread_get_role(void);

/**
 * Check if Thread network is attached
 * @return 1 if attached, 0 otherwise
 */
uint8_t nert_hal_thread_is_attached(void);

/**
 * Get Thread network name
 * @param name  Buffer for name (17 bytes)
 * @return 0 on success
 */
int nert_hal_thread_get_network_name(char *name);

#endif /* NERT_NRF_USE_THREAD */

#ifdef __cplusplus
}
#endif

#endif /* NERT_NRF52_HAL_H */
