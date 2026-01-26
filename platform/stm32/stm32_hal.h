/*
 * NERT HAL for STM32F4 - Header
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_STM32_HAL_H
#define NERT_STM32_HAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Configuration
 * ============================================================================ */

/* Transport selection (set one to 1) */
#ifndef NERT_STM32_USE_CAN
#define NERT_STM32_USE_CAN      1
#endif

#ifndef NERT_STM32_USE_LORA
#define NERT_STM32_USE_LORA     1
#endif

/* ============================================================================
 * GPIO Pin Definitions (adjust for your board)
 * ============================================================================ */

/* LoRa SX1276 SPI Pins (SPI1) */
#define LORA_SPI                SPI1
#define LORA_NSS_PORT           GPIOA
#define LORA_NSS_PIN            GPIO_PIN_4
#define LORA_RESET_PORT         GPIOB
#define LORA_RESET_PIN          GPIO_PIN_0
#define LORA_DIO0_PORT          GPIOB
#define LORA_DIO0_PIN           GPIO_PIN_1
#define LORA_DIO1_PORT          GPIOB
#define LORA_DIO1_PIN           GPIO_PIN_2

/* CAN Pins (CAN1) */
#define CAN_TX_PORT             GPIOA
#define CAN_TX_PIN              GPIO_PIN_12
#define CAN_RX_PORT             GPIOA
#define CAN_RX_PIN              GPIO_PIN_11

/* ============================================================================
 * LoRa Configuration
 * ============================================================================ */

/* Frequency bands (uncomment one) */
#define LORA_BAND_US915         1   /* 902-928 MHz (Americas) */
// #define LORA_BAND_EU868      1   /* 863-870 MHz (Europe) */
// #define LORA_BAND_AU915      1   /* 915-928 MHz (Australia) */
// #define LORA_BAND_AS923      1   /* 920-923 MHz (Asia) */

#if defined(LORA_BAND_US915)
    #define LORA_FREQUENCY      915000000
#elif defined(LORA_BAND_EU868)
    #define LORA_FREQUENCY      868100000
#elif defined(LORA_BAND_AU915)
    #define LORA_FREQUENCY      915000000
#elif defined(LORA_BAND_AS923)
    #define LORA_FREQUENCY      923200000
#else
    #define LORA_FREQUENCY      915000000
#endif

/* LoRa modulation parameters */
#define LORA_BANDWIDTH          125000      /* 125 kHz */
#define LORA_SPREADING_FACTOR   7           /* SF7 (fastest) */
#define LORA_CODING_RATE        5           /* 4/5 */
#define LORA_PREAMBLE_LENGTH    8
#define LORA_TX_POWER           14          /* dBm (max 20 with PA_BOOST) */

/* ============================================================================
 * CAN Configuration
 * ============================================================================ */

#define NERT_CAN_BITRATE        500000      /* 500 kbps */
#define NERT_CAN_FILTER_ID      0x4E52      /* "NR" */
#define NERT_CAN_FILTER_MASK    0xFFFF

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize STM32 HAL
 * Call this before nert_init()
 */
void nert_hal_init(void);

/**
 * Get PHY interface for NERT
 * @return Pointer to PHY interface structure
 */
struct nert_phy_interface* nert_phy_stm32_get(void);

/**
 * Enter STOP mode (low power, preserves RAM)
 * @param wakeup_ms  Wakeup time in milliseconds
 */
void nert_hal_enter_stop_mode(uint32_t wakeup_ms);

/**
 * Enter STANDBY mode (lowest power, loses RAM)
 */
void nert_hal_enter_standby_mode(void);

/**
 * Set LoRa TX power
 * @param power_dbm  Power in dBm (2-17 for PA_BOOST)
 */
void nert_hal_set_tx_power(int8_t power_dbm);

/**
 * Switch transport mode at runtime
 * @param use_lora  1 for LoRa, 0 for CAN
 */
void nert_hal_set_transport(uint8_t use_lora);

/**
 * Get current transport mode
 * @return 1 if LoRa, 0 if CAN
 */
uint8_t nert_hal_get_transport(void);

/**
 * Get LoRa RSSI of last received packet
 * @return RSSI in dBm
 */
int16_t nert_hal_get_rssi(void);

/**
 * Get LoRa SNR of last received packet
 * @return SNR in dB
 */
int8_t nert_hal_get_snr(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_STM32_HAL_H */
