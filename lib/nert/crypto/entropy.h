/*
 * NERT Entropy Collection and CSPRNG
 *
 * Provides cryptographically secure random number generation through:
 * - Entropy collection from multiple sources
 * - ChaCha8-based PRNG for extraction
 * - Health monitoring and quality estimation
 *
 * Entropy sources:
 * - Timer jitter (LSBs of timer reads)
 * - Interrupt timing variations
 * - ADC noise (on supported hardware)
 * - Initial SRAM state
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_ENTROPY_H
#define NERT_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Entropy pool size in bytes */
#define ENTROPY_POOL_SIZE           64

/* Minimum entropy before extraction is allowed (bits) */
#define ENTROPY_MIN_BITS            128

/* Minimum samples for health check */
#define ENTROPY_HEALTH_SAMPLES      64

/* Reseed interval (extractions before automatic reseed) */
#define ENTROPY_RESEED_INTERVAL     1000

/* Entropy source identifiers */
#define ENTROPY_SOURCE_TIMER        0x01
#define ENTROPY_SOURCE_INTERRUPT    0x02
#define ENTROPY_SOURCE_ADC          0x04
#define ENTROPY_SOURCE_SRAM         0x08
#define ENTROPY_SOURCE_EXTERNAL     0x10

/* Health status codes */
#define ENTROPY_HEALTH_OK           0
#define ENTROPY_HEALTH_LOW          1   /* Below minimum, still collecting */
#define ENTROPY_HEALTH_STUCK        2   /* Source appears stuck */
#define ENTROPY_HEALTH_BIAS         3   /* Statistical bias detected */
#define ENTROPY_HEALTH_FAIL         4   /* Critical failure */

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Entropy pool state
 */
struct entropy_pool {
    uint8_t  pool[ENTROPY_POOL_SIZE];   /* Accumulated entropy */
    uint32_t entropy_bits;              /* Estimated entropy bits */
    uint32_t collections;               /* Total collection events */
    uint32_t extractions;               /* Total extraction calls */
    uint32_t bytes_generated;           /* Total bytes generated */
    uint8_t  sources_active;            /* Bitmask of active sources */
    uint8_t  initialized;               /* Pool initialized flag */
    uint8_t  seeded;                    /* Has enough entropy been collected */
    uint8_t  _reserved;
};

/**
 * Entropy source statistics
 */
struct entropy_source_stats {
    uint32_t samples;                   /* Samples collected */
    uint32_t bits_contributed;          /* Estimated bits contributed */
    uint32_t last_value;                /* Last sampled value */
    uint16_t stuck_count;               /* Consecutive identical values */
    uint16_t health_status;             /* ENTROPY_HEALTH_* */
};

/**
 * Overall entropy statistics
 */
struct entropy_stats {
    struct entropy_source_stats timer;
    struct entropy_source_stats interrupt;
    struct entropy_source_stats adc;
    struct entropy_source_stats sram;
    struct entropy_source_stats external;
    uint32_t total_bits_collected;
    uint32_t total_bytes_extracted;
    uint32_t reseed_count;
    uint8_t  overall_health;
};

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize the entropy subsystem
 * Must be called before any other entropy functions.
 * Attempts to seed from SRAM noise if available.
 */
void entropy_init(void);

/**
 * Add entropy from raw data
 * Mixes the provided data into the entropy pool.
 *
 * @param data      Entropy source data
 * @param len       Length of data in bytes
 * @param est_bits  Estimated entropy bits (conservative estimate)
 * @param source    Source identifier (ENTROPY_SOURCE_*)
 */
void entropy_add(const void *data, size_t len, uint8_t est_bits, uint8_t source);

/**
 * Add entropy from timer jitter
 * Samples the system timer multiple times and uses LSB variation.
 * Should be called periodically from main loop.
 */
void entropy_add_timer_jitter(void);

/**
 * Add entropy from interrupt timing
 * Call this from interrupt handlers to capture timing variation.
 *
 * @param irq_num   Interrupt number (for mixing)
 */
void entropy_add_interrupt(uint8_t irq_num);

/**
 * Add entropy from ADC reading
 * Uses noise in ADC measurements.
 *
 * @param adc_value Raw ADC reading
 */
void entropy_add_adc(uint16_t adc_value);

/**
 * Extract random bytes from the pool
 * Uses ChaCha8 as the extraction function.
 *
 * @param buf       Output buffer
 * @param len       Number of bytes to extract
 * @return          0 on success, -1 if insufficient entropy
 */
int entropy_extract(void *buf, size_t len);

/**
 * Extract random bytes (blocking)
 * Will collect more entropy if needed before extracting.
 * May take significant time if entropy is low.
 *
 * @param buf       Output buffer
 * @param len       Number of bytes to extract
 * @param timeout_ms Maximum time to wait for entropy (0 = no timeout)
 * @return          0 on success, -1 on timeout
 */
int entropy_extract_blocking(void *buf, size_t len, uint32_t timeout_ms);

/**
 * Get current entropy estimate
 *
 * @return  Estimated bits of entropy in pool
 */
uint32_t entropy_available(void);

/**
 * Check if pool is adequately seeded
 *
 * @return  1 if seeded with minimum entropy, 0 otherwise
 */
int entropy_is_seeded(void);

/**
 * Get overall health status
 *
 * @return  ENTROPY_HEALTH_* status code
 */
int entropy_health(void);

/**
 * Get detailed entropy statistics
 *
 * @return  Pointer to stats structure (read-only)
 */
const struct entropy_stats* entropy_get_stats(void);

/**
 * Force reseed the PRNG from the pool
 * Normally done automatically based on extraction count.
 */
void entropy_reseed(void);

/**
 * Process entropy collection tick
 * Should be called periodically (e.g., every 10-100ms).
 * Collects timer jitter and processes health checks.
 */
void entropy_tick(void);

/**
 * Manually seed with external entropy
 * Use when high-quality external entropy is available
 * (e.g., hardware RNG, user input timing).
 *
 * @param seed      Seed data
 * @param len       Length of seed data
 */
void entropy_manual_seed(const void *seed, size_t len);

/**
 * Zero the entropy pool
 * Emergency function to clear all accumulated entropy.
 * Pool will need to be reseeded before use.
 */
void entropy_wipe(void);

/* ============================================================================
 * Platform-specific Hooks (weak symbols)
 * ============================================================================ */

/**
 * Get system timer value
 * Override for platform-specific timer access.
 *
 * @return  Current timer value (highest precision available)
 */
uint32_t entropy_get_timer(void);

/**
 * Read ADC value if available
 * Override if platform has ADC for entropy.
 *
 * @return  ADC reading, or 0 if not available
 */
uint16_t entropy_read_adc(void);

/**
 * Read uninitialized SRAM
 * Override for platform-specific SRAM entropy.
 *
 * @param buf   Buffer to fill
 * @param len   Bytes to read
 * @return      1 if SRAM entropy available, 0 otherwise
 */
int entropy_read_sram(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NERT_ENTROPY_H */
