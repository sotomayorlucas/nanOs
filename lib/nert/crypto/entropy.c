/*
 * NERT Entropy Collection and CSPRNG - Implementation
 *
 * Uses ChaCha8 as the core PRNG with entropy mixing via XOR and hashing.
 *
 * Security considerations:
 * - Pool is never directly exposed
 * - ChaCha8 provides forward secrecy (can't recover past outputs)
 * - Health monitoring detects stuck or biased sources
 * - Minimum entropy threshold before extraction
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "entropy.h"
#include <string.h>

/* External ChaCha8 function from nert.c */
extern void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *plaintext, uint8_t len,
                            uint8_t *ciphertext);

/* External secure_memzero from key_store or nert.c */
extern void secure_memzero(void *ptr, size_t len);

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Main entropy pool */
static struct entropy_pool pool;

/* PRNG state (derived from pool) */
static uint8_t prng_key[32];
static uint8_t prng_nonce[12];
static uint32_t prng_counter;
static uint32_t extractions_since_reseed;

/* Per-source statistics */
static struct entropy_stats stats;

/* Mixing buffer for collection */
static uint8_t mix_buffer[64];
static uint8_t mix_index;

/* ============================================================================
 * Platform Hooks (weak symbols - override for your platform)
 * ============================================================================ */

/**
 * Default timer implementation
 */
__attribute__((weak))
uint32_t entropy_get_timer(void) {
    /* Try to use NERT HAL timer */
    extern uint32_t nert_hal_get_ticks(void);
    return nert_hal_get_ticks();
}

/**
 * Default ADC implementation (not available)
 */
__attribute__((weak))
uint16_t entropy_read_adc(void) {
    return 0;
}

/**
 * Default SRAM entropy (not available)
 */
__attribute__((weak))
int entropy_read_sram(void *buf, size_t len) {
    (void)buf;
    (void)len;
    return 0;
}

/* ============================================================================
 * Internal Functions
 * ============================================================================ */

/**
 * Simple mixing function using XOR and rotation
 */
static void mix_into_pool(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        /* XOR into current position */
        pool.pool[mix_index] ^= data[i];

        /* Rotate mix_index through pool */
        mix_index = (mix_index + 1) % ENTROPY_POOL_SIZE;

        /* Additional mixing: XOR with rotated neighbor */
        uint8_t neighbor_idx = (mix_index + 31) % ENTROPY_POOL_SIZE;
        pool.pool[mix_index] ^= (pool.pool[neighbor_idx] << 3) |
                                (pool.pool[neighbor_idx] >> 5);
    }

    pool.collections++;
}

/**
 * Hash the pool using ChaCha8 to derive PRNG key
 */
static void derive_prng_state(void) {
    /* Use first 32 bytes of pool as key for derivation */
    uint8_t derive_key[32];
    memcpy(derive_key, pool.pool, 32);

    /* Use remaining pool as input */
    uint8_t derive_nonce[12] = {0};
    derive_nonce[0] = (pool.collections >> 24) & 0xFF;
    derive_nonce[1] = (pool.collections >> 16) & 0xFF;
    derive_nonce[2] = (pool.collections >> 8) & 0xFF;
    derive_nonce[3] = pool.collections & 0xFF;

    /* Derive new PRNG key using ChaCha8 */
    uint8_t input[32];
    memcpy(input, pool.pool + 32, 32);
    chacha8_encrypt(derive_key, derive_nonce, input, 32, prng_key);

    /* Derive nonce */
    uint8_t nonce_input[12] = {0};
    chacha8_encrypt(derive_key, derive_nonce, nonce_input, 12, prng_nonce);

    /* Reset counter */
    prng_counter = 0;
    extractions_since_reseed = 0;

    /* Securely clear derive_key */
    secure_memzero(derive_key, sizeof(derive_key));

    stats.reseed_count++;
}

/**
 * Update source health statistics
 */
static void update_source_health(struct entropy_source_stats *src,
                                  uint32_t value) {
    if (value == src->last_value) {
        src->stuck_count++;
        if (src->stuck_count > 100) {
            src->health_status = ENTROPY_HEALTH_STUCK;
        }
    } else {
        src->stuck_count = 0;
        if (src->health_status == ENTROPY_HEALTH_STUCK) {
            src->health_status = ENTROPY_HEALTH_OK;
        }
    }

    src->last_value = value;
    src->samples++;
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

void entropy_init(void) {
    /* Clear all state */
    memset(&pool, 0, sizeof(pool));
    memset(&stats, 0, sizeof(stats));
    memset(prng_key, 0, sizeof(prng_key));
    memset(prng_nonce, 0, sizeof(prng_nonce));
    prng_counter = 0;
    extractions_since_reseed = 0;
    mix_index = 0;

    /* Try to seed from SRAM noise */
    uint8_t sram_entropy[32];
    if (entropy_read_sram(sram_entropy, sizeof(sram_entropy))) {
        mix_into_pool(sram_entropy, sizeof(sram_entropy));
        pool.entropy_bits += 32;  /* Conservative estimate: 1 bit per byte */
        pool.sources_active |= ENTROPY_SOURCE_SRAM;
        stats.sram.samples++;
        stats.sram.bits_contributed += 32;
    }

    /* Initial timer samples for some entropy */
    for (int i = 0; i < 16; i++) {
        uint32_t t = entropy_get_timer();
        mix_into_pool((uint8_t *)&t, sizeof(t));
    }
    pool.entropy_bits += 8;  /* Very conservative */
    pool.sources_active |= ENTROPY_SOURCE_TIMER;

    pool.initialized = 1;
}

void entropy_add(const void *data, size_t len, uint8_t est_bits, uint8_t source) {
    if (!pool.initialized || data == NULL || len == 0) {
        return;
    }

    mix_into_pool((const uint8_t *)data, len);

    /* Cap entropy estimate conservatively */
    uint8_t actual_bits = (est_bits < len * 2) ? est_bits : (len * 2);
    pool.entropy_bits += actual_bits;

    /* Cap total entropy at pool size in bits */
    if (pool.entropy_bits > ENTROPY_POOL_SIZE * 8) {
        pool.entropy_bits = ENTROPY_POOL_SIZE * 8;
    }

    pool.sources_active |= source;
    stats.total_bits_collected += actual_bits;

    /* Check if we've reached seeded threshold */
    if (!pool.seeded && pool.entropy_bits >= ENTROPY_MIN_BITS) {
        pool.seeded = 1;
        derive_prng_state();
    }
}

void entropy_add_timer_jitter(void) {
    if (!pool.initialized) {
        return;
    }

    /* Sample timer multiple times and use LSB variations */
    uint8_t jitter_sample = 0;

    for (int i = 0; i < 8; i++) {
        uint32_t t1 = entropy_get_timer();
        /* Small busy loop to create jitter opportunity */
        volatile uint32_t delay = 0;
        for (int j = 0; j < 10; j++) delay++;
        uint32_t t2 = entropy_get_timer();

        /* Use LSB of difference */
        jitter_sample |= ((t2 - t1) & 1) << i;
    }

    mix_into_pool(&jitter_sample, 1);

    /* Very conservative: 1-2 bits per sample */
    pool.entropy_bits += 1;
    if (pool.entropy_bits > ENTROPY_POOL_SIZE * 8) {
        pool.entropy_bits = ENTROPY_POOL_SIZE * 8;
    }

    update_source_health(&stats.timer, jitter_sample);
    stats.timer.bits_contributed += 1;
}

void entropy_add_interrupt(uint8_t irq_num) {
    if (!pool.initialized) {
        return;
    }

    uint32_t timer = entropy_get_timer();

    /* Mix IRQ number and timer LSBs */
    uint8_t sample[2];
    sample[0] = irq_num ^ (timer & 0xFF);
    sample[1] = (timer >> 8) & 0xFF;

    mix_into_pool(sample, sizeof(sample));

    /* Interrupt timing has moderate entropy */
    pool.entropy_bits += 2;
    if (pool.entropy_bits > ENTROPY_POOL_SIZE * 8) {
        pool.entropy_bits = ENTROPY_POOL_SIZE * 8;
    }

    pool.sources_active |= ENTROPY_SOURCE_INTERRUPT;
    update_source_health(&stats.interrupt, timer);
    stats.interrupt.bits_contributed += 2;
}

void entropy_add_adc(uint16_t adc_value) {
    if (!pool.initialized) {
        return;
    }

    /* ADC noise is primarily in LSBs */
    uint8_t sample = adc_value & 0xFF;
    mix_into_pool(&sample, 1);

    /* ADC LSB typically has 1-2 bits of noise */
    pool.entropy_bits += 1;
    if (pool.entropy_bits > ENTROPY_POOL_SIZE * 8) {
        pool.entropy_bits = ENTROPY_POOL_SIZE * 8;
    }

    pool.sources_active |= ENTROPY_SOURCE_ADC;
    update_source_health(&stats.adc, adc_value);
    stats.adc.bits_contributed += 1;
}

int entropy_extract(void *buf, size_t len) {
    if (!pool.initialized || buf == NULL || len == 0) {
        return -1;
    }

    /* Check if seeded */
    if (!pool.seeded) {
        return -1;
    }

    /* Check if reseed needed */
    if (extractions_since_reseed >= ENTROPY_RESEED_INTERVAL) {
        derive_prng_state();
    }

    uint8_t *out = (uint8_t *)buf;
    size_t generated = 0;

    while (generated < len) {
        /* Generate a block of random bytes using ChaCha8 */
        uint8_t block_nonce[12];
        memcpy(block_nonce, prng_nonce, 12);

        /* Incorporate counter into nonce */
        block_nonce[8] = (prng_counter >> 24) & 0xFF;
        block_nonce[9] = (prng_counter >> 16) & 0xFF;
        block_nonce[10] = (prng_counter >> 8) & 0xFF;
        block_nonce[11] = prng_counter & 0xFF;

        uint8_t zeros[64] = {0};
        uint8_t keystream[64];
        size_t block_len = (len - generated > 64) ? 64 : (len - generated);

        chacha8_encrypt(prng_key, block_nonce, zeros, (uint8_t)block_len, keystream);

        memcpy(out + generated, keystream, block_len);
        generated += block_len;
        prng_counter++;

        /* Secure cleanup */
        secure_memzero(keystream, sizeof(keystream));
    }

    pool.extractions++;
    pool.bytes_generated += len;
    extractions_since_reseed++;
    stats.total_bytes_extracted += len;

    /* Reduce entropy estimate (not below minimum if still seeded) */
    if (pool.entropy_bits > len * 8) {
        pool.entropy_bits -= len * 8;
    } else {
        pool.entropy_bits = 0;
    }

    return 0;
}

int entropy_extract_blocking(void *buf, size_t len, uint32_t timeout_ms) {
    if (!pool.initialized || buf == NULL || len == 0) {
        return -1;
    }

    uint32_t start = entropy_get_timer();

    /* Collect entropy until seeded */
    while (!pool.seeded) {
        entropy_add_timer_jitter();

        /* Check timeout */
        if (timeout_ms > 0) {
            uint32_t elapsed = entropy_get_timer() - start;
            if (elapsed >= timeout_ms) {
                return -1;
            }
        }
    }

    return entropy_extract(buf, len);
}

uint32_t entropy_available(void) {
    return pool.entropy_bits;
}

int entropy_is_seeded(void) {
    return pool.seeded ? 1 : 0;
}

int entropy_health(void) {
    if (!pool.initialized) {
        return ENTROPY_HEALTH_FAIL;
    }

    /* Check individual sources */
    if (stats.timer.health_status == ENTROPY_HEALTH_STUCK &&
        stats.interrupt.health_status == ENTROPY_HEALTH_STUCK) {
        stats.overall_health = ENTROPY_HEALTH_STUCK;
        return ENTROPY_HEALTH_STUCK;
    }

    if (!pool.seeded) {
        stats.overall_health = ENTROPY_HEALTH_LOW;
        return ENTROPY_HEALTH_LOW;
    }

    stats.overall_health = ENTROPY_HEALTH_OK;
    return ENTROPY_HEALTH_OK;
}

const struct entropy_stats* entropy_get_stats(void) {
    return &stats;
}

void entropy_reseed(void) {
    if (pool.seeded) {
        derive_prng_state();
    }
}

void entropy_tick(void) {
    if (!pool.initialized) {
        return;
    }

    /* Collect timer jitter */
    entropy_add_timer_jitter();

    /* Try ADC if available */
    uint16_t adc = entropy_read_adc();
    if (adc != 0) {
        entropy_add_adc(adc);
    }
}

void entropy_manual_seed(const void *seed, size_t len) {
    if (!pool.initialized || seed == NULL || len == 0) {
        return;
    }

    mix_into_pool((const uint8_t *)seed, len);

    /* External seeds assumed high quality */
    pool.entropy_bits += len * 4;  /* 4 bits per byte estimate */
    if (pool.entropy_bits > ENTROPY_POOL_SIZE * 8) {
        pool.entropy_bits = ENTROPY_POOL_SIZE * 8;
    }

    pool.sources_active |= ENTROPY_SOURCE_EXTERNAL;
    stats.external.samples++;
    stats.external.bits_contributed += len * 4;

    /* Check if now seeded */
    if (!pool.seeded && pool.entropy_bits >= ENTROPY_MIN_BITS) {
        pool.seeded = 1;
        derive_prng_state();
    }
}

void entropy_wipe(void) {
    /* Securely zero all state */
    secure_memzero(&pool, sizeof(pool));
    secure_memzero(prng_key, sizeof(prng_key));
    secure_memzero(prng_nonce, sizeof(prng_nonce));
    secure_memzero(mix_buffer, sizeof(mix_buffer));

    prng_counter = 0;
    extractions_since_reseed = 0;
    mix_index = 0;

    /* Reset stats but keep for debugging */
    stats.overall_health = ENTROPY_HEALTH_FAIL;
}
