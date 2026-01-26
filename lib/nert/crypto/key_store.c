/*
 * NERT Secure Key Storage - Implementation
 *
 * Provides secure storage and lifecycle management for cryptographic keys.
 *
 * Security considerations:
 * - All key access uses volatile pointers
 * - Keys are zeroized before deletion
 * - No key material in return values
 * - Constant-time comparisons for identifiers
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "key_store.h"
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Key storage array */
static struct secure_key key_slots[KEY_STORE_MAX_KEYS];

/* Statistics */
static struct key_store_stats stats;

/* Initialization flag */
static uint8_t initialized = 0;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Secure memory zeroing - prevents compiler optimization
 */
void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * Constant-time memory comparison
 */
int secure_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;

    while (len--) {
        diff |= *pa++ ^ *pb++;
    }

    return diff;
}

/**
 * Find a key slot by ID
 * Returns slot index or -1 if not found
 */
static int find_key_slot(const uint8_t *id) {
    if (id == NULL) {
        return -1;
    }

    for (int i = 0; i < KEY_STORE_MAX_KEYS; i++) {
        if (key_slots[i].flags & KEY_FLAG_ACTIVE) {
            if (secure_memcmp(key_slots[i].id, id, KEY_STORE_ID_SIZE) == 0) {
                return i;
            }
        }
    }

    return -1;
}

/**
 * Find a free key slot
 * Returns slot index or -1 if no free slots
 */
static int find_free_slot(void) {
    for (int i = 0; i < KEY_STORE_MAX_KEYS; i++) {
        if (!(key_slots[i].flags & KEY_FLAG_ACTIVE)) {
            return i;
        }
    }

    return -1;
}

/**
 * Securely copy key material using volatile pointers
 */
static void secure_key_copy(uint8_t *dest, const uint8_t *src) {
    volatile uint8_t *vdest = (volatile uint8_t *)dest;
    const volatile uint8_t *vsrc = (const volatile uint8_t *)src;

    for (int i = 0; i < KEY_STORE_KEY_SIZE; i++) {
        vdest[i] = vsrc[i];
    }
}

/**
 * Get current tick (weak symbol - can be overridden)
 */
__attribute__((weak))
uint32_t key_store_get_ticks(void) {
    /* Default implementation returns 0
     * Should be overridden to use actual system tick */
    extern uint32_t nert_hal_get_ticks(void);
    return nert_hal_get_ticks();
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

void key_store_init(void) {
    /* Securely zero all key storage */
    for (int i = 0; i < KEY_STORE_MAX_KEYS; i++) {
        secure_memzero(&key_slots[i], sizeof(struct secure_key));
    }

    /* Initialize statistics */
    memset(&stats, 0, sizeof(stats));
    stats.slots_available = KEY_STORE_MAX_KEYS;

    initialized = 1;
}

int key_store_add(const uint8_t *id, const uint8_t *key,
                  uint32_t ttl_ms, uint8_t flags) {
    if (!initialized) {
        return KEY_STORE_ERR_INVALID;
    }

    if (key == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    /* Check if ID already exists */
    if (id != NULL && find_key_slot(id) >= 0) {
        return KEY_STORE_ERR_INVALID;
    }

    /* Find free slot */
    int slot = find_free_slot();
    if (slot < 0) {
        stats.access_denied++;
        return KEY_STORE_ERR_FULL;
    }

    /* Get current tick for timestamps */
    uint32_t now = key_store_get_ticks();

    /* Initialize the slot */
    struct secure_key *sk = &key_slots[slot];

    /* Copy key material securely */
    secure_key_copy(sk->key, key);

    /* Set or generate ID */
    if (id != NULL) {
        memcpy(sk->id, id, KEY_STORE_ID_SIZE);
    } else {
        /* Auto-generate ID from slot index and timestamp */
        secure_memzero(sk->id, KEY_STORE_ID_SIZE);
        sk->id[0] = (uint8_t)slot;
        sk->id[1] = (now >> 24) & 0xFF;
        sk->id[2] = (now >> 16) & 0xFF;
        sk->id[3] = (now >> 8) & 0xFF;
        sk->id[4] = now & 0xFF;
    }

    /* Set metadata */
    sk->usage_count = 0;
    sk->max_usage = 0;  /* Unlimited by default */
    sk->created_tick = now;
    sk->last_used_tick = 0;
    sk->key_type = 0;
    sk->flags = flags | KEY_FLAG_ACTIVE;

    /* Set expiration */
    if (ttl_ms > 0) {
        sk->expires_tick = now + ttl_ms;
    } else {
        sk->expires_tick = 0;  /* No expiration */
    }

    /* Update statistics */
    stats.keys_created++;
    stats.slots_used++;
    stats.slots_available--;

    return KEY_STORE_OK;
}

int key_store_get(const uint8_t *id, uint8_t *key_out) {
    if (!initialized || id == NULL || key_out == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        stats.access_denied++;
        return KEY_STORE_ERR_NOT_FOUND;
    }

    struct secure_key *sk = &key_slots[slot];
    uint32_t now = key_store_get_ticks();

    /* Check if locked due to compromise */
    if (sk->flags & KEY_FLAG_COMPROMISED) {
        /* Allow access but log it */
    }

    /* Check expiration */
    if (sk->expires_tick > 0 && now >= sk->expires_tick) {
        stats.access_denied++;
        return KEY_STORE_ERR_EXPIRED;
    }

    /* Check usage limit */
    if (sk->max_usage > 0 && sk->usage_count >= sk->max_usage) {
        stats.access_denied++;
        return KEY_STORE_ERR_USAGE_LIMIT;
    }

    /* Copy key to output using volatile access */
    secure_key_copy(key_out, sk->key);

    /* Update usage tracking */
    sk->usage_count++;
    sk->last_used_tick = now;
    stats.usage_total++;

    return KEY_STORE_OK;
}

int key_store_exists(const uint8_t *id) {
    if (!initialized || id == NULL) {
        return 0;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return 0;
    }

    struct secure_key *sk = &key_slots[slot];
    uint32_t now = key_store_get_ticks();

    /* Check if expired */
    if (sk->expires_tick > 0 && now >= sk->expires_tick) {
        return 0;
    }

    /* Check usage limit */
    if (sk->max_usage > 0 && sk->usage_count >= sk->max_usage) {
        return 0;
    }

    return 1;
}

int key_store_get_info(const uint8_t *id, uint32_t *usage_count,
                       uint32_t *expires_tick, uint8_t *flags) {
    if (!initialized || id == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    struct secure_key *sk = &key_slots[slot];

    if (usage_count != NULL) {
        *usage_count = sk->usage_count;
    }
    if (expires_tick != NULL) {
        *expires_tick = sk->expires_tick;
    }
    if (flags != NULL) {
        *flags = sk->flags;
    }

    return KEY_STORE_OK;
}

int key_store_delete(const uint8_t *id) {
    if (!initialized || id == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    struct secure_key *sk = &key_slots[slot];

    /* Check if locked */
    if (sk->flags & KEY_FLAG_LOCKED) {
        stats.access_denied++;
        return KEY_STORE_ERR_LOCKED;
    }

    /* Securely zeroize all key material */
    secure_memzero(sk, sizeof(struct secure_key));

    /* Update statistics */
    stats.keys_deleted++;
    stats.slots_used--;
    stats.slots_available++;

    return KEY_STORE_OK;
}

int key_store_rotate(const uint8_t *id, const uint8_t *new_key) {
    if (!initialized || id == NULL || new_key == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    struct secure_key *sk = &key_slots[slot];

    /* Check if locked */
    if (sk->flags & KEY_FLAG_LOCKED) {
        stats.access_denied++;
        return KEY_STORE_ERR_LOCKED;
    }

    /* Check if rotatable */
    if (!(sk->flags & KEY_FLAG_ROTATABLE)) {
        stats.access_denied++;
        return KEY_STORE_ERR_INVALID;
    }

    uint32_t now = key_store_get_ticks();

    /*
     * Atomic rotation:
     * 1. Zero old key
     * 2. Copy new key
     * 3. Update metadata
     *
     * If interrupted, key will be invalid (zeroed) rather than
     * leaving old key material accessible
     */

    /* Zero old key first */
    volatile uint8_t *vkey = (volatile uint8_t *)sk->key;
    for (int i = 0; i < KEY_STORE_KEY_SIZE; i++) {
        vkey[i] = 0;
    }

    /* Copy new key */
    secure_key_copy(sk->key, new_key);

    /* Update metadata */
    sk->usage_count = 0;
    sk->last_used_tick = now;

    /* Clear compromised flag if set */
    sk->flags &= ~KEY_FLAG_COMPROMISED;

    /* Update statistics */
    stats.keys_rotated++;

    return KEY_STORE_OK;
}

int key_store_set_max_usage(const uint8_t *id, uint32_t max_usage) {
    if (!initialized || id == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    struct secure_key *sk = &key_slots[slot];

    if (sk->flags & KEY_FLAG_LOCKED) {
        return KEY_STORE_ERR_LOCKED;
    }

    sk->max_usage = max_usage;
    return KEY_STORE_OK;
}

int key_store_lock(const uint8_t *id) {
    if (!initialized || id == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    key_slots[slot].flags |= KEY_FLAG_LOCKED;
    return KEY_STORE_OK;
}

int key_store_mark_compromised(const uint8_t *id) {
    if (!initialized || id == NULL) {
        return KEY_STORE_ERR_INVALID;
    }

    int slot = find_key_slot(id);
    if (slot < 0) {
        return KEY_STORE_ERR_NOT_FOUND;
    }

    key_slots[slot].flags |= KEY_FLAG_COMPROMISED;
    return KEY_STORE_OK;
}

int key_store_process_expirations(uint32_t current_tick) {
    if (!initialized) {
        return 0;
    }

    int expired_count = 0;

    for (int i = 0; i < KEY_STORE_MAX_KEYS; i++) {
        struct secure_key *sk = &key_slots[i];

        if (!(sk->flags & KEY_FLAG_ACTIVE)) {
            continue;
        }

        /* Check expiration */
        if (sk->expires_tick > 0 && current_tick >= sk->expires_tick) {
            /* Don't delete locked keys */
            if (!(sk->flags & KEY_FLAG_LOCKED)) {
                secure_memzero(sk, sizeof(struct secure_key));
                expired_count++;
                stats.keys_expired++;
                stats.slots_used--;
                stats.slots_available++;
            }
        }
    }

    return expired_count;
}

const struct key_store_stats* key_store_get_stats(void) {
    return &stats;
}

void key_store_reset_stats(void) {
    /* Keep slot counts accurate */
    uint16_t used = stats.slots_used;
    uint16_t available = stats.slots_available;

    memset(&stats, 0, sizeof(stats));

    stats.slots_used = used;
    stats.slots_available = available;
}

void key_store_wipe_all(void) {
    /* Emergency wipe - zero all keys regardless of flags */
    for (int i = 0; i < KEY_STORE_MAX_KEYS; i++) {
        secure_memzero(&key_slots[i], sizeof(struct secure_key));
    }

    /* Reset statistics */
    memset(&stats, 0, sizeof(stats));
    stats.slots_available = KEY_STORE_MAX_KEYS;

    initialized = 0;
}

int key_store_free_slots(void) {
    if (!initialized) {
        return KEY_STORE_MAX_KEYS;
    }

    return stats.slots_available;
}
