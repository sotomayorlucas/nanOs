/*
 * NERT Secure Key Storage
 *
 * Provides secure storage and lifecycle management for cryptographic keys.
 * All key material is protected with:
 * - Volatile access to prevent compiler optimization
 * - Secure zeroization on delete
 * - Usage counting and expiration
 * - Atomic key rotation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_KEY_STORE_H
#define NERT_KEY_STORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Maximum number of keys that can be stored */
#if defined(__arm__) || defined(ESP_PLATFORM)
    #define KEY_STORE_MAX_KEYS      4
#else
    #define KEY_STORE_MAX_KEYS      8
#endif

/* Key sizes */
#define KEY_STORE_KEY_SIZE          32      /* 256-bit keys */
#define KEY_STORE_ID_SIZE           16      /* Key identifier size */

/* Key flags */
#define KEY_FLAG_ACTIVE             0x01    /* Key is active and usable */
#define KEY_FLAG_EXPORTABLE         0x02    /* Key can be exported */
#define KEY_FLAG_ROTATABLE          0x04    /* Key can be rotated */
#define KEY_FLAG_MASTER             0x08    /* This is a master key */
#define KEY_FLAG_SESSION            0x10    /* This is a session key */
#define KEY_FLAG_EPHEMERAL          0x20    /* Key for single use */
#define KEY_FLAG_COMPROMISED        0x40    /* Key may be compromised */
#define KEY_FLAG_LOCKED             0x80    /* Key cannot be modified */

/* Error codes */
#define KEY_STORE_OK                0
#define KEY_STORE_ERR_FULL          -1      /* No free slots */
#define KEY_STORE_ERR_NOT_FOUND     -2      /* Key ID not found */
#define KEY_STORE_ERR_EXPIRED       -3      /* Key has expired */
#define KEY_STORE_ERR_LOCKED        -4      /* Key is locked */
#define KEY_STORE_ERR_INVALID       -5      /* Invalid parameters */
#define KEY_STORE_ERR_USAGE_LIMIT   -6      /* Usage count exceeded */

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Secure key container
 * All fields are accessed through volatile pointers to prevent
 * compiler optimizations that might leave key material in memory
 */
struct secure_key {
    uint8_t  key[KEY_STORE_KEY_SIZE];   /* Raw key material */
    uint8_t  id[KEY_STORE_ID_SIZE];     /* Key identifier */
    uint32_t usage_count;               /* Times key has been used */
    uint32_t max_usage;                 /* Maximum allowed uses (0=unlimited) */
    uint32_t created_tick;              /* Creation timestamp */
    uint32_t expires_tick;              /* Expiration timestamp (0=never) */
    uint32_t last_used_tick;            /* Last usage timestamp */
    uint8_t  flags;                     /* Key flags (KEY_FLAG_*) */
    uint8_t  key_type;                  /* Application-defined key type */
    uint8_t  _reserved[2];              /* Alignment padding */
};

/**
 * Key store statistics
 */
struct key_store_stats {
    uint32_t keys_created;              /* Total keys created */
    uint32_t keys_deleted;              /* Total keys deleted */
    uint32_t keys_rotated;              /* Total key rotations */
    uint32_t keys_expired;              /* Keys expired automatically */
    uint32_t usage_total;               /* Total key usages */
    uint32_t access_denied;             /* Access denied count */
    uint16_t slots_used;                /* Current slots in use */
    uint16_t slots_available;           /* Available slots */
};

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize the key store
 * Must be called before any other key store functions.
 * Securely zeros all key storage.
 */
void key_store_init(void);

/**
 * Add a new key to the store
 *
 * @param id        Key identifier (KEY_STORE_ID_SIZE bytes, or NULL for auto)
 * @param key       Key material (KEY_STORE_KEY_SIZE bytes)
 * @param ttl_ms    Time-to-live in milliseconds (0 = no expiration)
 * @param flags     Key flags (KEY_FLAG_*)
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_add(const uint8_t *id, const uint8_t *key,
                  uint32_t ttl_ms, uint8_t flags);

/**
 * Get a key for use
 * Increments usage counter and validates expiration.
 * Returns a volatile pointer to prevent optimization.
 *
 * @param id        Key identifier to look up
 * @param key_out   Output buffer for key (KEY_STORE_KEY_SIZE bytes)
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_get(const uint8_t *id, uint8_t *key_out);

/**
 * Check if a key exists and is valid
 *
 * @param id        Key identifier to check
 * @return          1 if valid, 0 if not found or invalid
 */
int key_store_exists(const uint8_t *id);

/**
 * Get key metadata without retrieving the key
 *
 * @param id            Key identifier
 * @param usage_count   Output: current usage count (can be NULL)
 * @param expires_tick  Output: expiration tick (can be NULL)
 * @param flags         Output: key flags (can be NULL)
 * @return              KEY_STORE_OK on success, error code on failure
 */
int key_store_get_info(const uint8_t *id, uint32_t *usage_count,
                       uint32_t *expires_tick, uint8_t *flags);

/**
 * Delete a key from the store
 * Securely zeroizes all key material before freeing the slot.
 *
 * @param id        Key identifier to delete
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_delete(const uint8_t *id);

/**
 * Rotate a key atomically
 * The old key is securely zeroized and replaced with the new key.
 * This is atomic - either both operations complete or neither does.
 *
 * @param id        Key identifier to rotate
 * @param new_key   New key material (KEY_STORE_KEY_SIZE bytes)
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_rotate(const uint8_t *id, const uint8_t *new_key);

/**
 * Set maximum usage count for a key
 *
 * @param id        Key identifier
 * @param max_usage Maximum uses (0 = unlimited)
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_set_max_usage(const uint8_t *id, uint32_t max_usage);

/**
 * Lock a key to prevent modification or deletion
 *
 * @param id        Key identifier to lock
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_lock(const uint8_t *id);

/**
 * Mark a key as potentially compromised
 * The key remains usable but is flagged for rotation.
 *
 * @param id        Key identifier
 * @return          KEY_STORE_OK on success, error code on failure
 */
int key_store_mark_compromised(const uint8_t *id);

/**
 * Process key expirations
 * Should be called periodically (e.g., from timer tick).
 * Deletes any expired keys.
 *
 * @param current_tick  Current system tick
 * @return              Number of keys expired
 */
int key_store_process_expirations(uint32_t current_tick);

/**
 * Get key store statistics
 *
 * @return  Pointer to stats structure (read-only)
 */
const struct key_store_stats* key_store_get_stats(void);

/**
 * Reset key store statistics
 */
void key_store_reset_stats(void);

/**
 * Securely wipe all keys
 * Emergency function to clear all key material.
 * Used in case of suspected compromise.
 */
void key_store_wipe_all(void);

/**
 * Get number of free slots
 *
 * @return  Number of available key slots
 */
int key_store_free_slots(void);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Secure memory zeroing
 * Uses volatile pointers to prevent compiler optimization.
 *
 * @param ptr   Pointer to memory to zero
 * @param len   Number of bytes to zero
 */
void secure_memzero(void *ptr, size_t len);

/**
 * Constant-time memory comparison
 * Prevents timing attacks when comparing key material.
 *
 * @param a     First buffer
 * @param b     Second buffer
 * @param len   Length to compare
 * @return      0 if equal, non-zero if different
 */
int secure_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NERT_KEY_STORE_H */
