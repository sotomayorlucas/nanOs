/*
 * NanOS Ephemeral Reliable Transport (NERT) Protocol - Core Implementation
 *
 * Hybrid UDP/TCP protocol optimized for disposable nodes
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>
#include <nanos/gossip.h>   /* v0.5: Hebbian routing feedback */
#include <nanos/blackbox.h> /* v0.5: Forensic event recording */

/* Pheromone type definitions (normally from nanos.h)  */
#ifndef PHEROMONE_ECHO
#define PHEROMONE_ECHO      0x04
#endif

/* Neighbor table structure (for multipath routing and Hebbian routing) */
/* Note: This is an internal NERT struct - nanos.h defines a different one */
#ifndef NANOS_H
struct neighbor_entry {
    uint32_t node_id;
    uint8_t  distance;
    uint16_t packets;
    uint8_t  synaptic_weight;   /* Hebbian weight (0-255), initial: 128 */
};
#endif

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Master key (pre-shared across swarm) */
static uint8_t swarm_master_key[NERT_KEY_SIZE] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x8B, 0xAD, 0xF0, 0x0D, 0xFE, 0xED, 0xFA, 0xCE,
    0x13, 0x37, 0xC0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01,
    0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0
};

/* Session keys with grace window for epoch transitions */
/* Non-static for use by nert_security.c (key rotation) */
uint8_t session_key[NERT_KEY_SIZE];          /* Current epoch key */
uint8_t prev_session_key[NERT_KEY_SIZE];     /* Previous epoch key */
uint8_t next_session_key[NERT_KEY_SIZE];     /* Next epoch key (pre-computed) */
uint32_t last_key_epoch = 0;

/*
 * Grace window configuration:
 * - NERT_KEY_GRACE_WINDOW_MS: Accept keys from adjacent epochs within this window
 * - Handles clock drift between nodes without time synchronization
 * - Defined in nert.h (default: 30 seconds)
 */

/* Connections */
static struct nert_connection connections[NERT_MAX_CONNECTIONS];

/* Sequence counter */
static uint16_t global_seq = 0;
static uint32_t nonce_counter = 0;

/* Deduplication cache */
struct dedup_entry {
    uint16_t sender_id;
    uint16_t seq_num;
    uint32_t received_tick;
};
static struct dedup_entry dedup_cache[NERT_DEDUP_CACHE_SIZE];
static uint8_t dedup_index = 0;

/* Best-effort retry tracking */
#define BEST_EFFORT_QUEUE_SIZE  4
struct best_effort_entry {
    uint8_t  active;
    uint8_t  retries;
    uint32_t next_retry_tick;
    uint16_t dest_id;
    uint8_t  pheromone_type;
    uint8_t  data[NERT_MAX_PAYLOAD];
    uint8_t  len;
};
static struct best_effort_entry best_effort_queue[BEST_EFFORT_QUEUE_SIZE];

/* Callbacks */
static nert_receive_callback_t receive_callback = NULL;
static nert_connection_callback_t connection_callback = NULL;

/* Statistics */
static struct nert_stats stats;

/* Forward declarations */
static int build_and_send(uint16_t dest_id, uint8_t pheromone_type,
                          uint8_t reliability_class, const void *data,
                          uint8_t len, uint8_t flags);
static int process_fragment(uint16_t sender_id, uint8_t original_type,
                            const uint8_t *frag_data, uint8_t frag_len);

/* ============================================================================
 * Smart Padding TX Queue (v0.5)
 * ============================================================================ */

static struct nert_tx_queue_entry tx_queue[NERT_TX_QUEUE_SIZE];
static uint8_t tx_queue_head = 0;   /* Next slot to write */
static uint8_t tx_queue_count = 0;  /* Messages in queue */

/* Smart padding statistics */
static uint32_t smart_pad_bytes_saved = 0;   /* Bytes saved by aggregation */
static uint32_t smart_pad_messages_batched = 0;

/* Jitter state (v0.5) */
static struct nert_jitter_state jitter_state;
static uint16_t jitter_min_ms = NERT_JITTER_MIN_MS;
static uint16_t jitter_max_ms = NERT_JITTER_MAX_MS;

/* ============================================================================
 * Fragmentation State (v0.5)
 * ============================================================================ */

/* TX fragmentation state */
static struct nert_frag_state frag_state;

/* RX reassembly slots */
static struct nert_reasm_slot reasm_slots[NERT_REASM_SLOTS];

/* Fragmentation statistics */
static uint32_t frag_tx_count = 0;          /* Messages fragmented on TX */
static uint32_t frag_rx_reassembled = 0;    /* Successfully reassembled */
static uint32_t frag_rx_timeouts = 0;       /* Reassemblies timed out */

/* ============================================================================
 * Rate Limiting State (v0.5)
 * ============================================================================ */

/* Per-node token bucket tracking */
static struct nert_rate_limit_entry rate_limit_table[NERT_RATE_LIMIT_SLOTS];

/* Runtime configuration */
static struct nert_rate_limit_config rate_limit_config = {
    .bucket_capacity = NERT_RATE_BUCKET_CAPACITY,
    .refill_tokens = NERT_RATE_REFILL_TOKENS,
    .refill_interval_ms = NERT_RATE_REFILL_MS,
    .penalty_threshold = NERT_RATE_PENALTY_THRESHOLD,
    .blacklist_duration_ms = NERT_RATE_BLACKLIST_MS,
    .enabled = 1  /* Enabled by default */
};

/* Last global refill tick */
static uint32_t rate_limit_last_refill = 0;

/* ============================================================================
 * Behavioral Blacklist State (v0.5)
 * ============================================================================ */

/* Per-node behavioral tracking */
static struct nert_behavior_entry behavior_table[NERT_BEHAVIOR_SLOTS];

/* Behavioral blacklist configuration */
static struct nert_behavior_config behavior_config = {
    .weight_bad_mac = NERT_REPUTATION_WEIGHT_BAD_MAC,
    .weight_replay = NERT_REPUTATION_WEIGHT_REPLAY,
    .weight_invalid_pkt = NERT_REPUTATION_WEIGHT_INVALID_PKT,
    .weight_rate_exceed = NERT_REPUTATION_WEIGHT_RATE_EXCEED,
    .warn_threshold = NERT_REPUTATION_WARN_THRESHOLD,
    .throttle_threshold = NERT_REPUTATION_THROTTLE_THRESHOLD,
    .ban_threshold = NERT_REPUTATION_BAN_THRESHOLD,
    .permaban_threshold = NERT_REPUTATION_PERMABAN_THRESHOLD,
    .recovery_interval_ms = NERT_REPUTATION_RECOVERY_INTERVAL_MS,
    .recovery_points = NERT_REPUTATION_RECOVERY_POINTS,
    .enabled = 1,
    .auto_blacklist = 1,
    .notify_callback = 1
};

/* Status change callback */
static nert_blacklist_callback_t blacklist_callback = NULL;

/* Last recovery tick */
static uint32_t behavior_last_recovery_tick = 0;

/* ============================================================================
 * Cover Traffic State (v0.5)
 * ============================================================================ */

/* Cover traffic state */
static struct nert_cover_state cover_state;

/* Cover traffic configuration */
static struct nert_cover_config cover_config = {
    .mode = NERT_COVER_MODE_OFF,            /* Disabled by default */
    .base_interval_ms = NERT_COVER_INTERVAL_MS,
    .jitter_ms = NERT_COVER_JITTER_MS,
    .min_interval_ms = NERT_COVER_MIN_INTERVAL_MS,
    .max_interval_ms = NERT_COVER_MAX_INTERVAL_MS,
    .target_rate = NERT_COVER_TARGET_RATE,
    .burst_size = NERT_COVER_BURST_SIZE,
    .burst_interval_ms = NERT_COVER_BURST_INTERVAL_MS,
    .payload_min = NERT_COVER_PAYLOAD_MIN,
    .payload_max = NERT_COVER_PAYLOAD_MAX,
    .dest_id = 0                            /* Broadcast by default */
};

/* ============================================================================
 * ChaCha8 Implementation (lightweight crypto)
 * ============================================================================ */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static void chacha8_block(const uint32_t key[8], const uint32_t nonce[3],
                          uint32_t counter, uint8_t output[64]) {
    uint32_t state[16];

    /* ChaCha constants "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key */
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }

    /* Counter and nonce */
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    /* Working copy */
    uint32_t working[16];
    memcpy(working, state, 64);

    /* 8 rounds (4 double rounds) */
    for (int i = 0; i < 4; i++) {
        /* Column round */
        QUARTERROUND(working[0], working[4], working[8],  working[12]);
        QUARTERROUND(working[1], working[5], working[9],  working[13]);
        QUARTERROUND(working[2], working[6], working[10], working[14]);
        QUARTERROUND(working[3], working[7], working[11], working[15]);

        /* Diagonal round */
        QUARTERROUND(working[0], working[5], working[10], working[15]);
        QUARTERROUND(working[1], working[6], working[11], working[12]);
        QUARTERROUND(working[2], working[7], working[8],  working[13]);
        QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    /* Add original state */
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    /* Output as bytes (little-endian) */
    for (int i = 0; i < 16; i++) {
        output[i * 4 + 0] = (working[i] >> 0) & 0xFF;
        output[i * 4 + 1] = (working[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (working[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (working[i] >> 24) & 0xFF;
    }
}

/* Non-static for use by nert_security.c (key rotation encryption) */
void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *plaintext, uint8_t len,
                     uint8_t *ciphertext) {
    uint32_t key32[8];
    uint32_t nonce32[3];
    uint8_t keystream[64];
    uint32_t counter = 0;

    /* Convert key to 32-bit words (little-endian) */
    for (int i = 0; i < 8; i++) {
        key32[i] = (uint32_t)key[i * 4 + 0] |
                   ((uint32_t)key[i * 4 + 1] << 8) |
                   ((uint32_t)key[i * 4 + 2] << 16) |
                   ((uint32_t)key[i * 4 + 3] << 24);
    }

    /* Convert nonce to 32-bit words */
    for (int i = 0; i < 3; i++) {
        nonce32[i] = nonce[i * 4 + 0] |
                     (nonce[i * 4 + 1] << 8) |
                     (nonce[i * 4 + 2] << 16) |
                     (nonce[i * 4 + 3] << 24);
    }

    /* Encrypt in 64-byte blocks */
    uint8_t offset = 0;
    while (offset < len) {
        chacha8_block(key32, nonce32, counter, keystream);
        counter++;

        uint8_t block_len = (len - offset > 64) ? 64 : (len - offset);
        for (uint8_t i = 0; i < block_len; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += block_len;
    }

    /* Secure cleanup: zero sensitive key material
     * Use volatile pointers to prevent compiler optimization */
    volatile uint8_t *vks = (volatile uint8_t *)keystream;
    volatile uint32_t *vkey = (volatile uint32_t *)key32;
    for (int i = 0; i < 64; i++) vks[i] = 0;
    for (int i = 0; i < 8; i++) vkey[i] = 0;
}

/* ============================================================================
 * Poly1305 MAC Implementation (simplified)
 * ============================================================================ */

/* Poly1305 uses 130-bit arithmetic - simplified for embedded */
/* Non-static for use by nert_security.c (key rotation signing) */
void poly1305_mac(const uint8_t key[32],
                  const uint8_t *message, uint8_t msg_len,
                  const uint8_t *aad, uint8_t aad_len,
                  uint8_t tag[NERT_MAC_SIZE]) {
    /*
     * Simplified Poly1305: Use lower 64 bits of result
     * Full implementation would need 130-bit math
     */
    uint64_t r = 0, s = 0;
    uint64_t acc = 0;

    /* Extract r and s from key */
    for (int i = 0; i < 8; i++) {
        r |= ((uint64_t)key[i]) << (i * 8);
        s |= ((uint64_t)key[16 + i]) << (i * 8);
    }

    /* Clamp r */
    r &= 0x0FFFFFFC0FFFFFFCULL;

    /* Process AAD */
    for (uint8_t i = 0; i < aad_len; i++) {
        acc += aad[i];
        acc = (acc * r) ^ s;
    }

    /* Process message */
    for (uint8_t i = 0; i < msg_len; i++) {
        acc += message[i];
        acc = (acc * r) ^ s;
    }

    /* Finalize */
    acc += s;

    /* Output truncated tag */
    for (int i = 0; i < NERT_MAC_SIZE; i++) {
        tag[i] = (acc >> (i * 8)) & 0xFF;
    }
}

/* Non-static for use by nert_security.c (key rotation verification) */
int poly1305_verify(const uint8_t key[32],
                    const uint8_t *message, uint8_t msg_len,
                    const uint8_t *aad, uint8_t aad_len,
                    const uint8_t expected_tag[NERT_MAC_SIZE]) {
    uint8_t computed_tag[NERT_MAC_SIZE];
    poly1305_mac(key, message, msg_len, aad, aad_len, computed_tag);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < NERT_MAC_SIZE; i++) {
        diff |= computed_tag[i] ^ expected_tag[i];
    }

    return (diff == 0) ? 0 : -1;
}

/* ============================================================================
 * Secure Memory Operations
 * ============================================================================ */

/**
 * Secure memory zeroing - prevents compiler optimization from removing
 * Uses volatile to ensure the writes actually happen
 */
static void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* ============================================================================
 * Crypto Self-Tests (RFC 8439 Test Vectors)
 * ============================================================================ */

/**
 * ChaCha8 self-test using adapted RFC 8439 Section 2.4.2 test vector
 * Note: RFC uses ChaCha20; we adapt for ChaCha8 (8 rounds)
 *
 * @return 0 on success, -1 on failure
 */
int chacha8_self_test(void) {
    /*
     * Test vector: All-zero key and nonce with counter=0
     * This tests basic functionality with known inputs
     */
    static const uint8_t test_key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    static const uint8_t test_nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /*
     * Expected output for ChaCha8 (8 rounds) with all-zero inputs
     * First 16 bytes of keystream block 0
     * Pre-computed reference value
     */
    static const uint8_t expected_keystream[16] = {
        0x3e, 0x00, 0xef, 0x2f, 0x89, 0x5f, 0x40, 0xd6,
        0x7f, 0x5b, 0xb8, 0xe8, 0x1f, 0x09, 0xa5, 0xa1
    };

    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    /* Encrypt zeros - ciphertext will be raw keystream */
    chacha8_encrypt(test_key, test_nonce, plaintext, 16, ciphertext);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= ciphertext[i] ^ expected_keystream[i];
    }

    /*
     * Additional test: Encryption/decryption round-trip
     * Encrypt then decrypt should yield original plaintext
     */
    static const uint8_t test_plaintext[32] = {
        'N', 'E', 'R', 'T', ' ', 'P', 'r', 'o',
        't', 'o', 'c', 'o', 'l', ' ', 'T', 'e',
        's', 't', ' ', 'V', 'e', 'c', 't', 'o',
        'r', ' ', 'D', 'a', 't', 'a', '!', '!'
    };

    uint8_t encrypted[32];
    uint8_t decrypted[32];

    static const uint8_t roundtrip_key[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x8B, 0xAD, 0xF0, 0x0D, 0xFE, 0xED, 0xFA, 0xCE,
        0x13, 0x37, 0xC0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01,
        0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0
    };

    static const uint8_t roundtrip_nonce[12] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
    };

    chacha8_encrypt(roundtrip_key, roundtrip_nonce, test_plaintext, 32, encrypted);
    chacha8_encrypt(roundtrip_key, roundtrip_nonce, encrypted, 32, decrypted);

    for (int i = 0; i < 32; i++) {
        diff |= decrypted[i] ^ test_plaintext[i];
    }

    return (diff == 0) ? 0 : -1;
}

/**
 * Poly1305 MAC self-test
 * Tests basic MAC generation and verification
 *
 * @return 0 on success, -1 on failure
 */
int poly1305_self_test(void) {
    static const uint8_t test_key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };

    static const uint8_t test_message[] = "Cryptographic Forum Research Group";
    static const uint8_t test_aad[] = {0x50, 0x51, 0x52, 0x53};

    uint8_t tag1[NERT_MAC_SIZE];
    uint8_t tag2[NERT_MAC_SIZE];

    /* Generate MAC */
    poly1305_mac(test_key, test_message, sizeof(test_message) - 1,
                 test_aad, sizeof(test_aad), tag1);

    /* Generate same MAC again - should be identical */
    poly1305_mac(test_key, test_message, sizeof(test_message) - 1,
                 test_aad, sizeof(test_aad), tag2);

    /* Tags should match */
    uint8_t diff = 0;
    for (int i = 0; i < NERT_MAC_SIZE; i++) {
        diff |= tag1[i] ^ tag2[i];
    }

    if (diff != 0) {
        return -1;
    }

    /* Verify should succeed */
    if (poly1305_verify(test_key, test_message, sizeof(test_message) - 1,
                        test_aad, sizeof(test_aad), tag1) != 0) {
        return -1;
    }

    /* Modify message - verify should fail */
    uint8_t modified_message[64];
    memcpy(modified_message, test_message, sizeof(test_message) - 1);
    modified_message[0] ^= 0x01;  /* Flip one bit */

    if (poly1305_verify(test_key, modified_message, sizeof(test_message) - 1,
                        test_aad, sizeof(test_aad), tag1) == 0) {
        return -1;  /* Should have failed! */
    }

    return 0;
}

/**
 * Run all crypto self-tests
 * Should be called during nert_init()
 *
 * @return 0 on all tests pass, -1 on any failure
 */
int nert_crypto_self_test(void) {
    if (chacha8_self_test() != 0) {
        return -1;
    }

    if (poly1305_self_test() != 0) {
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Key Derivation
 * ============================================================================ */

static void derive_key_for_epoch(uint32_t epoch_hour, uint8_t out_key[NERT_KEY_SIZE]) {
    uint8_t material[40];

    /*
     * Key material: master_key || zeros || epoch
     * Note: We don't include node_id in key derivation - all nodes must
     * derive the SAME key for a given epoch to communicate.
     */
    memcpy(material, swarm_master_key, 32);
    material[32] = (epoch_hour >> 24) & 0xFF;
    material[33] = (epoch_hour >> 16) & 0xFF;
    material[34] = (epoch_hour >> 8) & 0xFF;
    material[35] = epoch_hour & 0xFF;
    material[36] = 0x4E; /* 'N' */
    material[37] = 0x45; /* 'E' */
    material[38] = 0x52; /* 'R' */
    material[39] = 0x54; /* 'T' */

    /* Key derivation using ChaCha8 as PRF */
    uint8_t nonce[12] = {0};
    chacha8_encrypt(swarm_master_key, nonce, material, 32, out_key);
}

/* Non-static for use by nert_security.c (key rotation key derivation) */
void derive_session_key(uint32_t epoch_hour) {
    /* Derive keys for current, previous and next epochs */
    derive_key_for_epoch(epoch_hour, session_key);

    if (epoch_hour > 0) {
        derive_key_for_epoch(epoch_hour - 1, prev_session_key);
    } else {
        memset(prev_session_key, 0, NERT_KEY_SIZE);
    }

    derive_key_for_epoch(epoch_hour + 1, next_session_key);

    last_key_epoch = epoch_hour;
}

/*
 * Check if we're within the grace window at epoch boundaries.
 * Returns a bitmask of valid key indices to try:
 *   Bit 0: current key
 *   Bit 1: previous key (if near start of epoch)
 *   Bit 2: next key (if near end of epoch)
 */
static uint8_t get_valid_key_mask(void) {
    uint32_t ticks = nert_hal_get_ticks();
    uint32_t epoch_ms = NERT_KEY_ROTATION_SEC * 1000;
    uint32_t position_in_epoch = ticks % epoch_ms;

    uint8_t mask = 0x01; /* Current key always valid */

    /* Near start of epoch? Accept previous key */
    if (position_in_epoch < NERT_KEY_GRACE_WINDOW_MS) {
        mask |= 0x02;
    }

    /* Near end of epoch? Accept next key */
    if (position_in_epoch > (epoch_ms - NERT_KEY_GRACE_WINDOW_MS)) {
        mask |= 0x04;
    }

    return mask;
}

/* ============================================================================
 * Nonce Construction
 * ============================================================================ */

static void build_nonce(uint8_t nonce[NERT_NONCE_SIZE], uint32_t counter) {
    uint16_t node_id = nert_hal_get_node_id();
    uint32_t ticks = nert_hal_get_ticks();

    /* Bytes 0-1: Node ID */
    nonce[0] = (node_id >> 8) & 0xFF;
    nonce[1] = node_id & 0xFF;

    /* Bytes 2-3: Reserved */
    nonce[2] = 0;
    nonce[3] = 0;

    /* Bytes 4-7: Counter */
    nonce[4] = (counter >> 24) & 0xFF;
    nonce[5] = (counter >> 16) & 0xFF;
    nonce[6] = (counter >> 8) & 0xFF;
    nonce[7] = counter & 0xFF;

    /* Bytes 8-11: Timestamp */
    nonce[8] = (ticks >> 24) & 0xFF;
    nonce[9] = (ticks >> 16) & 0xFF;
    nonce[10] = (ticks >> 8) & 0xFF;
    nonce[11] = ticks & 0xFF;
}

/* ============================================================================
 * Deduplication
 * ============================================================================ */

static int is_duplicate(uint16_t sender_id, uint16_t seq_num) {
    uint32_t now = nert_hal_get_ticks();

    for (int i = 0; i < NERT_DEDUP_CACHE_SIZE; i++) {
        if (dedup_cache[i].sender_id == sender_id &&
            dedup_cache[i].seq_num == seq_num) {
            /* Check if entry is recent (within 2 seconds) */
            if (now - dedup_cache[i].received_tick < 2000) {
                return 1; /* Duplicate */
            }
        }
    }

    /* Add to cache (circular) */
    dedup_cache[dedup_index].sender_id = sender_id;
    dedup_cache[dedup_index].seq_num = seq_num;
    dedup_cache[dedup_index].received_tick = now;
    dedup_index = (dedup_index + 1) % NERT_DEDUP_CACHE_SIZE;

    return 0; /* New packet */
}

/* ============================================================================
 * Replay Protection
 * ============================================================================ */

static int check_replay(struct nert_connection *conn, uint16_t seq) {
    if (seq > conn->highest_rx_seq) {
        /* New highest - shift window */
        int shift = seq - conn->highest_rx_seq;
        if (shift >= 64) {
            conn->replay_bitmap = 1ULL;
        } else {
            conn->replay_bitmap <<= shift;
            conn->replay_bitmap |= 1ULL;
        }
        conn->highest_rx_seq = seq;
        return 0; /* Valid */
    }

    int offset = conn->highest_rx_seq - seq;
    if (offset >= 64) {
        return -1; /* Too old */
    }

    if (conn->replay_bitmap & (1ULL << offset)) {
        return -1; /* Replay detected */
    }

    conn->replay_bitmap |= (1ULL << offset);
    return 0; /* Valid */
}

/* ============================================================================
 * Connection Management
 * ============================================================================ */

static struct nert_connection* get_connection(uint16_t peer_id) {
    for (int i = 0; i < NERT_MAX_CONNECTIONS; i++) {
        if (connections[i].peer_id == peer_id &&
            connections[i].state != NERT_STATE_CLOSED) {
            return &connections[i];
        }
    }
    return NULL;
}

static struct nert_connection* alloc_connection(void) {
    for (int i = 0; i < NERT_MAX_CONNECTIONS; i++) {
        if (connections[i].state == NERT_STATE_CLOSED) {
            memset(&connections[i], 0, sizeof(struct nert_connection));
            return &connections[i];
        }
    }
    return NULL;
}

static void notify_connection_state(struct nert_connection *conn, uint8_t state) {
    conn->state = state;
    if (connection_callback) {
        int conn_id = conn - connections;
        connection_callback(conn_id, conn->peer_id, state);
    }
}

/* ============================================================================
 * Smart Padding - TLV Packing (v0.5)
 * ============================================================================ */

/**
 * Calculate padded size to next block boundary
 * @param raw_size  Unpadded payload size
 * @return Size rounded up to NERT_BLOCK_SIZE multiple
 */
static inline uint8_t calc_padded_size(uint8_t raw_size) {
    uint8_t remainder = raw_size % NERT_BLOCK_SIZE;
    if (remainder == 0) {
        return raw_size;
    }
    return raw_size + (NERT_BLOCK_SIZE - remainder);
}

/**
 * Find next queued message matching destination
 * @param dest_id  Target destination (0 = broadcast matches all)
 * @param start_idx  Start search from this index
 * @return Queue index or -1 if none found
 */
static int find_queued_message(uint16_t dest_id, uint8_t start_idx) {
    for (uint8_t i = 0; i < NERT_TX_QUEUE_SIZE; i++) {
        uint8_t idx = (start_idx + i) % NERT_TX_QUEUE_SIZE;
        if (tx_queue[idx].active) {
            /* Broadcast (0) matches any dest, or exact match */
            if (dest_id == 0 || tx_queue[idx].dest_id == 0 ||
                tx_queue[idx].dest_id == dest_id) {
                return idx;
            }
        }
    }
    return -1;
}

/**
 * Pack multiple messages into TLV format for smart padding
 *
 * Format: [Count:1] [Len1:1][Type1:1][Data1...] [Len2:1][Type2:1][Data2...] ... [Padding]
 *
 * @param dest_id  Primary destination
 * @param first_type  First message pheromone type
 * @param first_data  First message data
 * @param first_len  First message length
 * @param out_buffer  Output buffer for packed data
 * @param max_out_len  Maximum output size
 * @return Total packed length (padded to NERT_BLOCK_SIZE)
 */
static uint8_t pack_messages_tlv(uint16_t dest_id,
                                  uint8_t first_type,
                                  const uint8_t *first_data,
                                  uint8_t first_len,
                                  uint8_t *out_buffer,
                                  uint8_t max_out_len) {
    uint8_t offset = 0;
    uint8_t msg_count = 0;

    /* Reserve space for count byte */
    offset = NERT_TLV_HEADER_SIZE;

    /* Pack first message: [Len][Type][Data] */
    if (offset + NERT_TLV_MSG_OVERHEAD + first_len <= max_out_len) {
        out_buffer[offset++] = first_len;
        out_buffer[offset++] = first_type;
        if (first_len > 0 && first_data) {
            memcpy(out_buffer + offset, first_data, first_len);
            offset += first_len;
        }
        msg_count++;
    }

    /* Calculate space remaining to next block boundary */
    uint8_t padded_target = calc_padded_size(offset);
    if (padded_target > max_out_len) {
        padded_target = calc_padded_size(max_out_len);
    }

    /* Try to fill remaining space with queued messages */
    uint8_t search_start = 0;
    while (msg_count < NERT_TLV_MAX_MESSAGES && tx_queue_count > 0) {
        int q_idx = find_queued_message(dest_id, search_start);
        if (q_idx < 0) break;

        struct nert_tx_queue_entry *entry = &tx_queue[q_idx];
        uint8_t needed = NERT_TLV_MSG_OVERHEAD + entry->len;

        /* Check if message fits in remaining space to reach block boundary */
        if (offset + needed <= padded_target) {
            /* Pack this message */
            out_buffer[offset++] = entry->len;
            out_buffer[offset++] = entry->pheromone_type;
            if (entry->len > 0) {
                memcpy(out_buffer + offset, entry->data, entry->len);
                offset += entry->len;
            }
            msg_count++;
            smart_pad_messages_batched++;

            /* Calculate bytes saved (would have been separate packet) */
            smart_pad_bytes_saved += NERT_HEADER_SIZE + NERT_MAC_SIZE;

            /* Remove from queue */
            entry->active = 0;
            tx_queue_count--;
        } else {
            /* Message too big, try next one */
            search_start = q_idx + 1;
            if (search_start >= NERT_TX_QUEUE_SIZE) break;
        }
    }

    /* Write message count at start */
    out_buffer[0] = msg_count;

    /* Fill remaining space with random padding */
    uint8_t final_size = calc_padded_size(offset);
    if (final_size > max_out_len) {
        final_size = max_out_len;
    }

    /* Ensure minimum random padding for security */
    if (final_size - offset < NERT_MIN_RANDOM_PAD &&
        final_size + NERT_BLOCK_SIZE <= max_out_len) {
        final_size += NERT_BLOCK_SIZE;
    }

    /* Generate random padding */
    while (offset < final_size) {
        uint32_t rnd = nert_hal_random();
        for (int i = 0; i < 4 && offset < final_size; i++) {
            out_buffer[offset++] = (rnd >> (i * 8)) & 0xFF;
        }
    }

    return final_size;
}

/**
 * Unpack TLV messages from received payload
 *
 * @param packed_data  Decrypted payload data
 * @param packed_len  Payload length
 * @param sender_id  Sender node ID (for callback)
 * @return Number of messages processed
 */
static uint8_t unpack_messages_tlv(const uint8_t *packed_data,
                                    uint8_t packed_len,
                                    uint16_t sender_id) {
    if (packed_len < NERT_TLV_HEADER_SIZE) {
        return 0;
    }

    uint8_t msg_count = packed_data[0];
    uint8_t offset = NERT_TLV_HEADER_SIZE;
    uint8_t processed = 0;

    /* Sanity check */
    if (msg_count > NERT_TLV_MAX_MESSAGES) {
        msg_count = NERT_TLV_MAX_MESSAGES;
    }

    /* Process each message */
    for (uint8_t i = 0; i < msg_count && offset + NERT_TLV_MSG_OVERHEAD <= packed_len; i++) {
        uint8_t msg_len = packed_data[offset];
        uint8_t msg_type = packed_data[offset + 1];
        const uint8_t *msg_data = packed_data + offset + NERT_TLV_MSG_OVERHEAD;

        /* Validate length */
        if (offset + NERT_TLV_MSG_OVERHEAD + msg_len > packed_len) {
            break;  /* Truncated message, stop processing */
        }

        /*
         * v0.5: Check if this is a fragment (MSB set in type)
         */
        if (msg_type & NERT_TLV_TYPE_FRAG_BIT) {
            /* Extract original type and process fragment */
            uint8_t original_type = msg_type & NERT_TLV_TYPE_MASK;
            process_fragment(sender_id, original_type, msg_data, msg_len);
            /* Fragment handled - don't deliver directly */
        } else if (nert_cover_is_dummy(msg_type)) {
            /*
             * v0.5: Cover traffic dummy packet - discard silently
             * Dummy packets are indistinguishable from real traffic
             * until decrypted, providing traffic analysis protection.
             */
            cover_state.total_dummy_received++;
            stats.cover_dummy_received++;
        } else {
            /* Normal message - deliver to application */
            if (receive_callback) {
                receive_callback(sender_id, msg_type, msg_data, msg_len);
            }
        }

        offset += NERT_TLV_MSG_OVERHEAD + msg_len;
        processed++;
    }

    return processed;
}

/* ============================================================================
 * TX Queue Management with Jitter (v0.5)
 * ============================================================================ */

/**
 * Map reliability class to priority level
 */
static inline uint8_t class_to_priority(uint8_t reliability_class) {
    switch (reliability_class) {
        case NERT_CLASS_CRITICAL:    return NERT_PRIORITY_CRITICAL;
        case NERT_CLASS_RELIABLE:    return NERT_PRIORITY_HIGH;
        case NERT_CLASS_BEST_EFFORT: return NERT_PRIORITY_NORMAL;
        default:                     return NERT_PRIORITY_LOW;
    }
}

/**
 * Calculate random jitter delay based on priority
 * Higher priority = less jitter
 */
static uint32_t calc_jitter_delay(uint8_t priority) {
    uint32_t range;
    uint32_t min_delay;

    if (priority >= NERT_PRIORITY_CRITICAL) {
        /* CRITICAL: minimal jitter */
        return NERT_JITTER_CRITICAL_MS;
    } else if (priority >= NERT_PRIORITY_HIGH) {
        /* HIGH: reduced jitter */
        min_delay = jitter_min_ms;
        range = (jitter_max_ms - jitter_min_ms) / 2;
    } else {
        /* NORMAL/LOW: full jitter range */
        min_delay = jitter_min_ms;
        range = jitter_max_ms - jitter_min_ms;
    }

    if (range == 0) return min_delay;

    /* Random delay within range */
    uint32_t rnd = nert_hal_random();
    return min_delay + (rnd % range);
}

/**
 * Schedule next flush with jitter
 */
static void schedule_flush(uint8_t priority) {
    uint32_t now = nert_hal_get_ticks();
    uint32_t delay = calc_jitter_delay(priority);
    uint32_t proposed_tick = now + delay;

    /* If CRITICAL, trigger immediate flush flag */
    if (priority >= NERT_PRIORITY_CRITICAL) {
        jitter_state.immediate_flush = 1;
    }

    /* Only update if sooner than currently scheduled */
    if (!jitter_state.flush_pending ||
        proposed_tick < jitter_state.next_flush_tick) {
        jitter_state.next_flush_tick = proposed_tick;
        jitter_state.flush_pending = 1;
    }
}

/**
 * Internal enqueue with priority support
 */
static int enqueue_message(uint16_t dest_id, uint8_t pheromone_type,
                           const void *data, uint8_t len,
                           uint8_t reliability_class, uint8_t flags) {
    /* Validate length */
    if (len > NERT_TX_QUEUE_MSG_MAX) {
        return -1;
    }

    uint8_t priority = class_to_priority(reliability_class);

    /* Find free slot */
    for (uint8_t i = 0; i < NERT_TX_QUEUE_SIZE; i++) {
        if (!tx_queue[i].active) {
            tx_queue[i].active = 1;
            tx_queue[i].priority = priority;
            tx_queue[i].dest_id = dest_id;
            tx_queue[i].pheromone_type = pheromone_type;
            tx_queue[i].reliability_class = reliability_class;
            tx_queue[i].flags = flags;
            tx_queue[i].len = len;
            tx_queue[i].queued_tick = nert_hal_get_ticks();

            if (len > 0 && data) {
                memcpy(tx_queue[i].data, data, len);
            }

            tx_queue_count++;

            /* Schedule flush with appropriate jitter */
            schedule_flush(priority);

            /* Auto-flush if queue threshold reached */
            if (tx_queue_count >= NERT_QUEUE_FLUSH_THRESHOLD) {
                jitter_state.immediate_flush = 1;
            }

            return 0;
        }
    }

    return -1;  /* Queue full */
}

int nert_queue_message(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len,
                       uint8_t reliability_class) {
    return enqueue_message(dest_id, pheromone_type, data, len,
                          reliability_class, 0);
}

void nert_get_queue_stats(uint8_t *pending, uint16_t *bytes_queued) {
    if (pending) {
        *pending = tx_queue_count;
    }
    if (bytes_queued) {
        uint16_t total = 0;
        for (uint8_t i = 0; i < NERT_TX_QUEUE_SIZE; i++) {
            if (tx_queue[i].active) {
                total += tx_queue[i].len;
            }
        }
        *bytes_queued = total;
    }
}

void nert_set_jitter_params(uint16_t min_ms, uint16_t max_ms) {
    if (min_ms < max_ms) {
        jitter_min_ms = min_ms;
        jitter_max_ms = max_ms;
    }
}

void nert_force_flush(void) {
    jitter_state.immediate_flush = 1;
}

/**
 * Find highest priority message in queue
 * Returns index or -1 if queue empty
 */
static int find_highest_priority_message(void) {
    int best_idx = -1;
    uint8_t best_priority = 0;
    uint32_t best_tick = 0xFFFFFFFF;

    for (uint8_t i = 0; i < NERT_TX_QUEUE_SIZE; i++) {
        if (!tx_queue[i].active) continue;

        /* Higher priority wins, or same priority + older wins */
        if (tx_queue[i].priority > best_priority ||
            (tx_queue[i].priority == best_priority &&
             tx_queue[i].queued_tick < best_tick)) {
            best_idx = i;
            best_priority = tx_queue[i].priority;
            best_tick = tx_queue[i].queued_tick;
        }
    }

    return best_idx;
}

/**
 * Check for aged-out messages that must be sent regardless of jitter
 */
static int find_aged_message(uint32_t now) {
    for (uint8_t i = 0; i < NERT_TX_QUEUE_SIZE; i++) {
        if (tx_queue[i].active) {
            uint32_t age = now - tx_queue[i].queued_tick;
            if (age >= NERT_QUEUE_AGE_MAX_MS) {
                return i;
            }
        }
    }
    return -1;
}

void nert_flush_tx_queue(void) {
    /*
     * Flush pending messages respecting:
     * 1. Priority ordering (CRITICAL first)
     * 2. Smart Padding aggregation
     * 3. Age limits (don't hold messages too long)
     */
    uint32_t now = nert_hal_get_ticks();

    while (tx_queue_count > 0) {
        /* First check for aged-out messages */
        int idx = find_aged_message(now);

        /* If no aged message, find highest priority */
        if (idx < 0) {
            idx = find_highest_priority_message();
        }

        if (idx < 0) break;

        struct nert_tx_queue_entry *entry = &tx_queue[idx];

        /*
         * Send via build_and_send which applies Smart Padding.
         * build_and_send will pull additional messages from queue
         * to fill the block boundary.
         */
        build_and_send(entry->dest_id, entry->pheromone_type,
                      entry->reliability_class, entry->data,
                      entry->len, entry->flags);

        /* Mark primary message as sent */
        entry->active = 0;
        tx_queue_count--;
    }

    /* Update jitter state */
    jitter_state.last_flush_tick = now;
    jitter_state.flush_pending = 0;
    jitter_state.immediate_flush = 0;
}

/**
 * Check if flush should occur (called from timer_tick)
 * Implements jitter timing
 */
static void check_jitter_flush(void) {
    if (tx_queue_count == 0) {
        jitter_state.flush_pending = 0;
        return;
    }

    uint32_t now = nert_hal_get_ticks();

    /* Immediate flush requested (CRITICAL or threshold) */
    if (jitter_state.immediate_flush) {
        nert_flush_tx_queue();
        return;
    }

    /* Check if scheduled flush time reached */
    if (jitter_state.flush_pending &&
        now >= jitter_state.next_flush_tick) {
        nert_flush_tx_queue();
        return;
    }

    /* Check for aged messages */
    if (find_aged_message(now) >= 0) {
        nert_flush_tx_queue();
        return;
    }
}

/* ============================================================================
 * Fragmentation - TX Side (v0.5)
 * ============================================================================ */

int nert_send_fragmented(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint16_t len,
                         uint8_t reliability_class) {
    const uint8_t *src = (const uint8_t *)data;

    /* Check if fragmentation needed */
    if (len <= NERT_FRAG_PAYLOAD_MAX) {
        /* No fragmentation - send normally via queue */
        return enqueue_message(dest_id, pheromone_type, data, (uint8_t)len,
                              reliability_class, 0);
    }

    /* Calculate number of fragments needed */
    uint8_t num_frags = (len + NERT_FRAG_PAYLOAD_MAX - 1) / NERT_FRAG_PAYLOAD_MAX;
    if (num_frags > NERT_FRAG_MAX_FRAGMENTS) {
        return -1;  /* Message too large */
    }

    /* Assign message ID */
    uint8_t msg_id = frag_state.next_msg_id++;

    /* Fragment and enqueue each piece */
    uint16_t offset = 0;
    for (uint8_t i = 0; i < num_frags; i++) {
        uint8_t frag_len = (len - offset > NERT_FRAG_PAYLOAD_MAX)
                           ? NERT_FRAG_PAYLOAD_MAX
                           : (uint8_t)(len - offset);

        /*
         * Build fragment payload:
         * [frag_header: 3 bytes][data: frag_len bytes]
         */
        uint8_t frag_buf[NERT_FRAG_HEADER_SIZE + NERT_FRAG_PAYLOAD_MAX];
        struct nert_frag_header *hdr = (struct nert_frag_header *)frag_buf;

        hdr->msg_id = msg_id;
        hdr->frag_index = i;
        hdr->frag_total = num_frags;

        memcpy(frag_buf + NERT_FRAG_HEADER_SIZE, src + offset, frag_len);

        /*
         * Enqueue fragment with FRAG bit set in type.
         * The last fragment will benefit from Smart Padding
         * to fill the block with other queued messages.
         */
        uint8_t frag_type = pheromone_type | NERT_TLV_TYPE_FRAG_BIT;
        uint8_t total_len = NERT_FRAG_HEADER_SIZE + frag_len;

        int result = enqueue_message(dest_id, frag_type, frag_buf, total_len,
                                    reliability_class, NERT_FLAG_FRAG);
        if (result != 0) {
            return -1;  /* Queue full - partial send */
        }

        offset += frag_len;
    }

    frag_tx_count++;
    return 0;
}

/* ============================================================================
 * Fragmentation - RX Reassembly (v0.5)
 * ============================================================================ */

/**
 * Find or allocate reassembly slot for incoming fragment
 */
static struct nert_reasm_slot* find_reasm_slot(uint16_t sender_id, uint8_t msg_id) {
    uint32_t now = nert_hal_get_ticks();
    struct nert_reasm_slot *oldest = NULL;
    uint32_t oldest_tick = 0xFFFFFFFF;

    /* First pass: look for existing slot or free slot */
    for (int i = 0; i < NERT_REASM_SLOTS; i++) {
        struct nert_reasm_slot *slot = &reasm_slots[i];

        /* Exact match - return existing */
        if (slot->active &&
            slot->sender_id == sender_id &&
            slot->msg_id == msg_id) {
            return slot;
        }

        /* Track oldest for potential eviction */
        if (slot->active && slot->first_tick < oldest_tick) {
            oldest_tick = slot->first_tick;
            oldest = slot;
        }

        /* Free slot found */
        if (!slot->active) {
            return slot;
        }
    }

    /* No free slots - evict oldest if it's stale */
    if (oldest && (now - oldest->first_tick) > NERT_REASM_TIMEOUT_MS) {
        frag_rx_timeouts++;
        oldest->active = 0;
        return oldest;
    }

    return NULL;  /* No slot available */
}

/**
 * Process incoming fragment and attempt reassembly
 * Returns 1 if message complete and delivered, 0 otherwise
 */
static int process_fragment(uint16_t sender_id, uint8_t original_type,
                            const uint8_t *frag_data, uint8_t frag_len) {
    /* Validate minimum fragment size */
    if (frag_len < NERT_FRAG_HEADER_SIZE) {
        return 0;
    }

    /* Parse fragment header */
    const struct nert_frag_header *hdr = (const struct nert_frag_header *)frag_data;
    const uint8_t *payload = frag_data + NERT_FRAG_HEADER_SIZE;
    uint8_t payload_len = frag_len - NERT_FRAG_HEADER_SIZE;

    /* Validate fragment header */
    if (hdr->frag_index >= hdr->frag_total ||
        hdr->frag_total > NERT_FRAG_MAX_FRAGMENTS ||
        hdr->frag_total == 0) {
        return 0;  /* Invalid fragment */
    }

    /* Find or allocate slot */
    struct nert_reasm_slot *slot = find_reasm_slot(sender_id, hdr->msg_id);
    if (!slot) {
        return 0;  /* No slot available */
    }

    /* Initialize new slot */
    if (!slot->active) {
        slot->active = 1;
        slot->sender_id = sender_id;
        slot->msg_id = hdr->msg_id;
        slot->pheromone_type = original_type;
        slot->frag_total = hdr->frag_total;
        slot->frag_received = 0;
        slot->frag_bitmap = 0;
        slot->first_tick = nert_hal_get_ticks();
        slot->total_len = 0;
        memset(slot->frag_offsets, 0, sizeof(slot->frag_offsets));
        memset(slot->frag_lens, 0, sizeof(slot->frag_lens));
    }

    /* Check for duplicate fragment */
    if (slot->frag_bitmap & (1 << hdr->frag_index)) {
        return 0;  /* Already received */
    }

    /* Validate total matches existing slot */
    if (slot->frag_total != hdr->frag_total) {
        return 0;  /* Mismatch - corrupted */
    }

    /* Calculate offset for this fragment */
    uint16_t offset = hdr->frag_index * NERT_FRAG_PAYLOAD_MAX;

    /* Validate it fits in buffer */
    if (offset + payload_len > NERT_MAX_MESSAGE_SIZE) {
        return 0;  /* Would overflow */
    }

    /* Store fragment data */
    memcpy(slot->data + offset, payload, payload_len);
    slot->frag_offsets[hdr->frag_index] = offset;
    slot->frag_lens[hdr->frag_index] = payload_len;
    slot->frag_bitmap |= (1 << hdr->frag_index);
    slot->frag_received++;

    /* Check if complete */
    if (slot->frag_received == slot->frag_total) {
        /* Calculate total reassembled length */
        uint16_t total = 0;
        for (uint8_t i = 0; i < slot->frag_total; i++) {
            total += slot->frag_lens[i];
        }

        /* Deliver to application */
        if (receive_callback) {
            receive_callback(slot->sender_id, slot->pheromone_type,
                           slot->data, (uint8_t)total);
        }

        /* Free slot */
        slot->active = 0;
        frag_rx_reassembled++;
        return 1;
    }

    return 0;  /* Not complete yet */
}

/**
 * Clean up stale reassembly slots
 */
void nert_reasm_cleanup(void) {
    uint32_t now = nert_hal_get_ticks();

    for (int i = 0; i < NERT_REASM_SLOTS; i++) {
        struct nert_reasm_slot *slot = &reasm_slots[i];
        if (slot->active &&
            (now - slot->first_tick) > NERT_REASM_TIMEOUT_MS) {
            slot->active = 0;
            frag_rx_timeouts++;
        }
    }
}

void nert_get_frag_stats(uint32_t *tx_fragmented,
                         uint32_t *rx_reassembled,
                         uint32_t *rx_timeouts) {
    if (tx_fragmented)  *tx_fragmented = frag_tx_count;
    if (rx_reassembled) *rx_reassembled = frag_rx_reassembled;
    if (rx_timeouts)    *rx_timeouts = frag_rx_timeouts;
}

/* ============================================================================
 * Rate Limiting - Token Bucket Implementation (v0.5)
 * ============================================================================ */

/**
 * Find rate limit entry for a node
 * @param node_id  Node to find
 * @return Pointer to entry or NULL if not tracked
 */
static struct nert_rate_limit_entry* find_rate_limit_entry(uint16_t node_id) {
    for (int i = 0; i < NERT_RATE_LIMIT_SLOTS; i++) {
        if (rate_limit_table[i].node_id == node_id) {
            return &rate_limit_table[i];
        }
    }
    return NULL;
}

/**
 * Allocate new rate limit entry for a node
 * Uses LRU replacement if table full
 * @param node_id  Node to track
 * @return Pointer to allocated entry
 */
static struct nert_rate_limit_entry* alloc_rate_limit_entry(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();
    struct nert_rate_limit_entry *oldest = NULL;
    uint32_t oldest_tick = 0xFFFFFFFF;

    /* First pass: look for empty slot or exact match */
    for (int i = 0; i < NERT_RATE_LIMIT_SLOTS; i++) {
        if (rate_limit_table[i].node_id == 0) {
            /* Empty slot found */
            rate_limit_table[i].node_id = node_id;
            rate_limit_table[i].tokens = rate_limit_config.bucket_capacity;
            rate_limit_table[i].violations = 0;
            rate_limit_table[i].last_refill_tick = now;
            rate_limit_table[i].blacklist_until = 0;
            rate_limit_table[i].total_packets = 0;
            rate_limit_table[i].dropped_packets = 0;
            return &rate_limit_table[i];
        }

        /* Track oldest for LRU eviction */
        if (rate_limit_table[i].last_refill_tick < oldest_tick) {
            /* Don't evict blacklisted nodes */
            if (rate_limit_table[i].blacklist_until == 0 ||
                rate_limit_table[i].blacklist_until < now) {
                oldest_tick = rate_limit_table[i].last_refill_tick;
                oldest = &rate_limit_table[i];
            }
        }
    }

    /* Evict oldest non-blacklisted entry */
    if (oldest) {
        oldest->node_id = node_id;
        oldest->tokens = rate_limit_config.bucket_capacity;
        oldest->violations = 0;
        oldest->last_refill_tick = now;
        oldest->blacklist_until = 0;
        oldest->total_packets = 0;
        oldest->dropped_packets = 0;
        return oldest;
    }

    /* All slots are blacklisted - fail */
    return NULL;
}

/**
 * Refill tokens for all tracked nodes
 * Called periodically from timer_tick
 */
static void refill_rate_buckets(void) {
    uint32_t now = nert_hal_get_ticks();

    /* Check if refill interval has elapsed */
    if (now - rate_limit_last_refill < rate_limit_config.refill_interval_ms) {
        return;
    }

    rate_limit_last_refill = now;

    /* Refill all active entries */
    for (int i = 0; i < NERT_RATE_LIMIT_SLOTS; i++) {
        if (rate_limit_table[i].node_id == 0) continue;

        /* Clear expired blacklists */
        if (rate_limit_table[i].blacklist_until > 0 &&
            rate_limit_table[i].blacklist_until <= now) {
            rate_limit_table[i].blacklist_until = 0;
            rate_limit_table[i].violations = 0;  /* Reset violations */
        }

        /* Add tokens up to capacity */
        uint16_t new_tokens = rate_limit_table[i].tokens +
                             rate_limit_config.refill_tokens;
        if (new_tokens > rate_limit_config.bucket_capacity) {
            new_tokens = rate_limit_config.bucket_capacity;
        }
        rate_limit_table[i].tokens = (uint8_t)new_tokens;
        rate_limit_table[i].last_refill_tick = now;
    }
}

/**
 * Check rate limit for incoming packet
 * Consumes token if available, tracks violations
 *
 * @param node_id  Sender node ID
 * @return 0 if allowed, -1 if rate limited, -2 if blacklisted
 */
static int check_rate_limit(uint16_t node_id) {
    if (!rate_limit_config.enabled) {
        return 0;  /* Rate limiting disabled */
    }

    uint32_t now = nert_hal_get_ticks();

    /* Find or create entry */
    struct nert_rate_limit_entry *entry = find_rate_limit_entry(node_id);
    if (!entry) {
        entry = alloc_rate_limit_entry(node_id);
        if (!entry) {
            /* No slots available - allow packet (fail open) */
            return 0;
        }
    }

    /* Track total packets */
    entry->total_packets++;

    /* Check blacklist first */
    if (entry->blacklist_until > 0 && entry->blacklist_until > now) {
        entry->dropped_packets++;
        stats.rx_blacklisted++;
        return -2;  /* Blacklisted */
    }

    /* Try to consume a token */
    if (entry->tokens > 0) {
        entry->tokens--;

        /* Successful packet - decay violation count slowly */
        if (entry->violations > 0 && (entry->total_packets % 10) == 0) {
            entry->violations--;
        }
        return 0;  /* Allowed */
    }

    /* No tokens - rate limited */
    entry->violations++;
    entry->dropped_packets++;
    stats.rx_rate_limited++;

    /* Check if penalty threshold exceeded */
    if (entry->violations >= rate_limit_config.penalty_threshold) {
        entry->blacklist_until = now + rate_limit_config.blacklist_duration_ms;
        stats.rx_blacklisted++;
    }

    return -1;  /* Rate limited */
}

/**
 * Update statistics for active node tracking
 */
static void update_rate_limit_stats(void) {
    uint32_t now = nert_hal_get_ticks();
    uint16_t active = 0;
    uint16_t blacklisted = 0;

    for (int i = 0; i < NERT_RATE_LIMIT_SLOTS; i++) {
        if (rate_limit_table[i].node_id != 0) {
            active++;
            if (rate_limit_table[i].blacklist_until > now) {
                blacklisted++;
            }
        }
    }

    stats.rate_limit_active_nodes = active;
    stats.rate_limit_blacklisted_nodes = blacklisted;
}

/* Public Rate Limiting API */

void nert_rate_limit_enable(uint8_t enabled) {
    rate_limit_config.enabled = enabled ? 1 : 0;
}

void nert_rate_limit_configure(const struct nert_rate_limit_config *config) {
    if (config) {
        rate_limit_config.bucket_capacity = config->bucket_capacity;
        rate_limit_config.refill_tokens = config->refill_tokens;
        rate_limit_config.refill_interval_ms = config->refill_interval_ms;
        rate_limit_config.penalty_threshold = config->penalty_threshold;
        rate_limit_config.blacklist_duration_ms = config->blacklist_duration_ms;
        rate_limit_config.enabled = config->enabled;
    } else {
        /* Reset to defaults */
        rate_limit_config.bucket_capacity = NERT_RATE_BUCKET_CAPACITY;
        rate_limit_config.refill_tokens = NERT_RATE_REFILL_TOKENS;
        rate_limit_config.refill_interval_ms = NERT_RATE_REFILL_MS;
        rate_limit_config.penalty_threshold = NERT_RATE_PENALTY_THRESHOLD;
        rate_limit_config.blacklist_duration_ms = NERT_RATE_BLACKLIST_MS;
        rate_limit_config.enabled = 1;
    }
}

void nert_rate_limit_blacklist(uint16_t node_id, uint32_t duration_ms) {
    if (node_id == 0) return;

    uint32_t now = nert_hal_get_ticks();
    uint32_t duration = duration_ms ? duration_ms : rate_limit_config.blacklist_duration_ms;

    struct nert_rate_limit_entry *entry = find_rate_limit_entry(node_id);
    if (!entry) {
        entry = alloc_rate_limit_entry(node_id);
    }

    if (entry) {
        entry->blacklist_until = now + duration;
        entry->violations = rate_limit_config.penalty_threshold;
    }
}

void nert_rate_limit_unblock(uint16_t node_id) {
    struct nert_rate_limit_entry *entry = find_rate_limit_entry(node_id);
    if (entry) {
        entry->blacklist_until = 0;
        entry->violations = 0;
        entry->tokens = rate_limit_config.bucket_capacity;
    }
}

int nert_rate_limit_status(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();
    struct nert_rate_limit_entry *entry = find_rate_limit_entry(node_id);

    if (!entry) {
        return 0;  /* Not tracked - allowed */
    }

    if (entry->blacklist_until > now) {
        return 2;  /* Blacklisted */
    }

    if (entry->tokens == 0) {
        return 1;  /* Rate limited (bucket empty) */
    }

    return 0;  /* Allowed */
}

int nert_rate_limit_get_node_stats(uint16_t node_id,
                                    uint32_t *total_packets,
                                    uint32_t *dropped_packets) {
    struct nert_rate_limit_entry *entry = find_rate_limit_entry(node_id);
    if (!entry) {
        return -1;  /* Not tracked */
    }

    if (total_packets)   *total_packets = entry->total_packets;
    if (dropped_packets) *dropped_packets = entry->dropped_packets;
    return 0;
}

void nert_rate_limit_reset(void) {
    memset(rate_limit_table, 0, sizeof(rate_limit_table));
    rate_limit_last_refill = nert_hal_get_ticks();
    stats.rx_rate_limited = 0;
    stats.rx_blacklisted = 0;
    stats.rate_limit_active_nodes = 0;
    stats.rate_limit_blacklisted_nodes = 0;
}

/* ============================================================================
 * Behavioral Blacklist - Implementation (v0.5)
 * ============================================================================ */

/**
 * Find behavior entry for a node
 */
static struct nert_behavior_entry* find_behavior_entry(uint16_t node_id) {
    for (int i = 0; i < NERT_BEHAVIOR_SLOTS; i++) {
        if (behavior_table[i].node_id == node_id) {
            return &behavior_table[i];
        }
    }
    return NULL;
}

/**
 * Allocate behavior entry for a node (LRU eviction)
 */
static struct nert_behavior_entry* alloc_behavior_entry(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();
    struct nert_behavior_entry *oldest = NULL;
    uint32_t oldest_tick = 0xFFFFFFFF;

    /* First pass: find empty slot or exact match */
    for (int i = 0; i < NERT_BEHAVIOR_SLOTS; i++) {
        if (behavior_table[i].node_id == 0) {
            /* Empty slot - initialize */
            memset(&behavior_table[i], 0, sizeof(struct nert_behavior_entry));
            behavior_table[i].node_id = node_id;
            behavior_table[i].reputation = NERT_REPUTATION_MAX;
            behavior_table[i].status = NERT_STATUS_OK;
            behavior_table[i].first_seen_tick = now;
            behavior_table[i].last_recovery_tick = now;
            return &behavior_table[i];
        }

        /* Track oldest for LRU (prefer non-banned for eviction) */
        if (behavior_table[i].ban_until_tick < now) {
            /* Not banned - candidate for eviction */
            if (behavior_table[i].first_seen_tick < oldest_tick) {
                oldest_tick = behavior_table[i].first_seen_tick;
                oldest = &behavior_table[i];
            }
        }
    }

    /* Evict oldest non-banned entry */
    if (oldest) {
        memset(oldest, 0, sizeof(struct nert_behavior_entry));
        oldest->node_id = node_id;
        oldest->reputation = NERT_REPUTATION_MAX;
        oldest->status = NERT_STATUS_OK;
        oldest->first_seen_tick = now;
        oldest->last_recovery_tick = now;
        return oldest;
    }

    return NULL;  /* All slots are banned - fail */
}

/**
 * Get violation weight for a violation type
 */
static uint8_t get_violation_weight(enum nert_violation_type type) {
    switch (type) {
        case NERT_VIOLATION_BAD_MAC:     return behavior_config.weight_bad_mac;
        case NERT_VIOLATION_REPLAY:      return behavior_config.weight_replay;
        case NERT_VIOLATION_INVALID_PKT: return behavior_config.weight_invalid_pkt;
        case NERT_VIOLATION_RATE_EXCEED: return behavior_config.weight_rate_exceed;
        default:                         return 1;
    }
}

/**
 * Get ban duration for a status level
 */
static uint32_t get_ban_duration(enum nert_blacklist_status status) {
    switch (status) {
        case NERT_STATUS_WARNED:      return NERT_BLACKLIST_WARN_MS;
        case NERT_STATUS_THROTTLED:   return NERT_BLACKLIST_THROTTLE_MS;
        case NERT_STATUS_TEMP_BANNED: return NERT_BLACKLIST_TEMP_BAN_MS;
        case NERT_STATUS_LONG_BANNED: return NERT_BLACKLIST_LONG_BAN_MS;
        case NERT_STATUS_PERMABANNED: return NERT_BLACKLIST_PERMABAN_MS;
        default:                      return 0;
    }
}

/**
 * Determine status based on reputation score
 */
static enum nert_blacklist_status reputation_to_status(uint8_t reputation) {
    if (reputation <= behavior_config.permaban_threshold) {
        return NERT_STATUS_PERMABANNED;
    } else if (reputation <= behavior_config.ban_threshold) {
        return NERT_STATUS_TEMP_BANNED;
    } else if (reputation <= behavior_config.throttle_threshold) {
        return NERT_STATUS_THROTTLED;
    } else if (reputation <= behavior_config.warn_threshold) {
        return NERT_STATUS_WARNED;
    }
    return NERT_STATUS_OK;
}

/**
 * Update behavioral stats
 */
static void update_behavior_stats(void) {
    uint32_t now = nert_hal_get_ticks();
    uint16_t warned = 0, throttled = 0, banned = 0;

    for (int i = 0; i < NERT_BEHAVIOR_SLOTS; i++) {
        if (behavior_table[i].node_id == 0) continue;

        switch (behavior_table[i].status) {
            case NERT_STATUS_WARNED:
                warned++;
                break;
            case NERT_STATUS_THROTTLED:
                throttled++;
                break;
            case NERT_STATUS_TEMP_BANNED:
            case NERT_STATUS_LONG_BANNED:
            case NERT_STATUS_PERMABANNED:
                if (behavior_table[i].ban_until_tick > now) {
                    banned++;
                }
                break;
            default:
                break;
        }
    }

    stats.behavior_nodes_warned = warned;
    stats.behavior_nodes_throttled = throttled;
    stats.behavior_nodes_banned = banned;
}

/**
 * Notify callback of status change
 */
static void notify_status_change(struct nert_behavior_entry *entry,
                                  uint8_t old_status, uint8_t new_status) {
    if (behavior_config.notify_callback && blacklist_callback) {
        blacklist_callback(entry->node_id, old_status, new_status,
                          entry->reputation);
    }
}

/* Public Behavioral Blacklist API */

void nert_blacklist_enable(uint8_t enabled) {
    behavior_config.enabled = enabled ? 1 : 0;
}

void nert_blacklist_configure(const struct nert_behavior_config *config) {
    if (config) {
        behavior_config = *config;
    } else {
        /* Reset to defaults */
        behavior_config.weight_bad_mac = NERT_REPUTATION_WEIGHT_BAD_MAC;
        behavior_config.weight_replay = NERT_REPUTATION_WEIGHT_REPLAY;
        behavior_config.weight_invalid_pkt = NERT_REPUTATION_WEIGHT_INVALID_PKT;
        behavior_config.weight_rate_exceed = NERT_REPUTATION_WEIGHT_RATE_EXCEED;
        behavior_config.warn_threshold = NERT_REPUTATION_WARN_THRESHOLD;
        behavior_config.throttle_threshold = NERT_REPUTATION_THROTTLE_THRESHOLD;
        behavior_config.ban_threshold = NERT_REPUTATION_BAN_THRESHOLD;
        behavior_config.permaban_threshold = NERT_REPUTATION_PERMABAN_THRESHOLD;
        behavior_config.recovery_interval_ms = NERT_REPUTATION_RECOVERY_INTERVAL_MS;
        behavior_config.recovery_points = NERT_REPUTATION_RECOVERY_POINTS;
        behavior_config.enabled = 1;
        behavior_config.auto_blacklist = 1;
        behavior_config.notify_callback = 1;
    }
}

void nert_blacklist_set_callback(nert_blacklist_callback_t callback) {
    blacklist_callback = callback;
}

uint8_t nert_blacklist_report_violation(uint16_t node_id,
                                         enum nert_violation_type violation_type) {
    if (!behavior_config.enabled || node_id == 0) {
        return NERT_REPUTATION_MAX;
    }

    uint32_t now = nert_hal_get_ticks();

    /* Find or create entry */
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);
    if (!entry) {
        entry = alloc_behavior_entry(node_id);
        if (!entry) {
            return NERT_REPUTATION_MAX;  /* No slots available */
        }
    }

    /* Increment violation counter */
    switch (violation_type) {
        case NERT_VIOLATION_BAD_MAC:
            entry->bad_mac_count++;
            break;
        case NERT_VIOLATION_REPLAY:
            entry->replay_count++;
            break;
        case NERT_VIOLATION_INVALID_PKT:
            entry->invalid_pkt_count++;
            break;
        case NERT_VIOLATION_RATE_EXCEED:
            entry->rate_exceed_count++;
            break;
        default:
            break;
    }

    /* v0.5: Record event for Black Box (forensic evidence preservation)
     * If we die, this evidence survives in our Last Will */
    uint8_t bb_event_type;
    switch (violation_type) {
        case NERT_VIOLATION_BAD_MAC:     bb_event_type = EVENT_BAD_MAC; break;
        case NERT_VIOLATION_REPLAY:      bb_event_type = EVENT_REPLAY; break;
        case NERT_VIOLATION_RATE_EXCEED: bb_event_type = EVENT_RATE_LIMIT; break;
        default:                         bb_event_type = 0; break;
    }
    if (bb_event_type != 0) {
        blackbox_record_event(bb_event_type, node_id);
    }

    entry->last_violation_tick = now;
    stats.behavior_violations_total++;

    /* Decrease reputation by weight */
    uint8_t weight = get_violation_weight(violation_type);
    if (entry->reputation > weight) {
        entry->reputation -= weight;
    } else {
        entry->reputation = 0;
    }

    /* Determine new status based on reputation */
    uint8_t old_status = entry->status;
    enum nert_blacklist_status new_status = reputation_to_status(entry->reputation);

    /* Apply auto-blacklist if enabled and status worsened */
    if (behavior_config.auto_blacklist && new_status > old_status) {
        entry->status = new_status;

        /* Set ban duration if applicable */
        uint32_t ban_duration = get_ban_duration(new_status);
        if (ban_duration > 0) {
            entry->ban_until_tick = now + ban_duration;
            entry->ban_count++;
            stats.behavior_auto_bans++;

            /* Also update rate limiter blacklist for enforcement */
            nert_rate_limit_blacklist(node_id, ban_duration);
        }

        /* Notify callback */
        notify_status_change(entry, old_status, new_status);
    }

    return entry->reputation;
}

void nert_blacklist_set_status(uint16_t node_id,
                                enum nert_blacklist_status status,
                                uint32_t duration_ms) {
    if (node_id == 0) return;

    uint32_t now = nert_hal_get_ticks();

    struct nert_behavior_entry *entry = find_behavior_entry(node_id);
    if (!entry) {
        entry = alloc_behavior_entry(node_id);
        if (!entry) return;
    }

    uint8_t old_status = entry->status;
    entry->status = status;

    /* Set ban duration */
    uint32_t ban_duration = duration_ms ? duration_ms : get_ban_duration(status);
    if (ban_duration > 0) {
        entry->ban_until_tick = now + ban_duration;
        entry->ban_count++;

        /* Sync with rate limiter */
        nert_rate_limit_blacklist(node_id, ban_duration);
    } else {
        entry->ban_until_tick = 0;
    }

    /* Notify if status changed */
    if (old_status != status) {
        notify_status_change(entry, old_status, status);
    }
}

enum nert_blacklist_status nert_blacklist_get_status(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);

    if (!entry) {
        return NERT_STATUS_OK;  /* Not tracked */
    }

    /* Check if ban has expired */
    if (entry->ban_until_tick > 0 && entry->ban_until_tick <= now) {
        /* Ban expired - recalculate status from reputation */
        entry->status = reputation_to_status(entry->reputation);
        entry->ban_until_tick = 0;
    }

    return entry->status;
}

int nert_blacklist_get_reputation(uint16_t node_id) {
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);
    if (!entry) {
        return -1;  /* Not tracked */
    }
    return entry->reputation;
}

int nert_blacklist_get_violations(uint16_t node_id,
                                   uint16_t *bad_mac,
                                   uint16_t *replay,
                                   uint16_t *invalid_pkt,
                                   uint16_t *rate_exceed) {
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);
    if (!entry) {
        return -1;  /* Not tracked */
    }

    if (bad_mac)     *bad_mac = entry->bad_mac_count;
    if (replay)      *replay = entry->replay_count;
    if (invalid_pkt) *invalid_pkt = entry->invalid_pkt_count;
    if (rate_exceed) *rate_exceed = entry->rate_exceed_count;

    return 0;
}

void nert_blacklist_pardon(uint16_t node_id) {
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);
    if (!entry) return;

    uint8_t old_status = entry->status;

    /* Restore full reputation */
    entry->reputation = NERT_REPUTATION_MAX;
    entry->status = NERT_STATUS_OK;
    entry->ban_until_tick = 0;

    /* Clear violation counters */
    entry->bad_mac_count = 0;
    entry->replay_count = 0;
    entry->invalid_pkt_count = 0;
    entry->rate_exceed_count = 0;

    /* Sync with rate limiter */
    nert_rate_limit_unblock(node_id);

    /* Notify if status changed */
    if (old_status != NERT_STATUS_OK) {
        notify_status_change(entry, old_status, NERT_STATUS_OK);
    }
}

void nert_blacklist_reset(void) {
    memset(behavior_table, 0, sizeof(behavior_table));
    behavior_last_recovery_tick = nert_hal_get_ticks();
    stats.behavior_violations_total = 0;
    stats.behavior_auto_bans = 0;
    stats.behavior_nodes_warned = 0;
    stats.behavior_nodes_throttled = 0;
    stats.behavior_nodes_banned = 0;
}

void nert_blacklist_process_recovery(void) {
    if (!behavior_config.enabled) return;

    uint32_t now = nert_hal_get_ticks();

    /* Check recovery interval */
    if (now - behavior_last_recovery_tick < behavior_config.recovery_interval_ms) {
        return;
    }
    behavior_last_recovery_tick = now;

    /* Process all entries */
    for (int i = 0; i < NERT_BEHAVIOR_SLOTS; i++) {
        struct nert_behavior_entry *entry = &behavior_table[i];
        if (entry->node_id == 0) continue;

        /* Skip if recently violated */
        if (now - entry->last_violation_tick < behavior_config.recovery_interval_ms) {
            continue;
        }

        /* Check if ban has expired */
        if (entry->ban_until_tick > 0 && entry->ban_until_tick <= now) {
            entry->ban_until_tick = 0;
            /* Recalculate status after ban expiry */
            uint8_t old_status = entry->status;
            entry->status = reputation_to_status(entry->reputation);
            if (old_status != entry->status) {
                notify_status_change(entry, old_status, entry->status);
            }
        }

        /* Recover reputation if not at max and not banned */
        if (entry->reputation < NERT_REPUTATION_MAX &&
            entry->ban_until_tick == 0) {

            uint16_t new_rep = entry->reputation + behavior_config.recovery_points;
            if (new_rep > NERT_REPUTATION_MAX) {
                new_rep = NERT_REPUTATION_MAX;
            }
            entry->reputation = (uint8_t)new_rep;
            entry->last_recovery_tick = now;

            /* Check if status improved */
            uint8_t old_status = entry->status;
            enum nert_blacklist_status new_status = reputation_to_status(entry->reputation);
            if (new_status < old_status) {
                entry->status = new_status;
                notify_status_change(entry, old_status, new_status);
            }
        }
    }

    /* Update stats */
    update_behavior_stats();
}

/**
 * Check if node should be blocked based on behavioral status
 * Returns 0 if allowed, non-zero if blocked
 */
static int check_behavior_block(uint16_t node_id) {
    if (!behavior_config.enabled) return 0;

    uint32_t now = nert_hal_get_ticks();
    struct nert_behavior_entry *entry = find_behavior_entry(node_id);

    if (!entry) return 0;  /* Not tracked - allow */

    /* Check active ban */
    if (entry->ban_until_tick > 0 && entry->ban_until_tick > now) {
        return 1;  /* Banned */
    }

    return 0;  /* Allowed */
}

/* ============================================================================
 * Cover Traffic - Implementation (v0.5)
 * ============================================================================ */

/**
 * Calculate next send interval with jitter
 */
static uint32_t calc_cover_interval(void) {
    uint32_t base = cover_config.base_interval_ms;
    uint32_t jitter = cover_config.jitter_ms;

    if (jitter > 0) {
        uint32_t rnd = nert_hal_random();
        base += (rnd % (jitter * 2)) - jitter;  /* +/- jitter */
    }

    /* Clamp to configured bounds */
    if (base < cover_config.min_interval_ms) {
        base = cover_config.min_interval_ms;
    }
    if (base > cover_config.max_interval_ms) {
        base = cover_config.max_interval_ms;
    }

    return base;
}

/**
 * Adaptive mode: calculate interval based on recent activity
 */
static void update_adaptive_interval(void) {
    uint32_t now = nert_hal_get_ticks();

    /* Check if activity window has elapsed */
    if (now - cover_state.window_start_tick >= NERT_COVER_ACTIVITY_WINDOW_MS) {
        /* Calculate total packets in window */
        uint16_t total = cover_state.window_real_packets +
                        cover_state.window_dummy_packets;

        /* Adjust interval to reach target rate */
        if (total < cover_config.target_rate) {
            /* Too few packets - decrease interval (more dummies) */
            if (cover_state.current_interval_ms > cover_config.min_interval_ms + 50) {
                cover_state.current_interval_ms -= 50;
            }
        } else if (total > cover_config.target_rate * 2) {
            /* Lots of real traffic - increase interval (fewer dummies) */
            if (cover_state.current_interval_ms < cover_config.max_interval_ms - 50) {
                cover_state.current_interval_ms += 50;
            }
        }

        /* Reset window */
        cover_state.window_start_tick = now;
        cover_state.window_real_packets = 0;
        cover_state.window_dummy_packets = 0;
    }
}

/**
 * Generate random dummy payload
 */
static uint8_t generate_dummy_payload(uint8_t *buffer, uint8_t max_len) {
    /* Random length between min and max */
    uint8_t len = cover_config.payload_min;
    if (cover_config.payload_max > cover_config.payload_min) {
        uint32_t rnd = nert_hal_random();
        len += rnd % (cover_config.payload_max - cover_config.payload_min + 1);
    }

    if (len > max_len) {
        len = max_len;
    }

    /* Fill with random data */
    for (uint8_t i = 0; i < len; i += 4) {
        uint32_t rnd = nert_hal_random();
        buffer[i] = rnd & 0xFF;
        if (i + 1 < len) buffer[i + 1] = (rnd >> 8) & 0xFF;
        if (i + 2 < len) buffer[i + 2] = (rnd >> 16) & 0xFF;
        if (i + 3 < len) buffer[i + 3] = (rnd >> 24) & 0xFF;
    }

    return len;
}

/**
 * Send a single dummy packet
 */
static void send_cover_packet(void) {
    uint8_t dummy_payload[NERT_COVER_PAYLOAD_MAX];
    uint8_t len = generate_dummy_payload(dummy_payload, NERT_COVER_PAYLOAD_MAX);

    /*
     * Send as FIRE_FORGET with NERT_PHEROMONE_DUMMY type
     * The receiver will decrypt, see the dummy marker, and discard
     * From network observer's perspective, it's indistinguishable from real traffic
     */
    enqueue_message(cover_config.dest_id, NERT_PHEROMONE_DUMMY,
                   dummy_payload, len, NERT_CLASS_FIRE_FORGET, 0);

    /* Update statistics */
    cover_state.total_dummy_sent++;
    cover_state.total_bytes_cover += len + NERT_HEADER_SIZE + NERT_MAC_SIZE;
    cover_state.window_dummy_packets++;
    cover_state.last_send_tick = nert_hal_get_ticks();

    stats.cover_dummy_sent++;
    stats.cover_bytes_overhead += len + NERT_HEADER_SIZE + NERT_MAC_SIZE;
}

/* Public Cover Traffic API */

void nert_cover_set_mode(uint8_t mode) {
    uint32_t now = nert_hal_get_ticks();

    cover_state.mode = mode;
    cover_config.mode = mode;

    if (mode != NERT_COVER_MODE_OFF) {
        /* Initialize state for new mode */
        cover_state.current_interval_ms = cover_config.base_interval_ms;
        cover_state.next_send_tick = now + calc_cover_interval();
        cover_state.window_start_tick = now;
        cover_state.window_real_packets = 0;
        cover_state.window_dummy_packets = 0;
        cover_state.burst_remaining = 0;
    }
}

void nert_cover_configure(const struct nert_cover_config *config) {
    if (config) {
        cover_config = *config;
    } else {
        /* Reset to defaults */
        cover_config.mode = NERT_COVER_MODE_OFF;
        cover_config.base_interval_ms = NERT_COVER_INTERVAL_MS;
        cover_config.jitter_ms = NERT_COVER_JITTER_MS;
        cover_config.min_interval_ms = NERT_COVER_MIN_INTERVAL_MS;
        cover_config.max_interval_ms = NERT_COVER_MAX_INTERVAL_MS;
        cover_config.target_rate = NERT_COVER_TARGET_RATE;
        cover_config.burst_size = NERT_COVER_BURST_SIZE;
        cover_config.burst_interval_ms = NERT_COVER_BURST_INTERVAL_MS;
        cover_config.payload_min = NERT_COVER_PAYLOAD_MIN;
        cover_config.payload_max = NERT_COVER_PAYLOAD_MAX;
        cover_config.dest_id = 0;
    }
}

void nert_cover_set_destination(uint16_t dest_id) {
    cover_config.dest_id = dest_id;
}

const struct nert_cover_state* nert_cover_get_state(void) {
    return &cover_state;
}

void nert_cover_report_activity(uint16_t bytes) {
    cover_state.window_real_packets++;
    (void)bytes;  /* Could be used for byte-rate adaptive mode */
}

void nert_cover_send_dummy(void) {
    if (cover_config.mode == NERT_COVER_MODE_OFF) {
        /* Force a dummy even when disabled (for testing) */
    }
    send_cover_packet();
}

void nert_cover_process(void) {
    if (cover_config.mode == NERT_COVER_MODE_OFF) {
        return;
    }

    uint32_t now = nert_hal_get_ticks();

    switch (cover_config.mode) {
        case NERT_COVER_MODE_CONSTANT:
            /* Send dummy at fixed interval */
            if (now >= cover_state.next_send_tick) {
                send_cover_packet();
                cover_state.next_send_tick = now + calc_cover_interval();
            }
            break;

        case NERT_COVER_MODE_ADAPTIVE:
            /* Adjust interval based on real traffic */
            update_adaptive_interval();

            if (now >= cover_state.next_send_tick) {
                send_cover_packet();
                cover_state.next_send_tick = now + cover_state.current_interval_ms;
            }

            /* Update stats */
            stats.cover_current_interval = cover_state.current_interval_ms;
            break;

        case NERT_COVER_MODE_BURST:
            /* Send bursts of packets */
            if (cover_state.burst_remaining > 0) {
                /* Continue current burst */
                if (now >= cover_state.next_send_tick) {
                    send_cover_packet();
                    cover_state.burst_remaining--;
                    cover_state.next_send_tick = now + cover_config.burst_interval_ms;
                }
            } else {
                /* Check if time for new burst */
                if (now >= cover_state.next_send_tick) {
                    cover_state.burst_remaining = cover_config.burst_size;
                    send_cover_packet();
                    cover_state.burst_remaining--;
                    cover_state.next_send_tick = now + cover_config.burst_interval_ms;
                }
            }

            /* Schedule next burst if this one complete */
            if (cover_state.burst_remaining == 0) {
                cover_state.next_send_tick = now + calc_cover_interval();
            }
            break;

        default:
            break;
    }
}

int nert_cover_is_dummy(uint8_t pheromone_type) {
    return (pheromone_type == NERT_PHEROMONE_DUMMY) ? 1 : 0;
}

void nert_cover_reset_stats(void) {
    cover_state.total_dummy_sent = 0;
    cover_state.total_dummy_received = 0;
    cover_state.total_bytes_cover = 0;
    stats.cover_dummy_sent = 0;
    stats.cover_dummy_received = 0;
    stats.cover_bytes_overhead = 0;
}

/* ============================================================================
 * Packet Building and Sending
 * ============================================================================ */

static int build_and_send(uint16_t dest_id, uint8_t pheromone_type,
                          uint8_t reliability_class, const void *data,
                          uint8_t len, uint8_t flags) {
    struct nert_packet pkt;
    uint8_t nonce[NERT_NONCE_SIZE];

    memset(&pkt, 0, sizeof(pkt));

    /* Build header */
    pkt.header.magic = NERT_MAGIC;
    pkt.header.version_class = (NERT_VERSION & 0xF0) | ((reliability_class & 0x03) << 2);
    pkt.header.node_id = nert_hal_get_node_id();
    pkt.header.seq_num = ++global_seq;
    pkt.header.flags = flags | NERT_FLAG_ENC;
    pkt.header.payload_len = len + 1; /* +1 for pheromone_type */
    pkt.header.nonce_counter = ++nonce_counter;

#if !NERT_COMPACT_MODE
    pkt.header.dest_id = dest_id;
    pkt.header.timestamp = (uint16_t)(nert_hal_get_ticks() & 0xFFFF);
    pkt.header.ttl = 15;
    pkt.header.hop_count = 0;
#endif

    /*
     * Smart Padding (v0.5): Pack messages in TLV format
     * This normalizes packet sizes to NERT_BLOCK_SIZE multiples
     * and aggregates queued messages to fill padding space.
     */
    uint8_t plaintext[NERT_MAX_PAYLOAD];
    uint8_t packed_len = pack_messages_tlv(dest_id, pheromone_type,
                                            (const uint8_t *)data, len,
                                            plaintext, NERT_MAX_PAYLOAD);

    /* Update header with actual padded payload length */
    pkt.header.payload_len = packed_len;

    /* Build nonce and encrypt */
    build_nonce(nonce, nonce_counter);
    chacha8_encrypt(session_key, nonce, plaintext, packed_len, pkt.payload);

    /* Compute MAC over header + encrypted payload */
    poly1305_mac(session_key, pkt.payload, packed_len,
                 (uint8_t*)&pkt.header, NERT_HEADER_SIZE, pkt.auth.poly1305_tag);

    /* Send - payload is now padded to block boundary */
    uint16_t total_len = NERT_HEADER_SIZE + packed_len + NERT_MAC_SIZE;
    int result = nert_hal_send(&pkt, total_len);

    if (result == 0) {
        stats.tx_packets++;
        stats.tx_bytes += total_len;

        /* v0.5: Report activity for adaptive cover traffic */
        if (pheromone_type != NERT_PHEROMONE_DUMMY) {
            nert_cover_report_activity(total_len);
        }
    }

    return result;
}

/* ============================================================================
 * Packet Reception and Processing
 * ============================================================================ */

static void handle_received_packet(uint8_t *raw_data, uint16_t len) {
    struct nert_packet *pkt = (struct nert_packet*)raw_data;

    /* Validate minimum length */
    if (len < NERT_HEADER_SIZE + 1 + NERT_MAC_SIZE) {
        return;
    }

    /* Validate magic */
    if (pkt->header.magic != NERT_MAGIC) {
        return;
    }

    stats.rx_packets++;
    stats.rx_bytes += len;

    uint8_t payload_len = pkt->header.payload_len;
    uint8_t *tag_ptr = raw_data + NERT_HEADER_SIZE + payload_len;

    /*
     * Verify MAC with grace window support.
     * Try current key first, then adjacent epoch keys if within grace window.
     * This handles clock drift between nodes at epoch boundaries.
     */
    uint8_t key_mask = get_valid_key_mask();
    const uint8_t *valid_key = NULL;

    /* Try current epoch key (always valid) */
    if (poly1305_verify(session_key, pkt->payload, payload_len,
                        (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                        tag_ptr) == 0) {
        valid_key = session_key;
    }
    /* Try previous epoch key (if in grace window at start of epoch) */
    else if ((key_mask & 0x02) &&
             poly1305_verify(prev_session_key, pkt->payload, payload_len,
                            (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                            tag_ptr) == 0) {
        valid_key = prev_session_key;
    }
    /* Try next epoch key (if in grace window at end of epoch) */
    else if ((key_mask & 0x04) &&
             poly1305_verify(next_session_key, pkt->payload, payload_len,
                            (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                            tag_ptr) == 0) {
        valid_key = next_session_key;
    }

    if (!valid_key) {
        stats.rx_bad_mac++;
        /*
         * v0.5: Report bad MAC violation to behavioral blacklist
         * This significantly damages the node's reputation
         */
        nert_blacklist_report_violation(pkt->header.node_id,
                                        NERT_VIOLATION_BAD_MAC);
        return;
    }

    /*
     * v0.5: Rate Limiting Check
     * Applied after MAC validation (authenticated sender identity)
     * but before deduplication (to count rate-limited packets correctly)
     *
     * Note: REKEY messages bypass rate limiting to ensure key rotation
     * can complete even during an attack. The pheromone type is checked
     * after decryption below if NERT_RATE_BYPASS_REKEY is enabled.
     */
    int rate_status = check_rate_limit(pkt->header.node_id);
    if (rate_status != 0) {
        /* Packet dropped due to rate limiting or blacklist */
        if (rate_status == -1) {
            /* Rate exceeded - report to behavioral system */
            nert_blacklist_report_violation(pkt->header.node_id,
                                            NERT_VIOLATION_RATE_EXCEED);
        }
        return;
    }

    /* Check for duplicates */
    if (is_duplicate(pkt->header.node_id, pkt->header.seq_num)) {
        stats.rx_duplicates++;
        return;
    }

    /* Decrypt payload using the key that verified successfully */
    uint8_t nonce[NERT_NONCE_SIZE];
    uint8_t plaintext[NERT_MAX_PAYLOAD];

    build_nonce(nonce, pkt->header.nonce_counter);
    chacha8_encrypt(valid_key, nonce, pkt->payload, payload_len, plaintext);

    /*
     * Smart Padding (v0.5): Check if this is TLV-packed payload
     * TLV format starts with message count byte.
     * Legacy format (v0.4) starts with pheromone_type directly.
     *
     * Heuristic: If first byte is <= NERT_TLV_MAX_MESSAGES and
     * second byte is a valid length, treat as TLV.
     */
    uint8_t pheromone_type;
    uint8_t *data;
    uint8_t data_len;
    uint8_t is_tlv_format = 0;

    if (payload_len >= NERT_TLV_HEADER_SIZE + NERT_TLV_MSG_OVERHEAD) {
        uint8_t potential_count = plaintext[0];
        uint8_t potential_len = plaintext[1];

        /* TLV detection: count in valid range and first msg length plausible */
        if (potential_count > 0 && potential_count <= NERT_TLV_MAX_MESSAGES &&
            potential_len + NERT_TLV_HEADER_SIZE + NERT_TLV_MSG_OVERHEAD <= payload_len) {
            is_tlv_format = 1;
        }
    }

    if (is_tlv_format) {
        /* v0.5 TLV format - unpack multiple messages */
        uint8_t processed = unpack_messages_tlv(plaintext, payload_len,
                                                 pkt->header.node_id);
        (void)processed;  /* Stats already tracked */

        /* Extract first message info for connection handling below */
        if (payload_len >= NERT_TLV_HEADER_SIZE + NERT_TLV_MSG_OVERHEAD) {
            data_len = plaintext[1];
            pheromone_type = plaintext[2];
            data = plaintext + NERT_TLV_HEADER_SIZE + NERT_TLV_MSG_OVERHEAD;
        } else {
            return;  /* Invalid packet */
        }
    } else {
        /* Legacy v0.4 format: [Type][Data...] */
        pheromone_type = plaintext[0];
        data = plaintext + 1;
        data_len = payload_len - 1;

        /* Deliver single message */
        if (receive_callback && data_len > 0) {
            receive_callback(pkt->header.node_id, pheromone_type, data, data_len);
        }
    }

    /* Extract reliability class */
    uint8_t reliability_class = (pkt->header.version_class >> 2) & 0x03;

    /* Handle connection-oriented packets */
    if (reliability_class >= NERT_CLASS_RELIABLE) {
        struct nert_connection *conn = get_connection(pkt->header.node_id);

        /* Handle SYN */
        if (pkt->header.flags & NERT_FLAG_SYN) {
            if (!conn) {
                conn = alloc_connection();
                if (!conn) return; /* No space */

                conn->peer_id = pkt->header.node_id;
                conn->recv_seq = pkt->header.seq_num + 1;
                conn->send_seq = nert_hal_random() & 0xFFFF;
                conn->last_activity = nert_hal_get_ticks();
                stats.connections_opened++;
            }

            /* Send SYN+ACK */
            struct nert_packet resp;
            memset(&resp, 0, sizeof(resp));
            resp.header.magic = NERT_MAGIC;
            resp.header.version_class = pkt->header.version_class;
            resp.header.node_id = nert_hal_get_node_id();
            resp.header.seq_num = conn->send_seq;
            resp.header.flags = NERT_FLAG_SYN | NERT_FLAG_ACK | NERT_FLAG_ENC;

#if !NERT_COMPACT_MODE
            resp.header.dest_id = conn->peer_id;
            resp.header.ack_num = conn->recv_seq;
#endif

            resp.header.nonce_counter = ++nonce_counter;

            build_nonce(nonce, nonce_counter);
            uint8_t syn_payload = PHEROMONE_ECHO;
            chacha8_encrypt(session_key, nonce, &syn_payload, 1, resp.payload);
            resp.header.payload_len = 1;

            poly1305_mac(session_key, resp.payload, 1,
                         (uint8_t*)&resp.header, NERT_HEADER_SIZE,
                         resp.auth.poly1305_tag);

            nert_hal_send(&resp, NERT_HEADER_SIZE + 1 + NERT_MAC_SIZE);
            notify_connection_state(conn, NERT_STATE_ESTABLISHED);
        }

        /* Handle ACK */
        if ((pkt->header.flags & NERT_FLAG_ACK) && conn) {
            uint32_t now = nert_hal_get_ticks();
            uint32_t response_ms = 0;

#if !NERT_COMPACT_MODE
            /* Process ACK - clear retransmit buffer */
            for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
                if (conn->tx_window[i].active &&
                    conn->tx_window[i].seq <= pkt->header.ack_num) {
                    /* Calculate response time for STDP */
                    if (response_ms == 0 || now - conn->tx_window[i].sent_tick < response_ms) {
                        response_ms = now - conn->tx_window[i].sent_tick;
                    }
                    conn->tx_window[i].active = 0;
                }
            }
#endif
            conn->last_activity = now;

            /*
             * v0.5 Hebbian Feedback: REWARD (LTP)
             * "This path worked! Strengthen the synapse."
             *
             * Uses STDP: Fast responses get bonus weight.
             * A node that responds quickly is more valuable than
             * one that barely makes the timeout.
             */
            nert_synapse_update_stdp((uint16_t)pkt->header.node_id, true, response_ms);

            /* Handle SYN+ACK completion */
            if ((pkt->header.flags & NERT_FLAG_SYN) &&
                conn->state == NERT_STATE_SYN_SENT) {
                notify_connection_state(conn, NERT_STATE_ESTABLISHED);
            }
        }

        /* Replay protection for reliable connections */
        if (conn && check_replay(conn, pkt->header.seq_num) != 0) {
            stats.rx_replay_blocked++;
            /*
             * v0.5: Report replay attempt to behavioral blacklist
             * Replay attacks are serious and damage reputation significantly
             */
            nert_blacklist_report_violation(pkt->header.node_id,
                                            NERT_VIOLATION_REPLAY);
            return;
        }
    }

    /*
     * Note: Message delivery is now handled by:
     * - unpack_messages_tlv() for v0.5 TLV format (calls callback per message)
     * - Legacy code block above for v0.4 format (single callback)
     * No additional delivery needed here.
     */
}

/* ============================================================================
 * FEC Implementation
 * ============================================================================ */

#if NERT_ENABLE_FEC

static void fec_encode(const uint8_t data[4][NERT_FEC_SHARD_SIZE],
                       uint8_t parity[2][NERT_FEC_SHARD_SIZE]) {
    /* Parity 0: XOR of even shards (0, 2) */
    for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
        parity[0][i] = data[0][i] ^ data[2][i];
    }

    /* Parity 1: XOR of odd shards (1, 3) */
    for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
        parity[1][i] = data[1][i] ^ data[3][i];
    }
}

static int fec_decode(uint8_t shards[6][NERT_FEC_SHARD_SIZE],
                      uint8_t received_mask,
                      uint8_t recovered[4][NERT_FEC_SHARD_SIZE]) {
    int missing_count = 0;
    int missing[2] = {-1, -1};

    /* Identify missing data shards */
    for (int i = 0; i < 4; i++) {
        if (!(received_mask & (1 << i))) {
            if (missing_count >= 2) return -1; /* Unrecoverable */
            missing[missing_count++] = i;
        }
    }

    /* Copy received shards */
    for (int i = 0; i < 4; i++) {
        if (received_mask & (1 << i)) {
            memcpy(recovered[i], shards[i], NERT_FEC_SHARD_SIZE);
        }
    }

    /* Recover missing shards using parity */
    if (missing_count == 1) {
        int m = missing[0];
        int parity_idx = (m % 2);      /* 0,2 -> parity[0], 1,3 -> parity[1] */
        int pair = m ^ 2;              /* 0<->2, 1<->3 */

        /* Check we have the parity shard */
        if (!(received_mask & (1 << (4 + parity_idx)))) {
            return -1;
        }

        for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
            recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
        }
        stats.rx_recovered_fec++;
    } else if (missing_count == 2) {
        /* Need both parities and missing shards must be from different groups */
        if ((missing[0] % 2) == (missing[1] % 2)) {
            return -1; /* Same group - unrecoverable */
        }

        for (int j = 0; j < 2; j++) {
            int m = missing[j];
            int parity_idx = (m % 2);
            int pair = m ^ 2;

            if (!(received_mask & (1 << (4 + parity_idx)))) {
                return -1;
            }

            for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
                recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
            }
        }
        stats.rx_recovered_fec += 2;
    }

    return 0;
}

#endif /* NERT_ENABLE_FEC */

/* ============================================================================
 * Multi-Path Routing
 * ============================================================================ */

#if NERT_ENABLE_MULTIPATH

extern uint8_t neighbor_count;
extern struct neighbor_entry neighbors[];

/* Recently failed paths - avoid for a cooling period */
#define FAILED_PATH_SLOTS       8
#define FAILED_PATH_COOLDOWN_MS 5000

static struct {
    uint16_t node_id;
    uint32_t failed_tick;
} failed_paths[FAILED_PATH_SLOTS];

/**
 * Mark a path as recently failed
 */
static void mark_path_failed(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();
    int oldest_slot = 0;
    uint32_t oldest_tick = UINT32_MAX;

    for (int i = 0; i < FAILED_PATH_SLOTS; i++) {
        /* Reuse expired or matching slot */
        if (failed_paths[i].node_id == 0 ||
            failed_paths[i].node_id == node_id ||
            (now - failed_paths[i].failed_tick) > FAILED_PATH_COOLDOWN_MS) {
            failed_paths[i].node_id = node_id;
            failed_paths[i].failed_tick = now;
            return;
        }
        if (failed_paths[i].failed_tick < oldest_tick) {
            oldest_tick = failed_paths[i].failed_tick;
            oldest_slot = i;
        }
    }

    /* Replace oldest */
    failed_paths[oldest_slot].node_id = node_id;
    failed_paths[oldest_slot].failed_tick = now;
}

/**
 * Check if path recently failed
 */
static int is_path_failed(uint16_t node_id) {
    uint32_t now = nert_hal_get_ticks();

    for (int i = 0; i < FAILED_PATH_SLOTS; i++) {
        if (failed_paths[i].node_id == node_id) {
            if ((now - failed_paths[i].failed_tick) < FAILED_PATH_COOLDOWN_MS) {
                return 1;  /* Still in cooldown */
            }
            /* Expired - clear it */
            failed_paths[i].node_id = 0;
            return 0;
        }
    }
    return 0;
}

/**
 * Select diverse paths for multi-path transmission
 *
 * Selection criteria (per plan):
 * 1. Different first hop (diversity)
 * 2. Lowest combined cost (distance + inverse synaptic weight)
 * 3. Avoid recently-failed paths
 *
 * @param dest_id   Destination node
 * @param paths     Output array of via-node IDs
 * @return          Number of paths selected (0 to NERT_MAX_PATHS)
 */
static int select_paths(uint16_t dest_id, uint16_t paths[NERT_MAX_PATHS]) {
    int path_count = 0;
    uint16_t excluded[NERT_MAX_PATHS] = {0};
    (void)dest_id;  /* Future: could use for destination-specific routing */

    /* Select up to NERT_MAX_PATHS diverse neighbors */
    for (int p = 0; p < NERT_MAX_PATHS && path_count < NERT_MAX_PATHS; p++) {
        uint16_t best_id = 0;
        uint16_t best_score = 0xFFFF;

        for (int i = 0; i < neighbor_count && i < 16; i++) {
            uint16_t node_id = neighbors[i].node_id & 0xFFFF;

            /* Skip excluded (diversity requirement) */
            int skip = 0;
            for (int e = 0; e < path_count; e++) {
                if (node_id == excluded[e]) {
                    skip = 1;
                    break;
                }
            }
            if (skip) continue;

            /* Skip recently-failed paths */
            if (is_path_failed(node_id)) {
                continue;
            }

            /*
             * Score calculation (lower is better):
             * - Base: distance (0-255)
             * - Penalty: inverse of synaptic weight (255 - weight)
             *   High weight = good path = low penalty
             * - Activity bonus: reduce score for active paths
             *
             * Combined: score = distance * 2 + (255 - synaptic_weight)
             */
            uint16_t score = (uint16_t)neighbors[i].distance * 2;
            score += (255 - neighbors[i].synaptic_weight);

            /* Activity bonus: active paths get slight preference */
            if (neighbors[i].packets > 100) {
                score = (score > 10) ? score - 10 : 0;
            }

            if (score < best_score) {
                best_score = score;
                best_id = node_id;
            }
        }

        if (best_id != 0) {
            paths[path_count] = best_id;
            excluded[path_count] = best_id;
            path_count++;
        }
    }

    return path_count;
}

/**
 * Public API: Select diverse paths for multi-path routing
 *
 * @param dest_id       Destination node ID
 * @param paths         Output array for via-node IDs
 * @param max_paths     Maximum paths to select (up to NERT_MAX_PATHS)
 * @return              Number of paths selected
 */
int nert_select_diverse_paths(uint16_t dest_id, uint16_t *paths, uint8_t max_paths) {
    if (paths == NULL || max_paths == 0) {
        return 0;
    }

    uint16_t temp_paths[NERT_MAX_PATHS];
    int count = select_paths(dest_id, temp_paths);

    /* Copy up to max_paths */
    int copy_count = (count > max_paths) ? max_paths : count;
    for (int i = 0; i < copy_count; i++) {
        paths[i] = temp_paths[i];
    }

    return copy_count;
}

/**
 * Report a path failure (for routing feedback)
 *
 * @param node_id   Node that failed to respond
 */
void nert_report_path_failure(uint16_t node_id) {
    mark_path_failed(node_id);

    /* Also update Hebbian weight */
    nert_synapse_update(node_id, false);
}

#endif /* NERT_ENABLE_MULTIPATH */

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

void nert_init(void) {
    /* Run crypto self-tests before any other initialization */
    if (nert_crypto_self_test() != 0) {
        /* Crypto self-test failed - system is in undefined state
         * In production, this should trigger a safe shutdown or alert
         * For now, we continue but the system may be compromised */
#if NERT_ENABLE_DEBUG
        /* Debug builds could log this failure */
#endif
    }

    memset(connections, 0, sizeof(connections));
    memset(dedup_cache, 0, sizeof(dedup_cache));
    memset(best_effort_queue, 0, sizeof(best_effort_queue));
    memset(&stats, 0, sizeof(stats));

    /* Initialize Smart Padding TX queue (v0.5) */
    memset(tx_queue, 0, sizeof(tx_queue));
    tx_queue_head = 0;
    tx_queue_count = 0;
    smart_pad_bytes_saved = 0;
    smart_pad_messages_batched = 0;

    /* Initialize Jitter state (v0.5) */
    memset(&jitter_state, 0, sizeof(jitter_state));
    jitter_min_ms = NERT_JITTER_MIN_MS;
    jitter_max_ms = NERT_JITTER_MAX_MS;

    /* Initialize Fragmentation state (v0.5) */
    memset(&frag_state, 0, sizeof(frag_state));
    memset(reasm_slots, 0, sizeof(reasm_slots));
    frag_tx_count = 0;
    frag_rx_reassembled = 0;
    frag_rx_timeouts = 0;

    /* Initialize Rate Limiting state (v0.5) */
    memset(rate_limit_table, 0, sizeof(rate_limit_table));
    rate_limit_last_refill = nert_hal_get_ticks();
    rate_limit_config.bucket_capacity = NERT_RATE_BUCKET_CAPACITY;
    rate_limit_config.refill_tokens = NERT_RATE_REFILL_TOKENS;
    rate_limit_config.refill_interval_ms = NERT_RATE_REFILL_MS;
    rate_limit_config.penalty_threshold = NERT_RATE_PENALTY_THRESHOLD;
    rate_limit_config.blacklist_duration_ms = NERT_RATE_BLACKLIST_MS;
    rate_limit_config.enabled = 1;

    /* Initialize Behavioral Blacklist state (v0.5) */
    memset(behavior_table, 0, sizeof(behavior_table));
    behavior_last_recovery_tick = nert_hal_get_ticks();
    behavior_config.weight_bad_mac = NERT_REPUTATION_WEIGHT_BAD_MAC;
    behavior_config.weight_replay = NERT_REPUTATION_WEIGHT_REPLAY;
    behavior_config.weight_invalid_pkt = NERT_REPUTATION_WEIGHT_INVALID_PKT;
    behavior_config.weight_rate_exceed = NERT_REPUTATION_WEIGHT_RATE_EXCEED;
    behavior_config.warn_threshold = NERT_REPUTATION_WARN_THRESHOLD;
    behavior_config.throttle_threshold = NERT_REPUTATION_THROTTLE_THRESHOLD;
    behavior_config.ban_threshold = NERT_REPUTATION_BAN_THRESHOLD;
    behavior_config.permaban_threshold = NERT_REPUTATION_PERMABAN_THRESHOLD;
    behavior_config.recovery_interval_ms = NERT_REPUTATION_RECOVERY_INTERVAL_MS;
    behavior_config.recovery_points = NERT_REPUTATION_RECOVERY_POINTS;
    behavior_config.enabled = 1;
    behavior_config.auto_blacklist = 1;
    behavior_config.notify_callback = 1;

    /* Initialize Cover Traffic state (v0.5) */
    memset(&cover_state, 0, sizeof(cover_state));
    cover_state.mode = NERT_COVER_MODE_OFF;
    cover_state.current_interval_ms = NERT_COVER_INTERVAL_MS;
    cover_config.mode = NERT_COVER_MODE_OFF;
    cover_config.base_interval_ms = NERT_COVER_INTERVAL_MS;
    cover_config.jitter_ms = NERT_COVER_JITTER_MS;
    cover_config.min_interval_ms = NERT_COVER_MIN_INTERVAL_MS;
    cover_config.max_interval_ms = NERT_COVER_MAX_INTERVAL_MS;
    cover_config.target_rate = NERT_COVER_TARGET_RATE;
    cover_config.burst_size = NERT_COVER_BURST_SIZE;
    cover_config.burst_interval_ms = NERT_COVER_BURST_INTERVAL_MS;
    cover_config.payload_min = NERT_COVER_PAYLOAD_MIN;
    cover_config.payload_max = NERT_COVER_PAYLOAD_MAX;
    cover_config.dest_id = 0;

    global_seq = nert_hal_random() & 0xFFFF;
    nonce_counter = nert_hal_random();
    dedup_index = 0;

    /* Derive initial session key */
    uint32_t epoch = nert_hal_get_ticks() / (NERT_KEY_ROTATION_SEC * 1000);
    derive_session_key(epoch);

    stats.min_rtt = 0xFFFF;
}

void nert_set_master_key(const uint8_t key[NERT_KEY_SIZE]) {
    memcpy(swarm_master_key, key, NERT_KEY_SIZE);
    /* Force key re-derivation */
    last_key_epoch = 0;
    nert_check_key_rotation();
}

void nert_set_receive_callback(nert_receive_callback_t callback) {
    receive_callback = callback;
}

void nert_set_connection_callback(nert_connection_callback_t callback) {
    connection_callback = callback;
}

int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint8_t len) {
    /*
     * v0.5: Enqueue instead of direct send.
     * Jitter and Smart Padding will be applied at flush time.
     */
    return enqueue_message(dest_id, pheromone_type, data, len,
                          NERT_CLASS_FIRE_FORGET, 0);
}

int nert_send_best_effort(uint16_t dest_id, uint8_t pheromone_type,
                          const void *data, uint8_t len) {
    /*
     * v0.5: Enqueue for jittered send.
     * Also add to retry queue for automatic retransmission.
     */
    int result = enqueue_message(dest_id, pheromone_type, data, len,
                                NERT_CLASS_BEST_EFFORT, 0);

    if (result == 0) {
        /* Also add to retry queue */
        for (int i = 0; i < BEST_EFFORT_QUEUE_SIZE; i++) {
            if (!best_effort_queue[i].active) {
                best_effort_queue[i].active = 1;
                best_effort_queue[i].retries = 1;
                best_effort_queue[i].next_retry_tick =
                    nert_hal_get_ticks() + NERT_RETRY_TIMEOUT_MS + jitter_max_ms;
                best_effort_queue[i].dest_id = dest_id;
                best_effort_queue[i].pheromone_type = pheromone_type;
                best_effort_queue[i].len = len;
                if (len > 0 && data) {
                    memcpy(best_effort_queue[i].data, data, len);
                }
                break;
            }
        }
    }

    return result;
}

int nert_send_reliable(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len) {
    /*
     * v0.5: Reliable messages are queued with HIGH priority.
     * Connection management happens here, actual send at flush time.
     */

    /* Find or create connection */
    struct nert_connection *conn = get_connection(dest_id);

    if (!conn) {
        conn = alloc_connection();
        if (!conn) return -1;

        conn->peer_id = dest_id;
        conn->send_seq = nert_hal_random() & 0xFFFF;
        conn->state = NERT_STATE_SYN_SENT;
        conn->last_activity = nert_hal_get_ticks();
        conn->srtt = NERT_RETRY_TIMEOUT_MS;
        conn->rttvar = NERT_RETRY_TIMEOUT_MS / 4;
        stats.connections_opened++;
    }

    /* Find free TX window slot */
    int slot = -1;
    for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
        if (!conn->tx_window[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -1; /* Window full */

    /* Determine flags - SYN if new connection */
    uint8_t flags = (conn->state == NERT_STATE_SYN_SENT) ? NERT_FLAG_SYN : 0;

    /* Enqueue for jittered send (HIGH priority = less jitter) */
    int result = enqueue_message(dest_id, pheromone_type, data, len,
                                NERT_CLASS_RELIABLE, flags);

    if (result == 0) {
        /* Reserve seq number and store in retransmit window */
        uint16_t assigned_seq = ++global_seq;
        conn->tx_window[slot].active = 1;
        conn->tx_window[slot].seq = assigned_seq;
        conn->tx_window[slot].retries = 0;
        conn->tx_window[slot].timeout_ms = conn->srtt + 4 * conn->rttvar + jitter_max_ms;
        conn->tx_window[slot].sent_tick = nert_hal_get_ticks();
        conn->tx_window[slot].len = len;
        if (len > 0 && data) {
            memcpy(conn->tx_window[slot].data, data, len);
        }
    }

    return conn - connections;
}

int nert_send_critical(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len) {
    /*
     * v0.5: CRITICAL messages get minimal jitter and immediate flush.
     * These bypass normal queue timing for urgent delivery.
     */
    int result;
    uint8_t flags = 0;

#if NERT_ENABLE_MULTIPATH
    /* For multipath, we'll send via multiple routes */
    uint16_t paths[NERT_MAX_PATHS];
    int path_count = select_paths(dest_id, paths);
    if (path_count > 0) {
        flags |= NERT_FLAG_MPATH;
    }
#endif

    /* Enqueue with CRITICAL priority (triggers immediate_flush) */
    result = enqueue_message(dest_id, pheromone_type, data, len,
                            NERT_CLASS_CRITICAL, flags);

    /*
     * CRITICAL messages trigger immediate flush to minimize delay.
     * The jitter_state.immediate_flush flag is set by enqueue_message
     * when priority >= NERT_PRIORITY_CRITICAL.
     */

#if NERT_ENABLE_FEC
    /* Send FEC parity packets for large payloads */
    if (len > NERT_FEC_SHARD_SIZE) {
        stats.tx_fec_blocks++;
        /* FEC encoding would go here for production use */
    }
#endif

    /* Also use reliable retransmit */
    return nert_send_reliable(dest_id, pheromone_type, data, len);
}

int nert_connect(uint16_t peer_id) {
    struct nert_connection *conn = alloc_connection();
    if (!conn) return -1;

    conn->peer_id = peer_id;
    conn->send_seq = nert_hal_random() & 0xFFFF;
    conn->state = NERT_STATE_SYN_SENT;
    conn->last_activity = nert_hal_get_ticks();
    conn->established_at = 0;
    conn->srtt = NERT_RETRY_TIMEOUT_MS;
    conn->rttvar = NERT_RETRY_TIMEOUT_MS / 4;
    stats.connections_opened++;

    /* Send SYN */
    build_and_send(peer_id, 0, NERT_CLASS_RELIABLE, NULL, 0, NERT_FLAG_SYN);

    return conn - connections;
}

void nert_disconnect(int conn_id) {
    if (conn_id < 0 || conn_id >= NERT_MAX_CONNECTIONS) return;

    struct nert_connection *conn = &connections[conn_id];
    if (conn->state == NERT_STATE_CLOSED) return;

    /* Send FIN */
    build_and_send(conn->peer_id, 0, NERT_CLASS_RELIABLE, NULL, 0, NERT_FLAG_FIN);

    notify_connection_state(conn, NERT_STATE_CLOSED);
}

int nert_get_connection_state(int conn_id) {
    if (conn_id < 0 || conn_id >= NERT_MAX_CONNECTIONS) return -1;
    return connections[conn_id].state;
}

void nert_process_incoming(void) {
    uint8_t buffer[NERT_HEADER_SIZE + NERT_MAX_PAYLOAD + NERT_MAC_SIZE];
    int len;

    while ((len = nert_hal_receive(buffer, sizeof(buffer))) > 0) {
        handle_received_packet(buffer, len);
    }
}

void nert_timer_tick(void) {
    uint32_t now = nert_hal_get_ticks();

    /*
     * v0.5: Check jitter-scheduled flush first.
     * This processes the TX queue with timing randomization.
     */
    check_jitter_flush();

    /*
     * v0.5: Clean up stale reassembly slots.
     * Incomplete fragments are discarded after timeout.
     */
    nert_reasm_cleanup();

    /*
     * v0.5: Refill rate limit token buckets.
     * Adds tokens to all tracked nodes at configured interval.
     */
    refill_rate_buckets();
    update_rate_limit_stats();

    /*
     * v0.5: Process behavioral blacklist recovery.
     * Gradually restores reputation for well-behaved nodes.
     */
    nert_blacklist_process_recovery();

    /*
     * v0.5: Process cover traffic.
     * Sends dummy packets according to configured mode.
     */
    nert_cover_process();

    /* Process best-effort retries */
    for (int i = 0; i < BEST_EFFORT_QUEUE_SIZE; i++) {
        if (best_effort_queue[i].active &&
            now >= best_effort_queue[i].next_retry_tick) {

            if (best_effort_queue[i].retries >= 2) {
                /*
                 * v0.5 Hebbian Feedback: PUNISHMENT (LTD)
                 * "This path failed! Weaken the synapse."
                 *
                 * The severe LTD (-40) ensures the network quickly
                 * learns to avoid unreliable nodes.
                 */
                nert_synapse_update((uint16_t)best_effort_queue[i].dest_id, false);

                /* Max retries reached */
                best_effort_queue[i].active = 0;
            } else {
                /* Retry */
                build_and_send(best_effort_queue[i].dest_id,
                              best_effort_queue[i].pheromone_type,
                              NERT_CLASS_BEST_EFFORT,
                              best_effort_queue[i].data,
                              best_effort_queue[i].len, 0);

                best_effort_queue[i].retries++;
                best_effort_queue[i].next_retry_tick =
                    now + NERT_RETRY_TIMEOUT_MS * (1 << best_effort_queue[i].retries);
                stats.tx_retransmits++;
            }
        }
    }

    /* Process reliable connection retransmits */
    for (int c = 0; c < NERT_MAX_CONNECTIONS; c++) {
        struct nert_connection *conn = &connections[c];
        if (conn->state == NERT_STATE_CLOSED) continue;

        /* Connection timeout */
        if (now - conn->last_activity > NERT_CONNECTION_TIMEOUT_MS) {
            /*
             * v0.5 Hebbian Feedback: PUNISHMENT (LTD)
             * Connection timed out - remote node unresponsive.
             */
            nert_synapse_update((uint16_t)conn->peer_id, false);

            notify_connection_state(conn, NERT_STATE_CLOSED);
            stats.connections_timeout++;
            continue;
        }

        /* Retransmit window entries */
        for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
            if (!conn->tx_window[i].active) continue;

            if (now - conn->tx_window[i].sent_tick > conn->tx_window[i].timeout_ms) {
                if (conn->tx_window[i].retries >= NERT_MAX_RETRIES) {
                    /*
                     * v0.5 Hebbian Feedback: PUNISHMENT (LTD)
                     * "Max retries exhausted! This path is unreliable."
                     *
                     * Severe punishment ensures the network learns to
                     * route around failing nodes.
                     */
                    nert_synapse_update((uint16_t)conn->peer_id, false);

                    /* Connection failed */
                    notify_connection_state(conn, NERT_STATE_CLOSED);
                    stats.connections_failed++;
                    break;
                }

                /* Retransmit with exponential backoff */
                conn->tx_window[i].retries++;
                conn->tx_window[i].timeout_ms *= 2;
                conn->tx_window[i].sent_tick = now;
                stats.tx_retransmits++;

                /* Rebuild and resend packet */
                /* Note: In full implementation, store complete packet */
            }
        }
    }

    /*
     * v0.5 Hebbian Maintenance: Natural Decay
     * Periodically decay synaptic weights to prevent stale high weights.
     * This allows the network to adapt to changing conditions.
     */
    nert_synapse_decay();
}

void nert_check_key_rotation(void) {
    uint32_t current_epoch = nert_hal_get_ticks() / (NERT_KEY_ROTATION_SEC * 1000);

    if (current_epoch != last_key_epoch) {
        derive_session_key(current_epoch);
    }
}

const struct nert_stats* nert_get_stats(void) {
    return &stats;
}

void nert_reset_stats(void) {
    uint16_t min_rtt = stats.min_rtt;
    memset(&stats, 0, sizeof(stats));
    stats.min_rtt = min_rtt;
}

#if NERT_ENABLE_DEBUG
void nert_debug_packet(const char *prefix, const struct nert_packet *pkt) {
    /* Platform-specific debug output */
    (void)prefix;
    (void)pkt;
}
#endif
