/*
 * NERT Security Extensions
 * Enhanced security features for v0.4
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_SECURITY_H
#define NERT_SECURITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NERT_KEY_SIZE       32
#define NERT_NONCE_SIZE     12
#define NERT_MAC_SIZE       8

/* ============================================================================
 * Key Management
 * ============================================================================ */

/**
 * Key rotation request structure
 * Sent from Queen/Coordinator to initiate key rotation
 */
struct nert_rekey_request {
    uint32_t new_epoch;                 /* New epoch number */
    uint8_t encrypted_seed[32];         /* New key seed (encrypted with current key) */
    uint8_t signature[16];              /* HMAC signature for authenticity */
} __attribute__((packed));

/**
 * Key rotation acknowledgment
 * Nodes send this back to confirm they've rotated keys
 */
struct nert_rekey_ack {
    uint32_t epoch;                     /* Epoch they've switched to */
    uint16_t node_id;                   /* Node confirming */
} __attribute__((packed));

/* ============================================================================
 * Payload Validation
 * ============================================================================ */

/**
 * Payload constraints for each message type
 * Used for defensive input validation
 */
struct nert_payload_constraints {
    uint8_t msg_type;                   /* Message type */
    uint8_t min_len;                    /* Minimum payload length */
    uint8_t max_len;                    /* Maximum payload length */
    uint8_t fixed_size;                 /* 1 if fixed size, 0 if variable */
};

/* ============================================================================
 * Security API
 * ============================================================================ */

/**
 * Initiate key rotation (Queen/Coordinator only)
 * Generates new key seed and broadcasts to swarm
 * @param new_epoch  New epoch number
 * @return 0 on success, -1 on error
 */
int nert_security_initiate_rekey(uint32_t new_epoch);

/**
 * Handle key rotation request
 * Called when node receives PHEROMONE_REKEY
 * @param request  Rekey request data
 * @return 0 on success, -1 if validation fails
 */
int nert_security_handle_rekey(const struct nert_rekey_request *request);

/**
 * Validate payload against constraints
 * @param msg_type  Message type
 * @param payload  Payload data
 * @param len  Payload length
 * @return 0 if valid, -1 if invalid
 */
int nert_security_validate_payload(uint8_t msg_type, const void *payload, uint8_t len);

/**
 * Register custom payload constraints
 * Applications can register validation rules for custom message types
 * @param msg_type  Message type
 * @param min_len  Minimum allowed length
 * @param max_len  Maximum allowed length
 * @param fixed_size  1 if exact size required, 0 if variable
 * @return 0 on success, -1 on error
 */
int nert_security_register_constraints(uint8_t msg_type, uint8_t min_len,
                                       uint8_t max_len, uint8_t fixed_size);

/**
 * Wipe sensitive data from memory
 * Called during apoptosis or key rotation
 */
void nert_security_wipe_keys(void);

/**
 * Get current security statistics
 * @param bad_mac_count  Out: Number of bad MAC attempts
 * @param replay_count  Out: Number of replay attempts blocked
 * @param invalid_payload_count  Out: Number of invalid payloads rejected
 */
void nert_security_get_stats(uint32_t *bad_mac_count,
                             uint32_t *replay_count,
                             uint32_t *invalid_payload_count);

/* ============================================================================
 * Cryptographic Primitives (Internal)
 * ============================================================================ */

/**
 * ChaCha8 encryption
 * Lightweight cipher for embedded systems
 */
void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *plaintext, uint8_t len,
                     uint8_t *ciphertext);

/**
 * Poly1305 MAC computation
 * Simplified for embedded systems (64-bit output)
 */
void poly1305_mac(const uint8_t key[32],
                  const uint8_t *message, uint8_t msg_len,
                  const uint8_t *aad, uint8_t aad_len,
                  uint8_t tag[NERT_MAC_SIZE]);

/**
 * Poly1305 MAC verification
 */
int poly1305_verify(const uint8_t key[32],
                    const uint8_t *message, uint8_t msg_len,
                    const uint8_t *aad, uint8_t aad_len,
                    const uint8_t expected_tag[NERT_MAC_SIZE]);

/**
 * Derive key from master key and epoch
 * Uses ChaCha8 as PRF (Pseudo-Random Function)
 */
void derive_key_for_epoch(const uint8_t master_key[NERT_KEY_SIZE],
                          uint32_t epoch,
                          uint8_t out_key[NERT_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* NERT_SECURITY_H */
