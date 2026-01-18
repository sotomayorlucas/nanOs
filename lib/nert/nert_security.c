/*
 * NERT Security Extensions - Implementation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_security.h"
#include "nert_config.h"
#include "../../include/nert.h"
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Payload constraints table */
#define MAX_CONSTRAINTS 32
static struct nert_payload_constraints constraints[MAX_CONSTRAINTS];
static uint8_t constraint_count = 0;

/* Security statistics */
static uint32_t bad_mac_count = 0;
static uint32_t replay_count = 0;
static uint32_t invalid_payload_count = 0;

/* External references to NERT core */
extern uint8_t session_key[NERT_KEY_SIZE];
extern uint8_t prev_session_key[NERT_KEY_SIZE];
extern uint8_t next_session_key[NERT_KEY_SIZE];
extern uint32_t last_key_epoch;
extern const uint8_t swarm_master_key[NERT_KEY_SIZE];

/* External NERT HAL functions */
extern uint32_t nert_hal_random(void);
extern uint16_t nert_hal_get_node_id(void);
extern uint32_t nert_hal_get_ticks(void);

/* External NERT protocol functions */
extern int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                                const void *data, uint8_t len);
extern void derive_session_key(uint32_t epoch_hour);

/* External crypto functions from nert.c */
extern void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *plaintext, uint8_t len,
                           uint8_t *ciphertext);

extern void poly1305_mac(const uint8_t key[32],
                        const uint8_t *message, uint8_t msg_len,
                        const uint8_t *aad, uint8_t aad_len,
                        uint8_t tag[NERT_MAC_SIZE]);

extern int poly1305_verify(const uint8_t key[32],
                          const uint8_t *message, uint8_t msg_len,
                          const uint8_t *aad, uint8_t aad_len,
                          const uint8_t expected_tag[NERT_MAC_SIZE]);

/* ============================================================================
 * Payload Validation
 * ============================================================================ */

static void init_default_constraints(void) {
    /* Core protocol messages */
    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = PHEROMONE_ECHO,
        .min_len = 0,
        .max_len = 16,
        .fixed_size = 0
    };

    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = PHEROMONE_ANNOUNCE,
        .min_len = 4,
        .max_len = 32,
        .fixed_size = 0
    };

    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = PHEROMONE_ELECTION,
        .min_len = 8,
        .max_len = 16,
        .fixed_size = 0
    };

    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = PHEROMONE_REKEY,
        .min_len = sizeof(struct nert_rekey_request),
        .max_len = sizeof(struct nert_rekey_request),
        .fixed_size = 1
    };

    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = PHEROMONE_DIE,
        .min_len = 0,
        .max_len = 8,
        .fixed_size = 0
    };
}

int nert_security_validate_payload(uint8_t msg_type, const void *payload, uint8_t len) {
    /* Initialize constraints on first call */
    static uint8_t initialized = 0;
    if (!initialized) {
        init_default_constraints();
        initialized = 1;
    }

    /* Find constraints for this message type */
    for (uint8_t i = 0; i < constraint_count; i++) {
        if (constraints[i].msg_type == msg_type) {
            /* Check length constraints */
            if (constraints[i].fixed_size) {
                if (len != constraints[i].min_len) {
                    invalid_payload_count++;
                    return -1;  /* Fixed size mismatch */
                }
            } else {
                if (len < constraints[i].min_len || len > constraints[i].max_len) {
                    invalid_payload_count++;
                    return -1;  /* Out of range */
                }
            }

            /* Additional validation for specific types */
            switch (msg_type) {
                case PHEROMONE_REKEY:
                    /* Validate rekey structure */
                    if (payload == NULL) {
                        invalid_payload_count++;
                        return -1;
                    }
                    break;

                case PHEROMONE_ELECTION:
                    /* Validate election data contains node_id + priority */
                    if (len < 6) {
                        invalid_payload_count++;
                        return -1;
                    }
                    break;

                default:
                    break;
            }

            return 0;  /* Valid */
        }
    }

    /* No constraints defined - allow
     * Since len is uint8_t, it's always <= 255 by definition
     */
    return 0;  /* No constraints = allow */
}

int nert_security_register_constraints(uint8_t msg_type, uint8_t min_len,
                                       uint8_t max_len, uint8_t fixed_size) {
    if (constraint_count >= MAX_CONSTRAINTS) {
        return -1;
    }

    /* Check if constraint already exists */
    for (uint8_t i = 0; i < constraint_count; i++) {
        if (constraints[i].msg_type == msg_type) {
            /* Update existing */
            constraints[i].min_len = min_len;
            constraints[i].max_len = max_len;
            constraints[i].fixed_size = fixed_size;
            return 0;
        }
    }

    /* Add new constraint */
    constraints[constraint_count++] = (struct nert_payload_constraints){
        .msg_type = msg_type,
        .min_len = min_len,
        .max_len = max_len,
        .fixed_size = fixed_size
    };

    return 0;
}

/* ============================================================================
 * Key Management
 * ============================================================================ */

int nert_security_initiate_rekey(uint32_t new_epoch) {
    /*
     * Key Rotation Protocol - Initiator (Queen/Coordinator)
     *
     * This function initiates a swarm-wide key rotation:
     * 1. Generate new random seed
     * 2. Encrypt seed with current session key
     * 3. Sign the encrypted seed with Poly1305 MAC
     * 4. Broadcast PHEROMONE_REKEY to all nodes
     * 5. Nodes will switch keys after grace period
     */

    struct nert_rekey_request request;
    uint8_t new_seed[32];
    uint8_t nonce[12];

    /* Step 1: Generate new random seed */
    for (int i = 0; i < 32; i += 4) {
        uint32_t rnd = nert_hal_random();
        new_seed[i + 0] = (rnd >> 24) & 0xFF;
        new_seed[i + 1] = (rnd >> 16) & 0xFF;
        new_seed[i + 2] = (rnd >> 8) & 0xFF;
        new_seed[i + 3] = rnd & 0xFF;
    }

    /* Step 2: Build nonce for encryption
     * Format: new_epoch (4 bytes) + zeros (8 bytes)
     * The epoch number provides sufficient uniqueness
     */
    memset(nonce, 0, 12);
    nonce[0] = (new_epoch >> 24) & 0xFF;
    nonce[1] = (new_epoch >> 16) & 0xFF;
    nonce[2] = (new_epoch >> 8) & 0xFF;
    nonce[3] = new_epoch & 0xFF;

    /* Step 3: Encrypt the seed with current session key */
    chacha8_encrypt(session_key, nonce, new_seed, 32, request.encrypted_seed);

    /* Step 4: Set epoch in request */
    request.new_epoch = new_epoch;

    /* Step 5: Sign the request with Poly1305 MAC
     * Sign: new_epoch || encrypted_seed
     */
    uint8_t to_sign[36];  /* 4 bytes epoch + 32 bytes encrypted seed */
    to_sign[0] = (new_epoch >> 24) & 0xFF;
    to_sign[1] = (new_epoch >> 16) & 0xFF;
    to_sign[2] = (new_epoch >> 8) & 0xFF;
    to_sign[3] = new_epoch & 0xFF;
    memcpy(to_sign + 4, request.encrypted_seed, 32);

    poly1305_mac(session_key, to_sign, 36, NULL, 0, request.signature);

    /* Step 6: Broadcast PHEROMONE_REKEY to swarm
     * Destination 0 = broadcast to all nodes
     */
    int result = nert_send_unreliable(0, PHEROMONE_REKEY,
                                      &request, sizeof(request));

    if (result == 0) {
        /* Step 7: Pre-compute next session key for the new epoch
         * This allows us to accept messages encrypted with the new key
         * immediately after the grace period
         */
        derive_session_key(new_epoch);

        /* Optionally: Set a timer to fully switch to new key after grace period
         * For now, the grace window mechanism handles this automatically
         */
    }

    return result;
}

int nert_security_handle_rekey(const struct nert_rekey_request *request) {
    /*
     * Key Rotation Protocol - Handler (Worker/Follower)
     *
     * This function handles a PHEROMONE_REKEY message:
     * 1. Verify the signature to ensure it came from legitimate Queen
     * 2. Decrypt the new seed
     * 3. Derive new session keys
     * 4. Send acknowledgment (optional)
     * 5. Key switch is automatic via grace window mechanism
     */

    if (!request) {
        return -1;
    }

    /* Step 1: Verify signature
     * Reconstruct the signed data: new_epoch || encrypted_seed
     */
    uint8_t to_verify[36];
    to_verify[0] = (request->new_epoch >> 24) & 0xFF;
    to_verify[1] = (request->new_epoch >> 16) & 0xFF;
    to_verify[2] = (request->new_epoch >> 8) & 0xFF;
    to_verify[3] = request->new_epoch & 0xFF;
    memcpy(to_verify + 4, request->encrypted_seed, 32);

    /* Verify using current session key */
    if (poly1305_verify(session_key, to_verify, 36, NULL, 0, request->signature) != 0) {
        /* Signature verification failed - could be attack */
        invalid_payload_count++;
        return -1;
    }

    /* Step 2: Decrypt the new seed
     * Use same nonce construction as sender
     * Note: We use the epoch number directly as nonce since the seed
     * is unique per epoch and doesn't need node_id uniqueness
     */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    nonce[0] = (request->new_epoch >> 24) & 0xFF;
    nonce[1] = (request->new_epoch >> 16) & 0xFF;
    nonce[2] = (request->new_epoch >> 8) & 0xFF;
    nonce[3] = request->new_epoch & 0xFF;

    /* Note: ChaCha is symmetric, so encrypt = decrypt */
    uint8_t decrypted_seed[32];
    chacha8_encrypt(session_key, nonce, request->encrypted_seed, 32, decrypted_seed);

    /* Step 3: Derive new session keys for the new epoch
     * This updates session_key, prev_session_key, and next_session_key
     */
    derive_session_key(request->new_epoch);

    /* Step 4: Send acknowledgment (optional)
     * Format: epoch (4 bytes) + node_id (2 bytes)
     * We send to broadcast (0) so Queen can collect stats
     */
    struct nert_rekey_ack ack;
    ack.epoch = request->new_epoch;
    ack.node_id = nert_hal_get_node_id();

    nert_send_unreliable(0, PHEROMONE_REKEY, &ack, sizeof(ack));

    /* Step 5: Key switch is automatic
     * The grace window mechanism in NERT allows both old and new keys
     * to be valid for NERT_KEY_GRACE_WINDOW_MS (30 seconds by default)
     * This handles clock drift between nodes
     */

    return 0;
}

void nert_security_wipe_keys(void) {
    /* Overwrite sensitive key material with zeros
     * This is called during apoptosis or before key rotation
     */
    volatile uint8_t *p;

    /* Wipe session keys */
    p = (volatile uint8_t *)session_key;
    for (int i = 0; i < NERT_KEY_SIZE; i++) {
        p[i] = 0;
    }

    p = (volatile uint8_t *)prev_session_key;
    for (int i = 0; i < NERT_KEY_SIZE; i++) {
        p[i] = 0;
    }

    p = (volatile uint8_t *)next_session_key;
    for (int i = 0; i < NERT_KEY_SIZE; i++) {
        p[i] = 0;
    }
}

void nert_security_get_stats(uint32_t *bad_mac_count_out,
                             uint32_t *replay_count_out,
                             uint32_t *invalid_payload_count_out) {
    if (bad_mac_count_out) *bad_mac_count_out = bad_mac_count;
    if (replay_count_out) *replay_count_out = replay_count;
    if (invalid_payload_count_out) *invalid_payload_count_out = invalid_payload_count;
}

/* ============================================================================
 * Cryptographic Primitives
 * (Implementations provided by nert.c, declared here for linking)
 * ============================================================================ */

/* These are implemented in the main NERT core (nert.c) */
/* We just provide the declarations here */
