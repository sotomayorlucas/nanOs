/*
 * NERT Security Extensions - Implementation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_security.h"
#include "nert_config.h"
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

    /* No constraints defined - allow if within reasonable bounds */
    if (len > 255) {
        invalid_payload_count++;
        return -1;
    }

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
    /* TODO: Implement key rotation broadcast
     * This should:
     * 1. Generate new key seed
     * 2. Encrypt with current session key
     * 3. Broadcast PHEROMONE_REKEY to swarm
     * 4. Wait for acknowledgments
     * 5. Switch to new key after grace period
     */
    (void)new_epoch;
    return 0;
}

int nert_security_handle_rekey(const struct nert_rekey_request *request) {
    /* TODO: Implement key rotation handler
     * This should:
     * 1. Verify signature
     * 2. Decrypt new seed
     * 3. Derive new session key
     * 4. Send acknowledgment
     * 5. Schedule key switch
     */
    (void)request;
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
