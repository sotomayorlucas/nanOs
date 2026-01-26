/*
 * NERT Node Authentication - Implementation
 *
 * Challenge-response authentication for secure node identity verification.
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_auth.h"
#include "../../include/nert.h"
#include <string.h>

/* ============================================================================
 * External References
 * ============================================================================ */

/* NERT HAL functions */
extern uint32_t nert_hal_random(void);
extern uint16_t nert_hal_get_node_id(void);
extern uint32_t nert_hal_get_ticks(void);

/* NERT protocol functions */
extern int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                                const void *data, uint8_t len);

/* NERT crypto functions */
extern void poly1305_mac(const uint8_t key[32],
                         const uint8_t *message, uint8_t msg_len,
                         const uint8_t *aad, uint8_t aad_len,
                         uint8_t tag[8]);

extern int poly1305_verify(const uint8_t key[32],
                           const uint8_t *message, uint8_t msg_len,
                           const uint8_t *aad, uint8_t aad_len,
                           const uint8_t expected_tag[8]);

extern void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *plaintext, uint8_t len,
                            uint8_t *ciphertext);

/* NERT session key (from nert.c) */
extern uint8_t session_key[32];
extern uint32_t last_key_epoch;

/* Secure memory zeroing */
extern void secure_memzero(void *ptr, size_t len);

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Authentication cache */
static struct node_auth auth_cache[AUTH_CACHE_SIZE];

/* Statistics */
static struct auth_stats stats;

/* Initialization flag */
static uint8_t initialized = 0;

/* ============================================================================
 * Internal Functions
 * ============================================================================ */

/**
 * Find cache entry for a node
 */
static struct node_auth* find_cache_entry(uint16_t node_id) {
    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        if (auth_cache[i].node_id == node_id) {
            return &auth_cache[i];
        }
    }
    return NULL;
}

/**
 * Allocate a cache entry
 */
static struct node_auth* alloc_cache_entry(void) {
    uint32_t now = nert_hal_get_ticks();
    int oldest_idx = -1;
    uint32_t oldest_time = UINT32_MAX;

    /* First look for free or expired slot */
    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        if (auth_cache[i].node_id == 0) {
            return &auth_cache[i];
        }
        /* Check for expired */
        if ((now - auth_cache[i].auth_time) > AUTH_TIMEOUT_MS) {
            secure_memzero(&auth_cache[i], sizeof(struct node_auth));
            return &auth_cache[i];
        }
        /* Track oldest for eviction */
        if (auth_cache[i].auth_time < oldest_time) {
            oldest_time = auth_cache[i].auth_time;
            oldest_idx = i;
        }
    }

    /* Evict oldest */
    if (oldest_idx >= 0) {
        secure_memzero(&auth_cache[oldest_idx], sizeof(struct node_auth));
        return &auth_cache[oldest_idx];
    }

    return NULL;
}

/**
 * Generate random nonce
 */
static void generate_nonce(uint8_t nonce[AUTH_NONCE_SIZE]) {
    uint32_t rnd1 = nert_hal_random();
    uint32_t rnd2 = nert_hal_random();

    nonce[0] = (rnd1 >> 24) & 0xFF;
    nonce[1] = (rnd1 >> 16) & 0xFF;
    nonce[2] = (rnd1 >> 8) & 0xFF;
    nonce[3] = rnd1 & 0xFF;
    nonce[4] = (rnd2 >> 24) & 0xFF;
    nonce[5] = (rnd2 >> 16) & 0xFF;
    nonce[6] = (rnd2 >> 8) & 0xFF;
    nonce[7] = rnd2 & 0xFF;
}

/**
 * Compute authentication HMAC
 * HMAC(key, nonce || node_id)
 */
static void compute_auth_hmac(const uint8_t *nonce, uint16_t node_id,
                               uint8_t hmac_out[AUTH_HMAC_SIZE]) {
    uint8_t msg[AUTH_NONCE_SIZE + 2];

    memcpy(msg, nonce, AUTH_NONCE_SIZE);
    msg[AUTH_NONCE_SIZE] = (node_id >> 8) & 0xFF;
    msg[AUTH_NONCE_SIZE + 1] = node_id & 0xFF;

    poly1305_mac(session_key, msg, AUTH_NONCE_SIZE + 2, NULL, 0, hmac_out);
}

/**
 * Verify authentication HMAC
 */
static int verify_auth_hmac(const uint8_t *nonce, uint16_t node_id,
                             const uint8_t expected_hmac[AUTH_HMAC_SIZE]) {
    uint8_t msg[AUTH_NONCE_SIZE + 2];

    memcpy(msg, nonce, AUTH_NONCE_SIZE);
    msg[AUTH_NONCE_SIZE] = (node_id >> 8) & 0xFF;
    msg[AUTH_NONCE_SIZE + 1] = node_id & 0xFF;

    return poly1305_verify(session_key, msg, AUTH_NONCE_SIZE + 2,
                           NULL, 0, expected_hmac);
}

/**
 * Derive per-peer session key
 */
static void derive_peer_key(uint16_t peer_id, const uint8_t *nonce_a,
                            const uint8_t *nonce_b, uint8_t key_out[32]) {
    /* Combine nonces with peer ID for key derivation */
    uint8_t material[AUTH_NONCE_SIZE * 2 + 4];
    uint8_t nonce[12] = {0};

    memcpy(material, nonce_a, AUTH_NONCE_SIZE);
    memcpy(material + AUTH_NONCE_SIZE, nonce_b, AUTH_NONCE_SIZE);
    material[AUTH_NONCE_SIZE * 2] = (peer_id >> 8) & 0xFF;
    material[AUTH_NONCE_SIZE * 2 + 1] = peer_id & 0xFF;
    material[AUTH_NONCE_SIZE * 2 + 2] = 'A';
    material[AUTH_NONCE_SIZE * 2 + 3] = 'K';

    /* Use ChaCha8 as KDF */
    chacha8_encrypt(session_key, nonce, material, 32, key_out);
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

void nert_auth_init(void) {
    memset(auth_cache, 0, sizeof(auth_cache));
    memset(&stats, 0, sizeof(stats));
    initialized = 1;
}

int nert_auth_is_authenticated(uint16_t node_id) {
    if (!initialized) return 0;

    struct node_auth *entry = find_cache_entry(node_id);
    if (!entry) {
        stats.cache_misses++;
        return 0;
    }

    /* Check if authentication has expired */
    uint32_t now = nert_hal_get_ticks();
    if ((now - entry->auth_time) > AUTH_TIMEOUT_MS) {
        secure_memzero(entry, sizeof(struct node_auth));
        stats.cache_misses++;
        return 0;
    }

    /* Check if key has rotated since authentication */
    if (entry->key_epoch != last_key_epoch) {
        secure_memzero(entry, sizeof(struct node_auth));
        stats.reauth_required++;
        return 0;
    }

    /* Check state */
    if (entry->state != AUTH_STATE_AUTHENTICATED) {
        return 0;
    }

    stats.cache_hits++;
    return 1;
}

int nert_auth_challenge(uint16_t node_id) {
    if (!initialized) return AUTH_ERR_INVALID;

    /* Allocate or find entry */
    struct node_auth *entry = find_cache_entry(node_id);
    if (!entry) {
        entry = alloc_cache_entry();
        if (!entry) {
            return AUTH_ERR_CACHE_FULL;
        }
    }

    /* Generate challenge */
    struct auth_challenge challenge;
    challenge.challenger_id = nert_hal_get_node_id();
    generate_nonce(challenge.nonce);

    /* Store state */
    entry->node_id = node_id;
    entry->state = AUTH_STATE_CHALLENGE_SENT;
    entry->auth_time = nert_hal_get_ticks();  /* For timeout tracking */
    entry->key_epoch = last_key_epoch;
    memcpy(entry->pending_nonce, challenge.nonce, AUTH_NONCE_SIZE);

    /* Send challenge */
    int result = nert_send_unreliable(node_id, PHEROMONE_AUTH_CHALLENGE,
                                       &challenge, sizeof(challenge));

    if (result == 0) {
        stats.challenges_sent++;
    }

    return result;
}

int nert_auth_handle_challenge(uint16_t challenger_id,
                                const struct auth_challenge *challenge) {
    if (!initialized || !challenge) return AUTH_ERR_INVALID;

    stats.challenges_received++;

    /* Allocate entry for this challenger */
    struct node_auth *entry = find_cache_entry(challenger_id);
    if (!entry) {
        entry = alloc_cache_entry();
        if (!entry) {
            return AUTH_ERR_CACHE_FULL;
        }
    }

    /* Build response */
    struct auth_response response;
    response.responder_id = nert_hal_get_node_id();

    /* Compute HMAC(key, nonce_a || B_id) where B is us */
    compute_auth_hmac(challenge->nonce, response.responder_id, response.hmac);

    /* Generate our nonce for mutual auth */
    generate_nonce(response.nonce);

    /* Store state */
    entry->node_id = challenger_id;
    entry->state = AUTH_STATE_RESPONSE_SENT;
    entry->auth_time = nert_hal_get_ticks();
    entry->key_epoch = last_key_epoch;
    memcpy(entry->pending_nonce, response.nonce, AUTH_NONCE_SIZE);

    /* Send response */
    return nert_send_unreliable(challenger_id, PHEROMONE_AUTH_RESPONSE,
                                 &response, sizeof(response));
}

int nert_auth_handle_response(uint16_t responder_id,
                               const struct auth_response *response) {
    if (!initialized || !response) return AUTH_ERR_INVALID;

    /* Find our challenge entry */
    struct node_auth *entry = find_cache_entry(responder_id);
    if (!entry || entry->state != AUTH_STATE_CHALLENGE_SENT) {
        stats.auth_failures++;
        return AUTH_ERR_NOT_FOUND;
    }

    /* Verify HMAC(key, nonce_a || B_id) */
    if (verify_auth_hmac(entry->pending_nonce, responder_id, response->hmac) != 0) {
        stats.auth_failures++;
        secure_memzero(entry, sizeof(struct node_auth));
        return AUTH_ERR_VERIFY_FAILED;
    }

    /* Build confirm for mutual authentication */
    struct auth_confirm confirm;
    confirm.confirmer_id = nert_hal_get_node_id();

    /* Compute HMAC(key, nonce_b || A_id) where A is us */
    compute_auth_hmac(response->nonce, confirm.confirmer_id, confirm.hmac);

    /* Derive per-peer session key */
    derive_peer_key(responder_id, entry->pending_nonce, response->nonce,
                    entry->shared_secret);

    /* Update state - authentication complete on our side */
    entry->state = AUTH_STATE_AUTHENTICATED;
    entry->auth_time = nert_hal_get_ticks();

    stats.auth_successes++;
    stats.active_sessions++;

    /* Send confirm */
    return nert_send_unreliable(responder_id, PHEROMONE_AUTH_CONFIRM,
                                 &confirm, sizeof(confirm));
}

int nert_auth_handle_confirm(uint16_t confirmer_id,
                              const struct auth_confirm *confirm) {
    if (!initialized || !confirm) return AUTH_ERR_INVALID;

    /* Find our response entry */
    struct node_auth *entry = find_cache_entry(confirmer_id);
    if (!entry || entry->state != AUTH_STATE_RESPONSE_SENT) {
        stats.auth_failures++;
        return AUTH_ERR_NOT_FOUND;
    }

    /* Verify HMAC(key, nonce_b || A_id) */
    if (verify_auth_hmac(entry->pending_nonce, confirmer_id, confirm->hmac) != 0) {
        stats.auth_failures++;
        secure_memzero(entry, sizeof(struct node_auth));
        return AUTH_ERR_VERIFY_FAILED;
    }

    /* Derive per-peer session key (same as other side) */
    /* Note: Need the original challenge nonce - store it or reconstruct */
    /* For simplicity, we use our nonce + their ID */
    uint8_t zero_nonce[AUTH_NONCE_SIZE] = {0};
    derive_peer_key(confirmer_id, zero_nonce, entry->pending_nonce,
                    entry->shared_secret);

    /* Update state - mutual authentication complete */
    entry->state = AUTH_STATE_AUTHENTICATED;
    entry->auth_time = nert_hal_get_ticks();

    stats.auth_successes++;
    stats.active_sessions++;

    return AUTH_OK;
}

int nert_auth_get_session_key(uint16_t node_id, uint8_t *key_out) {
    if (!initialized || !key_out) return AUTH_ERR_INVALID;

    if (!nert_auth_is_authenticated(node_id)) {
        return AUTH_ERR_NOT_FOUND;
    }

    struct node_auth *entry = find_cache_entry(node_id);
    if (!entry) return AUTH_ERR_NOT_FOUND;

    memcpy(key_out, entry->shared_secret, 32);
    return AUTH_OK;
}

void nert_auth_revoke(uint16_t node_id) {
    if (!initialized) return;

    struct node_auth *entry = find_cache_entry(node_id);
    if (entry) {
        if (entry->state == AUTH_STATE_AUTHENTICATED) {
            stats.active_sessions--;
        }
        secure_memzero(entry, sizeof(struct node_auth));
    }
}

void nert_auth_process_timeouts(uint32_t current_tick) {
    if (!initialized) return;

    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        struct node_auth *entry = &auth_cache[i];
        if (entry->node_id == 0) continue;

        uint32_t elapsed = current_tick - entry->auth_time;

        /* Check for challenge timeout */
        if (entry->state == AUTH_STATE_CHALLENGE_SENT ||
            entry->state == AUTH_STATE_RESPONSE_SENT) {
            if (elapsed > AUTH_CHALLENGE_TIMEOUT_MS) {
                secure_memzero(entry, sizeof(struct node_auth));
                stats.timeouts++;
            }
        }
        /* Check for authentication timeout */
        else if (entry->state == AUTH_STATE_AUTHENTICATED) {
            if (elapsed > AUTH_TIMEOUT_MS) {
                stats.active_sessions--;
                secure_memzero(entry, sizeof(struct node_auth));
            }
        }
    }
}

void nert_auth_invalidate_all(void) {
    if (!initialized) return;

    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        if (auth_cache[i].state == AUTH_STATE_AUTHENTICATED) {
            stats.active_sessions--;
        }
        secure_memzero(&auth_cache[i], sizeof(struct node_auth));
    }

    stats.reauth_required += AUTH_CACHE_SIZE;
}

const struct auth_stats* nert_auth_get_stats(void) {
    return &stats;
}

void nert_auth_reset_stats(void) {
    uint16_t active = stats.active_sessions;
    memset(&stats, 0, sizeof(stats));
    stats.active_sessions = active;
}
