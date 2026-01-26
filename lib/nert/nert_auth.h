/*
 * NERT Node Authentication
 *
 * Challenge-response authentication protocol for node identity verification.
 *
 * Protocol flow:
 * 1. A -> B: AUTH_CHALLENGE, nonce_a
 * 2. B -> A: AUTH_RESPONSE, HMAC(key, nonce_a || B_id), nonce_b
 * 3. A -> B: AUTH_CONFIRM, HMAC(key, nonce_b || A_id)
 *
 * Features:
 * - Mutual authentication
 * - Replay protection via nonces
 * - Cached authentication with timeout
 * - Automatic re-auth after key rotation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_AUTH_H
#define NERT_AUTH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Maximum cached authenticated nodes */
#if defined(__arm__) || defined(ESP_PLATFORM)
    #define AUTH_CACHE_SIZE             8
#else
    #define AUTH_CACHE_SIZE             16
#endif

/* Authentication timeout (5 minutes) */
#define AUTH_TIMEOUT_MS                 300000

/* Challenge timeout (10 seconds to respond) */
#define AUTH_CHALLENGE_TIMEOUT_MS       10000

/* Nonce size */
#define AUTH_NONCE_SIZE                 8

/* HMAC size (truncated) */
#define AUTH_HMAC_SIZE                  8

/* Authentication states */
#define AUTH_STATE_NONE                 0
#define AUTH_STATE_CHALLENGE_SENT       1
#define AUTH_STATE_RESPONSE_SENT        2
#define AUTH_STATE_AUTHENTICATED        3

/* Pheromone types for authentication */
#define PHEROMONE_AUTH_CHALLENGE        0x20
#define PHEROMONE_AUTH_RESPONSE         0x21
#define PHEROMONE_AUTH_CONFIRM          0x22

/* Error codes */
#define AUTH_OK                         0
#define AUTH_ERR_INVALID                -1
#define AUTH_ERR_TIMEOUT                -2
#define AUTH_ERR_VERIFY_FAILED          -3
#define AUTH_ERR_CACHE_FULL             -4
#define AUTH_ERR_NOT_FOUND              -5

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Node authentication cache entry
 */
struct node_auth {
    uint16_t node_id;                   /* Authenticated node ID (0 = free slot) */
    uint8_t  state;                     /* AUTH_STATE_* */
    uint8_t  _reserved;
    uint32_t auth_time;                 /* When authentication completed */
    uint32_t key_epoch;                 /* Key epoch at authentication time */
    uint8_t  pending_nonce[AUTH_NONCE_SIZE];  /* Our nonce (awaiting response) */
    uint8_t  shared_secret[32];         /* Derived session key for this peer */
};

/**
 * Challenge message
 */
struct auth_challenge {
    uint16_t challenger_id;             /* Who is challenging */
    uint8_t  nonce[AUTH_NONCE_SIZE];    /* Random nonce */
} __attribute__((packed));

/**
 * Response message
 */
struct auth_response {
    uint16_t responder_id;              /* Who is responding */
    uint8_t  hmac[AUTH_HMAC_SIZE];      /* HMAC(key, nonce_a || B_id) */
    uint8_t  nonce[AUTH_NONCE_SIZE];    /* Responder's nonce for mutual auth */
} __attribute__((packed));

/**
 * Confirm message (mutual authentication)
 */
struct auth_confirm {
    uint16_t confirmer_id;              /* Who is confirming */
    uint8_t  hmac[AUTH_HMAC_SIZE];      /* HMAC(key, nonce_b || A_id) */
} __attribute__((packed));

/**
 * Authentication statistics
 */
struct auth_stats {
    uint32_t challenges_sent;           /* Challenges initiated */
    uint32_t challenges_received;       /* Challenges from others */
    uint32_t auth_successes;            /* Successful authentications */
    uint32_t auth_failures;             /* Failed authentications */
    uint32_t cache_hits;                /* Cache lookups that found valid entry */
    uint32_t cache_misses;              /* Cache lookups that didn't find entry */
    uint32_t timeouts;                  /* Challenge timeouts */
    uint32_t reauth_required;           /* Re-auths after key rotation */
    uint16_t active_sessions;           /* Currently authenticated nodes */
};

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize authentication subsystem
 */
void nert_auth_init(void);

/**
 * Check if a node is authenticated
 *
 * @param node_id   Node to check
 * @return          1 if authenticated, 0 if not
 */
int nert_auth_is_authenticated(uint16_t node_id);

/**
 * Initiate authentication with a node
 * Sends AUTH_CHALLENGE and waits for response.
 *
 * @param node_id   Node to authenticate
 * @return          AUTH_OK on success, error code on failure
 */
int nert_auth_challenge(uint16_t node_id);

/**
 * Handle received AUTH_CHALLENGE
 * Verifies and sends AUTH_RESPONSE.
 *
 * @param challenger_id Node that sent the challenge
 * @param challenge     Challenge message data
 * @return              AUTH_OK on success, error code on failure
 */
int nert_auth_handle_challenge(uint16_t challenger_id,
                                const struct auth_challenge *challenge);

/**
 * Handle received AUTH_RESPONSE
 * Verifies response and sends AUTH_CONFIRM for mutual auth.
 *
 * @param responder_id  Node that sent the response
 * @param response      Response message data
 * @return              AUTH_OK on success, error code on failure
 */
int nert_auth_handle_response(uint16_t responder_id,
                               const struct auth_response *response);

/**
 * Handle received AUTH_CONFIRM
 * Completes mutual authentication.
 *
 * @param confirmer_id  Node that sent the confirm
 * @param confirm       Confirm message data
 * @return              AUTH_OK on success, error code on failure
 */
int nert_auth_handle_confirm(uint16_t confirmer_id,
                              const struct auth_confirm *confirm);

/**
 * Get derived session key for authenticated peer
 *
 * @param node_id       Authenticated node
 * @param key_out       Output buffer (32 bytes)
 * @return              AUTH_OK on success, error code on failure
 */
int nert_auth_get_session_key(uint16_t node_id, uint8_t *key_out);

/**
 * Revoke authentication for a node
 *
 * @param node_id   Node to deauthenticate
 */
void nert_auth_revoke(uint16_t node_id);

/**
 * Process authentication timeouts
 * Should be called periodically from timer tick.
 *
 * @param current_tick  Current system tick
 */
void nert_auth_process_timeouts(uint32_t current_tick);

/**
 * Invalidate all authentications
 * Called after key rotation.
 */
void nert_auth_invalidate_all(void);

/**
 * Get authentication statistics
 *
 * @return  Pointer to stats structure (read-only)
 */
const struct auth_stats* nert_auth_get_stats(void);

/**
 * Reset authentication statistics
 */
void nert_auth_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_AUTH_H */
