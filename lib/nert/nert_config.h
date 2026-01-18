/*
 * NERT Framework Configuration
 * Decouples protocol from application logic
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_CONFIG_H
#define NERT_CONFIG_H

#include <stdint.h>
#include "nert_phy_if.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct nert_phy_interface;

/* ============================================================================
 * Message Types (Pheromones)
 * Application can define custom types starting from 0x80
 * ============================================================================ */

/* Core protocol messages */
#define PHEROMONE_ECHO          0x00    /* Keep-alive / ping */
#define PHEROMONE_ANNOUNCE      0x01    /* Node announcement */
#define PHEROMONE_ELECTION      0x02    /* Leader election */
#define PHEROMONE_REKEY         0x03    /* Key rotation (NEW in v0.4) */

/* Application messages */
#define PHEROMONE_DATA          0x10    /* Generic data */
#define PHEROMONE_ALARM         0x11    /* Alert/alarm */
#define PHEROMONE_COMMAND       0x12    /* Command/control */
#define PHEROMONE_DIE           0x13    /* Apoptosis trigger */

/* Application-defined start */
#define PHEROMONE_APP_BASE      0x80

/* ============================================================================
 * Security Configuration
 * ============================================================================ */

#define NERT_KEY_SIZE           32

/**
 * Security configuration
 */
struct nert_security_config {
    /**
     * Swarm master key (32 bytes)
     * Pre-shared across all nodes in the swarm
     */
    uint8_t master_key[NERT_KEY_SIZE];

    /**
     * Enable automatic key rotation
     * If enabled, keys rotate every NERT_KEY_ROTATION_SEC
     */
    uint8_t enable_key_rotation;

    /**
     * Key rotation period in seconds
     * Default: 3600 (1 hour)
     */
    uint32_t key_rotation_period_sec;

    /**
     * Grace window for clock drift in milliseconds
     * Default: 30000 (30 seconds)
     */
    uint32_t grace_window_ms;

    /**
     * Enable replay protection
     * Uses per-connection bitmap to detect replayed packets
     */
    uint8_t enable_replay_protection;
};

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * Callback for received messages
 * @param sender_id  Source node ID
 * @param msg_type  Message type (PHEROMONE_*)
 * @param data  Decrypted payload data
 * @param len  Payload length
 * @param user_ctx  User context passed during registration
 */
typedef void (*nert_message_callback_t)(uint16_t sender_id,
                                         uint8_t msg_type,
                                         const void *data,
                                         uint8_t len,
                                         void *user_ctx);

/**
 * Callback for connection state changes (framework version with context)
 * @param conn_id  Connection ID
 * @param peer_id  Peer node ID
 * @param new_state  New connection state
 * @param user_ctx  User context passed during registration
 */
typedef void (*nert_connection_state_callback_t)(int conn_id,
                                                  uint16_t peer_id,
                                                  uint8_t new_state,
                                                  void *user_ctx);

/**
 * Callback for security events
 * @param event_type  Event type (bad MAC, replay attempt, etc.)
 * @param peer_id  Peer node ID involved
 * @param details  Event-specific details
 * @param user_ctx  User context passed during registration
 */
typedef void (*nert_security_callback_t)(uint8_t event_type,
                                          uint16_t peer_id,
                                          const char *details,
                                          void *user_ctx);

/* Security event types */
#define NERT_SEC_EVENT_BAD_MAC          1
#define NERT_SEC_EVENT_REPLAY_BLOCKED   2
#define NERT_SEC_EVENT_KEY_ROTATED      3
#define NERT_SEC_EVENT_INVALID_PAYLOAD  4

/* ============================================================================
 * Message Handler Registration
 * ============================================================================ */

#define NERT_MAX_HANDLERS   8

/**
 * Message handler entry
 */
struct nert_message_handler {
    uint8_t msg_type;                   /* Message type to handle */
    nert_message_callback_t callback;   /* Handler function */
    void *user_ctx;                     /* User context */
};

/* ============================================================================
 * Main Configuration Structure
 * ============================================================================ */

/**
 * NERT Framework Configuration
 * Pass this to nert_init_ex() to configure the stack
 */
struct nert_config {
    /**
     * Node identity
     */
    uint16_t node_id;

    /**
     * Security configuration
     */
    struct nert_security_config security;

    /**
     * Physical layer interface
     * Must be provided by the platform
     */
    struct nert_phy_interface *phy;

    /**
     * Message handlers (pub/sub pattern)
     * Register handlers for specific message types
     */
    struct nert_message_handler handlers[NERT_MAX_HANDLERS];
    uint8_t handler_count;

    /**
     * Connection state callback (optional)
     */
    nert_connection_state_callback_t connection_callback;
    void *connection_ctx;

    /**
     * Security event callback (optional)
     */
    nert_security_callback_t security_callback;
    void *security_ctx;
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * Initialize a config structure with defaults
 * @param config  Config structure to initialize
 * @param node_id  Node identifier
 * @param master_key  32-byte master key
 * @param phy  Physical layer interface
 */
void nert_config_init(struct nert_config *config,
                      uint16_t node_id,
                      const uint8_t master_key[NERT_KEY_SIZE],
                      struct nert_phy_interface *phy);

/**
 * Register a message handler
 * @param config  Config structure
 * @param msg_type  Message type to handle
 * @param callback  Handler function
 * @param user_ctx  User context (optional)
 * @return 0 on success, -1 if handler table full
 */
int nert_config_add_handler(struct nert_config *config,
                            uint8_t msg_type,
                            nert_message_callback_t callback,
                            void *user_ctx);

#ifdef __cplusplus
}
#endif

#endif /* NERT_CONFIG_H */
