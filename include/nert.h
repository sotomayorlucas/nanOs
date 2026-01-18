/*
 * NanOS Ephemeral Reliable Transport (NERT) Protocol
 * Hybrid UDP/TCP protocol for disposable node communication
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_H
#define NERT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#if defined(__arm__) || defined(ESP_PLATFORM)
    #define NERT_COMPACT_MODE       1
    #define NERT_MAX_CONNECTIONS    4
    #define NERT_WINDOW_SIZE        2
    #define NERT_DEDUP_CACHE_SIZE   8
#else
    #define NERT_COMPACT_MODE       0
    #define NERT_MAX_CONNECTIONS    8
    #define NERT_WINDOW_SIZE        4
    #define NERT_DEDUP_CACHE_SIZE   16
#endif

/* Feature flags */
#define NERT_ENABLE_FEC             1
#define NERT_ENABLE_MULTIPATH       1
#define NERT_ENABLE_DEBUG           0

/* Protocol constants */
#define NERT_MAGIC                  0x4E        /* 'N' */
#define NERT_VERSION                0x10        /* v1.0 */
#define NERT_ETH_TYPE               0x4E52      /* "NR" */

/* Timing constants */
#define NERT_TICK_INTERVAL_MS       50
#define NERT_RETRY_TIMEOUT_MS       200
#define NERT_MAX_RETRIES            5
#define NERT_MAX_RETRIES_CRITICAL   10
#define NERT_CONNECTION_TIMEOUT_MS  30000
#define NERT_KEY_ROTATION_SEC       3600
#define NERT_KEY_GRACE_WINDOW_MS    30000   /* Grace window for clock drift */

/* Crypto constants */
#define NERT_CHACHA_ROUNDS          8
#define NERT_KEY_SIZE               32
#define NERT_NONCE_SIZE             12
#define NERT_MAC_SIZE               8

/* FEC constants */
#define NERT_FEC_DATA_SHARDS        4
#define NERT_FEC_PARITY_SHARDS      2
#define NERT_FEC_SHARD_SIZE         32

/* Multi-path constants */
#define NERT_MAX_PATHS              3

/* Replay protection */
#define NERT_REPLAY_WINDOW_SIZE     64

/* ============================================================================
 * Reliability Classes
 * ============================================================================ */

#define NERT_CLASS_FIRE_FORGET      0x00    /* UDP pure - no ACK */
#define NERT_CLASS_BEST_EFFORT      0x01    /* UDP + retry without ACK */
#define NERT_CLASS_RELIABLE         0x02    /* TCP-like with ACK */
#define NERT_CLASS_CRITICAL         0x03    /* Reliable + FEC + Multi-path */

/* ============================================================================
 * Flags
 * ============================================================================ */

#define NERT_FLAG_SYN               0x01    /* Connection initiation */
#define NERT_FLAG_ACK               0x02    /* Contains valid ACK */
#define NERT_FLAG_FIN               0x04    /* End of stream */
#define NERT_FLAG_RST               0x08    /* Reset connection */
#define NERT_FLAG_ENC               0x10    /* Payload encrypted */
#define NERT_FLAG_FEC               0x20    /* Includes FEC block */
#define NERT_FLAG_FRAG              0x40    /* Fragmented packet */
#define NERT_FLAG_MPATH             0x80    /* Multi-path enabled */

/* ============================================================================
 * Connection States
 * ============================================================================ */

#define NERT_STATE_CLOSED           0
#define NERT_STATE_SYN_SENT         1
#define NERT_STATE_ESTABLISHED      2
#define NERT_STATE_FIN_SENT         3
#define NERT_STATE_CLOSE_WAIT       4
#define NERT_STATE_TIME_WAIT        5

/* ============================================================================
 * Packet Structures
 * ============================================================================ */

#if NERT_COMPACT_MODE

/* Compact header for ARM/ESP32 (12 bytes) */
struct nert_header {
    uint8_t  magic;             /* 0x4E = 'N' */
    uint8_t  version_class;     /* [7:4]=version, [3:2]=class, [1:0]=rsvd */
    uint16_t node_id;           /* Sender ID (16-bit) */
    uint16_t seq_num;           /* Sequence number */
    uint8_t  flags;             /* Packet flags */
    uint8_t  payload_len;       /* Payload length (0-255) */
    uint32_t nonce_counter;     /* Crypto nonce counter */
} __attribute__((packed));

#define NERT_HEADER_SIZE        12
#define NERT_MAX_PAYLOAD        64

#else

/* Full header for x86 (20 bytes) */
struct nert_header {
    uint8_t  magic;             /* 0x4E = 'N' */
    uint8_t  version_class;     /* [7:4]=version, [3:2]=class, [1:0]=rsvd */
    uint16_t node_id;           /* Sender ID (16-bit) */
    uint16_t dest_id;           /* Destination ID (0=broadcast) */
    uint16_t seq_num;           /* Sequence number */
    uint16_t ack_num;           /* ACK number (piggyback) */
    uint8_t  flags;             /* Packet flags */
    uint8_t  payload_len;       /* Payload length (0-255) */
    uint16_t timestamp;         /* Ticks since boot (for RTT) */
    uint8_t  ttl;               /* Time-to-live (hops) */
    uint8_t  hop_count;         /* Hops traveled */
    uint32_t nonce_counter;     /* Crypto nonce counter */
} __attribute__((packed));

#define NERT_HEADER_SIZE        20
#define NERT_MAX_PAYLOAD        200

#endif

/* Authentication tag */
struct nert_auth_tag {
    uint8_t poly1305_tag[NERT_MAC_SIZE];
} __attribute__((packed));

/* Selective ACK structure */
struct nert_sack {
    uint16_t base_ack;          /* Cumulative ACK */
    uint8_t  bitmap;            /* Bitmap for next 8 packets */
} __attribute__((packed));

/* Multi-path header extension */
struct nert_multipath {
    uint8_t  path_count;        /* Number of active paths */
    uint8_t  path_index;        /* Index of this path */
    uint16_t via_nodes[NERT_MAX_PATHS];
} __attribute__((packed));

/* FEC block structure */
struct nert_fec_block {
    uint8_t  block_id;          /* FEC block ID */
    uint8_t  shard_index;       /* 0-3=data, 4-5=parity */
    uint8_t  total_shards;      /* Total shards in block */
    uint8_t  reserved;
    uint8_t  data[NERT_FEC_SHARD_SIZE];
} __attribute__((packed));

/* Complete packet structure */
struct nert_packet {
    struct nert_header header;
    uint8_t payload[NERT_MAX_PAYLOAD];
    struct nert_auth_tag auth;
};

/* ============================================================================
 * Connection Structure
 * ============================================================================ */

/* TX window entry */
struct nert_tx_entry {
    uint16_t seq;
    uint8_t  retries;
    uint8_t  active;
    uint16_t timeout_ms;
    uint32_t sent_tick;
    uint8_t  data[NERT_MAX_PAYLOAD + NERT_HEADER_SIZE + NERT_MAC_SIZE];
    uint8_t  len;
};

/* Connection state */
struct nert_connection {
    uint16_t peer_id;           /* Peer node ID */
    uint8_t  state;             /* Connection state */
    uint8_t  reliability_class; /* Class for this connection */

    uint16_t send_seq;          /* Next seq to send */
    uint16_t recv_seq;          /* Next expected seq */
    uint16_t ack_pending;       /* Pending ACK to send */

    /* Retransmission window */
    struct nert_tx_entry tx_window[NERT_WINDOW_SIZE];

    /* RTT estimation (Jacobson algorithm) */
    uint16_t srtt;              /* Smoothed RTT */
    uint16_t rttvar;            /* RTT variance */

    /* Activity tracking */
    uint32_t last_activity;     /* Last activity tick */
    uint32_t established_at;    /* Connection start tick */

    /* Replay protection */
    uint16_t highest_rx_seq;
    uint64_t replay_bitmap;
};

/* ============================================================================
 * Statistics
 * ============================================================================ */

struct nert_stats {
    /* TX counters */
    uint32_t tx_packets;
    uint32_t tx_bytes;
    uint32_t tx_retransmits;
    uint32_t tx_fec_blocks;

    /* RX counters */
    uint32_t rx_packets;
    uint32_t rx_bytes;
    uint32_t rx_duplicates;
    uint32_t rx_recovered_fec;
    uint32_t rx_bad_mac;
    uint32_t rx_replay_blocked;

    /* Connection counters */
    uint32_t connections_opened;
    uint32_t connections_failed;
    uint32_t connections_timeout;

    /* Timing stats */
    uint16_t avg_rtt;
    uint16_t min_rtt;
    uint16_t max_rtt;
};

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * Callback for received packets
 * @param sender_id  Source node ID
 * @param pheromone_type  Message type (PHEROMONE_*)
 * @param data  Decrypted payload data
 * @param len  Payload length
 */
typedef void (*nert_receive_callback_t)(uint16_t sender_id,
                                         uint8_t pheromone_type,
                                         const void *data,
                                         uint8_t len);

/**
 * Callback for connection state changes
 * @param conn_id  Connection ID
 * @param peer_id  Peer node ID
 * @param new_state  New connection state
 */
typedef void (*nert_connection_callback_t)(int conn_id,
                                            uint16_t peer_id,
                                            uint8_t new_state);

/* ============================================================================
 * API Functions
 * ============================================================================ */

/**
 * Initialize NERT subsystem
 * Must be called before any other NERT functions
 */
void nert_init(void);

/**
 * Set the swarm master key
 * @param key  32-byte master key
 */
void nert_set_master_key(const uint8_t key[NERT_KEY_SIZE]);

/**
 * Set receive callback
 * @param callback  Function to call on packet reception
 */
void nert_set_receive_callback(nert_receive_callback_t callback);

/**
 * Set connection state callback
 * @param callback  Function to call on state changes
 */
void nert_set_connection_callback(nert_connection_callback_t callback);

/* ----------------------------------------------------------------------------
 * Sending Functions
 * ---------------------------------------------------------------------------- */

/**
 * Send unreliable message (FIRE_FORGET)
 * No ACK, no retry. For frequent telemetry.
 *
 * @param dest_id  Destination (0 for broadcast)
 * @param pheromone_type  Message type
 * @param data  Payload data
 * @param len  Payload length
 * @return 0 on success, -1 on error
 */
int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint8_t len);

/**
 * Send best-effort message (BEST_EFFORT)
 * Automatic retry without ACK. For important data.
 *
 * @param dest_id  Destination (0 for broadcast)
 * @param pheromone_type  Message type
 * @param data  Payload data
 * @param len  Payload length
 * @return 0 on success, -1 on error
 */
int nert_send_best_effort(uint16_t dest_id, uint8_t pheromone_type,
                          const void *data, uint8_t len);

/**
 * Send reliable message (RELIABLE)
 * Guaranteed delivery with ACK. For commands.
 *
 * @param dest_id  Destination node ID
 * @param pheromone_type  Message type
 * @param data  Payload data
 * @param len  Payload length
 * @return Connection ID on success, -1 on error
 */
int nert_send_reliable(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len);

/**
 * Send critical message (CRITICAL)
 * Reliable + FEC + Multi-path. For vital control.
 *
 * @param dest_id  Destination node ID
 * @param pheromone_type  Message type
 * @param data  Payload data
 * @param len  Payload length
 * @return Connection ID on success, -1 on error
 */
int nert_send_critical(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len);

/* ----------------------------------------------------------------------------
 * Connection Management
 * ---------------------------------------------------------------------------- */

/**
 * Open a reliable connection to a peer
 * @param peer_id  Target node ID
 * @return Connection ID or -1 on error
 */
int nert_connect(uint16_t peer_id);

/**
 * Close a connection
 * @param conn_id  Connection ID
 */
void nert_disconnect(int conn_id);

/**
 * Get connection state
 * @param conn_id  Connection ID
 * @return Connection state or -1 if invalid
 */
int nert_get_connection_state(int conn_id);

/* ----------------------------------------------------------------------------
 * Processing Functions
 * ---------------------------------------------------------------------------- */

/**
 * Process incoming packets
 * Should be called from main loop
 */
void nert_process_incoming(void);

/**
 * Timer tick for retransmissions
 * Should be called every NERT_TICK_INTERVAL_MS
 */
void nert_timer_tick(void);

/**
 * Check and rotate session keys if needed
 */
void nert_check_key_rotation(void);

/* ----------------------------------------------------------------------------
 * Statistics and Debug
 * ---------------------------------------------------------------------------- */

/**
 * Get protocol statistics
 * @return Pointer to stats structure
 */
const struct nert_stats* nert_get_stats(void);

/**
 * Reset statistics counters
 */
void nert_reset_stats(void);

#if NERT_ENABLE_DEBUG
/**
 * Print packet debug info
 * @param prefix  Debug prefix string
 * @param pkt  Packet to debug
 */
void nert_debug_packet(const char *prefix, const struct nert_packet *pkt);
#endif

/* ============================================================================
 * HAL Interface (to be implemented per platform)
 * ============================================================================ */

/**
 * Send raw packet over network
 * @param data  Packet data
 * @param len  Data length
 * @return 0 on success, -1 on error
 */
extern int nert_hal_send(const void *data, uint16_t len);

/**
 * Receive packet from network (non-blocking)
 * @param buffer  Receive buffer
 * @param max_len  Buffer size
 * @return Bytes received, 0 if no packet, -1 on error
 */
extern int nert_hal_receive(void *buffer, uint16_t max_len);

/**
 * Get current tick count in milliseconds
 * @return Tick count
 */
extern uint32_t nert_hal_get_ticks(void);

/**
 * Get random number
 * @return 32-bit random value
 */
extern uint32_t nert_hal_random(void);

/**
 * Get local node ID
 * @return 16-bit node ID
 */
extern uint16_t nert_hal_get_node_id(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_H */
