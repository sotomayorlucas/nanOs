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
 * Smart Padding (v0.5) - Traffic Analysis Mitigation
 * ============================================================================ */

/* Block size for padding - all packets padded to multiples of this */
#define NERT_BLOCK_SIZE             64

/* TX Queue for message aggregation */
#if NERT_COMPACT_MODE
    #define NERT_TX_QUEUE_SIZE      4
    #define NERT_TX_QUEUE_MSG_MAX   48
#else
    #define NERT_TX_QUEUE_SIZE      8
    #define NERT_TX_QUEUE_MSG_MAX   128
#endif

/* TLV format overhead: [Count:1] + per-message [Len:1][Type:1] */
#define NERT_TLV_HEADER_SIZE        1       /* Count byte */
#define NERT_TLV_MSG_OVERHEAD       2       /* Len + Type per message */
#define NERT_TLV_MAX_MESSAGES       8       /* Max messages per packet */

/*
 * Fragment indicator in TLV type field:
 * If MSB is set, the message is a fragment and includes frag_header
 * Type = 0x80 | original_pheromone_type
 */
#define NERT_TLV_TYPE_FRAG_BIT      0x80
#define NERT_TLV_TYPE_MASK          0x7F    /* Extract original type */

/* Minimum random padding when no messages available */
#define NERT_MIN_RANDOM_PAD         4

/* Jitter configuration for timing attack mitigation */
#define NERT_JITTER_MIN_MS          10      /* Minimum delay before flush */
#define NERT_JITTER_MAX_MS          100     /* Maximum delay before flush */
#define NERT_JITTER_CRITICAL_MS     5       /* Max delay for CRITICAL class */
#define NERT_QUEUE_FLUSH_THRESHOLD  3       /* Auto-flush when N messages queued */
#define NERT_QUEUE_AGE_MAX_MS       200     /* Max time message can wait in queue */

/* Priority levels (higher = more urgent) */
#define NERT_PRIORITY_LOW           0       /* FIRE_FORGET */
#define NERT_PRIORITY_NORMAL        1       /* BEST_EFFORT */
#define NERT_PRIORITY_HIGH          2       /* RELIABLE */
#define NERT_PRIORITY_CRITICAL      3       /* CRITICAL - minimal jitter */

/* ============================================================================
 * Fragmentation (v0.5) - Large Message Support
 * ============================================================================ */

/*
 * Fragment sizing:
 * - Each fragment must fit in one TLV entry within a padded block
 * - Overhead per fragment: TLV_MSG_OVERHEAD(2) + FRAG_HEADER(3) = 5 bytes
 * - Usable payload per fragment: NERT_BLOCK_SIZE - TLV_HEADER(1) - 5 = 58 bytes
 */
#define NERT_FRAG_HEADER_SIZE       3       /* msg_id:1 + index:1 + total:1 */
#define NERT_FRAG_PAYLOAD_MAX       (NERT_BLOCK_SIZE - NERT_TLV_HEADER_SIZE - \
                                     NERT_TLV_MSG_OVERHEAD - NERT_FRAG_HEADER_SIZE)

/* Maximum message size after reassembly */
#if NERT_COMPACT_MODE
    #define NERT_FRAG_MAX_FRAGMENTS 4       /* 4 × 58 = 232 bytes max msg */
    #define NERT_REASM_SLOTS        2       /* Concurrent reassemblies */
    #define NERT_MAX_MESSAGE_SIZE   (NERT_FRAG_MAX_FRAGMENTS * NERT_FRAG_PAYLOAD_MAX)
#else
    #define NERT_FRAG_MAX_FRAGMENTS 8       /* 8 × 58 = 464 bytes max msg */
    #define NERT_REASM_SLOTS        4       /* Concurrent reassemblies */
    #define NERT_MAX_MESSAGE_SIZE   (NERT_FRAG_MAX_FRAGMENTS * NERT_FRAG_PAYLOAD_MAX)
#endif

/* Reassembly timeout - discard incomplete after this */
#define NERT_REASM_TIMEOUT_MS       5000

/* Fragment message ID wraps at this value */
#define NERT_FRAG_MSG_ID_MAX        256

/* ============================================================================
 * Rate Limiting (v0.5) - DoS Resilience
 * ============================================================================ */

/*
 * Token Bucket Rate Limiter:
 * - Each node tracked has a bucket with CAPACITY tokens
 * - Each received packet consumes 1 token
 * - Tokens refill at REFILL_TOKENS per REFILL_MS interval
 * - When bucket empty (tokens=0), packets are dropped
 * - After PENALTY_THRESHOLD violations, node enters temp blacklist
 */

#if NERT_COMPACT_MODE
    #define NERT_RATE_LIMIT_SLOTS       8       /* Tracked nodes (ARM) */
#else
    #define NERT_RATE_LIMIT_SLOTS       16      /* Tracked nodes (x86) */
#endif

/* Token bucket parameters */
#define NERT_RATE_BUCKET_CAPACITY       10      /* Max tokens per node */
#define NERT_RATE_REFILL_MS             1000    /* Refill interval (ms) */
#define NERT_RATE_REFILL_TOKENS         5       /* Tokens per refill */

/* Penalty escalation */
#define NERT_RATE_PENALTY_THRESHOLD     5       /* Violations before blacklist */
#define NERT_RATE_BLACKLIST_MS          30000   /* Blacklist duration (30s) */

/* Rate limit bypass for critical protocol messages */
#define NERT_RATE_BYPASS_REKEY          1       /* Don't rate-limit REKEY msgs */

/* ============================================================================
 * Behavioral Blacklist (v0.5) - Malicious Node Isolation
 * ============================================================================ */

/*
 * Behavioral Reputation System:
 * - Tracks security violations per node (bad MAC, replay, invalid payload)
 * - Each violation type has a severity weight
 * - Reputation score decreases with violations, increases over time
 * - When score drops below threshold, node is auto-blacklisted
 * - Graduated penalties: warn → throttle → temporary ban → permanent ban
 */

/* Reputation scoring weights (higher = more severe) */
#define NERT_REPUTATION_WEIGHT_BAD_MAC      10  /* Failed authentication */
#define NERT_REPUTATION_WEIGHT_REPLAY       8   /* Replay attack attempt */
#define NERT_REPUTATION_WEIGHT_INVALID_PKT  5   /* Malformed packet */
#define NERT_REPUTATION_WEIGHT_RATE_EXCEED  3   /* Rate limit violation */

/* Reputation thresholds */
#define NERT_REPUTATION_MAX                 100 /* Starting/max reputation */
#define NERT_REPUTATION_WARN_THRESHOLD      70  /* Log warning */
#define NERT_REPUTATION_THROTTLE_THRESHOLD  50  /* Apply extra throttling */
#define NERT_REPUTATION_BAN_THRESHOLD       20  /* Temporary blacklist */
#define NERT_REPUTATION_PERMABAN_THRESHOLD  5   /* Long-term blacklist */

/* Reputation recovery */
#define NERT_REPUTATION_RECOVERY_INTERVAL_MS 60000  /* Recovery check every 60s */
#define NERT_REPUTATION_RECOVERY_POINTS     5       /* Points recovered per interval */

/* Blacklist durations (graduated) */
#define NERT_BLACKLIST_WARN_MS              0       /* No ban, just log */
#define NERT_BLACKLIST_THROTTLE_MS          0       /* Extra rate limiting */
#define NERT_BLACKLIST_TEMP_BAN_MS          60000   /* 1 minute ban */
#define NERT_BLACKLIST_LONG_BAN_MS          300000  /* 5 minute ban */
#define NERT_BLACKLIST_PERMABAN_MS          3600000 /* 1 hour ban */

/* Behavioral tracking table size */
#if NERT_COMPACT_MODE
    #define NERT_BEHAVIOR_SLOTS             8
#else
    #define NERT_BEHAVIOR_SLOTS             16
#endif

/* ============================================================================
 * Cover Traffic (v0.5) - Traffic Analysis Mitigation
 * ============================================================================ */

/*
 * Cover Traffic System:
 * - Generates dummy packets at configurable intervals
 * - Maintains constant traffic rate regardless of real activity
 * - Dummy packets are indistinguishable from real traffic (encrypted)
 * - Adaptive mode adjusts rate based on network activity
 * - Receivers silently discard dummy packets after decryption
 */

/* Cover traffic modes */
#define NERT_COVER_MODE_OFF             0   /* Disabled */
#define NERT_COVER_MODE_CONSTANT        1   /* Fixed interval dummy packets */
#define NERT_COVER_MODE_ADAPTIVE        2   /* Adjusts based on real traffic */
#define NERT_COVER_MODE_BURST           3   /* Burst mode for high-security */

/* Timing parameters */
#define NERT_COVER_INTERVAL_MS          500     /* Base interval between dummies */
#define NERT_COVER_JITTER_MS            100     /* Random jitter on interval */
#define NERT_COVER_MIN_INTERVAL_MS      100     /* Minimum interval (adaptive) */
#define NERT_COVER_MAX_INTERVAL_MS      2000    /* Maximum interval (adaptive) */

/* Adaptive mode parameters */
#define NERT_COVER_ACTIVITY_WINDOW_MS   5000    /* Window to measure activity */
#define NERT_COVER_TARGET_RATE          10      /* Target packets per window */

/* Burst mode parameters */
#define NERT_COVER_BURST_SIZE           3       /* Packets per burst */
#define NERT_COVER_BURST_INTERVAL_MS    50      /* Interval within burst */

/* Special pheromone type for dummy packets (high bit set) */
#define NERT_PHEROMONE_DUMMY            0x7F    /* Dummy marker (discarded on RX) */

/* Dummy payload constraints */
#define NERT_COVER_PAYLOAD_MIN          8       /* Minimum dummy payload */
#define NERT_COVER_PAYLOAD_MAX          48      /* Maximum dummy payload */

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
 * Smart Padding Structures (v0.5)
 * ============================================================================ */

/**
 * TX Queue Entry - Pending message for aggregation
 * Used by Smart Padding to batch multiple messages into one packet
 */
struct nert_tx_queue_entry {
    uint8_t  active;                        /* Entry in use */
    uint8_t  priority;                      /* NERT_PRIORITY_* (higher = urgent) */
    uint16_t dest_id;                       /* Target node (0 = broadcast) */
    uint8_t  pheromone_type;                /* Message type */
    uint8_t  reliability_class;             /* FIRE_FORGET, BEST_EFFORT, etc */
    uint8_t  flags;                         /* Original packet flags */
    uint8_t  len;                           /* Payload length */
    uint8_t  data[NERT_TX_QUEUE_MSG_MAX];   /* Message payload */
    uint32_t queued_tick;                   /* When message was queued */
};

/**
 * Jitter state for timing randomization
 */
struct nert_jitter_state {
    uint32_t next_flush_tick;               /* When to next attempt flush */
    uint32_t last_flush_tick;               /* When last flush occurred */
    uint8_t  flush_pending;                 /* Flush scheduled */
    uint8_t  immediate_flush;               /* CRITICAL msg bypasses jitter */
};

/**
 * TLV Message Header (packed into payload before encryption)
 * Format: [Len:1][Type:1][Data:Len]
 */
struct nert_tlv_msg {
    uint8_t len;                            /* Data length (excl header) */
    uint8_t type;                           /* Pheromone type */
    /* Data follows immediately */
} __attribute__((packed));

/* ============================================================================
 * Fragmentation Structures (v0.5)
 * ============================================================================ */

/**
 * Fragment header - prepended to each fragment's data
 * Format: [MsgID:1][Index:1][Total:1][Data...]
 *
 * MsgID: Unique per-sender message identifier (wraps at 256)
 * Index: Fragment index (0 = first, Total-1 = last)
 * Total: Total fragments in this message
 */
struct nert_frag_header {
    uint8_t msg_id;                         /* Message ID (per sender) */
    uint8_t frag_index;                     /* This fragment's index */
    uint8_t frag_total;                     /* Total fragments */
} __attribute__((packed));

/**
 * Reassembly slot - accumulates fragments until complete
 * Uses static buffer with bitmap for memory efficiency
 */
struct nert_reasm_slot {
    uint8_t  active;                        /* Slot in use */
    uint16_t sender_id;                     /* Source node */
    uint8_t  msg_id;                        /* Message being reassembled */
    uint8_t  pheromone_type;                /* Original message type */
    uint8_t  frag_total;                    /* Expected fragment count */
    uint8_t  frag_received;                 /* Fragments received so far */
    uint8_t  frag_bitmap;                   /* Bitmap of received fragments */
    uint32_t first_tick;                    /* When first fragment arrived */
    uint16_t total_len;                     /* Accumulated data length */
    uint8_t  data[NERT_MAX_MESSAGE_SIZE];   /* Reassembly buffer */
    /*
     * Fragment offsets - where each fragment's data starts in buffer
     * Needed because fragments may arrive out of order
     */
    uint16_t frag_offsets[NERT_FRAG_MAX_FRAGMENTS];
    uint8_t  frag_lens[NERT_FRAG_MAX_FRAGMENTS];
};

/**
 * Fragmentation state - TX side
 * Tracks current message ID for this node
 */
struct nert_frag_state {
    uint8_t next_msg_id;                    /* Next message ID to assign */
};

/* ============================================================================
 * Rate Limiting Structures (v0.5)
 * ============================================================================ */

/**
 * Rate limit entry - Token bucket state for one node
 * Tracks packet rate and applies throttling if exceeded
 */
struct nert_rate_limit_entry {
    uint16_t node_id;                       /* Tracked node (0 = slot free) */
    uint8_t  tokens;                        /* Current token count */
    uint8_t  violations;                    /* Consecutive rate violations */
    uint32_t last_refill_tick;              /* When tokens were last refilled */
    uint32_t blacklist_until;               /* If >0, node is blacklisted until this tick */
    uint32_t total_packets;                 /* Total packets from this node */
    uint32_t dropped_packets;               /* Packets dropped due to rate limit */
};

/**
 * Rate limiting configuration (runtime adjustable)
 */
struct nert_rate_limit_config {
    uint8_t  bucket_capacity;               /* Max tokens per bucket */
    uint8_t  refill_tokens;                 /* Tokens added per interval */
    uint16_t refill_interval_ms;            /* Refill interval */
    uint8_t  penalty_threshold;             /* Violations before blacklist */
    uint32_t blacklist_duration_ms;         /* Blacklist duration */
    uint8_t  enabled;                       /* 0=disabled, 1=enabled */
};

/* ============================================================================
 * Behavioral Blacklist Structures (v0.5)
 * ============================================================================ */

/**
 * Violation type enumeration
 * Used for reporting and tracking specific attack types
 */
enum nert_violation_type {
    NERT_VIOLATION_BAD_MAC      = 0,    /* Authentication failure */
    NERT_VIOLATION_REPLAY       = 1,    /* Replay attack detected */
    NERT_VIOLATION_INVALID_PKT  = 2,    /* Malformed/invalid packet */
    NERT_VIOLATION_RATE_EXCEED  = 3,    /* Rate limit exceeded */
    NERT_VIOLATION_COUNT        = 4     /* Total violation types */
};

/**
 * Blacklist status enumeration
 */
enum nert_blacklist_status {
    NERT_STATUS_OK              = 0,    /* Normal operation */
    NERT_STATUS_WARNED          = 1,    /* Warning issued */
    NERT_STATUS_THROTTLED       = 2,    /* Extra rate limiting applied */
    NERT_STATUS_TEMP_BANNED     = 3,    /* Temporarily banned */
    NERT_STATUS_LONG_BANNED     = 4,    /* Long-term ban */
    NERT_STATUS_PERMABANNED     = 5     /* Near-permanent ban */
};

/**
 * Behavioral tracking entry - Per-node reputation and violation history
 */
struct nert_behavior_entry {
    uint16_t node_id;                       /* Tracked node (0 = slot free) */
    uint8_t  reputation;                    /* Current reputation score (0-100) */
    uint8_t  status;                        /* Current blacklist status */

    /* Per-type violation counters */
    uint16_t bad_mac_count;                 /* Failed MAC verifications */
    uint16_t replay_count;                  /* Replay attempts blocked */
    uint16_t invalid_pkt_count;             /* Invalid packets received */
    uint16_t rate_exceed_count;             /* Rate limit violations */

    /* Timing */
    uint32_t first_seen_tick;               /* When first tracked */
    uint32_t last_violation_tick;           /* Last violation timestamp */
    uint32_t last_recovery_tick;            /* Last reputation recovery */
    uint32_t ban_until_tick;                /* Blacklist expiry (0 = not banned) */

    /* Escalation tracking */
    uint8_t  ban_count;                     /* Times this node has been banned */
    uint8_t  flags;                         /* Reserved for future use */
};

/**
 * Behavioral blacklist configuration
 */
struct nert_behavior_config {
    /* Violation weights */
    uint8_t  weight_bad_mac;
    uint8_t  weight_replay;
    uint8_t  weight_invalid_pkt;
    uint8_t  weight_rate_exceed;

    /* Thresholds */
    uint8_t  warn_threshold;
    uint8_t  throttle_threshold;
    uint8_t  ban_threshold;
    uint8_t  permaban_threshold;

    /* Recovery */
    uint32_t recovery_interval_ms;
    uint8_t  recovery_points;

    /* Feature flags */
    uint8_t  enabled;                       /* 0=disabled, 1=enabled */
    uint8_t  auto_blacklist;                /* Auto-ban on threshold */
    uint8_t  notify_callback;               /* Call callback on status change */
};

/**
 * Callback for blacklist status changes
 * @param node_id  Affected node
 * @param old_status  Previous status
 * @param new_status  New status
 * @param reputation  Current reputation score
 */
typedef void (*nert_blacklist_callback_t)(uint16_t node_id,
                                           uint8_t old_status,
                                           uint8_t new_status,
                                           uint8_t reputation);

/* ============================================================================
 * Cover Traffic Structures (v0.5)
 * ============================================================================ */

/**
 * Cover traffic state - Tracks dummy packet generation
 */
struct nert_cover_state {
    uint8_t  mode;                          /* NERT_COVER_MODE_* */
    uint8_t  burst_remaining;               /* Remaining packets in current burst */
    uint16_t current_interval_ms;           /* Current interval (adaptive) */
    uint32_t next_send_tick;                /* When to send next dummy */
    uint32_t last_send_tick;                /* When last dummy was sent */

    /* Activity tracking for adaptive mode */
    uint32_t window_start_tick;             /* Activity window start */
    uint16_t window_real_packets;           /* Real packets in current window */
    uint16_t window_dummy_packets;          /* Dummy packets in current window */

    /* Statistics */
    uint32_t total_dummy_sent;              /* Total dummy packets sent */
    uint32_t total_dummy_received;          /* Total dummy packets received (discarded) */
    uint32_t total_bytes_cover;             /* Total bytes used for cover traffic */
};

/**
 * Cover traffic configuration
 */
struct nert_cover_config {
    uint8_t  mode;                          /* Operating mode */
    uint16_t base_interval_ms;              /* Base interval between dummies */
    uint16_t jitter_ms;                     /* Random jitter added to interval */
    uint16_t min_interval_ms;               /* Minimum interval (adaptive) */
    uint16_t max_interval_ms;               /* Maximum interval (adaptive) */
    uint8_t  target_rate;                   /* Target packets per window (adaptive) */
    uint8_t  burst_size;                    /* Packets per burst (burst mode) */
    uint16_t burst_interval_ms;             /* Interval within burst */
    uint8_t  payload_min;                   /* Minimum dummy payload size */
    uint8_t  payload_max;                   /* Maximum dummy payload size */
    uint16_t dest_id;                       /* Destination for dummies (0=broadcast) */
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

    /* Rate limiting counters (v0.5) */
    uint32_t rx_rate_limited;               /* Packets dropped due to rate limit */
    uint32_t rx_blacklisted;                /* Packets from blacklisted nodes */
    uint16_t rate_limit_active_nodes;       /* Nodes currently being tracked */
    uint16_t rate_limit_blacklisted_nodes;  /* Nodes currently blacklisted */

    /* Behavioral blacklist counters (v0.5) */
    uint32_t behavior_violations_total;     /* Total violations recorded */
    uint32_t behavior_auto_bans;            /* Automatic bans triggered */
    uint16_t behavior_nodes_warned;         /* Nodes in warned state */
    uint16_t behavior_nodes_throttled;      /* Nodes being throttled */
    uint16_t behavior_nodes_banned;         /* Nodes currently banned */

    /* Cover traffic counters (v0.5) */
    uint32_t cover_dummy_sent;              /* Dummy packets transmitted */
    uint32_t cover_dummy_received;          /* Dummy packets received (discarded) */
    uint32_t cover_bytes_overhead;          /* Bytes used for cover traffic */
    uint16_t cover_current_interval;        /* Current interval (adaptive mode) */

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
 * Smart Padding API (v0.5)
 * ---------------------------------------------------------------------------- */

/**
 * Queue a message for smart aggregation
 * Messages are batched together to fill block boundaries
 *
 * @param dest_id  Destination (0 for broadcast)
 * @param pheromone_type  Message type
 * @param data  Payload data
 * @param len  Payload length
 * @param reliability_class  Message class
 * @return 0 on success, -1 if queue full
 */
int nert_queue_message(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len,
                       uint8_t reliability_class);

/**
 * Flush TX queue - send all pending messages
 * Called periodically or when queue threshold reached
 */
void nert_flush_tx_queue(void);

/**
 * Get TX queue stats
 * @param pending  Out: Number of pending messages
 * @param bytes_queued  Out: Total bytes queued
 */
void nert_get_queue_stats(uint8_t *pending, uint16_t *bytes_queued);

/**
 * Configure jitter parameters
 * @param min_ms  Minimum jitter delay (default: 10ms)
 * @param max_ms  Maximum jitter delay (default: 100ms)
 */
void nert_set_jitter_params(uint16_t min_ms, uint16_t max_ms);

/**
 * Force immediate flush (bypass jitter)
 * Use sparingly - defeats timing analysis protection
 */
void nert_force_flush(void);

/* ----------------------------------------------------------------------------
 * Fragmentation API (v0.5)
 * ---------------------------------------------------------------------------- */

/**
 * Send a large message with automatic fragmentation
 * Transparently fragments messages > NERT_FRAG_PAYLOAD_MAX
 * Last fragment uses Smart Padding for efficiency
 *
 * @param dest_id  Destination node
 * @param pheromone_type  Message type
 * @param data  Message data (can exceed block size)
 * @param len  Total message length
 * @param reliability_class  RELIABLE or CRITICAL recommended
 * @return 0 on success, -1 on error
 */
int nert_send_fragmented(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint16_t len,
                         uint8_t reliability_class);

/**
 * Get fragmentation statistics
 * @param tx_fragmented  Out: Messages fragmented on TX
 * @param rx_reassembled  Out: Messages successfully reassembled
 * @param rx_timeouts  Out: Reassemblies that timed out
 */
void nert_get_frag_stats(uint32_t *tx_fragmented,
                         uint32_t *rx_reassembled,
                         uint32_t *rx_timeouts);

/**
 * Clean up stale reassembly slots
 * Called automatically from timer_tick
 */
void nert_reasm_cleanup(void);

/* ----------------------------------------------------------------------------
 * Rate Limiting API (v0.5)
 * ---------------------------------------------------------------------------- */

/**
 * Enable or disable rate limiting
 * @param enabled  1 to enable, 0 to disable
 */
void nert_rate_limit_enable(uint8_t enabled);

/**
 * Configure rate limiting parameters
 * @param config  Configuration structure (NULL uses defaults)
 */
void nert_rate_limit_configure(const struct nert_rate_limit_config *config);

/**
 * Manually blacklist a node
 * @param node_id  Node to blacklist
 * @param duration_ms  Duration in ms (0 = use default)
 */
void nert_rate_limit_blacklist(uint16_t node_id, uint32_t duration_ms);

/**
 * Remove node from blacklist
 * @param node_id  Node to unblock
 */
void nert_rate_limit_unblock(uint16_t node_id);

/**
 * Check if node is currently rate-limited or blacklisted
 * @param node_id  Node to check
 * @return 0 if allowed, 1 if rate-limited, 2 if blacklisted
 */
int nert_rate_limit_status(uint16_t node_id);

/**
 * Get rate limiting statistics for a specific node
 * @param node_id  Node to query
 * @param total_packets  Out: Total packets received
 * @param dropped_packets  Out: Packets dropped
 * @return 0 if found, -1 if not tracked
 */
int nert_rate_limit_get_node_stats(uint16_t node_id,
                                    uint32_t *total_packets,
                                    uint32_t *dropped_packets);

/**
 * Reset rate limiting state for all nodes
 * Clears all tracking and blacklists
 */
void nert_rate_limit_reset(void);

/* ----------------------------------------------------------------------------
 * Behavioral Blacklist API (v0.5)
 * ---------------------------------------------------------------------------- */

/**
 * Enable or disable behavioral blacklisting
 * @param enabled  1 to enable, 0 to disable
 */
void nert_blacklist_enable(uint8_t enabled);

/**
 * Configure behavioral blacklist parameters
 * @param config  Configuration structure (NULL uses defaults)
 */
void nert_blacklist_configure(const struct nert_behavior_config *config);

/**
 * Set callback for blacklist status changes
 * @param callback  Function to call on status changes
 */
void nert_blacklist_set_callback(nert_blacklist_callback_t callback);

/**
 * Report a security violation for a node
 * Updates reputation and may trigger auto-blacklist
 *
 * @param node_id  Node that committed violation
 * @param violation_type  Type of violation (NERT_VIOLATION_*)
 * @return New reputation score (0-100)
 */
uint8_t nert_blacklist_report_violation(uint16_t node_id,
                                         enum nert_violation_type violation_type);

/**
 * Manually set blacklist status for a node
 * @param node_id  Node to modify
 * @param status  New status (NERT_STATUS_*)
 * @param duration_ms  Ban duration (0 = use default for status level)
 */
void nert_blacklist_set_status(uint16_t node_id,
                                enum nert_blacklist_status status,
                                uint32_t duration_ms);

/**
 * Get current blacklist status for a node
 * @param node_id  Node to query
 * @return Current status (NERT_STATUS_*)
 */
enum nert_blacklist_status nert_blacklist_get_status(uint16_t node_id);

/**
 * Get reputation score for a node
 * @param node_id  Node to query
 * @return Reputation score (0-100), or -1 if not tracked
 */
int nert_blacklist_get_reputation(uint16_t node_id);

/**
 * Get detailed violation statistics for a node
 * @param node_id  Node to query
 * @param bad_mac  Out: Bad MAC count
 * @param replay  Out: Replay attack count
 * @param invalid_pkt  Out: Invalid packet count
 * @param rate_exceed  Out: Rate exceed count
 * @return 0 if found, -1 if not tracked
 */
int nert_blacklist_get_violations(uint16_t node_id,
                                   uint16_t *bad_mac,
                                   uint16_t *replay,
                                   uint16_t *invalid_pkt,
                                   uint16_t *rate_exceed);

/**
 * Pardon a node - restore reputation and clear violations
 * @param node_id  Node to pardon
 */
void nert_blacklist_pardon(uint16_t node_id);

/**
 * Reset all behavioral tracking
 * Clears all nodes and statistics
 */
void nert_blacklist_reset(void);

/**
 * Process reputation recovery (called from timer_tick)
 * Gradually restores reputation for well-behaved nodes
 */
void nert_blacklist_process_recovery(void);

/* ----------------------------------------------------------------------------
 * Cover Traffic API (v0.5)
 * ---------------------------------------------------------------------------- */

/**
 * Enable cover traffic with specified mode
 * @param mode  NERT_COVER_MODE_* (OFF, CONSTANT, ADAPTIVE, BURST)
 */
void nert_cover_set_mode(uint8_t mode);

/**
 * Configure cover traffic parameters
 * @param config  Configuration structure (NULL uses defaults)
 */
void nert_cover_configure(const struct nert_cover_config *config);

/**
 * Set destination for dummy packets
 * @param dest_id  Destination node (0 = broadcast)
 */
void nert_cover_set_destination(uint16_t dest_id);

/**
 * Get current cover traffic state
 * @return Pointer to cover state (read-only)
 */
const struct nert_cover_state* nert_cover_get_state(void);

/**
 * Report real packet activity (for adaptive mode)
 * Called internally when real packets are sent
 * @param bytes  Bytes sent
 */
void nert_cover_report_activity(uint16_t bytes);

/**
 * Force immediate dummy packet (for testing)
 * Bypasses interval timing
 */
void nert_cover_send_dummy(void);

/**
 * Process cover traffic (called from timer_tick)
 * Sends dummy packets according to configured mode
 */
void nert_cover_process(void);

/**
 * Check if a received packet is a dummy
 * @param pheromone_type  Pheromone type from packet
 * @return 1 if dummy, 0 if real
 */
int nert_cover_is_dummy(uint8_t pheromone_type);

/**
 * Reset cover traffic statistics
 */
void nert_cover_reset_stats(void);

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
