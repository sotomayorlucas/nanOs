/*
 * NERT Batch Processing
 *
 * Optimizes throughput by processing multiple packets together:
 * - TX batching: Queue multiple packets, send with single PHY call
 * - RX batching: Process multiple received packets efficiently
 * - Batch encryption: Single key setup for multiple packets
 * - Batch MAC verification: Verify all MACs before decryption
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_BATCH_H
#define NERT_BATCH_H

#include <stdint.h>
#include "../../include/nert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Maximum packets per batch */
#if defined(__arm__) || defined(ESP_PLATFORM)
    #define NERT_BATCH_MAX_PACKETS      4
#else
    #define NERT_BATCH_MAX_PACKETS      8
#endif

/* Batch modes */
#define NERT_BATCH_MODE_IMMEDIATE   0   /* Process immediately */
#define NERT_BATCH_MODE_DEFERRED    1   /* Queue until flush */
#define NERT_BATCH_MODE_TIMED       2   /* Flush after timeout */

/* Batch flush triggers */
#define NERT_BATCH_FLUSH_FULL       0x01    /* Batch is full */
#define NERT_BATCH_FLUSH_TIMEOUT    0x02    /* Timeout reached */
#define NERT_BATCH_FLUSH_PRIORITY   0x04    /* High-priority packet arrived */
#define NERT_BATCH_FLUSH_MANUAL     0x08    /* Manual flush request */

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * TX batch entry
 */
struct nert_tx_batch_entry {
    uint8_t  active;                        /* Entry in use */
    uint16_t dest_id;                       /* Destination node */
    uint8_t  pheromone_type;                /* Message type */
    uint8_t  reliability_class;             /* Reliability class */
    uint8_t  priority;                      /* Priority level */
    uint8_t  len;                           /* Payload length */
    uint8_t  data[NERT_MAX_PAYLOAD];        /* Payload data */
    uint32_t queued_tick;                   /* When entry was queued */
};

/**
 * TX batch state
 */
struct nert_tx_batch {
    struct nert_tx_batch_entry entries[NERT_BATCH_MAX_PACKETS];
    uint8_t  count;                         /* Entries in batch */
    uint8_t  mode;                          /* NERT_BATCH_MODE_* */
    uint16_t timeout_ms;                    /* Flush timeout (timed mode) */
    uint32_t first_queued_tick;             /* When first entry was queued */
    uint8_t  key_setup_done;                /* Crypto key already set up */
};

/**
 * RX batch entry
 */
struct nert_rx_batch_entry {
    uint8_t  active;                        /* Entry in use */
    uint8_t  mac_verified;                  /* MAC verification passed */
    uint8_t  decrypted;                     /* Payload decrypted */
    uint16_t sender_id;                     /* Source node */
    uint8_t  pheromone_type;                /* Message type */
    uint8_t  len;                           /* Payload length */
    uint8_t  data[NERT_MAX_PAYLOAD + NERT_HEADER_SIZE + NERT_MAC_SIZE];
};

/**
 * RX batch state
 */
struct nert_rx_batch {
    struct nert_rx_batch_entry entries[NERT_BATCH_MAX_PACKETS];
    uint8_t  count;                         /* Entries in batch */
    uint8_t  verified_count;                /* Entries with verified MAC */
    uint8_t  processed_count;               /* Entries fully processed */
};

/**
 * Batch processing statistics
 */
struct nert_batch_stats {
    uint32_t tx_batches_sent;               /* TX batches transmitted */
    uint32_t tx_packets_batched;            /* Packets sent via batching */
    uint32_t tx_flushes_full;               /* Flushes due to batch full */
    uint32_t tx_flushes_timeout;            /* Flushes due to timeout */
    uint32_t tx_flushes_priority;           /* Flushes due to priority */
    uint32_t rx_batches_processed;          /* RX batches processed */
    uint32_t rx_packets_batched;            /* Packets received via batching */
    uint32_t rx_mac_failures;               /* MAC verification failures */
    uint32_t crypto_setups_saved;           /* Key setups avoided by batching */
};

/* ============================================================================
 * TX Batch API
 * ============================================================================ */

/**
 * Initialize TX batch
 *
 * @param batch     Batch state
 * @param mode      NERT_BATCH_MODE_*
 * @param timeout_ms Flush timeout (for timed mode)
 */
void nert_tx_batch_init(struct nert_tx_batch *batch, uint8_t mode, uint16_t timeout_ms);

/**
 * Add a packet to TX batch
 * May trigger automatic flush if batch is full or priority packet.
 *
 * @param batch     Batch state
 * @param dest_id   Destination node
 * @param pheromone_type Message type
 * @param data      Payload data
 * @param len       Payload length
 * @param reliability_class Reliability class
 * @param priority  Priority level
 * @return          0 on success, -1 if batch full (manual flush needed)
 */
int nert_tx_batch_add(struct nert_tx_batch *batch,
                       uint16_t dest_id,
                       uint8_t pheromone_type,
                       const void *data,
                       uint8_t len,
                       uint8_t reliability_class,
                       uint8_t priority);

/**
 * Check if TX batch should be flushed
 *
 * @param batch         Batch state
 * @param current_tick  Current system tick
 * @return              Bitmask of NERT_BATCH_FLUSH_* reasons, 0 if no flush needed
 */
uint8_t nert_tx_batch_should_flush(const struct nert_tx_batch *batch, uint32_t current_tick);

/**
 * Flush TX batch - send all queued packets
 * Uses batch encryption for efficiency.
 *
 * @param batch     Batch state
 * @return          Number of packets sent
 */
int nert_tx_batch_flush(struct nert_tx_batch *batch);

/**
 * Get number of pending packets in TX batch
 *
 * @param batch     Batch state
 * @return          Number of queued packets
 */
static inline uint8_t nert_tx_batch_pending(const struct nert_tx_batch *batch) {
    return batch ? batch->count : 0;
}

/* ============================================================================
 * RX Batch API
 * ============================================================================ */

/**
 * Initialize RX batch
 *
 * @param batch     Batch state
 */
void nert_rx_batch_init(struct nert_rx_batch *batch);

/**
 * Add a received packet to RX batch
 *
 * @param batch     Batch state
 * @param data      Raw packet data (including header and MAC)
 * @param len       Total packet length
 * @return          0 on success, -1 if batch full
 */
int nert_rx_batch_add(struct nert_rx_batch *batch,
                       const uint8_t *data,
                       uint16_t len);

/**
 * Verify all MACs in RX batch
 * Batch verification is more efficient than individual.
 *
 * @param batch     Batch state
 * @param key       MAC key
 * @return          Number of packets with valid MAC
 */
int nert_rx_batch_verify_macs(struct nert_rx_batch *batch, const uint8_t key[32]);

/**
 * Decrypt all verified packets in RX batch
 * Uses batch decryption for efficiency.
 *
 * @param batch     Batch state
 * @param key       Decryption key
 * @return          Number of packets decrypted
 */
int nert_rx_batch_decrypt(struct nert_rx_batch *batch, const uint8_t key[32]);

/**
 * Process all decrypted packets in RX batch
 * Calls the receive callback for each valid packet.
 *
 * @param batch     Batch state
 * @param callback  Receive callback function
 * @return          Number of packets processed
 */
int nert_rx_batch_process(struct nert_rx_batch *batch,
                           nert_receive_callback_t callback);

/**
 * Get number of pending packets in RX batch
 *
 * @param batch     Batch state
 * @return          Number of queued packets
 */
static inline uint8_t nert_rx_batch_pending(const struct nert_rx_batch *batch) {
    return batch ? batch->count : 0;
}

/* ============================================================================
 * Global Batch Processing
 * ============================================================================ */

/**
 * Initialize global batch processing subsystem
 */
void nert_batch_init(void);

/**
 * Process batch tick (called from timer_tick)
 * Handles timed TX batch flushing.
 *
 * @param current_tick  Current system tick
 */
void nert_batch_tick(uint32_t current_tick);

/**
 * Get batch processing statistics
 *
 * @return          Pointer to stats (read-only)
 */
const struct nert_batch_stats* nert_batch_get_stats(void);

/**
 * Reset batch processing statistics
 */
void nert_batch_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_BATCH_H */
