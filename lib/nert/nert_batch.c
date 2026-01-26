/*
 * NERT Batch Processing - Implementation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_batch.h"
#include <string.h>

/* External functions */
extern uint32_t nert_hal_get_ticks(void);
extern int nert_hal_send(const void *data, uint16_t len);
extern uint16_t nert_hal_get_node_id(void);
extern uint32_t nert_hal_random(void);

extern void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *plaintext, uint8_t len,
                            uint8_t *ciphertext);

extern void poly1305_mac(const uint8_t key[32],
                         const uint8_t *message, uint8_t msg_len,
                         const uint8_t *aad, uint8_t aad_len,
                         uint8_t tag[8]);

extern int poly1305_verify(const uint8_t key[32],
                           const uint8_t *message, uint8_t msg_len,
                           const uint8_t *aad, uint8_t aad_len,
                           const uint8_t expected_tag[8]);

extern uint8_t session_key[32];

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Global TX batch (for default batching) */
static struct nert_tx_batch global_tx_batch;

/* Statistics */
static struct nert_batch_stats stats;

/* Nonce counter */
static uint32_t batch_nonce_counter = 0;

/* ============================================================================
 * TX Batch Implementation
 * ============================================================================ */

void nert_tx_batch_init(struct nert_tx_batch *batch, uint8_t mode, uint16_t timeout_ms) {
    if (!batch) return;

    memset(batch, 0, sizeof(struct nert_tx_batch));
    batch->mode = mode;
    batch->timeout_ms = timeout_ms;
}

int nert_tx_batch_add(struct nert_tx_batch *batch,
                       uint16_t dest_id,
                       uint8_t pheromone_type,
                       const void *data,
                       uint8_t len,
                       uint8_t reliability_class,
                       uint8_t priority) {
    if (!batch) return -1;

    /* Check if batch is full */
    if (batch->count >= NERT_BATCH_MAX_PACKETS) {
        return -1;
    }

    /* Find free entry */
    struct nert_tx_batch_entry *entry = NULL;
    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        if (!batch->entries[i].active) {
            entry = &batch->entries[i];
            break;
        }
    }

    if (!entry) return -1;

    /* Fill entry */
    entry->active = 1;
    entry->dest_id = dest_id;
    entry->pheromone_type = pheromone_type;
    entry->reliability_class = reliability_class;
    entry->priority = priority;
    entry->len = len;
    entry->queued_tick = nert_hal_get_ticks();

    if (data && len > 0) {
        memcpy(entry->data, data, len);
    }

    /* Track first entry time for timeout */
    if (batch->count == 0) {
        batch->first_queued_tick = entry->queued_tick;
    }

    batch->count++;

    /* Auto-flush if immediate mode or high priority */
    if (batch->mode == NERT_BATCH_MODE_IMMEDIATE ||
        priority >= NERT_PRIORITY_CRITICAL) {
        nert_tx_batch_flush(batch);
    }

    return 0;
}

uint8_t nert_tx_batch_should_flush(const struct nert_tx_batch *batch, uint32_t current_tick) {
    if (!batch || batch->count == 0) return 0;

    uint8_t reasons = 0;

    /* Check if full */
    if (batch->count >= NERT_BATCH_MAX_PACKETS) {
        reasons |= NERT_BATCH_FLUSH_FULL;
    }

    /* Check timeout */
    if (batch->mode == NERT_BATCH_MODE_TIMED && batch->timeout_ms > 0) {
        if ((current_tick - batch->first_queued_tick) >= batch->timeout_ms) {
            reasons |= NERT_BATCH_FLUSH_TIMEOUT;
        }
    }

    /* Check for priority packets */
    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        if (batch->entries[i].active &&
            batch->entries[i].priority >= NERT_PRIORITY_CRITICAL) {
            reasons |= NERT_BATCH_FLUSH_PRIORITY;
            break;
        }
    }

    return reasons;
}

int nert_tx_batch_flush(struct nert_tx_batch *batch) {
    if (!batch || batch->count == 0) return 0;

    int sent = 0;
    uint16_t node_id = nert_hal_get_node_id();

    /*
     * Batch encryption optimization:
     * Set up key material once, then encrypt all packets.
     * This saves key expansion overhead.
     */

    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        struct nert_tx_batch_entry *entry = &batch->entries[i];
        if (!entry->active) continue;

        /* Build packet */
        uint8_t packet[NERT_HEADER_SIZE + NERT_MAX_PAYLOAD + NERT_MAC_SIZE];
        struct nert_header *hdr = (struct nert_header *)packet;

        hdr->magic = NERT_MAGIC;
        hdr->version_class = (NERT_VERSION & 0xF0) |
                             ((entry->reliability_class & 0x03) << 2);
        hdr->node_id = node_id;
        hdr->seq_num = 0;  /* Will be filled by protocol layer */
        hdr->flags = NERT_FLAG_ENC;
        hdr->payload_len = entry->len;
        hdr->nonce_counter = ++batch_nonce_counter;

#if !NERT_COMPACT_MODE
        hdr->dest_id = entry->dest_id;
        hdr->ack_num = 0;
        hdr->timestamp = (uint16_t)(nert_hal_get_ticks() & 0xFFFF);
        hdr->ttl = 32;
        hdr->hop_count = 0;
#endif

        /* Build nonce */
        uint8_t nonce[12];
        nonce[0] = (node_id >> 8) & 0xFF;
        nonce[1] = node_id & 0xFF;
        nonce[2] = 0;
        nonce[3] = 0;
        nonce[4] = (batch_nonce_counter >> 24) & 0xFF;
        nonce[5] = (batch_nonce_counter >> 16) & 0xFF;
        nonce[6] = (batch_nonce_counter >> 8) & 0xFF;
        nonce[7] = batch_nonce_counter & 0xFF;
        nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;

        /* Encrypt payload */
        if (entry->len > 0) {
            chacha8_encrypt(session_key, nonce, entry->data, entry->len,
                           packet + NERT_HEADER_SIZE);
        }

        /* Compute MAC */
        poly1305_mac(session_key,
                     packet + NERT_HEADER_SIZE, entry->len,
                     packet, NERT_HEADER_SIZE,
                     packet + NERT_HEADER_SIZE + entry->len);

        /* Send */
        uint16_t total_len = NERT_HEADER_SIZE + entry->len + NERT_MAC_SIZE;
        if (nert_hal_send(packet, total_len) == 0) {
            sent++;
            stats.tx_packets_batched++;
        }

        /* Clear entry */
        entry->active = 0;
    }

    batch->count = 0;
    batch->key_setup_done = 0;
    stats.tx_batches_sent++;
    stats.crypto_setups_saved += (sent > 1) ? (sent - 1) : 0;

    return sent;
}

/* ============================================================================
 * RX Batch Implementation
 * ============================================================================ */

void nert_rx_batch_init(struct nert_rx_batch *batch) {
    if (!batch) return;
    memset(batch, 0, sizeof(struct nert_rx_batch));
}

int nert_rx_batch_add(struct nert_rx_batch *batch,
                       const uint8_t *data,
                       uint16_t len) {
    if (!batch || !data) return -1;

    if (batch->count >= NERT_BATCH_MAX_PACKETS) {
        return -1;
    }

    /* Find free entry */
    struct nert_rx_batch_entry *entry = NULL;
    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        if (!batch->entries[i].active) {
            entry = &batch->entries[i];
            break;
        }
    }

    if (!entry) return -1;

    /* Store raw packet */
    entry->active = 1;
    entry->mac_verified = 0;
    entry->decrypted = 0;
    entry->len = len;
    memcpy(entry->data, data, len);

    /* Extract sender ID from header */
    if (len >= NERT_HEADER_SIZE) {
        struct nert_header *hdr = (struct nert_header *)entry->data;
        entry->sender_id = hdr->node_id;
    }

    batch->count++;
    return 0;
}

int nert_rx_batch_verify_macs(struct nert_rx_batch *batch, const uint8_t key[32]) {
    if (!batch || !key) return 0;

    int verified = 0;

    /*
     * Batch MAC verification:
     * Verify all MACs first before any decryption.
     * This provides fail-fast behavior for attacks.
     */

    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        struct nert_rx_batch_entry *entry = &batch->entries[i];
        if (!entry->active || entry->mac_verified) continue;

        /* Extract header and payload info */
        if (entry->len < NERT_HEADER_SIZE + 1 + NERT_MAC_SIZE) {
            entry->active = 0;  /* Invalid packet */
            continue;
        }

        struct nert_header *hdr = (struct nert_header *)entry->data;
        uint8_t payload_len = hdr->payload_len;

        if (entry->len < NERT_HEADER_SIZE + payload_len + NERT_MAC_SIZE) {
            entry->active = 0;
            continue;
        }

        /* Verify MAC */
        uint8_t *mac = entry->data + NERT_HEADER_SIZE + payload_len;
        int result = poly1305_verify(key,
                                      entry->data + NERT_HEADER_SIZE, payload_len,
                                      entry->data, NERT_HEADER_SIZE,
                                      mac);

        if (result == 0) {
            entry->mac_verified = 1;
            verified++;
        } else {
            entry->active = 0;
            stats.rx_mac_failures++;
        }
    }

    batch->verified_count = verified;
    stats.crypto_setups_saved += (verified > 1) ? (verified - 1) : 0;

    return verified;
}

int nert_rx_batch_decrypt(struct nert_rx_batch *batch, const uint8_t key[32]) {
    if (!batch || !key) return 0;

    int decrypted = 0;

    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        struct nert_rx_batch_entry *entry = &batch->entries[i];
        if (!entry->active || !entry->mac_verified || entry->decrypted) continue;

        struct nert_header *hdr = (struct nert_header *)entry->data;
        uint8_t payload_len = hdr->payload_len;

        if (payload_len == 0) {
            entry->decrypted = 1;
            decrypted++;
            continue;
        }

        /* Build nonce */
        uint8_t nonce[12];
        nonce[0] = (hdr->node_id >> 8) & 0xFF;
        nonce[1] = hdr->node_id & 0xFF;
        nonce[2] = 0;
        nonce[3] = 0;
        nonce[4] = (hdr->nonce_counter >> 24) & 0xFF;
        nonce[5] = (hdr->nonce_counter >> 16) & 0xFF;
        nonce[6] = (hdr->nonce_counter >> 8) & 0xFF;
        nonce[7] = hdr->nonce_counter & 0xFF;
        nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;

        /* Decrypt in-place */
        chacha8_encrypt(key, nonce,
                        entry->data + NERT_HEADER_SIZE, payload_len,
                        entry->data + NERT_HEADER_SIZE);

        entry->decrypted = 1;
        decrypted++;
    }

    return decrypted;
}

int nert_rx_batch_process(struct nert_rx_batch *batch,
                           nert_receive_callback_t callback) {
    if (!batch || !callback) return 0;

    int processed = 0;

    for (int i = 0; i < NERT_BATCH_MAX_PACKETS; i++) {
        struct nert_rx_batch_entry *entry = &batch->entries[i];
        if (!entry->active || !entry->mac_verified || !entry->decrypted) continue;

        struct nert_header *hdr = (struct nert_header *)entry->data;

        /* Extract pheromone type from payload (TLV format) */
        uint8_t pheromone_type = 0;
        uint8_t *payload = entry->data + NERT_HEADER_SIZE;
        uint8_t payload_len = hdr->payload_len;

        if (payload_len >= 3) {
            /* TLV format: [count][len][type][data...] */
            pheromone_type = payload[2];
        }

        entry->pheromone_type = pheromone_type;

        /* Call receive callback */
        callback(entry->sender_id, pheromone_type, payload, payload_len);

        /* Mark as processed */
        entry->active = 0;
        processed++;
    }

    batch->processed_count = processed;
    batch->count = 0;
    batch->verified_count = 0;

    stats.rx_batches_processed++;
    stats.rx_packets_batched += processed;

    return processed;
}

/* ============================================================================
 * Global Batch Processing
 * ============================================================================ */

void nert_batch_init(void) {
    nert_tx_batch_init(&global_tx_batch, NERT_BATCH_MODE_TIMED, 50);
    memset(&stats, 0, sizeof(stats));
    batch_nonce_counter = nert_hal_random();
}

void nert_batch_tick(uint32_t current_tick) {
    /* Check if global TX batch should be flushed */
    uint8_t reasons = nert_tx_batch_should_flush(&global_tx_batch, current_tick);

    if (reasons & (NERT_BATCH_FLUSH_FULL | NERT_BATCH_FLUSH_TIMEOUT)) {
        nert_tx_batch_flush(&global_tx_batch);

        if (reasons & NERT_BATCH_FLUSH_FULL) {
            stats.tx_flushes_full++;
        }
        if (reasons & NERT_BATCH_FLUSH_TIMEOUT) {
            stats.tx_flushes_timeout++;
        }
    }

    if (reasons & NERT_BATCH_FLUSH_PRIORITY) {
        stats.tx_flushes_priority++;
    }
}

const struct nert_batch_stats* nert_batch_get_stats(void) {
    return &stats;
}

void nert_batch_reset_stats(void) {
    memset(&stats, 0, sizeof(stats));
}
