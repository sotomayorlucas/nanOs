/*
 * NERT Forward Error Correction (FEC) - Implementation
 *
 * Implements XOR parity-based FEC for packet loss recovery.
 * Optimized for embedded systems with minimal memory overhead.
 *
 * Algorithm:
 * - For N data packets, compute parity P = D0 XOR D1 XOR ... XOR D(N-1)
 * - If any single packet Di is lost, recover: Di = P XOR (all other Dj)
 * - Handles variable-length packets by zero-padding to max length
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "fec.h"
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

static struct fec_stats stats;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Count set bits in a byte (population count)
 */
static uint8_t popcount8(uint8_t x) {
    x = x - ((x >> 1) & 0x55);
    x = (x & 0x33) + ((x >> 2) & 0x33);
    return (x + (x >> 4)) & 0x0F;
}

/**
 * Find index of the missing (zero) bit in bitmap
 * Returns -1 if no bits are missing or multiple are missing
 */
static int find_missing_bit(uint8_t bitmap, uint8_t num_bits) {
    uint8_t full_mask = (1 << num_bits) - 1;
    uint8_t missing = ~bitmap & full_mask;

    /* Count missing bits */
    uint8_t missing_count = popcount8(missing);

    if (missing_count != 1) {
        return -1;  /* Not exactly one missing */
    }

    /* Find the missing bit position */
    for (int i = 0; i < num_bits; i++) {
        if (missing & (1 << i)) {
            return i;
        }
    }

    return -1;
}

/**
 * Find a decoder block slot by ID
 */
static int find_decoder_block(struct fec_decoder *dec, uint8_t block_id) {
    for (int i = 0; i < FEC_DECODER_MAX_BLOCKS; i++) {
        if (dec->block_active[i] && dec->blocks[i].block_id == block_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Allocate a decoder block slot
 */
static int alloc_decoder_block(struct fec_decoder *dec) {
    for (int i = 0; i < FEC_DECODER_MAX_BLOCKS; i++) {
        if (!dec->block_active[i]) {
            return i;
        }
    }
    return -1;
}

/* ============================================================================
 * Block-level API Implementation
 * ============================================================================ */

uint8_t fec_compute_xor_parity(const uint8_t *packets[], const uint8_t *lengths,
                                uint8_t count, uint8_t *parity, uint8_t max_len) {
    if (count == 0 || parity == NULL) {
        return 0;
    }

    /* Find maximum length among all packets */
    uint8_t parity_len = 0;
    for (uint8_t i = 0; i < count; i++) {
        if (lengths[i] > parity_len) {
            parity_len = lengths[i];
        }
    }

    if (parity_len > max_len) {
        parity_len = max_len;
    }

    /* Initialize parity to zeros */
    memset(parity, 0, parity_len);

    /* XOR all packets into parity */
    for (uint8_t i = 0; i < count; i++) {
        if (packets[i] == NULL) continue;

        for (uint8_t j = 0; j < lengths[i] && j < parity_len; j++) {
            parity[j] ^= packets[i][j];
        }
    }

    return parity_len;
}

int fec_recover_xor(const uint8_t *packets[], const uint8_t *lengths,
                    uint8_t count, const uint8_t *parity, uint8_t parity_len,
                    uint8_t missing_idx, uint8_t *recovered, uint8_t *recovered_len) {
    if (parity == NULL || recovered == NULL || recovered_len == NULL) {
        return FEC_ERR_INVALID;
    }

    if (missing_idx >= count) {
        return FEC_ERR_INVALID;
    }

    /* Verify all other packets are present */
    for (uint8_t i = 0; i < count; i++) {
        if (i != missing_idx && packets[i] == NULL) {
            return FEC_ERR_NOT_RECOVERABLE;
        }
    }

    /* Start with parity */
    memcpy(recovered, parity, parity_len);
    *recovered_len = parity_len;

    /* XOR all present packets to recover the missing one */
    for (uint8_t i = 0; i < count; i++) {
        if (i == missing_idx) continue;

        for (uint8_t j = 0; j < lengths[i] && j < parity_len; j++) {
            recovered[j] ^= packets[i][j];
        }
    }

    stats.packets_recovered++;
    return FEC_OK;
}

int fec_can_recover(uint8_t received_bitmap, uint8_t num_packets,
                    uint8_t parity_received, int *missing_idx) {
    uint8_t full_mask = (1 << num_packets) - 1;
    uint8_t received_count = popcount8(received_bitmap & full_mask);

    if (missing_idx) {
        *missing_idx = -1;
    }

    /* All packets received - no recovery needed */
    if (received_count == num_packets) {
        return 1;
    }

    /* Can only recover if exactly one packet is missing AND parity is present */
    if (received_count == num_packets - 1 && parity_received) {
        int missing = find_missing_bit(received_bitmap, num_packets);
        if (missing >= 0) {
            if (missing_idx) {
                *missing_idx = missing;
            }
            return 1;
        }
    }

    return 0;
}

/* ============================================================================
 * Encoder API Implementation
 * ============================================================================ */

void fec_encoder_init(struct fec_encoder *enc, uint8_t mode, uint8_t block_size) {
    if (enc == NULL) return;

    memset(enc, 0, sizeof(struct fec_encoder));
    enc->block.mode = mode;
    enc->block.num_data_packets = (block_size > FEC_MAX_DATA_PACKETS) ?
                                   FEC_MAX_DATA_PACKETS : block_size;
    enc->auto_parity = 1;
}

int fec_encoder_add_packet(struct fec_encoder *enc, const uint8_t *data, uint8_t len) {
    if (enc == NULL || data == NULL) {
        return 0;
    }

    if (enc->packet_index >= enc->block.num_data_packets) {
        /* Block is full, need to get parity first */
        return 1;
    }

    /* Copy packet data */
    uint8_t copy_len = (len > FEC_MAX_PAYLOAD) ? FEC_MAX_PAYLOAD : len;
    memcpy(enc->block.data[enc->packet_index], data, copy_len);
    enc->block.data_len[enc->packet_index] = copy_len;
    enc->block.received_bitmap |= (1 << enc->packet_index);

    enc->packet_index++;

    /* Check if block is complete */
    if (enc->packet_index >= enc->block.num_data_packets) {
        /* Compute parity */
        const uint8_t *packets[FEC_MAX_DATA_PACKETS];
        for (int i = 0; i < enc->block.num_data_packets; i++) {
            packets[i] = enc->block.data[i];
        }

        enc->block.parity_len = fec_compute_xor_parity(
            packets, enc->block.data_len,
            enc->block.num_data_packets,
            enc->block.parity, FEC_MAX_PAYLOAD
        );

        enc->block.parity_received = 1;
        enc->block.block_id = enc->next_block_id++;

        stats.blocks_encoded++;
        return 1;
    }

    return 0;
}

int fec_encoder_get_parity(struct fec_encoder *enc, uint8_t *parity,
                           uint8_t *len, uint8_t *block_id) {
    if (enc == NULL || parity == NULL) {
        return FEC_ERR_INVALID;
    }

    if (!enc->block.parity_received) {
        return FEC_ERR_BLOCK_INCOMPLETE;
    }

    memcpy(parity, enc->block.parity, enc->block.parity_len);
    if (len) *len = enc->block.parity_len;
    if (block_id) *block_id = enc->block.block_id;

    stats.parity_packets_sent++;
    return FEC_OK;
}

int fec_encoder_flush(struct fec_encoder *enc) {
    if (enc == NULL) {
        return 0;
    }

    int count = enc->packet_index;

    if (count > 0 && count < enc->block.num_data_packets) {
        /* Partial block - compute parity for what we have */
        const uint8_t *packets[FEC_MAX_DATA_PACKETS];
        for (int i = 0; i < count; i++) {
            packets[i] = enc->block.data[i];
        }

        enc->block.parity_len = fec_compute_xor_parity(
            packets, enc->block.data_len,
            count, enc->block.parity, FEC_MAX_PAYLOAD
        );

        enc->block.parity_received = 1;
        enc->block.num_data_packets = count;
        enc->block.block_id = enc->next_block_id++;

        stats.blocks_encoded++;
    }

    return count;
}

void fec_encoder_reset(struct fec_encoder *enc) {
    if (enc == NULL) return;

    uint8_t mode = enc->block.mode;
    uint8_t num_packets = enc->block.num_data_packets;
    uint8_t next_id = enc->next_block_id;
    uint8_t auto_parity = enc->auto_parity;

    memset(enc, 0, sizeof(struct fec_encoder));

    enc->block.mode = mode;
    enc->block.num_data_packets = num_packets;
    enc->next_block_id = next_id;
    enc->auto_parity = auto_parity;
}

/* ============================================================================
 * Decoder API Implementation
 * ============================================================================ */

void fec_decoder_init(struct fec_decoder *dec, uint8_t mode) {
    if (dec == NULL) return;

    memset(dec, 0, sizeof(struct fec_decoder));

    for (int i = 0; i < FEC_DECODER_MAX_BLOCKS; i++) {
        dec->blocks[i].mode = mode;
    }
}

int fec_decoder_add_data(struct fec_decoder *dec, uint8_t block_id,
                         uint8_t pkt_index, const uint8_t *data, uint8_t len) {
    if (dec == NULL || data == NULL) {
        return FEC_ERR_INVALID;
    }

    if (pkt_index >= FEC_MAX_DATA_PACKETS) {
        return FEC_ERR_INVALID;
    }

    /* Find or allocate block */
    int slot = find_decoder_block(dec, block_id);
    if (slot < 0) {
        slot = alloc_decoder_block(dec);
        if (slot < 0) {
            return FEC_ERR_INVALID;  /* No free slots */
        }
        dec->block_active[slot] = 1;
        dec->blocks[slot].block_id = block_id;
        dec->blocks[slot].received_bitmap = 0;
        dec->blocks[slot].parity_received = 0;
    }

    struct fec_block *block = &dec->blocks[slot];

    /* Store packet */
    uint8_t copy_len = (len > FEC_MAX_PAYLOAD) ? FEC_MAX_PAYLOAD : len;
    memcpy(block->data[pkt_index], data, copy_len);
    block->data_len[pkt_index] = copy_len;
    block->received_bitmap |= (1 << pkt_index);

    /* Track highest packet index as num_data_packets */
    if (pkt_index + 1 > block->num_data_packets) {
        block->num_data_packets = pkt_index + 1;
    }

    return FEC_OK;
}

int fec_decoder_add_parity(struct fec_decoder *dec, uint8_t block_id,
                           const uint8_t *parity, uint8_t len, uint8_t num_data) {
    if (dec == NULL || parity == NULL) {
        return FEC_ERR_INVALID;
    }

    /* Find or allocate block */
    int slot = find_decoder_block(dec, block_id);
    if (slot < 0) {
        slot = alloc_decoder_block(dec);
        if (slot < 0) {
            return FEC_ERR_INVALID;
        }
        dec->block_active[slot] = 1;
        dec->blocks[slot].block_id = block_id;
        dec->blocks[slot].received_bitmap = 0;
    }

    struct fec_block *block = &dec->blocks[slot];

    /* Store parity */
    uint8_t copy_len = (len > FEC_MAX_PAYLOAD) ? FEC_MAX_PAYLOAD : len;
    memcpy(block->parity, parity, copy_len);
    block->parity_len = copy_len;
    block->parity_received = 1;
    block->num_data_packets = num_data;

    stats.parity_packets_recv++;
    return FEC_OK;
}

int fec_decoder_can_recover(struct fec_decoder *dec, uint8_t block_id) {
    if (dec == NULL) {
        return -1;
    }

    int slot = find_decoder_block(dec, block_id);
    if (slot < 0) {
        return -1;
    }

    struct fec_block *block = &dec->blocks[slot];
    return fec_can_recover(block->received_bitmap, block->num_data_packets,
                           block->parity_received, NULL);
}

int fec_decoder_recover(struct fec_decoder *dec, uint8_t block_id,
                        uint8_t *recovered, uint8_t *recovered_len,
                        uint8_t *pkt_index) {
    if (dec == NULL || recovered == NULL || recovered_len == NULL) {
        return FEC_ERR_INVALID;
    }

    int slot = find_decoder_block(dec, block_id);
    if (slot < 0) {
        return FEC_ERR_INVALID;
    }

    struct fec_block *block = &dec->blocks[slot];

    /* Check if recovery is possible */
    int missing_idx;
    if (!fec_can_recover(block->received_bitmap, block->num_data_packets,
                         block->parity_received, &missing_idx)) {
        stats.recovery_failures++;
        return FEC_ERR_NOT_RECOVERABLE;
    }

    /* If no packets missing, nothing to recover */
    if (missing_idx < 0) {
        return FEC_ERR_NOT_RECOVERABLE;
    }

    /* Setup packet pointers */
    const uint8_t *packets[FEC_MAX_DATA_PACKETS];
    for (int i = 0; i < block->num_data_packets; i++) {
        if (block->received_bitmap & (1 << i)) {
            packets[i] = block->data[i];
        } else {
            packets[i] = NULL;
        }
    }

    /* Perform recovery */
    int result = fec_recover_xor(packets, block->data_len,
                                  block->num_data_packets,
                                  block->parity, block->parity_len,
                                  missing_idx, recovered, recovered_len);

    if (result == FEC_OK && pkt_index) {
        *pkt_index = missing_idx;
    }

    stats.blocks_decoded++;
    return result;
}

void fec_decoder_remove_block(struct fec_decoder *dec, uint8_t block_id) {
    if (dec == NULL) return;

    int slot = find_decoder_block(dec, block_id);
    if (slot >= 0) {
        dec->block_active[slot] = 0;
        memset(&dec->blocks[slot], 0, sizeof(struct fec_block));
    }
}

int fec_decoder_process_timeouts(struct fec_decoder *dec, uint32_t current_tick) {
    if (dec == NULL) return 0;

    int removed = 0;

    for (int i = 0; i < FEC_DECODER_MAX_BLOCKS; i++) {
        if (dec->block_active[i] && dec->block_timeout[i] > 0) {
            if (current_tick >= dec->block_timeout[i]) {
                dec->block_active[i] = 0;
                memset(&dec->blocks[i], 0, sizeof(struct fec_block));
                removed++;
            }
        }
    }

    return removed;
}

void fec_decoder_reset(struct fec_decoder *dec) {
    if (dec == NULL) return;

    memset(dec, 0, sizeof(struct fec_decoder));
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

const struct fec_stats* fec_get_stats(void) {
    return &stats;
}

void fec_reset_stats(void) {
    memset(&stats, 0, sizeof(stats));
}
