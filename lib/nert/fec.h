/*
 * NERT Forward Error Correction (FEC)
 *
 * Provides packet loss recovery for CRITICAL reliability class.
 *
 * Two FEC schemes:
 * 1. Simple XOR parity - recovers 1 lost packet per block
 * 2. Reed-Solomon (future) - recovers multiple losses
 *
 * Design considerations:
 * - Minimal CPU overhead for embedded systems
 * - Works with NERT's block-padded packets
 * - Receiver can detect recovery capability
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_FEC_H
#define NERT_FEC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Maximum data packets per FEC block */
#define FEC_MAX_DATA_PACKETS        4

/* Maximum payload size per packet */
#define FEC_MAX_PAYLOAD             64

/* FEC modes */
#define FEC_MODE_NONE               0   /* No FEC */
#define FEC_MODE_XOR_PARITY         1   /* Simple XOR parity */
#define FEC_MODE_REED_SOLOMON       2   /* Reed-Solomon (future) */

/* Error codes */
#define FEC_OK                      0
#define FEC_ERR_INVALID             -1
#define FEC_ERR_NOT_RECOVERABLE     -2
#define FEC_ERR_BUFFER_TOO_SMALL    -3
#define FEC_ERR_BLOCK_INCOMPLETE    -4

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * FEC block for encoding/decoding
 * Holds data packets and parity for a single FEC block
 */
struct fec_block {
    uint8_t  data[FEC_MAX_DATA_PACKETS][FEC_MAX_PAYLOAD];   /* Data packets */
    uint8_t  parity[FEC_MAX_PAYLOAD];                        /* Parity packet */
    uint8_t  data_len[FEC_MAX_DATA_PACKETS];                 /* Length of each data packet */
    uint8_t  parity_len;                                     /* Length of parity packet */
    uint8_t  received_bitmap;                                /* Bitmap: bit i = packet i received */
    uint8_t  parity_received;                                /* Parity packet received */
    uint8_t  block_id;                                       /* Block identifier */
    uint8_t  num_data_packets;                               /* Number of data packets in block */
    uint8_t  mode;                                           /* FEC mode used */
};

/**
 * FEC encoder state
 * Tracks encoding progress across multiple sends
 */
struct fec_encoder {
    struct fec_block block;         /* Current block being built */
    uint8_t  packet_index;          /* Next packet index in block */
    uint8_t  next_block_id;         /* Next block ID to assign */
    uint8_t  auto_parity;           /* Automatically send parity when block full */
};

/**
 * FEC decoder state
 * Tracks multiple in-progress blocks for decoding
 */
#define FEC_DECODER_MAX_BLOCKS      2

struct fec_decoder {
    struct fec_block blocks[FEC_DECODER_MAX_BLOCKS];    /* In-progress blocks */
    uint8_t  block_active[FEC_DECODER_MAX_BLOCKS];      /* Block slot in use */
    uint32_t block_timeout[FEC_DECODER_MAX_BLOCKS];     /* Block expiry tick */
};

/**
 * FEC statistics
 */
struct fec_stats {
    uint32_t blocks_encoded;        /* Blocks encoded (TX) */
    uint32_t blocks_decoded;        /* Blocks decoded (RX) */
    uint32_t packets_recovered;     /* Packets recovered via FEC */
    uint32_t recovery_failures;     /* Failed recovery attempts */
    uint32_t parity_packets_sent;   /* Parity packets transmitted */
    uint32_t parity_packets_recv;   /* Parity packets received */
};

/* ============================================================================
 * Encoder API
 * ============================================================================ */

/**
 * Initialize FEC encoder
 *
 * @param enc       Encoder state
 * @param mode      FEC mode (FEC_MODE_*)
 * @param block_size Number of data packets per block (1-4)
 */
void fec_encoder_init(struct fec_encoder *enc, uint8_t mode, uint8_t block_size);

/**
 * Add a packet to the current FEC block
 * When block is full, parity is automatically computed.
 *
 * @param enc       Encoder state
 * @param data      Packet data
 * @param len       Packet length
 * @return          1 if block complete (parity ready), 0 otherwise
 */
int fec_encoder_add_packet(struct fec_encoder *enc, const uint8_t *data, uint8_t len);

/**
 * Get the computed parity packet
 * Call after fec_encoder_add_packet returns 1.
 *
 * @param enc       Encoder state
 * @param parity    Output buffer for parity (FEC_MAX_PAYLOAD bytes)
 * @param len       Output: parity length
 * @param block_id  Output: block ID for this parity
 * @return          FEC_OK on success, error code on failure
 */
int fec_encoder_get_parity(struct fec_encoder *enc, uint8_t *parity,
                           uint8_t *len, uint8_t *block_id);

/**
 * Force parity computation for partial block
 * Use when no more packets will be added to current block.
 *
 * @param enc       Encoder state
 * @return          Number of data packets in block (0 if empty)
 */
int fec_encoder_flush(struct fec_encoder *enc);

/**
 * Reset encoder state
 *
 * @param enc       Encoder state
 */
void fec_encoder_reset(struct fec_encoder *enc);

/* ============================================================================
 * Decoder API
 * ============================================================================ */

/**
 * Initialize FEC decoder
 *
 * @param dec       Decoder state
 * @param mode      FEC mode (FEC_MODE_*)
 */
void fec_decoder_init(struct fec_decoder *dec, uint8_t mode);

/**
 * Submit a data packet to the decoder
 *
 * @param dec       Decoder state
 * @param block_id  FEC block ID
 * @param pkt_index Packet index within block (0 to N-1)
 * @param data      Packet data
 * @param len       Packet length
 * @return          FEC_OK on success
 */
int fec_decoder_add_data(struct fec_decoder *dec, uint8_t block_id,
                         uint8_t pkt_index, const uint8_t *data, uint8_t len);

/**
 * Submit a parity packet to the decoder
 *
 * @param dec       Decoder state
 * @param block_id  FEC block ID
 * @param parity    Parity data
 * @param len       Parity length
 * @param num_data  Number of data packets in block
 * @return          FEC_OK on success
 */
int fec_decoder_add_parity(struct fec_decoder *dec, uint8_t block_id,
                           const uint8_t *parity, uint8_t len, uint8_t num_data);

/**
 * Check if a block can be recovered
 *
 * @param dec       Decoder state
 * @param block_id  FEC block ID to check
 * @return          1 if recoverable, 0 if not, -1 if block not found
 */
int fec_decoder_can_recover(struct fec_decoder *dec, uint8_t block_id);

/**
 * Attempt to recover a missing packet
 * If successful, returns the recovered packet data.
 *
 * @param dec           Decoder state
 * @param block_id      FEC block ID
 * @param recovered     Output buffer for recovered packet
 * @param recovered_len Output: length of recovered packet
 * @param pkt_index     Output: index of recovered packet
 * @return              FEC_OK on success, error code on failure
 */
int fec_decoder_recover(struct fec_decoder *dec, uint8_t block_id,
                        uint8_t *recovered, uint8_t *recovered_len,
                        uint8_t *pkt_index);

/**
 * Remove a completed or stale block
 *
 * @param dec       Decoder state
 * @param block_id  Block to remove
 */
void fec_decoder_remove_block(struct fec_decoder *dec, uint8_t block_id);

/**
 * Process block timeouts
 * Removes blocks that have expired without completion.
 *
 * @param dec           Decoder state
 * @param current_tick  Current system tick
 * @return              Number of blocks removed
 */
int fec_decoder_process_timeouts(struct fec_decoder *dec, uint32_t current_tick);

/**
 * Reset decoder state
 *
 * @param dec       Decoder state
 */
void fec_decoder_reset(struct fec_decoder *dec);

/* ============================================================================
 * Block-level API (for direct use)
 * ============================================================================ */

/**
 * Compute XOR parity of multiple packets
 *
 * @param packets   Array of packet buffers
 * @param lengths   Array of packet lengths
 * @param count     Number of packets
 * @param parity    Output buffer for parity
 * @param max_len   Maximum parity length (usually FEC_MAX_PAYLOAD)
 * @return          Length of parity packet
 */
uint8_t fec_compute_xor_parity(const uint8_t *packets[], const uint8_t *lengths,
                                uint8_t count, uint8_t *parity, uint8_t max_len);

/**
 * Recover a single missing packet using XOR parity
 *
 * @param packets       Array of packet buffers (NULL for missing)
 * @param lengths       Array of packet lengths (0 for missing)
 * @param count         Number of data packets
 * @param parity        Parity packet
 * @param parity_len    Parity length
 * @param missing_idx   Index of missing packet
 * @param recovered     Output buffer for recovered packet
 * @param recovered_len Output: length of recovered packet
 * @return              FEC_OK on success, error code on failure
 */
int fec_recover_xor(const uint8_t *packets[], const uint8_t *lengths,
                    uint8_t count, const uint8_t *parity, uint8_t parity_len,
                    uint8_t missing_idx, uint8_t *recovered, uint8_t *recovered_len);

/**
 * Check if recovery is possible given received bitmap
 * For XOR parity, exactly 1 packet can be missing.
 *
 * @param received_bitmap   Bitmap of received packets
 * @param num_packets       Total packets in block
 * @param parity_received   Whether parity was received
 * @param missing_idx       Output: index of missing packet (-1 if none)
 * @return                  1 if recoverable, 0 if not
 */
int fec_can_recover(uint8_t received_bitmap, uint8_t num_packets,
                    uint8_t parity_received, int *missing_idx);

/* ============================================================================
 * Statistics
 * ============================================================================ */

/**
 * Get FEC statistics
 *
 * @return  Pointer to stats structure (read-only)
 */
const struct fec_stats* fec_get_stats(void);

/**
 * Reset FEC statistics
 */
void fec_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_FEC_H */
