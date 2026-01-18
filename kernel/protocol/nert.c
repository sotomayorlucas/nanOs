/*
 * NanOS Ephemeral Reliable Transport (NERT) Protocol - Core Implementation
 *
 * Hybrid UDP/TCP protocol optimized for disposable nodes
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Master key (pre-shared across swarm) */
static uint8_t swarm_master_key[NERT_KEY_SIZE] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x8B, 0xAD, 0xF0, 0x0D, 0xFE, 0xED, 0xFA, 0xCE,
    0x13, 0x37, 0xC0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01,
    0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0
};

/* Session keys with grace window for epoch transitions */
static uint8_t session_key[NERT_KEY_SIZE];          /* Current epoch key */
static uint8_t prev_session_key[NERT_KEY_SIZE];     /* Previous epoch key */
static uint8_t next_session_key[NERT_KEY_SIZE];     /* Next epoch key (pre-computed) */
static uint32_t last_key_epoch = 0;

/*
 * Grace window configuration:
 * - NERT_KEY_GRACE_WINDOW_MS: Accept keys from adjacent epochs within this window
 * - Handles clock drift between nodes without time synchronization
 * - Defined in nert.h (default: 30 seconds)
 */

/* Connections */
static struct nert_connection connections[NERT_MAX_CONNECTIONS];

/* Sequence counter */
static uint16_t global_seq = 0;
static uint32_t nonce_counter = 0;

/* Deduplication cache */
struct dedup_entry {
    uint16_t sender_id;
    uint16_t seq_num;
    uint32_t received_tick;
};
static struct dedup_entry dedup_cache[NERT_DEDUP_CACHE_SIZE];
static uint8_t dedup_index = 0;

/* Best-effort retry tracking */
#define BEST_EFFORT_QUEUE_SIZE  4
struct best_effort_entry {
    uint8_t  active;
    uint8_t  retries;
    uint32_t next_retry_tick;
    uint16_t dest_id;
    uint8_t  pheromone_type;
    uint8_t  data[NERT_MAX_PAYLOAD];
    uint8_t  len;
};
static struct best_effort_entry best_effort_queue[BEST_EFFORT_QUEUE_SIZE];

/* Callbacks */
static nert_receive_callback_t receive_callback = NULL;
static nert_connection_callback_t connection_callback = NULL;

/* Statistics */
static struct nert_stats stats;

/* ============================================================================
 * ChaCha8 Implementation (lightweight crypto)
 * ============================================================================ */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static void chacha8_block(const uint32_t key[8], const uint32_t nonce[3],
                          uint32_t counter, uint8_t output[64]) {
    uint32_t state[16];

    /* ChaCha constants "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key */
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }

    /* Counter and nonce */
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    /* Working copy */
    uint32_t working[16];
    memcpy(working, state, 64);

    /* 8 rounds (4 double rounds) */
    for (int i = 0; i < 4; i++) {
        /* Column round */
        QUARTERROUND(working[0], working[4], working[8],  working[12]);
        QUARTERROUND(working[1], working[5], working[9],  working[13]);
        QUARTERROUND(working[2], working[6], working[10], working[14]);
        QUARTERROUND(working[3], working[7], working[11], working[15]);

        /* Diagonal round */
        QUARTERROUND(working[0], working[5], working[10], working[15]);
        QUARTERROUND(working[1], working[6], working[11], working[12]);
        QUARTERROUND(working[2], working[7], working[8],  working[13]);
        QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    /* Add original state */
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    /* Output as bytes (little-endian) */
    for (int i = 0; i < 16; i++) {
        output[i * 4 + 0] = (working[i] >> 0) & 0xFF;
        output[i * 4 + 1] = (working[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (working[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (working[i] >> 24) & 0xFF;
    }
}

static void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *plaintext, uint8_t len,
                            uint8_t *ciphertext) {
    uint32_t key32[8];
    uint32_t nonce32[3];
    uint8_t keystream[64];
    uint32_t counter = 0;

    /* Convert key to 32-bit words */
    for (int i = 0; i < 8; i++) {
        key32[i] = plaintext[0]; /* Dummy to avoid warning */
        key32[i] = key[i * 4 + 0] |
                   (key[i * 4 + 1] << 8) |
                   (key[i * 4 + 2] << 16) |
                   (key[i * 4 + 3] << 24);
    }

    /* Convert nonce to 32-bit words */
    for (int i = 0; i < 3; i++) {
        nonce32[i] = nonce[i * 4 + 0] |
                     (nonce[i * 4 + 1] << 8) |
                     (nonce[i * 4 + 2] << 16) |
                     (nonce[i * 4 + 3] << 24);
    }

    /* Encrypt in 64-byte blocks */
    uint8_t offset = 0;
    while (offset < len) {
        chacha8_block(key32, nonce32, counter, keystream);
        counter++;

        uint8_t block_len = (len - offset > 64) ? 64 : (len - offset);
        for (uint8_t i = 0; i < block_len; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += block_len;
    }
}

/* ============================================================================
 * Poly1305 MAC Implementation (simplified)
 * ============================================================================ */

/* Poly1305 uses 130-bit arithmetic - simplified for embedded */
static void poly1305_mac(const uint8_t key[32],
                         const uint8_t *message, uint8_t msg_len,
                         const uint8_t *aad, uint8_t aad_len,
                         uint8_t tag[NERT_MAC_SIZE]) {
    /*
     * Simplified Poly1305: Use lower 64 bits of result
     * Full implementation would need 130-bit math
     */
    uint64_t r = 0, s = 0;
    uint64_t acc = 0;

    /* Extract r and s from key */
    for (int i = 0; i < 8; i++) {
        r |= ((uint64_t)key[i]) << (i * 8);
        s |= ((uint64_t)key[16 + i]) << (i * 8);
    }

    /* Clamp r */
    r &= 0x0FFFFFFC0FFFFFFCULL;

    /* Process AAD */
    for (uint8_t i = 0; i < aad_len; i++) {
        acc += aad[i];
        acc = (acc * r) ^ s;
    }

    /* Process message */
    for (uint8_t i = 0; i < msg_len; i++) {
        acc += message[i];
        acc = (acc * r) ^ s;
    }

    /* Finalize */
    acc += s;

    /* Output truncated tag */
    for (int i = 0; i < NERT_MAC_SIZE; i++) {
        tag[i] = (acc >> (i * 8)) & 0xFF;
    }
}

static int poly1305_verify(const uint8_t key[32],
                           const uint8_t *message, uint8_t msg_len,
                           const uint8_t *aad, uint8_t aad_len,
                           const uint8_t expected_tag[NERT_MAC_SIZE]) {
    uint8_t computed_tag[NERT_MAC_SIZE];
    poly1305_mac(key, message, msg_len, aad, aad_len, computed_tag);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < NERT_MAC_SIZE; i++) {
        diff |= computed_tag[i] ^ expected_tag[i];
    }

    return (diff == 0) ? 0 : -1;
}

/* ============================================================================
 * Key Derivation
 * ============================================================================ */

static void derive_key_for_epoch(uint32_t epoch_hour, uint8_t out_key[NERT_KEY_SIZE]) {
    uint8_t material[40];

    /*
     * Key material: master_key || zeros || epoch
     * Note: We don't include node_id in key derivation - all nodes must
     * derive the SAME key for a given epoch to communicate.
     */
    memcpy(material, swarm_master_key, 32);
    material[32] = (epoch_hour >> 24) & 0xFF;
    material[33] = (epoch_hour >> 16) & 0xFF;
    material[34] = (epoch_hour >> 8) & 0xFF;
    material[35] = epoch_hour & 0xFF;
    material[36] = 0x4E; /* 'N' */
    material[37] = 0x45; /* 'E' */
    material[38] = 0x52; /* 'R' */
    material[39] = 0x54; /* 'T' */

    /* Key derivation using ChaCha8 as PRF */
    uint8_t nonce[12] = {0};
    chacha8_encrypt(swarm_master_key, nonce, material, 32, out_key);
}

static void derive_session_key(uint32_t epoch_hour) {
    /* Derive keys for current, previous and next epochs */
    derive_key_for_epoch(epoch_hour, session_key);

    if (epoch_hour > 0) {
        derive_key_for_epoch(epoch_hour - 1, prev_session_key);
    } else {
        memset(prev_session_key, 0, NERT_KEY_SIZE);
    }

    derive_key_for_epoch(epoch_hour + 1, next_session_key);

    last_key_epoch = epoch_hour;
}

/*
 * Check if we're within the grace window at epoch boundaries.
 * Returns a bitmask of valid key indices to try:
 *   Bit 0: current key
 *   Bit 1: previous key (if near start of epoch)
 *   Bit 2: next key (if near end of epoch)
 */
static uint8_t get_valid_key_mask(void) {
    uint32_t ticks = nert_hal_get_ticks();
    uint32_t epoch_ms = NERT_KEY_ROTATION_SEC * 1000;
    uint32_t position_in_epoch = ticks % epoch_ms;

    uint8_t mask = 0x01; /* Current key always valid */

    /* Near start of epoch? Accept previous key */
    if (position_in_epoch < NERT_KEY_GRACE_WINDOW_MS) {
        mask |= 0x02;
    }

    /* Near end of epoch? Accept next key */
    if (position_in_epoch > (epoch_ms - NERT_KEY_GRACE_WINDOW_MS)) {
        mask |= 0x04;
    }

    return mask;
}

/* ============================================================================
 * Nonce Construction
 * ============================================================================ */

static void build_nonce(uint8_t nonce[NERT_NONCE_SIZE], uint32_t counter) {
    uint16_t node_id = nert_hal_get_node_id();
    uint32_t ticks = nert_hal_get_ticks();

    /* Bytes 0-1: Node ID */
    nonce[0] = (node_id >> 8) & 0xFF;
    nonce[1] = node_id & 0xFF;

    /* Bytes 2-3: Reserved */
    nonce[2] = 0;
    nonce[3] = 0;

    /* Bytes 4-7: Counter */
    nonce[4] = (counter >> 24) & 0xFF;
    nonce[5] = (counter >> 16) & 0xFF;
    nonce[6] = (counter >> 8) & 0xFF;
    nonce[7] = counter & 0xFF;

    /* Bytes 8-11: Timestamp */
    nonce[8] = (ticks >> 24) & 0xFF;
    nonce[9] = (ticks >> 16) & 0xFF;
    nonce[10] = (ticks >> 8) & 0xFF;
    nonce[11] = ticks & 0xFF;
}

/* ============================================================================
 * Deduplication
 * ============================================================================ */

static int is_duplicate(uint16_t sender_id, uint16_t seq_num) {
    uint32_t now = nert_hal_get_ticks();

    for (int i = 0; i < NERT_DEDUP_CACHE_SIZE; i++) {
        if (dedup_cache[i].sender_id == sender_id &&
            dedup_cache[i].seq_num == seq_num) {
            /* Check if entry is recent (within 2 seconds) */
            if (now - dedup_cache[i].received_tick < 2000) {
                return 1; /* Duplicate */
            }
        }
    }

    /* Add to cache (circular) */
    dedup_cache[dedup_index].sender_id = sender_id;
    dedup_cache[dedup_index].seq_num = seq_num;
    dedup_cache[dedup_index].received_tick = now;
    dedup_index = (dedup_index + 1) % NERT_DEDUP_CACHE_SIZE;

    return 0; /* New packet */
}

/* ============================================================================
 * Replay Protection
 * ============================================================================ */

static int check_replay(struct nert_connection *conn, uint16_t seq) {
    if (seq > conn->highest_rx_seq) {
        /* New highest - shift window */
        int shift = seq - conn->highest_rx_seq;
        if (shift >= 64) {
            conn->replay_bitmap = 1ULL;
        } else {
            conn->replay_bitmap <<= shift;
            conn->replay_bitmap |= 1ULL;
        }
        conn->highest_rx_seq = seq;
        return 0; /* Valid */
    }

    int offset = conn->highest_rx_seq - seq;
    if (offset >= 64) {
        return -1; /* Too old */
    }

    if (conn->replay_bitmap & (1ULL << offset)) {
        return -1; /* Replay detected */
    }

    conn->replay_bitmap |= (1ULL << offset);
    return 0; /* Valid */
}

/* ============================================================================
 * Connection Management
 * ============================================================================ */

static struct nert_connection* get_connection(uint16_t peer_id) {
    for (int i = 0; i < NERT_MAX_CONNECTIONS; i++) {
        if (connections[i].peer_id == peer_id &&
            connections[i].state != NERT_STATE_CLOSED) {
            return &connections[i];
        }
    }
    return NULL;
}

static struct nert_connection* alloc_connection(void) {
    for (int i = 0; i < NERT_MAX_CONNECTIONS; i++) {
        if (connections[i].state == NERT_STATE_CLOSED) {
            memset(&connections[i], 0, sizeof(struct nert_connection));
            return &connections[i];
        }
    }
    return NULL;
}

static void notify_connection_state(struct nert_connection *conn, uint8_t state) {
    conn->state = state;
    if (connection_callback) {
        int conn_id = conn - connections;
        connection_callback(conn_id, conn->peer_id, state);
    }
}

/* ============================================================================
 * Packet Building and Sending
 * ============================================================================ */

static int build_and_send(uint16_t dest_id, uint8_t pheromone_type,
                          uint8_t reliability_class, const void *data,
                          uint8_t len, uint8_t flags) {
    struct nert_packet pkt;
    uint8_t nonce[NERT_NONCE_SIZE];

    memset(&pkt, 0, sizeof(pkt));

    /* Build header */
    pkt.header.magic = NERT_MAGIC;
    pkt.header.version_class = (NERT_VERSION & 0xF0) | ((reliability_class & 0x03) << 2);
    pkt.header.node_id = nert_hal_get_node_id();
    pkt.header.seq_num = ++global_seq;
    pkt.header.flags = flags | NERT_FLAG_ENC;
    pkt.header.payload_len = len + 1; /* +1 for pheromone_type */
    pkt.header.nonce_counter = ++nonce_counter;

#if !NERT_COMPACT_MODE
    pkt.header.dest_id = dest_id;
    pkt.header.timestamp = (uint16_t)(nert_hal_get_ticks() & 0xFFFF);
    pkt.header.ttl = 15;
    pkt.header.hop_count = 0;
#endif

    /* Prepare plaintext payload */
    uint8_t plaintext[NERT_MAX_PAYLOAD + 1];
    plaintext[0] = pheromone_type;
    if (len > 0 && data) {
        memcpy(plaintext + 1, data, len);
    }

    /* Build nonce and encrypt */
    build_nonce(nonce, nonce_counter);
    chacha8_encrypt(session_key, nonce, plaintext, len + 1, pkt.payload);

    /* Compute MAC over header + encrypted payload */
    poly1305_mac(session_key, pkt.payload, len + 1,
                 (uint8_t*)&pkt.header, NERT_HEADER_SIZE, pkt.auth.poly1305_tag);

    /* Send */
    uint16_t total_len = NERT_HEADER_SIZE + len + 1 + NERT_MAC_SIZE;
    int result = nert_hal_send(&pkt, total_len);

    if (result == 0) {
        stats.tx_packets++;
        stats.tx_bytes += total_len;
    }

    return result;
}

/* ============================================================================
 * Packet Reception and Processing
 * ============================================================================ */

static void handle_received_packet(uint8_t *raw_data, uint16_t len) {
    struct nert_packet *pkt = (struct nert_packet*)raw_data;

    /* Validate minimum length */
    if (len < NERT_HEADER_SIZE + 1 + NERT_MAC_SIZE) {
        return;
    }

    /* Validate magic */
    if (pkt->header.magic != NERT_MAGIC) {
        return;
    }

    stats.rx_packets++;
    stats.rx_bytes += len;

    uint8_t payload_len = pkt->header.payload_len;
    uint8_t *tag_ptr = raw_data + NERT_HEADER_SIZE + payload_len;

    /*
     * Verify MAC with grace window support.
     * Try current key first, then adjacent epoch keys if within grace window.
     * This handles clock drift between nodes at epoch boundaries.
     */
    uint8_t key_mask = get_valid_key_mask();
    const uint8_t *valid_key = NULL;

    /* Try current epoch key (always valid) */
    if (poly1305_verify(session_key, pkt->payload, payload_len,
                        (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                        tag_ptr) == 0) {
        valid_key = session_key;
    }
    /* Try previous epoch key (if in grace window at start of epoch) */
    else if ((key_mask & 0x02) &&
             poly1305_verify(prev_session_key, pkt->payload, payload_len,
                            (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                            tag_ptr) == 0) {
        valid_key = prev_session_key;
    }
    /* Try next epoch key (if in grace window at end of epoch) */
    else if ((key_mask & 0x04) &&
             poly1305_verify(next_session_key, pkt->payload, payload_len,
                            (uint8_t*)&pkt->header, NERT_HEADER_SIZE,
                            tag_ptr) == 0) {
        valid_key = next_session_key;
    }

    if (!valid_key) {
        stats.rx_bad_mac++;
        return;
    }

    /* Check for duplicates */
    if (is_duplicate(pkt->header.node_id, pkt->header.seq_num)) {
        stats.rx_duplicates++;
        return;
    }

    /* Decrypt payload using the key that verified successfully */
    uint8_t nonce[NERT_NONCE_SIZE];
    uint8_t plaintext[NERT_MAX_PAYLOAD + 1];

    build_nonce(nonce, pkt->header.nonce_counter);
    chacha8_encrypt(valid_key, nonce, pkt->payload, payload_len, plaintext);

    uint8_t pheromone_type = plaintext[0];
    uint8_t *data = plaintext + 1;
    uint8_t data_len = payload_len - 1;

    /* Extract reliability class */
    uint8_t reliability_class = (pkt->header.version_class >> 2) & 0x03;

    /* Handle connection-oriented packets */
    if (reliability_class >= NERT_CLASS_RELIABLE) {
        struct nert_connection *conn = get_connection(pkt->header.node_id);

        /* Handle SYN */
        if (pkt->header.flags & NERT_FLAG_SYN) {
            if (!conn) {
                conn = alloc_connection();
                if (!conn) return; /* No space */

                conn->peer_id = pkt->header.node_id;
                conn->recv_seq = pkt->header.seq_num + 1;
                conn->send_seq = nert_hal_random() & 0xFFFF;
                conn->last_activity = nert_hal_get_ticks();
                stats.connections_opened++;
            }

            /* Send SYN+ACK */
            struct nert_packet resp;
            memset(&resp, 0, sizeof(resp));
            resp.header.magic = NERT_MAGIC;
            resp.header.version_class = pkt->header.version_class;
            resp.header.node_id = nert_hal_get_node_id();
            resp.header.seq_num = conn->send_seq;
            resp.header.flags = NERT_FLAG_SYN | NERT_FLAG_ACK | NERT_FLAG_ENC;

#if !NERT_COMPACT_MODE
            resp.header.dest_id = conn->peer_id;
            resp.header.ack_num = conn->recv_seq;
#endif

            resp.header.nonce_counter = ++nonce_counter;

            build_nonce(nonce, nonce_counter);
            uint8_t syn_payload = PHEROMONE_ECHO;
            chacha8_encrypt(session_key, nonce, &syn_payload, 1, resp.payload);
            resp.header.payload_len = 1;

            poly1305_mac(session_key, resp.payload, 1,
                         (uint8_t*)&resp.header, NERT_HEADER_SIZE,
                         resp.auth.poly1305_tag);

            nert_hal_send(&resp, NERT_HEADER_SIZE + 1 + NERT_MAC_SIZE);
            notify_connection_state(conn, NERT_STATE_ESTABLISHED);
        }

        /* Handle ACK */
        if ((pkt->header.flags & NERT_FLAG_ACK) && conn) {
#if !NERT_COMPACT_MODE
            /* Process ACK - clear retransmit buffer */
            for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
                if (conn->tx_window[i].active &&
                    conn->tx_window[i].seq <= pkt->header.ack_num) {
                    conn->tx_window[i].active = 0;
                }
            }
#endif
            conn->last_activity = nert_hal_get_ticks();

            /* Handle SYN+ACK completion */
            if ((pkt->header.flags & NERT_FLAG_SYN) &&
                conn->state == NERT_STATE_SYN_SENT) {
                notify_connection_state(conn, NERT_STATE_ESTABLISHED);
            }
        }

        /* Replay protection for reliable connections */
        if (conn && check_replay(conn, pkt->header.seq_num) != 0) {
            stats.rx_replay_blocked++;
            return;
        }
    }

    /* Deliver to application */
    if (receive_callback && data_len > 0) {
        receive_callback(pkt->header.node_id, pheromone_type, data, data_len);
    }
}

/* ============================================================================
 * FEC Implementation
 * ============================================================================ */

#if NERT_ENABLE_FEC

static void fec_encode(const uint8_t data[4][NERT_FEC_SHARD_SIZE],
                       uint8_t parity[2][NERT_FEC_SHARD_SIZE]) {
    /* Parity 0: XOR of even shards (0, 2) */
    for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
        parity[0][i] = data[0][i] ^ data[2][i];
    }

    /* Parity 1: XOR of odd shards (1, 3) */
    for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
        parity[1][i] = data[1][i] ^ data[3][i];
    }
}

static int fec_decode(uint8_t shards[6][NERT_FEC_SHARD_SIZE],
                      uint8_t received_mask,
                      uint8_t recovered[4][NERT_FEC_SHARD_SIZE]) {
    int missing_count = 0;
    int missing[2] = {-1, -1};

    /* Identify missing data shards */
    for (int i = 0; i < 4; i++) {
        if (!(received_mask & (1 << i))) {
            if (missing_count >= 2) return -1; /* Unrecoverable */
            missing[missing_count++] = i;
        }
    }

    /* Copy received shards */
    for (int i = 0; i < 4; i++) {
        if (received_mask & (1 << i)) {
            memcpy(recovered[i], shards[i], NERT_FEC_SHARD_SIZE);
        }
    }

    /* Recover missing shards using parity */
    if (missing_count == 1) {
        int m = missing[0];
        int parity_idx = (m % 2);      /* 0,2 -> parity[0], 1,3 -> parity[1] */
        int pair = m ^ 2;              /* 0<->2, 1<->3 */

        /* Check we have the parity shard */
        if (!(received_mask & (1 << (4 + parity_idx)))) {
            return -1;
        }

        for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
            recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
        }
        stats.rx_recovered_fec++;
    } else if (missing_count == 2) {
        /* Need both parities and missing shards must be from different groups */
        if ((missing[0] % 2) == (missing[1] % 2)) {
            return -1; /* Same group - unrecoverable */
        }

        for (int j = 0; j < 2; j++) {
            int m = missing[j];
            int parity_idx = (m % 2);
            int pair = m ^ 2;

            if (!(received_mask & (1 << (4 + parity_idx)))) {
                return -1;
            }

            for (int i = 0; i < NERT_FEC_SHARD_SIZE; i++) {
                recovered[m][i] = shards[4 + parity_idx][i] ^ recovered[pair][i];
            }
        }
        stats.rx_recovered_fec += 2;
    }

    return 0;
}

#endif /* NERT_ENABLE_FEC */

/* ============================================================================
 * Multi-Path Routing
 * ============================================================================ */

#if NERT_ENABLE_MULTIPATH

extern uint8_t neighbor_count;
extern struct neighbor_entry {
    uint32_t node_id;
    uint8_t  distance;
    uint16_t packets;
} neighbors[];

static int select_paths(uint16_t dest_id, uint16_t paths[NERT_MAX_PATHS]) {
    int path_count = 0;
    uint16_t excluded[NERT_MAX_PATHS] = {0};

    /* Simple path selection: pick diverse neighbors */
    for (int p = 0; p < NERT_MAX_PATHS && path_count < NERT_MAX_PATHS; p++) {
        uint16_t best_id = 0;
        uint8_t best_score = 255;

        for (int i = 0; i < neighbor_count && i < 16; i++) {
            /* Skip excluded */
            int skip = 0;
            for (int e = 0; e < path_count; e++) {
                if ((neighbors[i].node_id & 0xFFFF) == excluded[e]) {
                    skip = 1;
                    break;
                }
            }
            if (skip) continue;

            /* Score based on distance and activity */
            uint8_t score = neighbors[i].distance;
            if (neighbors[i].packets < 100) {
                score += (100 - neighbors[i].packets) / 10;
            }

            if (score < best_score) {
                best_score = score;
                best_id = neighbors[i].node_id & 0xFFFF;
            }
        }

        if (best_id != 0) {
            paths[path_count] = best_id;
            excluded[path_count] = best_id;
            path_count++;
        }
    }

    return path_count;
}

#endif /* NERT_ENABLE_MULTIPATH */

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

void nert_init(void) {
    memset(connections, 0, sizeof(connections));
    memset(dedup_cache, 0, sizeof(dedup_cache));
    memset(best_effort_queue, 0, sizeof(best_effort_queue));
    memset(&stats, 0, sizeof(stats));

    global_seq = nert_hal_random() & 0xFFFF;
    nonce_counter = nert_hal_random();
    dedup_index = 0;

    /* Derive initial session key */
    uint32_t epoch = nert_hal_get_ticks() / (NERT_KEY_ROTATION_SEC * 1000);
    derive_session_key(epoch);

    stats.min_rtt = 0xFFFF;
}

void nert_set_master_key(const uint8_t key[NERT_KEY_SIZE]) {
    memcpy(swarm_master_key, key, NERT_KEY_SIZE);
    /* Force key re-derivation */
    last_key_epoch = 0;
    nert_check_key_rotation();
}

void nert_set_receive_callback(nert_receive_callback_t callback) {
    receive_callback = callback;
}

void nert_set_connection_callback(nert_connection_callback_t callback) {
    connection_callback = callback;
}

int nert_send_unreliable(uint16_t dest_id, uint8_t pheromone_type,
                         const void *data, uint8_t len) {
    return build_and_send(dest_id, pheromone_type, NERT_CLASS_FIRE_FORGET,
                          data, len, 0);
}

int nert_send_best_effort(uint16_t dest_id, uint8_t pheromone_type,
                          const void *data, uint8_t len) {
    int result = build_and_send(dest_id, pheromone_type, NERT_CLASS_BEST_EFFORT,
                                data, len, 0);

    if (result == 0) {
        /* Queue for retry */
        for (int i = 0; i < BEST_EFFORT_QUEUE_SIZE; i++) {
            if (!best_effort_queue[i].active) {
                best_effort_queue[i].active = 1;
                best_effort_queue[i].retries = 1;
                best_effort_queue[i].next_retry_tick =
                    nert_hal_get_ticks() + NERT_RETRY_TIMEOUT_MS;
                best_effort_queue[i].dest_id = dest_id;
                best_effort_queue[i].pheromone_type = pheromone_type;
                best_effort_queue[i].len = len;
                if (len > 0 && data) {
                    memcpy(best_effort_queue[i].data, data, len);
                }
                break;
            }
        }
    }

    return result;
}

int nert_send_reliable(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len) {
    /* Find or create connection */
    struct nert_connection *conn = get_connection(dest_id);

    if (!conn) {
        conn = alloc_connection();
        if (!conn) return -1;

        conn->peer_id = dest_id;
        conn->send_seq = nert_hal_random() & 0xFFFF;
        conn->state = NERT_STATE_SYN_SENT;
        conn->last_activity = nert_hal_get_ticks();
        conn->srtt = NERT_RETRY_TIMEOUT_MS;
        conn->rttvar = NERT_RETRY_TIMEOUT_MS / 4;
        stats.connections_opened++;
    }

    /* Find free TX window slot */
    int slot = -1;
    for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
        if (!conn->tx_window[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -1; /* Window full */

    /* Build and send with SYN if new connection */
    uint8_t flags = (conn->state == NERT_STATE_SYN_SENT) ? NERT_FLAG_SYN : 0;
    int result = build_and_send(dest_id, pheromone_type, NERT_CLASS_RELIABLE,
                                data, len, flags);

    if (result == 0) {
        /* Store in retransmit window */
        conn->tx_window[slot].active = 1;
        conn->tx_window[slot].seq = global_seq;
        conn->tx_window[slot].retries = 0;
        conn->tx_window[slot].timeout_ms = conn->srtt + 4 * conn->rttvar;
        conn->tx_window[slot].sent_tick = nert_hal_get_ticks();
        conn->tx_window[slot].len = len;
        if (len > 0 && data) {
            memcpy(conn->tx_window[slot].data, data, len);
        }
    }

    return conn - connections;
}

int nert_send_critical(uint16_t dest_id, uint8_t pheromone_type,
                       const void *data, uint8_t len) {
    int result;

#if NERT_ENABLE_MULTIPATH
    /* Send via multiple paths */
    uint16_t paths[NERT_MAX_PATHS];
    int path_count = select_paths(dest_id, paths);

    if (path_count > 0) {
        for (int p = 0; p < path_count; p++) {
            result = build_and_send(dest_id, pheromone_type, NERT_CLASS_CRITICAL,
                                    data, len, NERT_FLAG_MPATH);
        }
    } else
#endif
    {
        result = build_and_send(dest_id, pheromone_type, NERT_CLASS_CRITICAL,
                                data, len, 0);
    }

#if NERT_ENABLE_FEC
    /* Send FEC parity packets for large payloads */
    if (len > NERT_FEC_SHARD_SIZE) {
        stats.tx_fec_blocks++;
        /* FEC encoding would go here for production use */
    }
#endif

    /* Also use reliable retransmit */
    return nert_send_reliable(dest_id, pheromone_type, data, len);
}

int nert_connect(uint16_t peer_id) {
    struct nert_connection *conn = alloc_connection();
    if (!conn) return -1;

    conn->peer_id = peer_id;
    conn->send_seq = nert_hal_random() & 0xFFFF;
    conn->state = NERT_STATE_SYN_SENT;
    conn->last_activity = nert_hal_get_ticks();
    conn->established_at = 0;
    conn->srtt = NERT_RETRY_TIMEOUT_MS;
    conn->rttvar = NERT_RETRY_TIMEOUT_MS / 4;
    stats.connections_opened++;

    /* Send SYN */
    build_and_send(peer_id, 0, NERT_CLASS_RELIABLE, NULL, 0, NERT_FLAG_SYN);

    return conn - connections;
}

void nert_disconnect(int conn_id) {
    if (conn_id < 0 || conn_id >= NERT_MAX_CONNECTIONS) return;

    struct nert_connection *conn = &connections[conn_id];
    if (conn->state == NERT_STATE_CLOSED) return;

    /* Send FIN */
    build_and_send(conn->peer_id, 0, NERT_CLASS_RELIABLE, NULL, 0, NERT_FLAG_FIN);

    notify_connection_state(conn, NERT_STATE_CLOSED);
}

int nert_get_connection_state(int conn_id) {
    if (conn_id < 0 || conn_id >= NERT_MAX_CONNECTIONS) return -1;
    return connections[conn_id].state;
}

void nert_process_incoming(void) {
    uint8_t buffer[NERT_HEADER_SIZE + NERT_MAX_PAYLOAD + NERT_MAC_SIZE];
    int len;

    while ((len = nert_hal_receive(buffer, sizeof(buffer))) > 0) {
        handle_received_packet(buffer, len);
    }
}

void nert_timer_tick(void) {
    uint32_t now = nert_hal_get_ticks();

    /* Process best-effort retries */
    for (int i = 0; i < BEST_EFFORT_QUEUE_SIZE; i++) {
        if (best_effort_queue[i].active &&
            now >= best_effort_queue[i].next_retry_tick) {

            if (best_effort_queue[i].retries >= 2) {
                /* Max retries reached */
                best_effort_queue[i].active = 0;
            } else {
                /* Retry */
                build_and_send(best_effort_queue[i].dest_id,
                              best_effort_queue[i].pheromone_type,
                              NERT_CLASS_BEST_EFFORT,
                              best_effort_queue[i].data,
                              best_effort_queue[i].len, 0);

                best_effort_queue[i].retries++;
                best_effort_queue[i].next_retry_tick =
                    now + NERT_RETRY_TIMEOUT_MS * (1 << best_effort_queue[i].retries);
                stats.tx_retransmits++;
            }
        }
    }

    /* Process reliable connection retransmits */
    for (int c = 0; c < NERT_MAX_CONNECTIONS; c++) {
        struct nert_connection *conn = &connections[c];
        if (conn->state == NERT_STATE_CLOSED) continue;

        /* Connection timeout */
        if (now - conn->last_activity > NERT_CONNECTION_TIMEOUT_MS) {
            notify_connection_state(conn, NERT_STATE_CLOSED);
            stats.connections_timeout++;
            continue;
        }

        /* Retransmit window entries */
        for (int i = 0; i < NERT_WINDOW_SIZE; i++) {
            if (!conn->tx_window[i].active) continue;

            if (now - conn->tx_window[i].sent_tick > conn->tx_window[i].timeout_ms) {
                if (conn->tx_window[i].retries >= NERT_MAX_RETRIES) {
                    /* Connection failed */
                    notify_connection_state(conn, NERT_STATE_CLOSED);
                    stats.connections_failed++;
                    break;
                }

                /* Retransmit with exponential backoff */
                conn->tx_window[i].retries++;
                conn->tx_window[i].timeout_ms *= 2;
                conn->tx_window[i].sent_tick = now;
                stats.tx_retransmits++;

                /* Rebuild and resend packet */
                /* Note: In full implementation, store complete packet */
            }
        }
    }
}

void nert_check_key_rotation(void) {
    uint32_t current_epoch = nert_hal_get_ticks() / (NERT_KEY_ROTATION_SEC * 1000);

    if (current_epoch != last_key_epoch) {
        derive_session_key(current_epoch);
    }
}

const struct nert_stats* nert_get_stats(void) {
    return &stats;
}

void nert_reset_stats(void) {
    uint16_t min_rtt = stats.min_rtt;
    memset(&stats, 0, sizeof(stats));
    stats.min_rtt = min_rtt;
}

#if NERT_ENABLE_DEBUG
void nert_debug_packet(const char *prefix, const struct nert_packet *pkt) {
    /* Platform-specific debug output */
    (void)prefix;
    (void)pkt;
}
#endif
