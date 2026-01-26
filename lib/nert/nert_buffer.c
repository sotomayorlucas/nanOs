/*
 * NERT Buffer Pool and Zero-Copy Support - Implementation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_buffer.h"
#include <string.h>

/* External crypto functions */
extern void chacha8_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *plaintext, uint8_t len,
                            uint8_t *ciphertext);

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Raw buffer storage */
static uint8_t buffer_storage[NERT_BUFFER_POOL_SIZE][NERT_BUFFER_SIZE];

/* Buffer descriptors */
static struct nert_buffer buffer_pool[NERT_BUFFER_POOL_SIZE];

/* Statistics */
static struct nert_buffer_stats stats;

/* Initialization flag */
static uint8_t initialized = 0;

/* ============================================================================
 * Buffer Pool Implementation
 * ============================================================================ */

void nert_buffer_pool_init(void) {
    memset(buffer_storage, 0, sizeof(buffer_storage));
    memset(buffer_pool, 0, sizeof(buffer_pool));
    memset(&stats, 0, sizeof(stats));

    /* Initialize descriptors */
    for (int i = 0; i < NERT_BUFFER_POOL_SIZE; i++) {
        buffer_pool[i].pool_index = i;
        buffer_pool[i].capacity = NERT_BUFFER_SIZE;
    }

    initialized = 1;
}

struct nert_buffer* nert_buffer_alloc(uint16_t size) {
    if (!initialized) return NULL;
    if (size > NERT_BUFFER_SIZE) {
        stats.alloc_failures++;
        return NULL;
    }

    for (int i = 0; i < NERT_BUFFER_POOL_SIZE; i++) {
        if (!(buffer_pool[i].flags & NERT_BUF_FLAG_INUSE)) {
            struct nert_buffer *buf = &buffer_pool[i];

            buf->data = buffer_storage[i];
            buf->len = 0;
            buf->capacity = NERT_BUFFER_SIZE;
            buf->head_offset = 0;
            buf->flags = NERT_BUF_FLAG_INUSE;
            buf->refcount = 1;

            stats.alloc_count++;
            stats.buffers_in_use++;
            if (stats.buffers_in_use > stats.high_watermark) {
                stats.high_watermark = stats.buffers_in_use;
            }

            return buf;
        }
    }

    stats.alloc_failures++;
    return NULL;
}

struct nert_buffer* nert_buffer_alloc_headroom(uint16_t size, uint16_t headroom) {
    if (!initialized) return NULL;
    if (size + headroom > NERT_BUFFER_SIZE) {
        stats.alloc_failures++;
        return NULL;
    }

    struct nert_buffer *buf = nert_buffer_alloc(size + headroom);
    if (buf) {
        buf->data = buffer_storage[buf->pool_index] + headroom;
        buf->head_offset = headroom;
        buf->capacity = NERT_BUFFER_SIZE - headroom;
        buf->flags |= NERT_BUF_FLAG_HEADROOM;
    }

    return buf;
}

void nert_buffer_free(struct nert_buffer *buf) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return;
    }

    /* Decrement refcount */
    if (buf->refcount > 1) {
        buf->refcount--;
        return;
    }

    /* Clear buffer data for security */
    memset(buffer_storage[buf->pool_index], 0, NERT_BUFFER_SIZE);

    /* Reset descriptor */
    buf->data = NULL;
    buf->len = 0;
    buf->head_offset = 0;
    buf->flags = 0;
    buf->refcount = 0;

    stats.free_count++;
    stats.buffers_in_use--;
}

uint8_t nert_buffer_ref(struct nert_buffer *buf) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return 0;
    }

    if (buf->refcount < 255) {
        buf->refcount++;
    }

    return buf->refcount;
}

int nert_buffer_reserve_head(struct nert_buffer *buf, uint16_t headroom) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return NERT_BUF_ERR_INVALID;
    }

    if (buf->len > 0) {
        /* Can't reserve headroom after data written */
        return NERT_BUF_ERR_INVALID;
    }

    if (headroom > NERT_BUFFER_SIZE) {
        return NERT_BUF_ERR_TOO_LARGE;
    }

    buf->data = buffer_storage[buf->pool_index] + headroom;
    buf->head_offset = headroom;
    buf->capacity = NERT_BUFFER_SIZE - headroom;
    buf->flags |= NERT_BUF_FLAG_HEADROOM;

    return NERT_BUF_OK;
}

uint8_t* nert_buffer_push(struct nert_buffer *buf, uint16_t len) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return NULL;
    }

    if (len > buf->head_offset) {
        return NULL;  /* Not enough headroom */
    }

    buf->data -= len;
    buf->head_offset -= len;
    buf->len += len;
    buf->capacity += len;

    stats.memcpy_avoided++;
    stats.bytes_saved += len;

    return buf->data;
}

uint8_t* nert_buffer_pull(struct nert_buffer *buf, uint16_t len) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return NULL;
    }

    if (len > buf->len) {
        return NULL;
    }

    uint8_t *result = buf->data;
    buf->data += len;
    buf->len -= len;
    buf->head_offset += len;

    return result;
}

uint8_t* nert_buffer_put(struct nert_buffer *buf, uint16_t len) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return NULL;
    }

    if (buf->len + len > buf->capacity) {
        return NULL;  /* Not enough space */
    }

    uint8_t *result = buf->data + buf->len;
    buf->len += len;

    return result;
}

int nert_buffer_trim(struct nert_buffer *buf, uint16_t len) {
    if (!buf || !(buf->flags & NERT_BUF_FLAG_INUSE)) {
        return NERT_BUF_ERR_INVALID;
    }

    if (len > buf->len) {
        return NERT_BUF_ERR_INVALID;
    }

    buf->len -= len;
    return NERT_BUF_OK;
}

/* ============================================================================
 * Scatter-Gather Implementation
 * ============================================================================ */

void nert_sg_init(struct nert_sg_tx *sg) {
    if (!sg) return;
    memset(sg, 0, sizeof(struct nert_sg_tx));
}

int nert_sg_add(struct nert_sg_tx *sg, const uint8_t *data, uint16_t len) {
    if (!sg || !data || len == 0) {
        return NERT_BUF_ERR_INVALID;
    }

    if (sg->iov_count >= NERT_IOVEC_MAX) {
        return NERT_BUF_ERR_NO_MEMORY;
    }

    sg->iov[sg->iov_count].base = data;
    sg->iov[sg->iov_count].len = len;
    sg->iov_count++;
    sg->total_len += len;

    stats.memcpy_avoided++;
    stats.bytes_saved += len;

    return NERT_BUF_OK;
}

int nert_sg_add_buffer(struct nert_sg_tx *sg, const struct nert_buffer *buf) {
    if (!sg || !buf) {
        return NERT_BUF_ERR_INVALID;
    }

    return nert_sg_add(sg, buf->data, buf->len);
}

int nert_sg_flatten(const struct nert_sg_tx *sg, uint8_t *out, uint16_t max_len) {
    if (!sg || !out) {
        return NERT_BUF_ERR_INVALID;
    }

    if (sg->total_len > max_len) {
        return NERT_BUF_ERR_TOO_LARGE;
    }

    uint16_t offset = 0;
    for (int i = 0; i < sg->iov_count; i++) {
        memcpy(out + offset, sg->iov[i].base, sg->iov[i].len);
        offset += sg->iov[i].len;
    }

    return offset;
}

/* ============================================================================
 * Zero-Copy Encryption
 * ============================================================================ */

int nert_buffer_encrypt_inplace(struct nert_buffer *buf,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]) {
    if (!buf || !key || !nonce) {
        return NERT_BUF_ERR_INVALID;
    }

    if (!(buf->flags & NERT_BUF_FLAG_INUSE) || buf->len == 0) {
        return NERT_BUF_ERR_INVALID;
    }

    /* ChaCha8 XORs keystream with data - can encrypt in-place
     * by using same buffer for input and output */
    chacha8_encrypt(key, nonce, buf->data, (uint8_t)buf->len, buf->data);

    buf->flags |= NERT_BUF_FLAG_ENCRYPTED;
    stats.memcpy_avoided++;
    stats.bytes_saved += buf->len;

    return NERT_BUF_OK;
}

int nert_buffer_decrypt_inplace(struct nert_buffer *buf,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]) {
    if (!buf || !key || !nonce) {
        return NERT_BUF_ERR_INVALID;
    }

    if (!(buf->flags & NERT_BUF_FLAG_INUSE) || buf->len == 0) {
        return NERT_BUF_ERR_INVALID;
    }

    /* ChaCha8 is symmetric - decrypt is same as encrypt */
    chacha8_encrypt(key, nonce, buf->data, (uint8_t)buf->len, buf->data);

    buf->flags &= ~NERT_BUF_FLAG_ENCRYPTED;
    stats.memcpy_avoided++;
    stats.bytes_saved += buf->len;

    return NERT_BUF_OK;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

const struct nert_buffer_stats* nert_buffer_get_stats(void) {
    return &stats;
}

void nert_buffer_reset_stats(void) {
    uint16_t in_use = stats.buffers_in_use;
    uint16_t watermark = stats.high_watermark;

    memset(&stats, 0, sizeof(stats));

    stats.buffers_in_use = in_use;
    stats.high_watermark = watermark;
}

uint16_t nert_buffer_free_count(void) {
    if (!initialized) return NERT_BUFFER_POOL_SIZE;

    uint16_t free = 0;
    for (int i = 0; i < NERT_BUFFER_POOL_SIZE; i++) {
        if (!(buffer_pool[i].flags & NERT_BUF_FLAG_INUSE)) {
            free++;
        }
    }
    return free;
}
