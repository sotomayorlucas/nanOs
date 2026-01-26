/*
 * NERT Buffer Pool and Zero-Copy Support
 *
 * Provides efficient memory management for packet processing:
 * - Pre-allocated buffer pool to avoid malloc/free
 * - Scatter-gather I/O support for zero-copy TX
 * - In-place encryption/decryption
 * - Reference counting for shared buffers
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#ifndef NERT_BUFFER_H
#define NERT_BUFFER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Buffer pool sizes */
#if defined(__arm__) || defined(ESP_PLATFORM)
    #define NERT_BUFFER_POOL_SIZE       8       /* Number of buffers in pool */
    #define NERT_BUFFER_SIZE            128     /* Size of each buffer */
    #define NERT_IOVEC_MAX              4       /* Max scatter-gather entries */
#else
    #define NERT_BUFFER_POOL_SIZE       16
    #define NERT_BUFFER_SIZE            256
    #define NERT_IOVEC_MAX              8
#endif

/* Buffer flags */
#define NERT_BUF_FLAG_INUSE         0x01    /* Buffer is allocated */
#define NERT_BUF_FLAG_ENCRYPTED     0x02    /* Content is encrypted */
#define NERT_BUF_FLAG_ZEROCOPY      0x04    /* Don't copy on send */
#define NERT_BUF_FLAG_HEADROOM      0x08    /* Has header space reserved */
#define NERT_BUF_FLAG_TAILROOM      0x10    /* Has trailer space reserved */

/* Error codes */
#define NERT_BUF_OK                 0
#define NERT_BUF_ERR_NO_MEMORY      -1
#define NERT_BUF_ERR_INVALID        -2
#define NERT_BUF_ERR_TOO_LARGE      -3

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Buffer descriptor
 * Manages a single buffer from the pool
 */
struct nert_buffer {
    uint8_t *data;                  /* Pointer to actual data start */
    uint16_t len;                   /* Current data length */
    uint16_t capacity;              /* Total buffer capacity */
    uint16_t head_offset;           /* Offset from buffer start (for headroom) */
    uint8_t  flags;                 /* NERT_BUF_FLAG_* */
    uint8_t  refcount;              /* Reference count */
    uint8_t  pool_index;            /* Index in buffer pool */
    uint8_t  _reserved;
};

/**
 * Scatter-gather entry for zero-copy TX
 * Similar to POSIX iovec
 */
struct nert_iovec {
    const uint8_t *base;            /* Pointer to data */
    uint16_t len;                   /* Length of this segment */
};

/**
 * Scatter-gather TX descriptor
 */
struct nert_sg_tx {
    struct nert_iovec iov[NERT_IOVEC_MAX];  /* Scatter-gather entries */
    uint8_t  iov_count;                      /* Number of valid entries */
    uint16_t total_len;                      /* Total length across all entries */
};

/**
 * Buffer pool statistics
 */
struct nert_buffer_stats {
    uint32_t alloc_count;           /* Total allocations */
    uint32_t free_count;            /* Total frees */
    uint32_t alloc_failures;        /* Failed allocations */
    uint32_t bytes_saved;           /* Bytes saved by zero-copy */
    uint16_t buffers_in_use;        /* Currently allocated buffers */
    uint16_t high_watermark;        /* Max buffers ever in use */
    uint32_t memcpy_avoided;        /* Number of memcpy operations avoided */
};

/* ============================================================================
 * Buffer Pool API
 * ============================================================================ */

/**
 * Initialize the buffer pool
 * Must be called before any other buffer functions.
 */
void nert_buffer_pool_init(void);

/**
 * Allocate a buffer from the pool
 *
 * @param size      Minimum size needed (actual may be larger)
 * @return          Buffer pointer or NULL if pool exhausted
 */
struct nert_buffer* nert_buffer_alloc(uint16_t size);

/**
 * Allocate a buffer with headroom reserved
 * Useful for prepending headers without copying.
 *
 * @param size      Data size needed
 * @param headroom  Header space to reserve at front
 * @return          Buffer pointer or NULL if pool exhausted
 */
struct nert_buffer* nert_buffer_alloc_headroom(uint16_t size, uint16_t headroom);

/**
 * Free a buffer back to the pool
 * Decrements refcount; actually frees when refcount reaches 0.
 *
 * @param buf       Buffer to free
 */
void nert_buffer_free(struct nert_buffer *buf);

/**
 * Increment buffer reference count
 * Use when sharing a buffer between multiple users.
 *
 * @param buf       Buffer to reference
 * @return          New reference count
 */
uint8_t nert_buffer_ref(struct nert_buffer *buf);

/**
 * Get pointer to buffer data
 *
 * @param buf       Buffer
 * @return          Pointer to data area
 */
static inline uint8_t* nert_buffer_data(struct nert_buffer *buf) {
    return buf ? buf->data : NULL;
}

/**
 * Get buffer data length
 *
 * @param buf       Buffer
 * @return          Data length
 */
static inline uint16_t nert_buffer_len(const struct nert_buffer *buf) {
    return buf ? buf->len : 0;
}

/**
 * Reserve headroom in buffer
 * Moves data pointer forward, reserving space at front.
 *
 * @param buf       Buffer
 * @param headroom  Bytes to reserve
 * @return          NERT_BUF_OK or error
 */
int nert_buffer_reserve_head(struct nert_buffer *buf, uint16_t headroom);

/**
 * Push data at front of buffer (use headroom)
 *
 * @param buf       Buffer
 * @param len       Bytes to push
 * @return          Pointer to new data area or NULL
 */
uint8_t* nert_buffer_push(struct nert_buffer *buf, uint16_t len);

/**
 * Pull data from front of buffer
 *
 * @param buf       Buffer
 * @param len       Bytes to pull
 * @return          Pointer to pulled data or NULL
 */
uint8_t* nert_buffer_pull(struct nert_buffer *buf, uint16_t len);

/**
 * Append data at end of buffer
 *
 * @param buf       Buffer
 * @param len       Bytes to append
 * @return          Pointer to new data area or NULL
 */
uint8_t* nert_buffer_put(struct nert_buffer *buf, uint16_t len);

/**
 * Trim data from end of buffer
 *
 * @param buf       Buffer
 * @param len       Bytes to trim
 * @return          NERT_BUF_OK or error
 */
int nert_buffer_trim(struct nert_buffer *buf, uint16_t len);

/* ============================================================================
 * Scatter-Gather API
 * ============================================================================ */

/**
 * Initialize a scatter-gather TX descriptor
 *
 * @param sg        Descriptor to initialize
 */
void nert_sg_init(struct nert_sg_tx *sg);

/**
 * Add a segment to scatter-gather descriptor
 *
 * @param sg        Descriptor
 * @param data      Data pointer
 * @param len       Data length
 * @return          NERT_BUF_OK or error if full
 */
int nert_sg_add(struct nert_sg_tx *sg, const uint8_t *data, uint16_t len);

/**
 * Add a buffer to scatter-gather descriptor
 *
 * @param sg        Descriptor
 * @param buf       Buffer to add
 * @return          NERT_BUF_OK or error
 */
int nert_sg_add_buffer(struct nert_sg_tx *sg, const struct nert_buffer *buf);

/**
 * Flatten scatter-gather into contiguous buffer
 * Use when zero-copy is not possible.
 *
 * @param sg        Descriptor
 * @param out       Output buffer
 * @param max_len   Output buffer size
 * @return          Total bytes copied or error
 */
int nert_sg_flatten(const struct nert_sg_tx *sg, uint8_t *out, uint16_t max_len);

/**
 * Get total length of scatter-gather data
 *
 * @param sg        Descriptor
 * @return          Total length
 */
static inline uint16_t nert_sg_total_len(const struct nert_sg_tx *sg) {
    return sg ? sg->total_len : 0;
}

/* ============================================================================
 * Zero-Copy Encryption
 * ============================================================================ */

/**
 * Encrypt buffer in-place
 * Avoids copying by encrypting directly in the buffer.
 *
 * @param buf       Buffer containing plaintext
 * @param key       Encryption key (32 bytes)
 * @param nonce     Nonce (12 bytes)
 * @return          NERT_BUF_OK or error
 */
int nert_buffer_encrypt_inplace(struct nert_buffer *buf,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]);

/**
 * Decrypt buffer in-place
 *
 * @param buf       Buffer containing ciphertext
 * @param key       Decryption key (32 bytes)
 * @param nonce     Nonce (12 bytes)
 * @return          NERT_BUF_OK or error
 */
int nert_buffer_decrypt_inplace(struct nert_buffer *buf,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]);

/* ============================================================================
 * Statistics
 * ============================================================================ */

/**
 * Get buffer pool statistics
 *
 * @return          Pointer to stats (read-only)
 */
const struct nert_buffer_stats* nert_buffer_get_stats(void);

/**
 * Reset buffer pool statistics
 */
void nert_buffer_reset_stats(void);

/**
 * Get number of free buffers
 *
 * @return          Available buffers
 */
uint16_t nert_buffer_free_count(void);

#ifdef __cplusplus
}
#endif

#endif /* NERT_BUFFER_H */
