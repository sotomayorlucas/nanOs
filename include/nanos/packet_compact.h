/*
 * NanOS Compact Packet Format
 * Optimized for low-bandwidth radios (LoRa, 802.15.4, BLE)
 *
 * Standard packet: 64 bytes
 * Compact packet:  24 bytes (62% reduction)
 */
#ifndef NANOS_PACKET_COMPACT_H
#define NANOS_PACKET_COMPACT_H

#include "../nanos_config.h"
#include <stdint.h>

#ifdef NANOS_COMPACT_PACKETS

/* ==========================================================================
 * Compact Packet Format (24 bytes total)
 * ==========================================================================
 *
 * Byte  Field        Size  Description
 * ----  -----        ----  -----------
 * 0     magic        1     0xAA (reduced from 0xDEAD)
 * 1-2   node_id      2     Node ID (truncated to 16-bit)
 * 3     type         1     Pheromone type
 * 4     ttl_flags    1     TTL(4bit) + flags(4bit)
 * 5     seq          1     Sequence number (8-bit wrapping)
 * 6-7   dest_id      2     Destination (0 = broadcast)
 * 8     dist_hop     1     Distance(4bit) + hop_count(4bit)
 * 9-16  payload      8     Compact payload
 * 17-20 hmac         4     Truncated HMAC
 * 21-23 reserved     3     Future use / alignment
 *
 * Total: 24 bytes
 */

#define COMPACT_MAGIC       0xAA
#define COMPACT_PAYLOAD_SIZE    8
#define COMPACT_HMAC_SIZE       4
#define COMPACT_PKT_SIZE        24

/* Compact pheromone packet structure */
struct nanos_pheromone_compact {
    uint8_t  magic;                     /* 0xAA */
    uint16_t node_id;                   /* Truncated node ID */
    uint8_t  type;                      /* Pheromone type */
    uint8_t  ttl_flags;                 /* TTL(4) + flags(4) */
    uint8_t  seq;                       /* Sequence (8-bit) */
    uint16_t dest_id;                   /* Destination */
    uint8_t  dist_hop;                  /* distance(4) + hop(4) */
    uint8_t  payload[COMPACT_PAYLOAD_SIZE];
    uint8_t  hmac[COMPACT_HMAC_SIZE];
    uint8_t  reserved[3];
} __attribute__((packed));

/* ==========================================================================
 * Compact Payload Formats
 * ========================================================================== */

/*
 * HEARTBEAT payload (8 bytes)
 * - role:      1 byte
 * - neighbors: 1 byte
 * - battery:   1 byte (percentage)
 * - uptime:    2 bytes (minutes, max ~45 days)
 * - reserved:  3 bytes
 */
struct compact_heartbeat {
    uint8_t  role;
    uint8_t  neighbors;
    uint8_t  battery;
    uint16_t uptime_min;
    uint8_t  reserved[3];
} __attribute__((packed));

/*
 * DETECT payload (8 bytes)
 * - detect_type: 1 byte
 * - confidence:  1 byte
 * - sector:      1 byte
 * - intensity:   1 byte
 * - pos_x:       2 bytes (signed, decimeters)
 * - pos_y:       2 bytes (signed, decimeters)
 */
struct compact_detect {
    uint8_t  detect_type;
    uint8_t  confidence;
    uint8_t  sector;
    uint8_t  intensity;
    int16_t  pos_x;
    int16_t  pos_y;
} __attribute__((packed));

/*
 * SENSOR payload (8 bytes)
 * - sensor_type: 1 byte
 * - sensor_id:   1 byte
 * - value:       4 bytes (int32 or float)
 * - timestamp:   2 bytes (seconds since last hour)
 */
struct compact_sensor {
    uint8_t  sensor_type;
    uint8_t  sensor_id;
    int32_t  value;
    uint16_t timestamp;
} __attribute__((packed));

/*
 * KV_SET payload (8 bytes)
 * - key_hash: 2 bytes (FNV-1a hash of key)
 * - value:    6 bytes (direct value or hash)
 */
struct compact_kv {
    uint16_t key_hash;
    uint8_t  value[6];
} __attribute__((packed));

/*
 * ROBOT position payload (8 bytes)
 * - pos_x:    2 bytes (cm)
 * - pos_y:    2 bytes (cm)
 * - heading:  1 byte (0-255 = 0-360 degrees)
 * - speed:    1 byte (cm/s)
 * - battery:  1 byte (percentage)
 * - status:   1 byte (flags)
 */
struct compact_robot_pos {
    int16_t  pos_x;
    int16_t  pos_y;
    uint8_t  heading;
    uint8_t  speed;
    uint8_t  battery;
    uint8_t  status;
} __attribute__((packed));

/* ==========================================================================
 * Helper Macros for Compact Packets
 * ========================================================================== */

/* TTL and flags encoding */
#define COMPACT_GET_TTL(pkt)        (((pkt)->ttl_flags >> 4) & 0x0F)
#define COMPACT_GET_FLAGS(pkt)      ((pkt)->ttl_flags & 0x0F)
#define COMPACT_SET_TTL_FLAGS(ttl, flags)  ((((ttl) & 0x0F) << 4) | ((flags) & 0x0F))

/* Distance and hop count encoding */
#define COMPACT_GET_DISTANCE(pkt)   (((pkt)->dist_hop >> 4) & 0x0F)
#define COMPACT_GET_HOP(pkt)        ((pkt)->dist_hop & 0x0F)
#define COMPACT_SET_DIST_HOP(d, h)  ((((d) & 0x0F) << 4) | ((h) & 0x0F))

/* Node ID truncation (keep lower 16 bits) */
#define COMPACT_NODE_ID(full_id)    ((uint16_t)((full_id) & 0xFFFF))

/* ==========================================================================
 * Conversion Functions
 * ========================================================================== */

/* Convert standard packet to compact */
static inline void pkt_to_compact(const struct nanos_pheromone* std,
                                   struct nanos_pheromone_compact* cmp) {
    cmp->magic = COMPACT_MAGIC;
    cmp->node_id = COMPACT_NODE_ID(std->node_id);
    cmp->type = std->type;
    cmp->ttl_flags = COMPACT_SET_TTL_FLAGS(std->ttl & 0x0F, std->flags & 0x0F);
    cmp->seq = (uint8_t)(std->seq & 0xFF);
    cmp->dest_id = COMPACT_NODE_ID(std->dest_id);
    cmp->dist_hop = COMPACT_SET_DIST_HOP(std->distance & 0x0F, std->hop_count & 0x0F);

    /* Copy truncated payload */
    for (int i = 0; i < COMPACT_PAYLOAD_SIZE && i < sizeof(std->payload); i++) {
        cmp->payload[i] = std->payload[i];
    }

    /* Truncated HMAC */
    for (int i = 0; i < COMPACT_HMAC_SIZE && i < sizeof(std->hmac); i++) {
        cmp->hmac[i] = std->hmac[i];
    }

    cmp->reserved[0] = 0;
    cmp->reserved[1] = 0;
    cmp->reserved[2] = 0;
}

/* Convert compact packet to standard (for processing) */
static inline void pkt_from_compact(const struct nanos_pheromone_compact* cmp,
                                     struct nanos_pheromone* std) {
    std->magic = NANOS_MAGIC;
    std->node_id = (uint32_t)cmp->node_id;  /* Zero-extend */
    std->type = cmp->type;
    std->ttl = COMPACT_GET_TTL(cmp);
    std->flags = COMPACT_GET_FLAGS(cmp);
    std->version = NANOS_VERSION;
    std->seq = (uint32_t)cmp->seq;
    std->dest_id = (uint32_t)cmp->dest_id;
    std->distance = COMPACT_GET_DISTANCE(cmp);
    std->hop_count = COMPACT_GET_HOP(cmp);

    /* Clear and copy payload */
    for (int i = 0; i < sizeof(std->payload); i++) {
        std->payload[i] = (i < COMPACT_PAYLOAD_SIZE) ? cmp->payload[i] : 0;
    }

    /* Expand HMAC */
    for (int i = 0; i < sizeof(std->hmac); i++) {
        std->hmac[i] = (i < COMPACT_HMAC_SIZE) ? cmp->hmac[i] : 0;
    }
}

/* ==========================================================================
 * Compact HMAC (4-byte truncated)
 * ========================================================================== */

/* FNV-1a hash for quick 32-bit hash */
static inline uint32_t fnv1a_32(const uint8_t* data, uint16_t len) {
    uint32_t hash = 0x811c9dc5;  /* FNV offset basis */
    for (uint16_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;      /* FNV prime */
    }
    return hash;
}

/* Compute 4-byte HMAC for compact packet */
static inline void compact_compute_hmac(struct nanos_pheromone_compact* pkt,
                                         const uint8_t* key, uint8_t key_len) {
    /* Simple HMAC: hash(key || packet_data) */
    uint8_t buf[32];
    uint8_t pos = 0;

    /* Copy key */
    for (uint8_t i = 0; i < key_len && pos < 16; i++) {
        buf[pos++] = key[i];
    }

    /* Copy packet (excluding HMAC field) */
    buf[pos++] = pkt->magic;
    buf[pos++] = pkt->node_id & 0xFF;
    buf[pos++] = pkt->node_id >> 8;
    buf[pos++] = pkt->type;
    buf[pos++] = pkt->ttl_flags;
    buf[pos++] = pkt->seq;
    buf[pos++] = pkt->dest_id & 0xFF;
    buf[pos++] = pkt->dest_id >> 8;
    buf[pos++] = pkt->dist_hop;

    for (uint8_t i = 0; i < COMPACT_PAYLOAD_SIZE && pos < 32; i++) {
        buf[pos++] = pkt->payload[i];
    }

    uint32_t hash = fnv1a_32(buf, pos);

    /* Store as 4 bytes */
    pkt->hmac[0] = (hash >> 0) & 0xFF;
    pkt->hmac[1] = (hash >> 8) & 0xFF;
    pkt->hmac[2] = (hash >> 16) & 0xFF;
    pkt->hmac[3] = (hash >> 24) & 0xFF;
}

/* Verify compact HMAC */
static inline int compact_verify_hmac(struct nanos_pheromone_compact* pkt,
                                       const uint8_t* key, uint8_t key_len) {
    uint8_t saved[COMPACT_HMAC_SIZE];
    for (int i = 0; i < COMPACT_HMAC_SIZE; i++) {
        saved[i] = pkt->hmac[i];
    }

    compact_compute_hmac(pkt, key, key_len);

    int valid = 1;
    for (int i = 0; i < COMPACT_HMAC_SIZE; i++) {
        if (pkt->hmac[i] != saved[i]) valid = 0;
        pkt->hmac[i] = saved[i];  /* Restore */
    }

    return valid;
}

#endif /* NANOS_COMPACT_PACKETS */

/* ==========================================================================
 * LoRa-Specific Optimizations
 * ========================================================================== */

#ifdef NANOS_HAS_LORA

/*
 * LoRa timing parameters
 * SF7-SF12: Higher SF = longer range, lower bandwidth
 */
#define LORA_SF_SHORT_RANGE     7       /* ~2km, fast */
#define LORA_SF_MEDIUM_RANGE    9       /* ~5km, medium */
#define LORA_SF_LONG_RANGE      12      /* ~15km, slow */

/* Duty cycle limits (regulatory) */
#define LORA_DUTY_CYCLE_1PCT    100     /* 1% = 36s/hour max TX */
#define LORA_TX_INTERVAL_MIN_MS 1000    /* Minimum between TX */

/* Adaptive spreading factor based on RSSI */
static inline uint8_t lora_adaptive_sf(int16_t rssi) {
    if (rssi > -90) return LORA_SF_SHORT_RANGE;     /* Strong signal */
    if (rssi > -110) return LORA_SF_MEDIUM_RANGE;   /* Medium signal */
    return LORA_SF_LONG_RANGE;                       /* Weak signal */
}

#endif /* NANOS_HAS_LORA */

#endif /* NANOS_PACKET_COMPACT_H */
