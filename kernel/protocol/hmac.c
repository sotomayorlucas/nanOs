/*
 * NanOS HMAC Authentication - SipHash-inspired simplified HMAC
 *
 * Provides message authentication for critical pheromone types
 * (DIE, QUEEN_CMD, REBIRTH) using a shared swarm secret.
 */
#include <nanos.h>

/* ==========================================================================
 * Swarm Secret Key
 * ========================================================================== */
static uint32_t swarm_secret[4] = {
    SWARM_SECRET_0, SWARM_SECRET_1, SWARM_SECRET_2, SWARM_SECRET_3
};

/* ==========================================================================
 * SipHash Round Function
 * ========================================================================== */
static uint32_t siphash_round(uint32_t v0, uint32_t v1, uint32_t v2, uint32_t v3) {
    v0 += v1; v1 = (v1 << 5) | (v1 >> 27); v1 ^= v0;
    v2 += v3; v3 = (v3 << 8) | (v3 >> 24); v3 ^= v2;
    v0 += v3; v3 = (v3 << 7) | (v3 >> 25); v3 ^= v0;
    v2 += v1; v1 = (v1 << 13) | (v1 >> 19); v1 ^= v2;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

void compute_hmac(struct nanos_pheromone* pkt) {
    uint32_t v0 = swarm_secret[0] ^ pkt->magic;
    uint32_t v1 = swarm_secret[1] ^ pkt->node_id;
    uint32_t v2 = swarm_secret[2] ^ (pkt->type | (pkt->ttl << 8));
    uint32_t v3 = swarm_secret[3] ^ pkt->seq;

    uint32_t hash = siphash_round(v0, v1, v2, v3);
    hash = siphash_round(hash, v1, v2, v3);  /* Second round */

    /* Store truncated HMAC */
    pkt->hmac[0] = (hash >> 0) & 0xFF;
    pkt->hmac[1] = (hash >> 8) & 0xFF;
    pkt->hmac[2] = (hash >> 16) & 0xFF;
    pkt->hmac[3] = (hash >> 24) & 0xFF;
    hash = siphash_round(hash, v0, v2, v1);
    pkt->hmac[4] = (hash >> 0) & 0xFF;
    pkt->hmac[5] = (hash >> 8) & 0xFF;
    pkt->hmac[6] = (hash >> 16) & 0xFF;
    pkt->hmac[7] = (hash >> 24) & 0xFF;

    pkt->flags |= FLAG_AUTHENTICATED;
}

bool verify_hmac(struct nanos_pheromone* pkt) {
    uint8_t saved_hmac[HMAC_TAG_SIZE];
    for (int i = 0; i < HMAC_TAG_SIZE; i++) {
        saved_hmac[i] = pkt->hmac[i];
    }

    compute_hmac(pkt);

    for (int i = 0; i < HMAC_TAG_SIZE; i++) {
        if (pkt->hmac[i] != saved_hmac[i]) {
            return false;
        }
    }
    return true;
}

bool is_authenticated_type(uint8_t type) {
    return type == PHEROMONE_DIE ||
           type == PHEROMONE_QUEEN_CMD ||
           type == PHEROMONE_REBIRTH;
}
