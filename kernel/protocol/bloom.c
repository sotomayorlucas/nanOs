/*
 * NanOS Bloom Filter - O(1) Deduplication
 *
 * Uses 3 hash functions across rotating time slots to detect
 * duplicate pheromone packets with minimal memory overhead.
 */
#include <nanos.h>

/* External tick counter from kernel */
extern volatile uint32_t ticks;

/* ==========================================================================
 * Hash Functions
 * ========================================================================== */

static uint32_t bloom_hash_0(uint32_t node_id, uint32_t seq, uint8_t type) {
    uint32_t h = node_id;
    h ^= seq * 0x85EBCA6B;
    h ^= type * 0xC2B2AE35;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    return h % BLOOM_BITS;
}

static uint32_t bloom_hash_1(uint32_t node_id, uint32_t seq, uint8_t type) {
    uint32_t h = seq;
    h ^= node_id * 0xCC9E2D51;
    h ^= type * 0x1B873593;
    h ^= h >> 15;
    h *= 0xCC9E2D51;
    return h % BLOOM_BITS;
}

static uint32_t bloom_hash_2(uint32_t node_id, uint32_t seq, uint8_t type) {
    uint32_t h = type | (seq << 8);
    h ^= node_id;
    h = (h ^ (h >> 16)) * 0x7FEB352D;
    h = (h ^ (h >> 15)) * 0x846CA68B;
    return (h ^ (h >> 16)) % BLOOM_BITS;
}

/* ==========================================================================
 * Bit Operations
 * ========================================================================== */

static int bloom_test_bit(uint8_t* bits, uint32_t bit_pos) {
    return (bits[bit_pos / 8] >> (bit_pos % 8)) & 1;
}

static void bloom_set_bit(uint8_t* bits, uint32_t bit_pos) {
    bits[bit_pos / 8] |= (1 << (bit_pos % 8));
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

void bloom_init(void) {
    for (int slot = 0; slot < BLOOM_SLOTS; slot++) {
        for (int i = 0; i < BLOOM_BYTES; i++) {
            g_state.bloom.bits[slot][i] = 0;
        }
    }
    g_state.bloom.current_slot = 0;
    g_state.bloom.slot_start_tick = 0;
    g_state.bloom.insertions = 0;
    g_state.bloom.duplicates_blocked = 0;
}

bool bloom_check_and_add(struct nanos_pheromone* pkt) {
    uint32_t now = ticks;

    /* Rotate slot if window expired */
    if (now - g_state.bloom.slot_start_tick > (BLOOM_WINDOW_MS / 10)) {
        g_state.bloom.current_slot = (g_state.bloom.current_slot + 1) % BLOOM_SLOTS;
        /* Clear new slot */
        for (int i = 0; i < BLOOM_BYTES; i++) {
            g_state.bloom.bits[g_state.bloom.current_slot][i] = 0;
        }
        g_state.bloom.slot_start_tick = now;
    }

    /* Calculate hashes */
    uint32_t h0 = bloom_hash_0(pkt->node_id, pkt->seq, pkt->type);
    uint32_t h1 = bloom_hash_1(pkt->node_id, pkt->seq, pkt->type);
    uint32_t h2 = bloom_hash_2(pkt->node_id, pkt->seq, pkt->type);

    /* Check ALL slots (full time window) */
    for (int slot = 0; slot < BLOOM_SLOTS; slot++) {
        uint8_t* bits = g_state.bloom.bits[slot];
        if (bloom_test_bit(bits, h0) &&
            bloom_test_bit(bits, h1) &&
            bloom_test_bit(bits, h2)) {
            /* Probably seen before */
            g_state.bloom.duplicates_blocked++;
            return false;
        }
    }

    /* Not seen - add to current slot */
    uint8_t* current = g_state.bloom.bits[g_state.bloom.current_slot];
    bloom_set_bit(current, h0);
    bloom_set_bit(current, h1);
    bloom_set_bit(current, h2);
    g_state.bloom.insertions++;

    return true;  /* New packet */
}
