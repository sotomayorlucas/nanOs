/*
 * NanOS Gossip Protocol - Prevent Broadcast Storms
 *
 * Uses probabilistic relay with exponential decay to prevent
 * pheromone flooding in dense swarm networks.
 */
#include <nanos.h>

/* External dependencies */
extern volatile uint32_t ticks;
extern uint32_t random(void);

/* ==========================================================================
 * Public API
 * ========================================================================== */

uint32_t gossip_hash(struct nanos_pheromone* pkt) {
    /* Simple hash of identifying fields */
    uint32_t h = pkt->node_id;
    h = h * 31 + pkt->seq;
    h = h * 31 + pkt->type;
    h = h * 31 + (pkt->payload[0] | (pkt->payload[1] << 8));
    return h;
}

void gossip_record(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);

    /* Check if already in cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        if (g_state.gossip_cache[i].hash == hash) {
            g_state.gossip_cache[i].count++;
            return;
        }
    }

    /* Add to cache (circular) */
    struct gossip_entry* entry = &g_state.gossip_cache[g_state.gossip_index];
    entry->hash = hash;
    entry->timestamp = ticks;
    entry->count = 1;
    entry->relayed = 0;

    g_state.gossip_index = (g_state.gossip_index + 1) % GOSSIP_CACHE_SIZE;
}

bool gossip_should_relay(struct nanos_pheromone* pkt) {
    uint32_t hash = gossip_hash(pkt);

    /* Look up in cache */
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        struct gossip_entry* entry = &g_state.gossip_cache[i];

        if (entry->hash == hash) {
            /* Message still fresh? */
            if (ticks - entry->timestamp > (GOSSIP_IMMUNITY_MS / 10)) {
                entry->count = 1;  /* Reset - old message */
                entry->timestamp = ticks;
            }

            /* Already relayed? */
            if (entry->relayed) {
                return false;
            }

            /* Too many copies seen? */
            if (entry->count >= ALARM_MAX_ECHOES) {
                g_state.packets_dropped++;
                return false;
            }

            /* Probabilistic relay - decay with each copy seen */
            uint32_t prob = GOSSIP_PROB_BASE;
            for (uint8_t j = 1; j < entry->count && prob > 0; j++) {
                prob = (prob * (100 - GOSSIP_PROB_DECAY)) / 100;
            }

            if ((random() % 100) < prob) {
                entry->relayed = 1;
                return true;
            }

            return false;
        }
    }

    /* Not in cache - first time seeing it, relay */
    return true;
}
