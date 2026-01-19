/*
 * NanOS Gossip Protocol - Prevent Broadcast Storms
 *
 * Uses probabilistic relay with exponential decay to prevent
 * pheromone flooding in dense swarm networks.
 *
 * v0.5: Added Hebbian Routing ("Neurons that fire together, wire together")
 */
#include <nanos.h>
#include <nanos/gossip.h>

/* External dependencies */
extern volatile uint32_t ticks;
extern uint32_t random(void);

/* Last decay tick for Hebbian weights */
static uint32_t synapse_last_decay_tick = 0;

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

/* ==========================================================================
 * Hebbian Synapse Implementation (v0.5)
 * "Neurons that fire together, wire together"
 * ========================================================================== */

/**
 * Find neighbor entry by node ID
 * Returns NULL if not found
 */
static struct neighbor_entry* synapse_find_neighbor(uint16_t node_id) {
    if (node_id == 0) return (struct neighbor_entry*)0;

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id == (uint32_t)node_id) {
            return &g_state.neighbors[i];
        }
    }
    return (struct neighbor_entry*)0;
}

void nert_synapse_update(uint16_t node_id, bool success) {
    struct neighbor_entry* neighbor = synapse_find_neighbor(node_id);
    if (!neighbor) return;

    /*
     * Hebbian Learning Rule:
     * - Success (LTP): Strengthen connection quickly
     * - Failure (LTD): Weaken connection severely
     *
     * The asymmetry (fast reward, severe punishment) ensures the network
     * quickly learns to avoid unreliable paths.
     */

    if (success) {
        /* Long-Term Potentiation (LTP) - Reward */
        uint16_t new_weight = neighbor->synaptic_weight + SYNAPSE_LTP_INCREMENT;
        if (new_weight > SYNAPSE_WEIGHT_MAX) {
            new_weight = SYNAPSE_WEIGHT_MAX;
        }
        neighbor->synaptic_weight = (uint8_t)new_weight;
    } else {
        /* Long-Term Depression (LTD) - Punishment */
        if (neighbor->synaptic_weight > SYNAPSE_LTD_DECREMENT) {
            neighbor->synaptic_weight -= SYNAPSE_LTD_DECREMENT;
        } else {
            neighbor->synaptic_weight = SYNAPSE_WEIGHT_MIN;
        }
    }
}

void nert_synapse_update_stdp(uint16_t node_id, bool success, uint32_t response_ms) {
    struct neighbor_entry* neighbor = synapse_find_neighbor(node_id);
    if (!neighbor) return;

    /* Apply base update first */
    nert_synapse_update(node_id, success);

    /*
     * Spike-Timing Dependent Plasticity (STDP):
     * Fast responses get a bonus - this encourages using low-latency paths.
     * Only applies to successful communications.
     */
    if (success && response_ms < SYNAPSE_STDP_WINDOW_MS) {
        uint16_t new_weight = neighbor->synaptic_weight + SYNAPSE_STDP_BONUS;
        if (new_weight > SYNAPSE_WEIGHT_MAX) {
            new_weight = SYNAPSE_WEIGHT_MAX;
        }
        neighbor->synaptic_weight = (uint8_t)new_weight;
    }
}

uint8_t nert_synapse_get_weight(uint16_t node_id) {
    struct neighbor_entry* neighbor = synapse_find_neighbor(node_id);
    if (!neighbor) return 0;
    return neighbor->synaptic_weight;
}

bool nert_synapse_is_healthy(uint16_t node_id) {
    struct neighbor_entry* neighbor = synapse_find_neighbor(node_id);
    if (!neighbor) return false;
    return neighbor->synaptic_weight >= SYNAPSE_WEIGHT_THRESHOLD;
}

void nert_synapse_decay(void) {
    uint32_t now = ticks;

    /* Check if decay interval has elapsed */
    if (now - synapse_last_decay_tick < (SYNAPSE_DECAY_INTERVAL_MS / 10)) {
        return;
    }
    synapse_last_decay_tick = now;

    /*
     * Apply natural decay to all connections.
     * This prevents permanent high weights and allows the network
     * to adapt to changing conditions over time.
     */
    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id == 0) continue;

        /* Only decay weights above the neutral point */
        if (g_state.neighbors[i].synaptic_weight > SYNAPSE_WEIGHT_INITIAL) {
            g_state.neighbors[i].synaptic_weight -= SYNAPSE_DECAY_AMOUNT;
            if (g_state.neighbors[i].synaptic_weight < SYNAPSE_WEIGHT_INITIAL) {
                g_state.neighbors[i].synaptic_weight = SYNAPSE_WEIGHT_INITIAL;
            }
        }
    }
}

uint32_t nert_synapse_select_best(uint32_t exclude_id) {
    uint32_t best_id = 0;
    uint8_t best_weight = 0;

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        struct neighbor_entry* n = &g_state.neighbors[i];

        if (n->node_id == 0) continue;
        if (n->node_id == exclude_id) continue;

        /* Must be above health threshold */
        if (n->synaptic_weight < SYNAPSE_WEIGHT_THRESHOLD) continue;

        /* Select highest weight */
        if (n->synaptic_weight > best_weight) {
            best_weight = n->synaptic_weight;
            best_id = n->node_id;
        }
    }

    return best_id;
}

uint16_t nert_synapse_route_score(uint16_t node_id) {
    struct neighbor_entry* neighbor = synapse_find_neighbor(node_id);
    if (!neighbor) return 0xFFFF;  /* Invalid */

    /*
     * Route score combines distance and synaptic weight.
     * Lower score = better route.
     *
     * Formula: score = distance + (255 - synaptic_weight)
     *
     * This means:
     * - Low distance is good
     * - High weight is good (so we subtract from 255)
     * - A nearby unreliable node may be worse than a farther reliable one
     */
    uint16_t score = neighbor->distance;
    score += (SYNAPSE_WEIGHT_MAX - neighbor->synaptic_weight);

    return score;
}
