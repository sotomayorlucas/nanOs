/*
 * NanOS Gossip Protocol - Prevent Broadcast Storms
 * Probabilistic relay with exponential decay to prevent network flooding
 *
 * v0.5: Added Hebbian Routing ("Neurons that fire together, wire together")
 */
#ifndef NANOS_GOSSIP_H
#define NANOS_GOSSIP_H

#include <nanos.h>
#include <stdbool.h>

/* ==========================================================================
 * Hebbian Routing Constants (v0.5)
 * "Neurons that fire together, wire together"
 * ========================================================================== */

/* Synaptic weight range */
#define SYNAPSE_WEIGHT_MIN          1       /* Dead connection (but not zero) */
#define SYNAPSE_WEIGHT_MAX          255     /* Perfect connection */
#define SYNAPSE_WEIGHT_INITIAL      128     /* Neutral starting point */
#define SYNAPSE_WEIGHT_THRESHOLD    32      /* Below this = avoid route */

/* Long-Term Potentiation (LTP) - Reward for success */
#define SYNAPSE_LTP_INCREMENT       15      /* Weight gain on success */

/* Long-Term Depression (LTD) - Punishment for failure */
#define SYNAPSE_LTD_DECREMENT       40      /* Weight loss on failure (severe) */

/* Decay over time (prevents permanent high weights) */
#define SYNAPSE_DECAY_INTERVAL_MS   60000   /* Check decay every 60s */
#define SYNAPSE_DECAY_AMOUNT        2       /* Natural decay per interval */

/* Spike-Timing Dependent Plasticity (STDP) bonus */
#define SYNAPSE_STDP_WINDOW_MS      100     /* Bonus if ACK within this window */
#define SYNAPSE_STDP_BONUS          5       /* Extra weight for fast response */

/* ==========================================================================
 * Gossip Protocol API
 * ========================================================================== */

/* Hash a pheromone packet for cache lookup */
uint32_t gossip_hash(struct nanos_pheromone* pkt);

/* Record a pheromone in the gossip cache */
void gossip_record(struct nanos_pheromone* pkt);

/* Determine if this pheromone should be relayed
 * Returns true if should relay, false if should suppress
 */
bool gossip_should_relay(struct nanos_pheromone* pkt);

/* ==========================================================================
 * Hebbian Synapse API (v0.5)
 * ========================================================================== */

/**
 * Update synaptic weight for a neighbor based on communication outcome
 * Implements Hebbian learning: "Neurons that fire together, wire together"
 *
 * @param node_id   Neighbor node ID
 * @param success   true = communication succeeded (LTP), false = failed (LTD)
 *
 * LTP (success): weight = min(255, weight + 15)  -- Fast reward
 * LTD (failure): weight = max(1, weight - 40)    -- Severe punishment
 */
void nert_synapse_update(uint16_t node_id, bool success);

/**
 * Update with STDP (Spike-Timing Dependent Plasticity)
 * Adds bonus if response was fast (within STDP window)
 *
 * @param node_id       Neighbor node ID
 * @param success       true = succeeded, false = failed
 * @param response_ms   Response time in milliseconds
 */
void nert_synapse_update_stdp(uint16_t node_id, bool success, uint32_t response_ms);

/**
 * Get current synaptic weight for a neighbor
 *
 * @param node_id   Neighbor node ID
 * @return Weight (0-255), or 0 if neighbor not found
 */
uint8_t nert_synapse_get_weight(uint16_t node_id);

/**
 * Check if a neighbor connection is "healthy" (above threshold)
 *
 * @param node_id   Neighbor node ID
 * @return true if weight >= SYNAPSE_WEIGHT_THRESHOLD
 */
bool nert_synapse_is_healthy(uint16_t node_id);

/**
 * Apply natural decay to all synaptic weights
 * Called periodically to prevent permanent high weights
 */
void nert_synapse_decay(void);

/**
 * Select best neighbor based on synaptic weights (for routing)
 * Prefers neighbors with higher weights (more reliable)
 *
 * @param exclude_id    Node ID to exclude (0 = none)
 * @return Best neighbor's node_id, or 0 if none available
 */
uint32_t nert_synapse_select_best(uint32_t exclude_id);

/**
 * Get routing score combining distance and synaptic weight
 * Lower score = better route
 *
 * @param node_id   Neighbor node ID
 * @return Score (0-510), or 0xFFFF if neighbor not found
 */
uint16_t nert_synapse_route_score(uint16_t node_id);

#endif /* NANOS_GOSSIP_H */
