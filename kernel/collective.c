/*
 * NanOS - Collective Intelligence Module
 * Quorum Sensing, Queen Elections, and Gradient Routing
 *
 * This module gives the swarm emergent intelligence:
 * - Nodes adapt roles based on neighborhood composition
 * - Queens are elected democratically when absent
 * - Messages can be routed toward the queen efficiently
 */

#include "../include/nanos.h"
#include "../include/nanos/gossip.h"  /* Hebbian routing (v0.5) */

/* Use HAL for portable version, direct calls for x86 */
#ifdef ARCH_X86
    #define TICKS()         get_ticks()
    #define CONSOLE_PUTS(s) vga_puts(s)
    #define CONSOLE_HEX(v)  vga_put_hex(v)
    #define CONSOLE_DEC(v)  vga_put_dec(v)
    #define CONSOLE_COLOR(c) vga_set_color(c)
    #define NET_SEND(p,l)   e1000_send(p,l)
    #define RNG()           random()
    extern void vga_set_color(uint8_t color);
    extern int e1000_send(void* data, uint16_t length);
#else
    #include "../include/hal.h"
    #define TICKS()         hal_timer_ticks()
    #define CONSOLE_PUTS(s) hal_console_puts(s)
    #define CONSOLE_HEX(v)  hal_console_put_hex(v)
    #define CONSOLE_DEC(v)  hal_console_put_dec(v)
    #define CONSOLE_COLOR(c) hal_console_set_color(c)
    #define NET_SEND(p,l)   hal_net_send(p,l)
    #define RNG()           hal_rng_get()
#endif

/* ==========================================================================
 * Neighbor Table Management (Quorum Sensing)
 * ========================================================================== */

/*
 * Find or create a slot for a neighbor
 */
static struct neighbor_entry* neighbor_find_or_create(uint32_t node_id) {
    struct neighbor_entry* empty_slot = (struct neighbor_entry*)0;

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (g_state.neighbors[i].node_id == node_id) {
            return &g_state.neighbors[i];
        }
        if (g_state.neighbors[i].node_id == 0 && !empty_slot) {
            empty_slot = &g_state.neighbors[i];
        }
    }

    return empty_slot;  /* May be NULL if table full */
}

/*
 * Update neighbor table from received pheromone
 */
void neighbor_update(struct nanos_pheromone* pkt) {
    if (pkt->node_id == g_state.node_id) return;

    struct neighbor_entry* entry = neighbor_find_or_create(pkt->node_id);
    if (!entry) return;  /* Table full */

    uint32_t now = TICKS();
    uint8_t role = PKT_GET_ROLE(pkt);

    /* Update role counts if this is a new neighbor or role changed */
    if (entry->node_id == 0) {
        /* New neighbor - initialize Hebbian synaptic weight to neutral */
        g_state.neighbor_count++;
        entry->synaptic_weight = 128;  /* SYNAPSE_WEIGHT_INITIAL */
    } else if (entry->role != role) {
        /* Role changed - decrement old, will increment new below */
        if (entry->role > 0 && entry->role < 8) {
            g_state.role_counts[entry->role]--;
        }
    }

    /* Update entry */
    entry->node_id = pkt->node_id;
    entry->last_seen = now;
    entry->role = role;
    entry->distance = pkt->distance;
    entry->packets++;

    /* Update role count */
    if (role > 0 && role < 8) {
        g_state.role_counts[role]++;
    }

    /* Track queen presence */
    if (role == ROLE_QUEEN) {
        g_state.last_queen_seen = now;
        g_state.known_queen_id = pkt->node_id;
    }
}

/*
 * Expire stale neighbors (called periodically)
 */
void neighbor_expire(void) {
    uint32_t now = TICKS();

    for (int i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        struct neighbor_entry* entry = &g_state.neighbors[i];

        if (entry->node_id == 0) continue;

        if (now - entry->last_seen > NEIGHBOR_TIMEOUT) {
            /* Neighbor expired */
            if (entry->role > 0 && entry->role < 8) {
                g_state.role_counts[entry->role]--;
            }
            entry->node_id = 0;
            g_state.neighbor_count--;
        }
    }
}

/* ==========================================================================
 * Role Transition Logic (Quorum Sensing)
 * ========================================================================== */

/*
 * Suggest a role based on neighborhood composition
 */
uint8_t quorum_suggest_role(void) {
    if (g_state.neighbor_count == 0) {
        return g_state.role;  /* No neighbors, keep current role */
    }

    uint8_t sentinels = g_state.role_counts[ROLE_SENTINEL];
    uint8_t explorers = g_state.role_counts[ROLE_EXPLORER];
    uint8_t total = g_state.neighbor_count;

    /* Calculate current ratios (scaled by 100) */
    uint32_t sentinel_ratio = (sentinels * 100) / total;
    uint32_t explorer_ratio = (explorers * 100) / total;

    /* Check if we need more sentinels */
    if (sentinel_ratio < MIN_SENTINEL_RATIO) {
        if (g_state.role == ROLE_WORKER) {
            return ROLE_SENTINEL;
        }
    }

    /* Check if we need more explorers */
    if (explorer_ratio < MIN_EXPLORER_RATIO) {
        if (g_state.role == ROLE_WORKER) {
            return ROLE_EXPLORER;
        }
    }

    /* Check for too many of current role - consider demoting */
    if (g_state.role == ROLE_SENTINEL && sentinel_ratio > 30) {
        return ROLE_WORKER;
    }
    if (g_state.role == ROLE_EXPLORER && explorer_ratio > 30) {
        return ROLE_WORKER;
    }

    return g_state.role;  /* Keep current */
}

/*
 * Transition to a new role
 */
void role_transition(uint8_t new_role) {
    if (new_role == g_state.role) return;
    if (new_role == ROLE_QUEEN) return;  /* Can't self-promote to queen */

    CONSOLE_COLOR(0x0E);  /* Yellow */
    CONSOLE_PUTS("~ ROLE TRANSITION: ");

    const char* role_names[] = {"?", "WORKER", "EXPLORER", "SENTINEL", "QUEEN", "CANDIDATE"};
    CONSOLE_PUTS(role_names[g_state.role]);
    CONSOLE_PUTS(" -> ");
    CONSOLE_PUTS(role_names[new_role]);
    CONSOLE_PUTS("\n");

    CONSOLE_COLOR(0x0A);  /* Green */

    g_state.previous_role = g_state.role;
    g_state.role = new_role;
}

/*
 * Evaluate quorum and potentially change role
 */
void quorum_evaluate(void) {
    uint32_t now = TICKS();

    /* Don't evaluate too frequently */
    if (now - g_state.last_role_check < QUORUM_WINDOW) {
        return;
    }
    g_state.last_role_check = now;

    /* Queens don't change role (unless deposed) */
    if (g_state.role == ROLE_QUEEN) {
        return;
    }

    /* Candidates are busy with election */
    if (g_state.role == ROLE_CANDIDATE) {
        return;
    }

    /* Get suggested role */
    uint8_t suggested = quorum_suggest_role();

    if (suggested != g_state.role) {
        /* Probabilistic transition to avoid oscillation */
        if ((RNG() % 100) < TRANSITION_PROB) {
            role_transition(suggested);
        }
    }

    /* Check for queen absence - might need election */
    if (g_state.known_queen_id != 0 &&
        now - g_state.last_queen_seen > QUEEN_ABSENCE_TIME) {
        /* Queen has been absent too long */
        CONSOLE_COLOR(0x0C);
        CONSOLE_PUTS("! Queen absent for ");
        CONSOLE_DEC((now - g_state.last_queen_seen) / 100);
        CONSOLE_PUTS("s - starting election\n");
        CONSOLE_COLOR(0x0A);

        election_start();
    }
}

/* ==========================================================================
 * Queen Election Protocol
 * ========================================================================== */

/*
 * Start a new election
 */
void election_start(void) {
    uint32_t now = TICKS();

    if (g_state.election.participating) {
        return;  /* Already in an election */
    }

    /* Cooldown: don't start new election too soon after previous one */
    if (g_state.election.last_ended > 0 &&
        now - g_state.election.last_ended < ELECTION_COOLDOWN) {
        return;  /* Still in cooldown period */
    }

    /* Use node_id as election_id for deterministic convergence:
     * All nodes will converge to the same election (lowest ID wins) */
    g_state.election.election_id = g_state.node_id;
    g_state.election.started_at = now;
    g_state.election.participating = 1;
    g_state.election.phase = ELECTION_PHASE_VOTING;
    g_state.election.votes_received = 1;  /* Vote for self */
    g_state.election.highest_vote_id = g_state.node_id;
    g_state.election.my_vote = g_state.node_id;

    /* Become a candidate */
    g_state.previous_role = g_state.role;
    g_state.role = ROLE_CANDIDATE;

    CONSOLE_COLOR(0x0D);  /* Magenta */
    CONSOLE_PUTS(">> ELECTION STARTED: ");
    CONSOLE_HEX(g_state.election.election_id);
    CONSOLE_PUTS("\n");
    CONSOLE_COLOR(0x0A);

    /* Broadcast election message */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_ELECTION;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    PKT_SET_ROLE(&pkt, ROLE_CANDIDATE);
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;

    /* Election payload: election_id, candidate_id, votes */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = g_state.election.election_id; p += 4;
    *(uint32_t*)p = g_state.node_id;              p += 4;  /* Candidate */
    *(uint32_t*)p = g_state.election.votes_received; p += 4;

    NET_SEND(&pkt, sizeof(pkt));
}

/*
 * Process an election pheromone
 */
void election_process(struct nanos_pheromone* pkt) {
    uint32_t now = TICKS();

    /* Parse payload */
    uint32_t election_id = *(uint32_t*)(pkt->payload);
    uint32_t candidate_id = *(uint32_t*)(pkt->payload + 4);
    uint32_t votes = *(uint32_t*)(pkt->payload + 8);
    (void)votes;  /* Not used in new algorithm */

    /* If not participating, check cooldown before joining */
    if (!g_state.election.participating) {
        /* Respect cooldown even when receiving election packets */
        if (g_state.election.last_ended > 0 &&
            now - g_state.election.last_ended < ELECTION_COOLDOWN) {
            return;  /* In cooldown, ignore election */
        }

        g_state.election.election_id = election_id;
        g_state.election.started_at = now;
        g_state.election.participating = 1;
        g_state.election.phase = ELECTION_PHASE_VOTING;
        g_state.election.votes_received = 1;  /* Vote for self */
        g_state.election.my_vote = g_state.node_id;

        /* Start with highest as the greater of candidate or self */
        if (candidate_id > g_state.node_id) {
            g_state.election.highest_vote_id = candidate_id;
        } else {
            g_state.election.highest_vote_id = g_state.node_id;
        }

        /* Become candidate */
        g_state.previous_role = g_state.role;
        g_state.role = ROLE_CANDIDATE;

        CONSOLE_PUTS(">> Joined election ");
        CONSOLE_HEX(election_id);
        CONSOLE_PUTS("\n");
    }

    /* Converge to lowest election_id (deterministic) */
    if (election_id < g_state.election.election_id) {
        g_state.election.election_id = election_id;
        /* Reset start time to sync with other nodes */
        g_state.election.started_at = now;
    }

    /* Track highest node ID - this becomes the winner */
    if (candidate_id > g_state.election.highest_vote_id) {
        g_state.election.highest_vote_id = candidate_id;
    }
}

/*
 * Check if election has timed out
 */
void election_check_timeout(void) {
    if (!g_state.election.participating) return;

    uint32_t now = TICKS();

    if (now - g_state.election.started_at > ELECTION_DURATION) {
        /* Election ended - count results */
        g_state.election.phase = ELECTION_PHASE_COUNTING;

        CONSOLE_PUTS(">> Election ended. Highest ID: ");
        CONSOLE_HEX(g_state.election.highest_vote_id);
        CONSOLE_PUTS("\n");

        /* Winner is deterministically the highest node ID */
        if (g_state.election.highest_vote_id == g_state.node_id) {
            /* We won! */
            coronation_announce();
        } else {
            /* Someone else won - revert to previous role */
            g_state.role = g_state.previous_role;
            g_state.known_queen_id = g_state.election.highest_vote_id;
            g_state.last_queen_seen = now;
            CONSOLE_PUTS(">> New queen: ");
            CONSOLE_HEX(g_state.known_queen_id);
            CONSOLE_PUTS("\n");
        }

        /* Reset election state with cooldown */
        g_state.election.participating = 0;
        g_state.election.phase = ELECTION_PHASE_NONE;
        g_state.election.last_ended = now;  /* Start cooldown period */
    }
}

/*
 * Announce coronation (we became queen)
 */
void coronation_announce(void) {
    CONSOLE_COLOR(0x0D);  /* Magenta */
    CONSOLE_PUTS("\n*** CORONATION ***\n");
    CONSOLE_PUTS("    This node is now QUEEN\n\n");
    CONSOLE_COLOR(0x0A);

    g_state.role = ROLE_QUEEN;
    g_state.known_queen_id = g_state.node_id;
    g_state.distance_to_queen = 0;

    /* Broadcast coronation */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_CORONATION;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    PKT_SET_ROLE(&pkt, ROLE_QUEEN);
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = 0;  /* Queen is distance 0 */
    pkt.hop_count = 0;

    compute_hmac(&pkt);  /* Coronation should be authenticated */

    NET_SEND(&pkt, sizeof(pkt));
}

/* ==========================================================================
 * Neural Routing Cost (v0.5 Hebbian)
 * "The brain chooses paths that WORK, not just paths that are short"
 * ========================================================================== */

/*
 * Compute neural routing cost combining distance and synaptic weight
 *
 * Formula: Cost = (Hops * 10) + ((255 - synaptic_weight) / 8)
 *
 * Interpretation:
 * - Lower cost = better route
 * - Distance (hops) is the primary factor (scaled by 10)
 * - Synaptic weight is secondary (0-31 penalty range)
 *
 * Examples:
 * - Distance 1, weight 255 (perfect):   cost = 10 + 0  = 10
 * - Distance 1, weight 128 (neutral):   cost = 10 + 15 = 25
 * - Distance 1, weight 1   (dead):      cost = 10 + 31 = 41
 * - Distance 2, weight 255 (perfect):   cost = 20 + 0  = 20
 *
 * Key insight: A reliable 2-hop path (cost 20) beats an unreliable
 * 1-hop path (cost 41). The network learns to route around bad nodes.
 */
static uint16_t compute_route_cost(uint8_t distance, uint16_t node_id) {
    uint8_t weight = nert_synapse_get_weight(node_id);

    /* If neighbor not found, use neutral weight */
    if (weight == 0) {
        weight = SYNAPSE_WEIGHT_INITIAL;  /* 128 = neutral */
    }

    /* Cost = (hops * 10) + reliability_penalty */
    uint16_t cost = (uint16_t)(distance * 10);
    cost += (255 - weight) / 8;

    return cost;
}

/* ==========================================================================
 * Gradient Routing
 * ========================================================================== */

/*
 * Update gradient information from received pheromone
 */
void gradient_update(struct nanos_pheromone* pkt) {
    uint8_t sender_role = PKT_GET_ROLE(pkt);

    /* If sender is queen, they are distance 0 */
    if (sender_role == ROLE_QUEEN) {
        g_state.known_queen_id = pkt->node_id;
        g_state.last_queen_seen = TICKS();

        /* We are 1 hop from queen */
        if (g_state.distance_to_queen > 1 || g_state.role != ROLE_QUEEN) {
            g_state.distance_to_queen = 1;
            g_state.gradient_via = pkt->node_id;
        }
        return;
    }

    /*
     * Neural Routing (v0.5): Use composite cost instead of just distance
     *
     * The brain doesn't just pick the shortest path - it picks the path
     * that has WORKED before. A slightly longer but reliable path is
     * better than a short but flaky one.
     */
    if (pkt->distance < GRADIENT_INFINITY) {
        uint8_t candidate_distance = pkt->distance + 1;

        /* Compute cost for this candidate gateway */
        uint16_t candidate_cost = compute_route_cost(candidate_distance,
                                                     (uint16_t)pkt->node_id);

        /* Compute cost for current best gateway */
        uint16_t current_cost;
        if (g_state.gradient_via == 0) {
            /* No current gateway - accept any valid candidate */
            current_cost = 0xFFFF;
        } else {
            current_cost = compute_route_cost(g_state.distance_to_queen,
                                              (uint16_t)g_state.gradient_via);
        }

        /* Switch to new gateway if it offers better (lower) cost */
        if (candidate_cost < current_cost) {
            g_state.distance_to_queen = candidate_distance;
            g_state.gradient_via = pkt->node_id;

            /* Also update queen tracking if we learned about one */
            if (g_state.last_queen_seen == 0) {
                g_state.last_queen_seen = TICKS();
            }
        }
    }

    /* Cache route to this sender */
    for (int i = 0; i < ROUTE_CACHE_SIZE; i++) {
        if (g_state.routes[i].dest_id == pkt->node_id ||
            g_state.routes[i].valid == 0) {

            g_state.routes[i].dest_id = pkt->node_id;
            g_state.routes[i].via_id = pkt->node_id;  /* Direct */
            g_state.routes[i].distance = 1;
            g_state.routes[i].updated = TICKS();
            g_state.routes[i].valid = 1;
            break;
        }
    }
}

/*
 * Propagate gradient in heartbeat
 */
void gradient_propagate(void) {
    /* Queen is always distance 0 */
    if (g_state.role == ROLE_QUEEN) {
        g_state.distance_to_queen = 0;
    }

    /* Decay gradient if we haven't heard from queen recently */
    uint32_t now = TICKS();
    if (g_state.last_queen_seen > 0 &&
        now - g_state.last_queen_seen > QUEEN_ABSENCE_TIME / 2) {
        /* Increase distance (gradient decay) */
        if (g_state.distance_to_queen < GRADIENT_INFINITY) {
            g_state.distance_to_queen++;
        }
    }
}

/*
 * Find next hop for routing to destination
 *
 * v0.5: Now considers synaptic health when selecting routes.
 * Unhealthy routes are skipped in favor of gradient routing.
 */
uint32_t route_next_hop(uint32_t dest_id) {
    /* Check route cache first */
    for (int i = 0; i < ROUTE_CACHE_SIZE; i++) {
        if (g_state.routes[i].dest_id == dest_id &&
            g_state.routes[i].valid) {

            /*
             * v0.5 Hebbian check: Only use cached route if the
             * via node has healthy synaptic weight. Otherwise,
             * skip to gradient routing which uses neural selection.
             */
            uint16_t via = (uint16_t)g_state.routes[i].via_id;
            if (nert_synapse_is_healthy(via)) {
                return g_state.routes[i].via_id;
            }
            /* Unhealthy via node - skip this cached route */
        }
    }

    /* If destination is queen or 0 (broadcast to queen), use gradient */
    if (dest_id == 0 || dest_id == g_state.known_queen_id) {
        return g_state.gradient_via;
    }

    /*
     * v0.5: For unknown destinations, try best neighbor instead of broadcast
     * This uses Hebbian selection to pick the most reliable relay
     */
    uint32_t best = nert_synapse_select_best(g_state.node_id);
    if (best != 0) {
        return best;
    }

    /* No healthy route - return 0 for broadcast */
    return 0;
}

/*
 * Send a routed packet toward destination
 */
int route_send(uint32_t dest_id, uint8_t type, uint8_t* data, uint8_t len) {
    struct nanos_pheromone pkt;

    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = type;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = FLAG_ROUTED;
    PKT_SET_ROLE(&pkt, g_state.role);
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;

    pkt.dest_id = dest_id;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;

    /* Set via hint */
    uint32_t via = route_next_hop(dest_id);
    pkt.via_node_lo = via & 0xFF;
    pkt.via_node_hi = (via >> 8) & 0xFF;

    /* Copy payload */
    if (len > 32) len = 32;
    for (uint8_t i = 0; i < len; i++) {
        pkt.payload[i] = data[i];
    }

    if (is_authenticated_type(type)) {
        compute_hmac(&pkt);
    }

    return NET_SEND(&pkt, sizeof(pkt));
}

/*
 * Forward a routed packet
 */
void route_forward(struct nanos_pheromone* pkt) {
    if (pkt->ttl == 0) return;
    if (pkt->hop_count >= GRADIENT_MAX_HOPS) return;

    /* Am I the destination? */
    if (pkt->dest_id == g_state.node_id) {
        return;  /* Delivered - process_pheromone will handle */
    }

    /* Find next hop */
    uint32_t next = route_next_hop(pkt->dest_id);

    if (next == 0) {
        /* No route - drop */
        g_state.packets_dropped++;
        return;
    }

    /* Update packet */
    pkt->ttl--;
    pkt->hop_count++;
    pkt->via_node_lo = next & 0xFF;
    pkt->via_node_hi = (next >> 8) & 0xFF;

    NET_SEND(pkt, sizeof(*pkt));
    g_state.packets_routed++;
}
