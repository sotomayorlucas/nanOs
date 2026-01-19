/*
 * NanOS Tactical Terrain Exploration System
 * Collaborative terrain exploration with threat detection and pathfinding
 *
 * v0.5: Added Stigmergia - Digital Pheromones with Decay
 *       "Ants don't memorize the map; they leave chemicals that evaporate"
 */
#ifndef NANOS_TERRAIN_H
#define NANOS_TERRAIN_H

#include <nanos.h>

/* ==========================================================================
 * Stigmergia Constants (v0.5) - Digital Pheromones
 * ========================================================================== */

/* Pheromone types (stored as nibbles, 4 bits each) */
#define STIGMERGIA_DANGER       0   /* Danger zone: jamming, attacks, bad nodes */
#define STIGMERGIA_QUEEN        1   /* Path to queen (recruitment trail) */
#define STIGMERGIA_RESOURCE     2   /* Resource/objective marker */
#define STIGMERGIA_AVOID        3   /* General avoidance (not danger, just suboptimal) */
#define STIGMERGIA_TYPE_COUNT   4

/* Intensity range (4 bits = 0-15) */
#define STIGMERGIA_INTENSITY_MAX    15
#define STIGMERGIA_INTENSITY_HIGH   12
#define STIGMERGIA_INTENSITY_MEDIUM 8
#define STIGMERGIA_INTENSITY_LOW    4

/* Decay parameters */
#define STIGMERGIA_DECAY_INTERVAL_MS    1000    /* Decay check every 1 second */
#define STIGMERGIA_DECAY_AMOUNT         1       /* Subtract 1 per interval */

/* Propagation parameters */
#define STIGMERGIA_PROPAGATE_THRESHOLD  6       /* Min intensity to propagate */
#define STIGMERGIA_PROPAGATE_DECAY      3       /* Decay when propagating to neighbors */

/* Movement cost modifiers (added to base cost) */
#define STIGMERGIA_DANGER_COST_MULT     8       /* Cost += intensity * 8 */
#define STIGMERGIA_AVOID_COST_MULT      4       /* Cost += intensity * 4 */
#define STIGMERGIA_QUEEN_COST_BONUS     2       /* Cost -= intensity * 2 (attraction) */

/* Stigmergia grid resolution (coarser than terrain for memory efficiency)
 * Uses 2:1 mapping: stigmergia cell covers 2x2 terrain cells */
#define STIGMERGIA_SCALE            2
#define STIGMERGIA_SIZE             (TERRAIN_SIZE / STIGMERGIA_SCALE)
#define STIGMERGIA_CELLS            (STIGMERGIA_SIZE * STIGMERGIA_SIZE)

/* ==========================================================================
 * Stigmergia API (v0.5)
 * ========================================================================== */

/**
 * Initialize stigmergia pheromone map
 * Called from terrain_init()
 */
void stigmergia_init(void);

/**
 * Mark a pheromone at terrain coordinates
 * Coordinates are automatically scaled to stigmergia grid
 *
 * @param terrain_x, terrain_y  Terrain grid coordinates
 * @param type                  STIGMERGIA_* type
 * @param intensity             0-15 intensity (capped at STIGMERGIA_INTENSITY_MAX)
 */
void stigmergia_mark(uint8_t terrain_x, uint8_t terrain_y,
                     uint8_t type, uint8_t intensity);

/**
 * Get pheromone intensity at terrain coordinates
 *
 * @param terrain_x, terrain_y  Terrain grid coordinates
 * @param type                  STIGMERGIA_* type
 * @return Intensity 0-15
 */
uint8_t stigmergia_get(uint8_t terrain_x, uint8_t terrain_y, uint8_t type);

/**
 * Apply pheromone decay to all cells
 * Should be called every STIGMERGIA_DECAY_INTERVAL_MS from timer_tick
 */
void stigmergia_decay(void);

/**
 * Propagate pheromones to neighboring cells (diffusion)
 * High-intensity pheromones spread to adjacent cells with reduced intensity
 */
void stigmergia_propagate(void);

/**
 * Calculate movement cost modifier based on pheromones
 * Returns positive value to add to base movement cost
 *
 * @param terrain_x, terrain_y  Terrain grid coordinates
 * @return Cost modifier (can be negative for queen attraction)
 */
int8_t stigmergia_cost_modifier(uint8_t terrain_x, uint8_t terrain_y);

/**
 * Emit danger pheromone at current position and propagate
 * Called when detecting jamming, attacks, or malicious nodes
 *
 * @param intensity  Initial intensity (STIGMERGIA_INTENSITY_*)
 */
void stigmergia_emit_danger(uint8_t intensity);

/**
 * Emit queen trail pheromone along path to queen
 * Creates a chemical gradient toward the queen
 */
void stigmergia_emit_queen_trail(void);

/**
 * Process incoming stigmergia pheromone packet
 * Integrates pheromone reports from other nodes
 */
void terrain_process_stigmergia(struct nanos_pheromone* pkt);

/**
 * Share local pheromone state with neighbors
 * Broadcasts high-intensity pheromones to swarm
 */
void stigmergia_share(void);

/* ==========================================================================
 * Original Terrain API
 * ========================================================================== */

/* Initialize terrain exploration state */
void terrain_init(void);

/* Execute one terrain movement step */
void terrain_move(void);

/* Share terrain discoveries with swarm */
void terrain_share_discoveries(void);

/* Process incoming terrain pheromones */
void terrain_process_init(struct nanos_pheromone* pkt);
void terrain_process_report(struct nanos_pheromone* pkt);
void terrain_process_move(struct nanos_pheromone* pkt);
void terrain_process_threat(struct nanos_pheromone* pkt);
void terrain_process_strategy(struct nanos_pheromone* pkt);

/* Integrate tactical detection events into terrain threat map */
void terrain_integrate_detections(void);

#endif /* NANOS_TERRAIN_H */
