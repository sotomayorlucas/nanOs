/*
 * NanOS Tactical Terrain Exploration System
 * Collaborative terrain exploration with threat detection and pathfinding
 */
#ifndef NANOS_TERRAIN_H
#define NANOS_TERRAIN_H

#include <nanos.h>

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
