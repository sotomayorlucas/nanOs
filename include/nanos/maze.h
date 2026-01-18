/*
 * NanOS Maze Exploration System
 * Collaborative pathfinding with multiple explorers
 */
#ifndef NANOS_MAZE_H
#define NANOS_MAZE_H

#include <nanos.h>

/* Initialize maze exploration state */
void maze_init(void);

/* Execute one maze movement step */
void maze_move(void);

/* Share maze discoveries with swarm */
void maze_share_discoveries(void);

/* Process incoming maze pheromones */
void maze_process_init(struct nanos_pheromone* pkt);
void maze_process_discover(struct nanos_pheromone* pkt);
void maze_process_move(struct nanos_pheromone* pkt);
void maze_process_solved(struct nanos_pheromone* pkt);

#endif /* NANOS_MAZE_H */
