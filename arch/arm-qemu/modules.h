/*
 * NanOS ARM Modules - Shared Header
 * Common types and functions for maze/terrain modules
 */

#ifndef NANOS_ARM_MODULES_H
#define NANOS_ARM_MODULES_H

#include <stdint.h>

/* ==========================================================================
 * Pheromone Types (must match x86 kernel)
 * ========================================================================== */

/* Maze pheromones */
#define PHEROMONE_MAZE_INIT     0x70
#define PHEROMONE_MAZE_MOVE     0x71
#define PHEROMONE_MAZE_WALL     0x72
#define PHEROMONE_MAZE_SOLVED   0x73

/* Terrain pheromones */
#define PHEROMONE_TERRAIN_INIT   0x80
#define PHEROMONE_TERRAIN_REPORT 0x81
#define PHEROMONE_TERRAIN_THREAT 0x82
#define PHEROMONE_TERRAIN_MOVE   0x84

/* ==========================================================================
 * Compact Packet (24 bytes)
 * ========================================================================== */

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint16_t node_id;
    uint8_t  type;
    uint8_t  ttl_flags;
    uint8_t  seq;
    uint16_t dest_id;
    uint8_t  dist_hop;
    uint8_t  payload[8];
    uint8_t  hmac[4];
    uint8_t  reserved[3];
} arm_packet_t;

#define ARM_PKT_SIZE 24
#define ARM_MAGIC    0xAA

/* ==========================================================================
 * External Functions (provided by nanos_arm.c)
 * ========================================================================== */

/* UART output */
extern void uart_puts(const char* s);
extern void uart_putc(char c);
extern void uart_put_hex(uint32_t n);
extern void uart_put_dec(uint32_t n);

/* Network */
extern void eth_send(const void* data, uint16_t len);

/* Timing */
extern volatile uint32_t ticks;

/* Random */
extern uint32_t arm_random(void);

/* State access */
extern uint32_t arm_get_node_id(void);
extern uint8_t  arm_get_role(void);
extern uint16_t arm_get_seq(void);

/* ==========================================================================
 * Maze Module Interface
 * ========================================================================== */

#define MAZE_SIZE 16

typedef struct {
    uint8_t  active;
    uint8_t  solved;
    uint8_t  x, y;           /* Current position */
    uint8_t  start_x, start_y;
    uint8_t  goal_x, goal_y;
    uint8_t  grid[MAZE_SIZE][MAZE_SIZE];  /* 0=unknown, 1=open, 2=wall, 3=visited */
    uint16_t cells_explored;
    uint32_t started_at;
} maze_state_t;

extern maze_state_t maze;

void maze_init(void);
void maze_tick(void);
void maze_process_pkt(arm_packet_t* pkt);
void maze_start(uint8_t start_x, uint8_t start_y, uint8_t goal_x, uint8_t goal_y);

/* ==========================================================================
 * Terrain Module Interface
 * ========================================================================== */

#define TERRAIN_SIZE 32

/* Terrain types */
#define TERRAIN_UNKNOWN    0
#define TERRAIN_OPEN       1
#define TERRAIN_FOREST     2
#define TERRAIN_URBAN      3
#define TERRAIN_WATER      4
#define TERRAIN_ROCKY      5
#define TERRAIN_THREAT     6
#define TERRAIN_IMPASSABLE 7

typedef struct {
    uint8_t  active;
    uint8_t  x, y;           /* Current position */
    uint8_t  heading;        /* 0=N, 1=E, 2=S, 3=W */
    uint8_t  grid[TERRAIN_SIZE][TERRAIN_SIZE];
    uint16_t cells_explored;
    uint8_t  threats_found;
    uint32_t started_at;
    uint32_t last_move;
} terrain_state_t;

extern terrain_state_t terrain;

void terrain_init(void);
void terrain_tick(void);
void terrain_process_pkt(arm_packet_t* pkt);
void terrain_start(uint8_t start_x, uint8_t start_y);

#endif /* NANOS_ARM_MODULES_H */
