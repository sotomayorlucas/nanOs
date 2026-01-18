/*
 * NanOS ARM - Maze Exploration Module
 * Collaborative maze solving for embedded swarm
 */

#include "modules.h"

/* Global maze state */
maze_state_t maze;

/* Direction vectors: N, E, S, W */
static const int8_t dx[] = {0, 1, 0, -1};
static const int8_t dy[] = {-1, 0, 1, 0};

/* ==========================================================================
 * Maze Initialization
 * ========================================================================== */

void maze_init(void) {
    maze.active = 0;
    maze.solved = 0;
    maze.x = 1;
    maze.y = 1;
    maze.cells_explored = 0;

    /* Clear grid */
    for (int y = 0; y < MAZE_SIZE; y++) {
        for (int x = 0; x < MAZE_SIZE; x++) {
            maze.grid[y][x] = 0;  /* Unknown */
        }
    }
}

/* ==========================================================================
 * Maze Start
 * ========================================================================== */

void maze_start(uint8_t start_x, uint8_t start_y, uint8_t goal_x, uint8_t goal_y) {
    maze_init();

    maze.active = 1;
    maze.start_x = start_x;
    maze.start_y = start_y;
    maze.goal_x = goal_x;
    maze.goal_y = goal_y;
    maze.x = start_x;
    maze.y = start_y;
    maze.started_at = ticks;

    /* Mark start as visited */
    maze.grid[start_y][start_x] = 3;
    maze.cells_explored = 1;

    uart_puts("[MAZE] Started at ");
    uart_put_dec(start_x);
    uart_putc(',');
    uart_put_dec(start_y);
    uart_puts(" -> ");
    uart_put_dec(goal_x);
    uart_putc(',');
    uart_put_dec(goal_y);
    uart_puts("\n");

    /* Broadcast init packet */
    arm_packet_t pkt = {0};
    pkt.magic = ARM_MAGIC;
    pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
    pkt.type = PHEROMONE_MAZE_INIT;
    pkt.ttl_flags = (15 << 4);
    pkt.seq = arm_get_seq();
    pkt.payload[0] = start_x;
    pkt.payload[1] = start_y;
    pkt.payload[2] = goal_x;
    pkt.payload[3] = goal_y;

    eth_send(&pkt, ARM_PKT_SIZE);
}

/* ==========================================================================
 * Movement Logic
 * ========================================================================== */

static void maze_move(void) {
    if (!maze.active || maze.solved) return;

    /* Check if reached goal */
    if (maze.x == maze.goal_x && maze.y == maze.goal_y) {
        maze.solved = 1;
        uart_puts("[MAZE] SOLVED! cells=");
        uart_put_dec(maze.cells_explored);
        uart_puts(" time=");
        uart_put_dec((ticks - maze.started_at) / 100);
        uart_puts("s\n");

        /* Broadcast solved */
        arm_packet_t pkt = {0};
        pkt.magic = ARM_MAGIC;
        pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
        pkt.type = PHEROMONE_MAZE_SOLVED;
        pkt.ttl_flags = (15 << 4);
        pkt.seq = arm_get_seq();
        pkt.payload[0] = maze.x;
        pkt.payload[1] = maze.y;
        pkt.payload[2] = maze.cells_explored & 0xFF;
        pkt.payload[3] = (maze.cells_explored >> 8) & 0xFF;

        eth_send(&pkt, ARM_PKT_SIZE);
        return;
    }

    /* Find best direction to move */
    int best_dir = -1;
    int best_score = -1000;

    for (int dir = 0; dir < 4; dir++) {
        int nx = maze.x + dx[dir];
        int ny = maze.y + dy[dir];

        /* Check bounds */
        if (nx < 0 || nx >= MAZE_SIZE || ny < 0 || ny >= MAZE_SIZE) continue;

        /* Check if wall */
        if (maze.grid[ny][nx] == 2) continue;

        /* Score: prefer unexplored, then closer to goal */
        int score = 0;
        if (maze.grid[ny][nx] == 0) score += 100;  /* Unexplored bonus */
        else if (maze.grid[ny][nx] == 3) score -= 20;  /* Visited penalty */

        /* Manhattan distance to goal */
        int dist_now = (maze.x > maze.goal_x ? maze.x - maze.goal_x : maze.goal_x - maze.x) +
                       (maze.y > maze.goal_y ? maze.y - maze.goal_y : maze.goal_y - maze.y);
        int dist_new = (nx > maze.goal_x ? nx - maze.goal_x : maze.goal_x - nx) +
                       (ny > maze.goal_y ? ny - maze.goal_y : maze.goal_y - ny);
        score += (dist_now - dist_new) * 10;

        /* Add some randomness */
        score += (arm_random() % 20);

        if (score > best_score) {
            best_score = score;
            best_dir = dir;
        }
    }

    if (best_dir >= 0) {
        maze.x += dx[best_dir];
        maze.y += dy[best_dir];

        /* Mark as visited */
        if (maze.grid[maze.y][maze.x] == 0) {
            maze.cells_explored++;
        }
        maze.grid[maze.y][maze.x] = 3;

        /* Broadcast move */
        arm_packet_t pkt = {0};
        pkt.magic = ARM_MAGIC;
        pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
        pkt.type = PHEROMONE_MAZE_MOVE;
        pkt.ttl_flags = (8 << 4);
        pkt.seq = arm_get_seq();
        pkt.payload[0] = maze.x;
        pkt.payload[1] = maze.y;
        pkt.payload[2] = maze.cells_explored & 0xFF;

        eth_send(&pkt, ARM_PKT_SIZE);
    }
}

/* ==========================================================================
 * Process Incoming Packets
 * ========================================================================== */

void maze_process_pkt(arm_packet_t* pkt) {
    switch (pkt->type) {
        case PHEROMONE_MAZE_INIT:
            if (!maze.active) {
                /* Join maze exploration */
                uint8_t sx = pkt->payload[0];
                uint8_t sy = pkt->payload[1];
                uint8_t gx = pkt->payload[2];
                uint8_t gy = pkt->payload[3];

                /* Start at random offset from original start */
                uint8_t offset = arm_random() % 4;
                uint8_t nx = sx + (offset % 2);
                uint8_t ny = sy + (offset / 2);
                if (nx >= MAZE_SIZE) nx = sx;
                if (ny >= MAZE_SIZE) ny = sy;

                maze_start(nx, ny, gx, gy);
            }
            break;

        case PHEROMONE_MAZE_MOVE: {
            /* Learn from other explorers */
            uint8_t ox = pkt->payload[0];
            uint8_t oy = pkt->payload[1];
            if (ox < MAZE_SIZE && oy < MAZE_SIZE) {
                if (maze.grid[oy][ox] == 0) {
                    maze.grid[oy][ox] = 1;  /* Mark as open (discovered by peer) */
                }
            }
            break;
        }

        case PHEROMONE_MAZE_WALL: {
            /* Learn wall location */
            uint8_t wx = pkt->payload[0];
            uint8_t wy = pkt->payload[1];
            if (wx < MAZE_SIZE && wy < MAZE_SIZE) {
                maze.grid[wy][wx] = 2;  /* Mark as wall */
            }
            break;
        }

        case PHEROMONE_MAZE_SOLVED:
            if (maze.active && !maze.solved) {
                maze.solved = 1;
                uart_puts("[MAZE] Peer solved! node=0x");
                uart_put_hex(pkt->node_id);
                uart_puts("\n");
            }
            break;
    }
}

/* ==========================================================================
 * Periodic Tick (called from main loop)
 * ========================================================================== */

static uint32_t last_move_tick = 0;

void maze_tick(void) {
    if (!maze.active || maze.solved) return;

    /* Move every 500ms */
    if ((ticks - last_move_tick) >= 50) {
        last_move_tick = ticks;
        maze_move();

        /* Log position every 5 moves */
        static int move_count = 0;
        if (++move_count >= 5) {
            move_count = 0;
            uart_puts("[MAZE] node=");
            uart_put_hex(arm_get_node_id());
            uart_puts(" pos=");
            uart_put_dec(maze.x);
            uart_putc(',');
            uart_put_dec(maze.y);
            uart_puts(" cells=");
            uart_put_dec(maze.cells_explored);
            uart_puts("\n");
        }
    }
}
