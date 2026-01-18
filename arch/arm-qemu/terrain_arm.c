/*
 * NanOS ARM - Terrain Exploration Module
 * Collaborative terrain mapping for embedded swarm
 */

#include "modules.h"

/* Global terrain state */
terrain_state_t terrain;

/* Direction vectors: N, E, S, W */
static const int8_t dx[] = {0, 1, 0, -1};
static const int8_t dy[] = {-1, 0, 1, 0};
static const char* dir_names[] = {"N", "E", "S", "W"};

/* Terrain type names */
static const char* terrain_names[] = {
    "?", "OPEN", "FOREST", "URBAN", "WATER", "ROCKY", "THREAT", "IMPASS"
};

/* ==========================================================================
 * Terrain Initialization
 * ========================================================================== */

void terrain_init(void) {
    terrain.active = 0;
    terrain.x = TERRAIN_SIZE / 2;
    terrain.y = TERRAIN_SIZE / 2;
    terrain.heading = 0;
    terrain.cells_explored = 0;
    terrain.threats_found = 0;
    terrain.last_move = 0;

    /* Clear grid */
    for (int y = 0; y < TERRAIN_SIZE; y++) {
        for (int x = 0; x < TERRAIN_SIZE; x++) {
            terrain.grid[y][x] = TERRAIN_UNKNOWN;
        }
    }
}

/* ==========================================================================
 * Terrain Start
 * ========================================================================== */

void terrain_start(uint8_t start_x, uint8_t start_y) {
    terrain_init();

    terrain.active = 1;
    terrain.x = start_x;
    terrain.y = start_y;
    terrain.started_at = ticks;

    /* Generate random terrain for our area */
    for (int dy = -3; dy <= 3; dy++) {
        for (int dx = -3; dx <= 3; dx++) {
            int nx = start_x + dx;
            int ny = start_y + dy;
            if (nx >= 0 && nx < TERRAIN_SIZE && ny >= 0 && ny < TERRAIN_SIZE) {
                /* Generate terrain type based on position + randomness */
                uint8_t t = arm_random() % 100;
                if (t < 50) terrain.grid[ny][nx] = TERRAIN_OPEN;
                else if (t < 70) terrain.grid[ny][nx] = TERRAIN_FOREST;
                else if (t < 80) terrain.grid[ny][nx] = TERRAIN_URBAN;
                else if (t < 85) terrain.grid[ny][nx] = TERRAIN_WATER;
                else if (t < 90) terrain.grid[ny][nx] = TERRAIN_ROCKY;
                else if (t < 95) terrain.grid[ny][nx] = TERRAIN_THREAT;
                else terrain.grid[ny][nx] = TERRAIN_IMPASSABLE;

                if (terrain.grid[ny][nx] != TERRAIN_UNKNOWN) {
                    terrain.cells_explored++;
                }
                if (terrain.grid[ny][nx] == TERRAIN_THREAT) {
                    terrain.threats_found++;
                }
            }
        }
    }

    uart_puts("[TERRAIN] Started at ");
    uart_put_dec(start_x);
    uart_putc(',');
    uart_put_dec(start_y);
    uart_puts(" explored=");
    uart_put_dec(terrain.cells_explored);
    uart_puts("\n");

    /* Broadcast init */
    arm_packet_t pkt = {0};
    pkt.magic = ARM_MAGIC;
    pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
    pkt.type = PHEROMONE_TERRAIN_INIT;
    pkt.ttl_flags = (15 << 4);
    pkt.seq = arm_get_seq();
    pkt.payload[0] = start_x;
    pkt.payload[1] = start_y;

    eth_send(&pkt, ARM_PKT_SIZE);
}

/* ==========================================================================
 * Movement Logic
 * ========================================================================== */

static void terrain_move(void) {
    if (!terrain.active) return;

    /* Find best direction */
    int best_dir = -1;
    int best_score = -1000;

    for (int dir = 0; dir < 4; dir++) {
        int nx = terrain.x + dx[dir];
        int ny = terrain.y + dy[dir];

        /* Check bounds */
        if (nx < 0 || nx >= TERRAIN_SIZE || ny < 0 || ny >= TERRAIN_SIZE) continue;

        /* Check if impassable */
        if (terrain.grid[ny][nx] == TERRAIN_IMPASSABLE) continue;
        if (terrain.grid[ny][nx] == TERRAIN_WATER) continue;

        /* Score: prefer unexplored */
        int score = 0;
        if (terrain.grid[ny][nx] == TERRAIN_UNKNOWN) score += 100;

        /* Check neighbors for unexplored */
        for (int d2 = 0; d2 < 4; d2++) {
            int nnx = nx + dx[d2];
            int nny = ny + dy[d2];
            if (nnx >= 0 && nnx < TERRAIN_SIZE && nny >= 0 && nny < TERRAIN_SIZE) {
                if (terrain.grid[nny][nnx] == TERRAIN_UNKNOWN) score += 20;
            }
        }

        /* Prefer continuing in same direction */
        if (dir == terrain.heading) score += 15;

        /* Random factor */
        score += arm_random() % 30;

        if (score > best_score) {
            best_score = score;
            best_dir = dir;
        }
    }

    if (best_dir >= 0) {
        terrain.x += dx[best_dir];
        terrain.y += dy[best_dir];
        terrain.heading = best_dir;

        /* Explore around new position */
        int newly_explored = 0;
        for (int dy = -2; dy <= 2; dy++) {
            for (int dx = -2; dx <= 2; dx++) {
                int nx = terrain.x + dx;
                int ny = terrain.y + dy;
                if (nx >= 0 && nx < TERRAIN_SIZE && ny >= 0 && ny < TERRAIN_SIZE) {
                    if (terrain.grid[ny][nx] == TERRAIN_UNKNOWN) {
                        /* Generate terrain */
                        uint8_t t = arm_random() % 100;
                        if (t < 50) terrain.grid[ny][nx] = TERRAIN_OPEN;
                        else if (t < 70) terrain.grid[ny][nx] = TERRAIN_FOREST;
                        else if (t < 80) terrain.grid[ny][nx] = TERRAIN_URBAN;
                        else if (t < 85) terrain.grid[ny][nx] = TERRAIN_WATER;
                        else if (t < 90) terrain.grid[ny][nx] = TERRAIN_ROCKY;
                        else if (t < 95) {
                            terrain.grid[ny][nx] = TERRAIN_THREAT;
                            terrain.threats_found++;
                        }
                        else terrain.grid[ny][nx] = TERRAIN_IMPASSABLE;

                        terrain.cells_explored++;
                        newly_explored++;
                    }
                }
            }
        }

        /* Broadcast move + report */
        arm_packet_t pkt = {0};
        pkt.magic = ARM_MAGIC;
        pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
        pkt.type = PHEROMONE_TERRAIN_REPORT;
        pkt.ttl_flags = (8 << 4);
        pkt.seq = arm_get_seq();
        pkt.payload[0] = terrain.x;
        pkt.payload[1] = terrain.y;
        pkt.payload[2] = terrain.grid[terrain.y][terrain.x];
        pkt.payload[3] = terrain.heading;
        pkt.payload[4] = terrain.cells_explored & 0xFF;
        pkt.payload[5] = (terrain.cells_explored >> 8) & 0xFF;

        eth_send(&pkt, ARM_PKT_SIZE);

        /* Report threat if found nearby */
        for (int dy = -1; dy <= 1; dy++) {
            for (int dx = -1; dx <= 1; dx++) {
                int nx = terrain.x + dx;
                int ny = terrain.y + dy;
                if (nx >= 0 && nx < TERRAIN_SIZE && ny >= 0 && ny < TERRAIN_SIZE) {
                    if (terrain.grid[ny][nx] == TERRAIN_THREAT) {
                        arm_packet_t threat_pkt = {0};
                        threat_pkt.magic = ARM_MAGIC;
                        threat_pkt.node_id = (uint16_t)(arm_get_node_id() & 0xFFFF);
                        threat_pkt.type = PHEROMONE_TERRAIN_THREAT;
                        threat_pkt.ttl_flags = (15 << 4);
                        threat_pkt.seq = arm_get_seq();
                        threat_pkt.payload[0] = nx;
                        threat_pkt.payload[1] = ny;
                        threat_pkt.payload[2] = TERRAIN_THREAT;

                        eth_send(&threat_pkt, ARM_PKT_SIZE);
                        uart_puts("[TERRAIN] THREAT at ");
                        uart_put_dec(nx);
                        uart_putc(',');
                        uart_put_dec(ny);
                        uart_puts("!\n");
                    }
                }
            }
        }
    }
}

/* ==========================================================================
 * Process Incoming Packets
 * ========================================================================== */

void terrain_process_pkt(arm_packet_t* pkt) {
    switch (pkt->type) {
        case PHEROMONE_TERRAIN_INIT:
            if (!terrain.active) {
                /* Join terrain exploration at offset position */
                uint8_t ox = pkt->payload[0];
                uint8_t oy = pkt->payload[1];

                /* Start at random offset */
                int offset_x = (arm_random() % 10) - 5;
                int offset_y = (arm_random() % 10) - 5;
                int sx = ox + offset_x;
                int sy = oy + offset_y;

                if (sx < 2) sx = 2;
                if (sy < 2) sy = 2;
                if (sx >= TERRAIN_SIZE - 2) sx = TERRAIN_SIZE - 3;
                if (sy >= TERRAIN_SIZE - 2) sy = TERRAIN_SIZE - 3;

                terrain_start(sx, sy);
            }
            break;

        case PHEROMONE_TERRAIN_REPORT: {
            /* Learn from peer's exploration */
            uint8_t px = pkt->payload[0];
            uint8_t py = pkt->payload[1];
            uint8_t pt = pkt->payload[2];

            if (px < TERRAIN_SIZE && py < TERRAIN_SIZE && pt < 8) {
                if (terrain.grid[py][px] == TERRAIN_UNKNOWN) {
                    terrain.grid[py][px] = pt;
                    terrain.cells_explored++;
                }
            }
            break;
        }

        case PHEROMONE_TERRAIN_THREAT: {
            /* Learn threat location */
            uint8_t tx = pkt->payload[0];
            uint8_t ty = pkt->payload[1];

            if (tx < TERRAIN_SIZE && ty < TERRAIN_SIZE) {
                if (terrain.grid[ty][tx] != TERRAIN_THREAT) {
                    terrain.grid[ty][tx] = TERRAIN_THREAT;
                    terrain.threats_found++;
                    uart_puts("[TERRAIN] Peer found THREAT at ");
                    uart_put_dec(tx);
                    uart_putc(',');
                    uart_put_dec(ty);
                    uart_puts("\n");
                }
            }
            break;
        }

        case PHEROMONE_TERRAIN_MOVE:
            /* Peer movement - could use for coordination */
            break;
    }
}

/* ==========================================================================
 * Periodic Tick (called from main loop)
 * ========================================================================== */

void terrain_tick(void) {
    if (!terrain.active) return;

    /* Move every 300ms */
    if ((ticks - terrain.last_move) >= 30) {
        terrain.last_move = ticks;
        terrain_move();

        /* Log status every 10 moves */
        static int move_count = 0;
        if (++move_count >= 10) {
            move_count = 0;
            uart_puts("[TERRAIN] node=");
            uart_put_hex(arm_get_node_id());
            uart_puts(" pos=");
            uart_put_dec(terrain.x);
            uart_putc(',');
            uart_put_dec(terrain.y);
            uart_puts(" dir=");
            uart_puts(dir_names[terrain.heading]);
            uart_puts(" cells=");
            uart_put_dec(terrain.cells_explored);
            uart_puts(" threats=");
            uart_put_dec(terrain.threats_found);
            uart_puts("\n");
        }
    }
}
