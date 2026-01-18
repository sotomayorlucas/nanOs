/*
 * NanOS Maze Exploration System
 * Collaborative pathfinding with multiple explorers
 */
#include <nanos.h>
#include "../../include/nanos/maze.h"
#include "../../include/nanos/gossip.h"
#include "../../include/nanos/serial.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern void e1000_send(void* data, uint16_t len);
extern void vga_set_color(uint8_t color);
extern void vga_puts(const char* str);
extern void vga_put_hex(uint32_t value);
extern void vga_put_dec(uint32_t value);

/* ==========================================================================
 * Constants and Tables
 * ========================================================================== */

/* Direction deltas: N, E, S, W */
static const int8_t dx[4] = {  0,  1,  0, -1 };
static const int8_t dy[4] = { -1,  0,  1,  0 };

/* ==========================================================================
 * Internal Helper Functions
 * ========================================================================== */

/* Check if position is valid and passable */
static bool maze_can_move(uint8_t x, uint8_t y) {
    if (x >= MAZE_SIZE || y >= MAZE_SIZE) return false;
    uint8_t cell = g_state.maze.grid[y][x];
    return cell != MAZE_WALL;
}

/* Count unexplored neighbors */
static int maze_unexplored_neighbors(uint8_t x, uint8_t y) {
    int count = 0;
    for (int dir = 0; dir < DIR_COUNT; dir++) {
        int nx = x + dx[dir];
        int ny = y + dy[dir];
        if (nx >= 0 && nx < MAZE_SIZE && ny >= 0 && ny < MAZE_SIZE) {
            if (g_state.maze.grid[ny][nx] == MAZE_UNEXPLORED) {
                count++;
            }
        }
    }
    return count;
}

/* Check if another explorer is at position */
static bool maze_explorer_at(uint8_t x, uint8_t y) {
    for (int i = 0; i < MAZE_MAX_EXPLORERS; i++) {
        if (g_state.maze.explorers[i].node_id != 0 &&
            g_state.maze.explorers[i].node_id != g_state.node_id &&
            g_state.maze.explorers[i].x == x &&
            g_state.maze.explorers[i].y == y &&
            ticks - g_state.maze.explorers[i].last_seen < 100) {
            return true;
        }
    }
    return false;
}

/* Choose next move direction using swarm logic */
static int maze_choose_direction(void) {
    uint8_t x = g_state.maze.pos_x;
    uint8_t y = g_state.maze.pos_y;

    /* Priority 1: Move toward goal if visible path */
    int best_dir = -1;
    int best_score = -1000;

    for (int dir = 0; dir < DIR_COUNT; dir++) {
        int nx = x + dx[dir];
        int ny = y + dy[dir];

        if (!maze_can_move(nx, ny)) continue;
        if (maze_explorer_at(nx, ny)) continue;  /* Avoid other explorers */

        int score = 0;

        /* Prefer unexplored cells */
        if (g_state.maze.grid[ny][nx] == MAZE_UNEXPLORED) {
            score += 50;
        }

        /* Prefer cells with more unexplored neighbors (frontier) */
        score += maze_unexplored_neighbors(nx, ny) * 10;

        /* Slight preference toward goal direction */
        int goal_dx = (int)g_state.maze.goal_x - nx;
        int goal_dy = (int)g_state.maze.goal_y - ny;
        int goal_dist = (goal_dx < 0 ? -goal_dx : goal_dx) +
                        (goal_dy < 0 ? -goal_dy : goal_dy);
        score -= goal_dist;

        /* Add randomness to prevent deadlocks */
        score += (random() % 20);

        /* Avoid backtracking if not stuck */
        if (g_state.maze.path_len > 0 && g_state.maze.stuck_count < 3) {
            if (g_state.maze.path[g_state.maze.path_len - 1].x == nx &&
                g_state.maze.path[g_state.maze.path_len - 1].y == ny) {
                score -= 30;
            }
        }

        if (score > best_score) {
            best_score = score;
            best_dir = dir;
        }
    }

    return best_dir;
}

/* ==========================================================================
 * Public API Implementation
 * ========================================================================== */

/* Initialize maze exploration state */
void maze_init(void) {
    /* Clear grid - all unexplored */
    for (int y = 0; y < MAZE_SIZE; y++) {
        for (int x = 0; x < MAZE_SIZE; x++) {
            g_state.maze.grid[y][x] = MAZE_UNEXPLORED;
        }
    }

    g_state.maze.active = 0;
    g_state.maze.solved = 0;
    g_state.maze.stuck_count = 0;
    g_state.maze.path_len = 0;
    g_state.maze.last_move = 0;
    g_state.maze.last_share = 0;

    /* Clear explorer tracking */
    for (int i = 0; i < MAZE_MAX_EXPLORERS; i++) {
        g_state.maze.explorers[i].node_id = 0;
    }

    g_state.maze.cells_explored = 0;
    g_state.maze.moves_made = 0;
    g_state.maze.discoveries_shared = 0;
}

/* Make a move in the maze */
void maze_move(void) {
    if (!g_state.maze.active || g_state.maze.solved) return;
    if (ticks - g_state.maze.last_move < MAZE_MOVE_INTERVAL) return;

    g_state.maze.last_move = ticks;

    /* Check if we reached the goal */
    if (g_state.maze.pos_x == g_state.maze.goal_x &&
        g_state.maze.pos_y == g_state.maze.goal_y) {

        g_state.maze.solved = 1;

        vga_set_color(0x0D);
        vga_puts(">> MAZE SOLVED! Path length: ");
        vga_put_dec(g_state.maze.path_len);
        vga_puts("\n");
        vga_set_color(0x0A);

        serial_puts("[MAZE] SOLVED by node=");
        serial_put_hex(g_state.node_id);
        serial_puts(" path_len=");
        serial_put_dec(g_state.maze.path_len);
        serial_puts("\n");

        /* Broadcast solution */
        struct nanos_pheromone pkt;
        pkt.magic = NANOS_MAGIC;
        pkt.node_id = g_state.node_id;
        pkt.type = PHEROMONE_MAZE_SOLVED;
        pkt.ttl = GRADIENT_MAX_HOPS;
        pkt.flags = 0;
        pkt.version = NANOS_VERSION;
        pkt.seq = g_state.seq_counter++;
        pkt.dest_id = 0;
        pkt.distance = g_state.distance_to_queen;
        pkt.hop_count = 0;
        PKT_SET_ROLE(&pkt, g_state.role);

        /* Payload: path_len(1) + first 15 path points */
        pkt.payload[0] = g_state.maze.path_len;
        for (int i = 0; i < 15 && i < g_state.maze.path_len; i++) {
            pkt.payload[1 + i*2] = g_state.maze.path[i].x;
            pkt.payload[2 + i*2] = g_state.maze.path[i].y;
        }

        for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
        e1000_send(&pkt, sizeof(pkt));
        g_state.packets_tx++;

        return;
    }

    /* Choose direction */
    int dir = maze_choose_direction();

    if (dir < 0) {
        /* Stuck - try backtracking */
        g_state.maze.stuck_count++;
        if (g_state.maze.path_len > 0) {
            g_state.maze.path_len--;
            g_state.maze.pos_x = g_state.maze.path[g_state.maze.path_len].x;
            g_state.maze.pos_y = g_state.maze.path[g_state.maze.path_len].y;
        }
        return;
    }

    g_state.maze.stuck_count = 0;

    /* Record current position in path */
    if (g_state.maze.path_len < 64) {
        g_state.maze.path[g_state.maze.path_len].x = g_state.maze.pos_x;
        g_state.maze.path[g_state.maze.path_len].y = g_state.maze.pos_y;
        g_state.maze.path_len++;
    }

    /* Move to new position */
    uint8_t new_x = g_state.maze.pos_x + dx[dir];
    uint8_t new_y = g_state.maze.pos_y + dy[dir];
    g_state.maze.pos_x = new_x;
    g_state.maze.pos_y = new_y;
    g_state.maze.moves_made++;

    /* Mark as explored if it was unexplored */
    if (g_state.maze.grid[new_y][new_x] == MAZE_UNEXPLORED) {
        g_state.maze.grid[new_y][new_x] = MAZE_EXPLORED;
        g_state.maze.cells_explored++;
    }
}

/* Share discoveries with other nodes */
void maze_share_discoveries(void) {
    if (!g_state.maze.active) return;
    if (ticks - g_state.maze.last_share < MAZE_SHARE_INTERVAL) return;

    g_state.maze.last_share = ticks;

    /* Send position update */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_MAZE_MOVE;
    pkt.ttl = 2;  /* Local broadcast */
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    /* Payload: x(1) + y(1) + cells_explored(2) */
    pkt.payload[0] = g_state.maze.pos_x;
    pkt.payload[1] = g_state.maze.pos_y;
    pkt.payload[2] = g_state.maze.cells_explored & 0xFF;
    pkt.payload[3] = (g_state.maze.cells_explored >> 8) & 0xFF;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;
    g_state.maze.discoveries_shared++;

    /* Also share discovered cells */
    if (g_state.maze.cells_explored > 0) {
        pkt.type = PHEROMONE_MAZE_DISCOVER;
        pkt.seq = g_state.seq_counter++;

        /* Pack recent discoveries: up to 10 cells */
        int idx = 0;
        for (int y = 0; y < MAZE_SIZE && idx < 10; y++) {
            for (int x = 0; x < MAZE_SIZE && idx < 10; x++) {
                uint8_t cell = g_state.maze.grid[y][x];
                if (cell == MAZE_EXPLORED || cell == MAZE_WALL) {
                    pkt.payload[idx * 3] = x;
                    pkt.payload[idx * 3 + 1] = y;
                    pkt.payload[idx * 3 + 2] = cell;
                    idx++;
                }
            }
        }
        pkt.payload[30] = idx;  /* Count of cells */

        e1000_send(&pkt, sizeof(pkt));
        g_state.packets_tx++;
    }
}

/* Process maze initialization from dashboard */
void maze_process_init(struct nanos_pheromone* pkt) {
    /* Payload format:
     * [0]: start_x, [1]: start_y
     * [2]: goal_x, [3]: goal_y
     * [4-31]: packed wall bits (first 224 bits = 14 rows)
     */
    g_state.maze.start_x = pkt->payload[0] % MAZE_SIZE;
    g_state.maze.start_y = pkt->payload[1] % MAZE_SIZE;
    g_state.maze.goal_x = pkt->payload[2] % MAZE_SIZE;
    g_state.maze.goal_y = pkt->payload[3] % MAZE_SIZE;

    /* Clear and set up maze */
    for (int y = 0; y < MAZE_SIZE; y++) {
        for (int x = 0; x < MAZE_SIZE; x++) {
            g_state.maze.grid[y][x] = MAZE_UNEXPLORED;
        }
    }

    /* Unpack walls from payload */
    for (int i = 0; i < 28 * 8 && i < MAZE_CELLS; i++) {
        int byte_idx = 4 + (i / 8);
        int bit_idx = i % 8;
        if (byte_idx < 32 && (pkt->payload[byte_idx] & (1 << bit_idx))) {
            int x = i % MAZE_SIZE;
            int y = i / MAZE_SIZE;
            g_state.maze.grid[y][x] = MAZE_WALL;
        }
    }

    /* Mark start and goal */
    g_state.maze.grid[g_state.maze.start_y][g_state.maze.start_x] = MAZE_START;
    g_state.maze.grid[g_state.maze.goal_y][g_state.maze.goal_x] = MAZE_GOAL;

    /* Position at start with some offset based on node_id */
    g_state.maze.pos_x = g_state.maze.start_x;
    g_state.maze.pos_y = g_state.maze.start_y;

    /* Reset exploration state */
    g_state.maze.active = 1;
    g_state.maze.solved = 0;
    g_state.maze.stuck_count = 0;
    g_state.maze.path_len = 0;
    g_state.maze.last_move = ticks;
    g_state.maze.last_share = ticks;
    g_state.maze.cells_explored = 1;  /* Start cell is explored */
    g_state.maze.moves_made = 0;

    vga_set_color(0x0E);
    vga_puts(">> MAZE STARTED: ");
    vga_put_dec(g_state.maze.start_x);
    vga_puts(",");
    vga_put_dec(g_state.maze.start_y);
    vga_puts(" -> ");
    vga_put_dec(g_state.maze.goal_x);
    vga_puts(",");
    vga_put_dec(g_state.maze.goal_y);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[MAZE] Started exploration from ");
    serial_put_dec(g_state.maze.start_x);
    serial_puts(",");
    serial_put_dec(g_state.maze.start_y);
    serial_puts(" to ");
    serial_put_dec(g_state.maze.goal_x);
    serial_puts(",");
    serial_put_dec(g_state.maze.goal_y);
    serial_puts("\n");

    /* Relay to other nodes */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process discovery from another node */
void maze_process_discover(struct nanos_pheromone* pkt) {
    if (!g_state.maze.active) return;

    int count = pkt->payload[30];
    if (count > 10) count = 10;

    for (int i = 0; i < count; i++) {
        uint8_t x = pkt->payload[i * 3];
        uint8_t y = pkt->payload[i * 3 + 1];
        uint8_t cell = pkt->payload[i * 3 + 2];

        if (x < MAZE_SIZE && y < MAZE_SIZE) {
            /* Only update if we haven't explored this cell yet */
            if (g_state.maze.grid[y][x] == MAZE_UNEXPLORED) {
                g_state.maze.grid[y][x] = cell;
            }
        }
    }

    /* Relay */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process position update from another explorer */
void maze_process_move(struct nanos_pheromone* pkt) {
    if (!g_state.maze.active) return;

    uint32_t sender = pkt->node_id;
    uint8_t x = pkt->payload[0];
    uint8_t y = pkt->payload[1];

    /* Update explorer tracking */
    int slot = -1;
    for (int i = 0; i < MAZE_MAX_EXPLORERS; i++) {
        if (g_state.maze.explorers[i].node_id == sender) {
            slot = i;
            break;
        }
        if (slot < 0 && g_state.maze.explorers[i].node_id == 0) {
            slot = i;
        }
    }

    if (slot >= 0) {
        g_state.maze.explorers[slot].node_id = sender;
        g_state.maze.explorers[slot].x = x;
        g_state.maze.explorers[slot].y = y;
        g_state.maze.explorers[slot].last_seen = ticks;
    }

    /* Relay */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process solution announcement */
void maze_process_solved(struct nanos_pheromone* pkt) {
    if (g_state.maze.solved) return;  /* Already know it's solved */

    g_state.maze.solved = 1;
    g_state.maze.active = 0;

    uint8_t path_len = pkt->payload[0];

    vga_set_color(0x0D);
    vga_puts(">> MAZE SOLVED by ");
    vga_put_hex(pkt->node_id);
    vga_puts(" (");
    vga_put_dec(path_len);
    vga_puts(" steps)\n");
    vga_set_color(0x0A);

    serial_puts("[MAZE] Solved by node=");
    serial_put_hex(pkt->node_id);
    serial_puts(" path_len=");
    serial_put_dec(path_len);
    serial_puts("\n");

    /* Mark path cells */
    for (int i = 0; i < 15 && i < path_len; i++) {
        uint8_t px = pkt->payload[1 + i*2];
        uint8_t py = pkt->payload[2 + i*2];
        if (px < MAZE_SIZE && py < MAZE_SIZE) {
            g_state.maze.grid[py][px] = MAZE_PATH;
        }
    }

    /* Relay */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}
