/*
 * NanOS Tactical Terrain Exploration System
 * Collaborative terrain exploration with threat detection and pathfinding
 */
#include <nanos.h>
#include "../../include/nanos/terrain.h"
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

/* 8-directional movement deltas: N, NE, E, SE, S, SW, W, NW */
static const int8_t terrain_dx[8] = {  0,  1,  1,  1,  0, -1, -1, -1 };
static const int8_t terrain_dy[8] = { -1, -1,  0,  1,  1,  1,  0, -1 };

/* Default cover values per terrain type */
static const uint8_t terrain_default_cover[8] = {
    COVER_NONE,     /* OPEN */
    COVER_MEDIUM,   /* FOREST */
    COVER_HIGH,     /* URBAN */
    COVER_NONE,     /* WATER */
    COVER_LOW,      /* ROCKY */
    COVER_NONE,     /* MARSH */
    COVER_NONE,     /* ROAD */
    COVER_HIGH      /* IMPASSABLE */
};

/* Default passability per terrain type */
static const uint8_t terrain_default_pass[8] = {
    PASS_NORMAL,    /* OPEN */
    PASS_SLOW,      /* FOREST */
    PASS_NORMAL,    /* URBAN */
    PASS_BLOCKED,   /* WATER */
    PASS_DIFFICULT, /* ROCKY */
    PASS_DIFFICULT, /* MARSH */
    PASS_NORMAL,    /* ROAD (bonus handled elsewhere) */
    PASS_BLOCKED    /* IMPASSABLE */
};

/* ==========================================================================
 * Internal Helper Functions
 * ========================================================================== */

/* Deterministic hash function for procedural generation */
static uint32_t terrain_hash(uint32_t seed, uint8_t x, uint8_t y) {
    /* FNV-1a hash variant for terrain generation */
    uint32_t hash = seed ^ 0x811c9dc5;
    hash ^= x;
    hash *= 0x01000193;
    hash ^= y;
    hash *= 0x01000193;
    hash ^= (x * y);
    hash *= 0x01000193;
    /* Additional mixing for better distribution */
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

/* Generate terrain type from elevation and hash */
static uint8_t terrain_from_elevation(uint8_t elevation, uint32_t hash) {
    uint8_t r = (hash >> 8) % 100;

    if (elevation >= 6) {
        /* High altitude: rocky or impassable */
        return (r < 70) ? TERRAIN_ROCKY : TERRAIN_IMPASSABLE;
    } else if (elevation >= 4) {
        /* Medium-high: forest, rocky, or open */
        if (r < 40) return TERRAIN_FOREST;
        if (r < 70) return TERRAIN_OPEN;
        return TERRAIN_ROCKY;
    } else if (elevation <= 1) {
        /* Low altitude: water, marsh, or open */
        if (r < 30) return TERRAIN_WATER;
        if (r < 50) return TERRAIN_MARSH;
        return TERRAIN_OPEN;
    } else {
        /* Medium: varied terrain */
        if (r < 25) return TERRAIN_FOREST;
        if (r < 50) return TERRAIN_OPEN;
        if (r < 65) return TERRAIN_URBAN;
        if (r < 80) return TERRAIN_ROAD;
        return TERRAIN_ROCKY;
    }
}

/* Generate a single terrain cell using procedural generation */
static void terrain_generate_cell(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return;

    uint32_t hash = terrain_hash(g_state.terrain.seed, x, y);

    /* Generate elevation (0-7) using noise-like distribution */
    uint8_t elevation = (hash % 8);
    /* Smooth elevation with neighbor influence */
    if (x > 0 && y > 0) {
        uint32_t neighbor_hash = terrain_hash(g_state.terrain.seed, x-1, y-1);
        elevation = (elevation + (neighbor_hash % 8)) / 2;
    }

    /* Generate terrain type based on elevation */
    uint8_t terrain_type = terrain_from_elevation(elevation, hash);

    /* Get default cover and passability */
    uint8_t cover = terrain_default_cover[terrain_type];
    uint8_t pass = terrain_default_pass[terrain_type];

    /* Pack base byte: [7:6]cover | [5:3]elevation | [2:0]terrain */
    g_state.terrain.grid[y][x].base =
        terrain_type |
        (elevation << TERRAIN_ELEV_SHIFT) |
        (cover << TERRAIN_COVER_SHIFT);

    /* Pack meta byte: [7:5]threat | [4:3]strategic | [2:1]pass | [0]explored
     * Start with unknown threat, no strategic value, appropriate passability */
    g_state.terrain.grid[y][x].meta =
        (THREAT_UNKNOWN << TERRAIN_THREAT_SHIFT) |
        (STRATEGIC_NONE << TERRAIN_STRAT_SHIFT) |
        (pass << TERRAIN_PASS_SHIFT) |
        TERRAIN_EXPLORED;  /* Mark as generated/explored */

    g_state.terrain.cells_generated++;
}

/* Cell access helpers */
static uint8_t terrain_get_type(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return TERRAIN_IMPASSABLE;
    return g_state.terrain.grid[y][x].base & 0x07;
}

static uint8_t terrain_get_elevation(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return 0;
    return (g_state.terrain.grid[y][x].base >> TERRAIN_ELEV_SHIFT) & 0x07;
}

static uint8_t terrain_get_cover(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return 0;
    return (g_state.terrain.grid[y][x].base >> TERRAIN_COVER_SHIFT) & 0x03;
}

static uint8_t terrain_get_threat(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return THREAT_CRITICAL;
    return (g_state.terrain.grid[y][x].meta >> TERRAIN_THREAT_SHIFT) & 0x07;
}

static uint8_t terrain_get_passability(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return PASS_BLOCKED;
    return (g_state.terrain.grid[y][x].meta >> TERRAIN_PASS_SHIFT) & 0x03;
}

static uint8_t terrain_is_explored(uint8_t x, uint8_t y) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return 0;
    return g_state.terrain.grid[y][x].meta & TERRAIN_EXPLORED;
}

static void terrain_set_threat(uint8_t x, uint8_t y, uint8_t level) {
    if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) return;
    g_state.terrain.grid[y][x].meta =
        (g_state.terrain.grid[y][x].meta & ~TERRAIN_THREAT_MASK) |
        ((level & 0x07) << TERRAIN_THREAT_SHIFT);
}

/* Calculate movement cost to cell */
static uint8_t terrain_movement_cost(uint8_t x, uint8_t y) {
    uint8_t pass = terrain_get_passability(x, y);
    switch (pass) {
        case PASS_BLOCKED:   return 255;
        case PASS_DIFFICULT: return 3;
        case PASS_SLOW:      return 2;
        default:             return 1;
    }
}

/* Calculate visibility range from position (elevation bonus) */
static uint8_t terrain_visibility_range(uint8_t x, uint8_t y, uint8_t base_range) {
    uint8_t elevation = terrain_get_elevation(x, y);
    return base_range + (elevation / 2);
}

/* Check if another explorer is at position */
static bool terrain_explorer_at(uint8_t x, uint8_t y) {
    for (int i = 0; i < TERRAIN_MAX_EXPLORERS; i++) {
        if (g_state.terrain.explorers[i].node_id != 0 &&
            g_state.terrain.explorers[i].node_id != g_state.node_id &&
            g_state.terrain.explorers[i].x == x &&
            g_state.terrain.explorers[i].y == y &&
            ticks - g_state.terrain.explorers[i].last_seen < 200) {
            return true;
        }
    }
    return false;
}

/* Perform sensor scan - generate and reveal cells in range */
static void terrain_sensor_scan(void) {
    uint8_t cx = g_state.terrain.pos_x;
    uint8_t cy = g_state.terrain.pos_y;
    uint8_t range = terrain_visibility_range(cx, cy, g_state.terrain.sensor_range);

    /* Scan cells within range */
    for (int dy = -(int)range; dy <= (int)range; dy++) {
        for (int dx = -(int)range; dx <= (int)range; dx++) {
            int nx = cx + dx;
            int ny = cy + dy;

            if (nx < 0 || nx >= TERRAIN_SIZE || ny < 0 || ny >= TERRAIN_SIZE) continue;

            /* Manhattan distance check */
            int dist = (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy);
            if (dist > range) continue;

            /* Generate cell if not yet generated */
            if (!terrain_is_explored(nx, ny)) {
                terrain_generate_cell(nx, ny);
                g_state.terrain.cells_explored++;
            }
        }
    }
}

/* Add position to visited history (circular buffer) */
static void terrain_record_visited(uint8_t x, uint8_t y) {
    g_state.terrain.visited[g_state.terrain.visited_head].x = x;
    g_state.terrain.visited[g_state.terrain.visited_head].y = y;
    g_state.terrain.visited_head = (g_state.terrain.visited_head + 1) % 32;
    if (g_state.terrain.visited_count < 32) {
        g_state.terrain.visited_count++;
    }
}

/* Check if position was recently visited, return recency (0 = not visited, 1-32 = how recent) */
static int terrain_visit_recency(uint8_t x, uint8_t y) {
    for (int i = 0; i < g_state.terrain.visited_count; i++) {
        int idx = (g_state.terrain.visited_head - 1 - i + 32) % 32;
        if (g_state.terrain.visited[idx].x == x && g_state.terrain.visited[idx].y == y) {
            return i + 1;  /* 1 = most recent, higher = older */
        }
    }
    return 0;  /* Not in history */
}

/* Count unexplored cells adjacent to a position (frontier score) */
static int terrain_unexplored_neighbors(uint8_t x, uint8_t y) {
    int count = 0;
    for (int dir = 0; dir < 8; dir++) {
        int nx = x + terrain_dx[dir];
        int ny = y + terrain_dy[dir];
        if (nx >= 0 && nx < TERRAIN_SIZE && ny >= 0 && ny < TERRAIN_SIZE) {
            if (!terrain_is_explored(nx, ny)) {
                count++;
            }
        }
    }
    return count;
}

/* Find nearest frontier (explored cell with unexplored neighbors) */
static void terrain_find_frontier(void) {
    if (ticks - g_state.terrain.last_frontier_scan < 500) return;  /* Scan every ~5 seconds */
    g_state.terrain.last_frontier_scan = ticks;

    uint8_t px = g_state.terrain.pos_x;
    uint8_t py = g_state.terrain.pos_y;
    int best_dist = 10000;
    int best_x = -1, best_y = -1;

    /* Search in expanding squares for efficiency */
    for (int radius = 1; radius < TERRAIN_SIZE; radius++) {
        int found_this_ring = 0;

        for (int dx = -radius; dx <= radius; dx++) {
            for (int dy = -radius; dy <= radius; dy++) {
                /* Only check cells on this ring */
                if ((dx < 0 ? -dx : dx) != radius && (dy < 0 ? -dy : dy) != radius) continue;

                int nx = px + dx;
                int ny = py + dy;
                if (nx < 0 || nx >= TERRAIN_SIZE || ny < 0 || ny >= TERRAIN_SIZE) continue;

                /* Must be explored (generated) */
                if (!terrain_is_explored(nx, ny)) continue;

                /* Must be passable */
                if (terrain_get_passability(nx, ny) == PASS_BLOCKED) continue;

                /* Count unexplored neighbors */
                int unexplored = terrain_unexplored_neighbors(nx, ny);
                if (unexplored > 0) {
                    int dist = (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy);
                    /* Prefer frontiers with more unexplored neighbors */
                    dist -= unexplored * 2;
                    if (dist < best_dist) {
                        best_dist = dist;
                        best_x = nx;
                        best_y = ny;
                        found_this_ring = 1;
                    }
                }
            }
        }

        /* Stop early if we found a frontier and checked at least 3 rings */
        if (found_this_ring && radius >= 3) break;
    }

    if (best_x >= 0) {
        g_state.terrain.frontier_x = best_x;
        g_state.terrain.frontier_y = best_y;
        g_state.terrain.has_frontier = 1;
    } else {
        g_state.terrain.has_frontier = 0;
    }
}

/* Score a potential move */
static int terrain_score_move(uint8_t nx, uint8_t ny) {
    int score = 0;

    /* Check passability first */
    uint8_t pass = terrain_get_passability(nx, ny);
    if (pass == PASS_BLOCKED) return -10000;

    /* Unexplored cells are VERY valuable */
    if (!terrain_is_explored(nx, ny)) {
        score += 200;  /* Increased from 100 */
    } else {
        /* Explored cells with unexplored neighbors are valuable too */
        int unexplored_near = terrain_unexplored_neighbors(nx, ny);
        score += unexplored_near * 30;
    }

    /* HEAVILY penalize recently visited cells to prevent looping */
    int recency = terrain_visit_recency(nx, ny);
    if (recency > 0) {
        /* More recent = worse penalty: recency 1 = -300, recency 32 = -10 */
        score -= 300 / recency;
    }

    /* Bonus for moving toward frontier */
    if (g_state.terrain.has_frontier) {
        int curr_dist_to_frontier =
            (g_state.terrain.pos_x < g_state.terrain.frontier_x ?
             g_state.terrain.frontier_x - g_state.terrain.pos_x :
             g_state.terrain.pos_x - g_state.terrain.frontier_x) +
            (g_state.terrain.pos_y < g_state.terrain.frontier_y ?
             g_state.terrain.frontier_y - g_state.terrain.pos_y :
             g_state.terrain.pos_y - g_state.terrain.frontier_y);

        int new_dist_to_frontier =
            (nx < g_state.terrain.frontier_x ?
             g_state.terrain.frontier_x - nx :
             nx - g_state.terrain.frontier_x) +
            (ny < g_state.terrain.frontier_y ?
             g_state.terrain.frontier_y - ny :
             ny - g_state.terrain.frontier_y);

        /* Bonus for getting closer to frontier */
        score += (curr_dist_to_frontier - new_dist_to_frontier) * 25;
    }

    /* Movement cost penalty */
    score -= terrain_movement_cost(nx, ny) * 15;

    /* Threat avoidance */
    uint8_t threat = terrain_get_threat(nx, ny);
    if (threat > THREAT_UNKNOWN) {
        score -= threat * 40;
    }

    /* Cover bonus */
    score += terrain_get_cover(nx, ny) * 8;

    /* Elevation bonus for scouts */
    if (g_state.role == ROLE_EXPLORER) {
        score += terrain_get_elevation(nx, ny) * 5;
    }

    /* Terrain type preferences by role */
    uint8_t ttype = terrain_get_type(nx, ny);
    if (g_state.role == ROLE_WORKER && ttype == TERRAIN_ROAD) {
        score += 15;  /* Workers prefer roads for fast travel */
    } else if (g_state.role == ROLE_EXPLORER && ttype == TERRAIN_FOREST) {
        score += 10;  /* Scouts prefer forest for concealment */
    } else if (g_state.role == ROLE_SENTINEL &&
               (ttype == TERRAIN_URBAN || ttype == TERRAIN_ROCKY)) {
        score += 12;  /* Sentinels prefer urban/rocky for vantage */
    }

    /* Objective direction bonus */
    if (g_state.terrain.has_objective) {
        int obj_dx = (int)g_state.terrain.objective_x - (int)nx;
        int obj_dy = (int)g_state.terrain.objective_y - (int)ny;
        int obj_dist = (obj_dx < 0 ? -obj_dx : obj_dx) + (obj_dy < 0 ? -obj_dy : obj_dy);
        score -= obj_dist * 2;
    }

    /* Avoid other explorers */
    if (terrain_explorer_at(nx, ny)) {
        score -= 60;
    }

    /* Randomness to avoid deadlocks */
    score += (random() % 20);

    return score;
}

/* Choose next movement direction (8-way) */
static int terrain_choose_direction(void) {
    uint8_t x = g_state.terrain.pos_x;
    uint8_t y = g_state.terrain.pos_y;

    int best_dir = -1;
    int best_score = -10000;

    for (int dir = 0; dir < 8; dir++) {
        int nx = x + terrain_dx[dir];
        int ny = y + terrain_dy[dir];

        if (nx < 0 || nx >= TERRAIN_SIZE || ny < 0 || ny >= TERRAIN_SIZE) continue;

        int score = terrain_score_move(nx, ny);

        /* Penalize backtracking unless stuck */
        if (g_state.terrain.path_len > 0 && g_state.terrain.stuck_count < 3) {
            if (g_state.terrain.path[g_state.terrain.path_len - 1].x == (uint8_t)nx &&
                g_state.terrain.path[g_state.terrain.path_len - 1].y == (uint8_t)ny) {
                score -= 50;
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

/* Initialize terrain exploration state */
void terrain_init(void) {
    /* Clear entire terrain grid */
    for (int y = 0; y < TERRAIN_SIZE; y++) {
        for (int x = 0; x < TERRAIN_SIZE; x++) {
            g_state.terrain.grid[y][x].base = 0;
            g_state.terrain.grid[y][x].meta = 0;
        }
    }

    g_state.terrain.seed = 0;
    g_state.terrain.active = 0;
    g_state.terrain.mode = TERRAIN_MODE_EXPLORE;
    g_state.terrain.stuck_count = 0;
    g_state.terrain.path_len = 0;
    g_state.terrain.last_move = 0;
    g_state.terrain.last_share = 0;
    g_state.terrain.last_threat_check = 0;
    g_state.terrain.has_objective = 0;
    g_state.terrain.objective_count = 0;
    g_state.terrain.threat_count = 0;

    /* Anti-looping: visited history */
    g_state.terrain.visited_head = 0;
    g_state.terrain.visited_count = 0;

    /* Frontier-based exploration */
    g_state.terrain.has_frontier = 0;
    g_state.terrain.last_frontier_scan = 0;

    /* Set sensor range based on role */
    switch (g_state.role) {
        case ROLE_EXPLORER:
            g_state.terrain.sensor_range = SENSOR_RANGE_SCOUT;
            break;
        case ROLE_SENTINEL:
            g_state.terrain.sensor_range = SENSOR_RANGE_SENTINEL;
            break;
        case ROLE_QUEEN:
            g_state.terrain.sensor_range = SENSOR_RANGE_QUEEN;
            break;
        default:
            g_state.terrain.sensor_range = SENSOR_RANGE_WORKER;
    }

    /* Clear explorer tracking */
    for (int i = 0; i < TERRAIN_MAX_EXPLORERS; i++) {
        g_state.terrain.explorers[i].node_id = 0;
    }

    /* Clear objectives */
    for (int i = 0; i < TERRAIN_MAX_OBJECTIVES; i++) {
        g_state.terrain.objectives[i].x = 0;
        g_state.terrain.objectives[i].y = 0;
        g_state.terrain.objectives[i].type = 0;
        g_state.terrain.objectives[i].status = 0;
    }

    /* Clear threats */
    for (int i = 0; i < TERRAIN_MAX_THREATS; i++) {
        g_state.terrain.threats[i].x = 0;
        g_state.terrain.threats[i].y = 0;
        g_state.terrain.threats[i].threat_level = 0;
    }

    /* Reset statistics */
    g_state.terrain.cells_explored = 0;
    g_state.terrain.cells_generated = 0;
    g_state.terrain.threats_reported = 0;
    g_state.terrain.objectives_found = 0;
    g_state.terrain.moves_made = 0;
    g_state.terrain.reports_sent = 0;
}

/* Execute terrain movement */
void terrain_move(void) {
    if (!g_state.terrain.active) return;
    if (ticks - g_state.terrain.last_move < TERRAIN_MOVE_INTERVAL) return;

    g_state.terrain.last_move = ticks;

    /* Perform sensor scan first */
    terrain_sensor_scan();

    /* Update frontier target periodically */
    terrain_find_frontier();

    /* Check if at objective */
    if (g_state.terrain.has_objective &&
        g_state.terrain.pos_x == g_state.terrain.objective_x &&
        g_state.terrain.pos_y == g_state.terrain.objective_y) {
        g_state.terrain.has_objective = 0;
        serial_puts("[TERRAIN] Objective reached!\n");
    }

    /* Check if reached frontier */
    if (g_state.terrain.has_frontier &&
        g_state.terrain.pos_x == g_state.terrain.frontier_x &&
        g_state.terrain.pos_y == g_state.terrain.frontier_y) {
        /* Force new frontier search on next move */
        g_state.terrain.has_frontier = 0;
        g_state.terrain.last_frontier_scan = 0;
    }

    /* Record current position in visited history BEFORE moving */
    terrain_record_visited(g_state.terrain.pos_x, g_state.terrain.pos_y);

    /* Choose direction */
    int dir = terrain_choose_direction();

    if (dir < 0) {
        /* Stuck - backtrack and force frontier search */
        g_state.terrain.stuck_count++;
        g_state.terrain.last_frontier_scan = 0;  /* Force new frontier search */
        if (g_state.terrain.path_len > 0) {
            g_state.terrain.path_len--;
            g_state.terrain.pos_x = g_state.terrain.path[g_state.terrain.path_len].x;
            g_state.terrain.pos_y = g_state.terrain.path[g_state.terrain.path_len].y;
        }
        return;
    }

    g_state.terrain.stuck_count = 0;

    /* Record current position in path */
    if (g_state.terrain.path_len < TERRAIN_PATH_LEN) {
        g_state.terrain.path[g_state.terrain.path_len].x = g_state.terrain.pos_x;
        g_state.terrain.path[g_state.terrain.path_len].y = g_state.terrain.pos_y;
        g_state.terrain.path_len++;
    }

    /* Move to new position */
    g_state.terrain.pos_x += terrain_dx[dir];
    g_state.terrain.pos_y += terrain_dy[dir];
    g_state.terrain.heading = dir;
    g_state.terrain.moves_made++;
}

/* Share terrain discoveries with swarm */
void terrain_share_discoveries(void) {
    if (!g_state.terrain.active) return;
    if (ticks - g_state.terrain.last_share < TERRAIN_SHARE_INTERVAL) return;

    g_state.terrain.last_share = ticks;

    /* Send position update (TERRAIN_MOVE) */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_TERRAIN_MOVE;
    pkt.ttl = 4;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    /* Build payload */
    pkt.payload[0] = g_state.terrain.pos_x;
    pkt.payload[1] = g_state.terrain.pos_y;
    pkt.payload[2] = g_state.terrain.heading;
    pkt.payload[3] = g_state.role;
    pkt.payload[4] = g_state.terrain.sensor_range;
    pkt.payload[5] = g_state.terrain.mode;
    pkt.payload[6] = g_state.terrain.cells_explored & 0xFF;
    pkt.payload[7] = (g_state.terrain.cells_explored >> 8) & 0xFF;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;
    g_state.terrain.reports_sent++;

    /* Log position for dashboard */
    serial_puts("[TERRAIN] node=");
    serial_put_hex(g_state.node_id);
    serial_puts(" pos=");
    serial_put_dec(g_state.terrain.pos_x);
    serial_puts(",");
    serial_put_dec(g_state.terrain.pos_y);
    serial_puts(" heading=");
    serial_put_dec(g_state.terrain.heading);
    serial_puts(" cells=");
    serial_put_dec(g_state.terrain.cells_explored);
    serial_puts("\n");

    /* Send cell reports (up to 4 cells) */
    pkt.type = PHEROMONE_TERRAIN_REPORT;
    pkt.seq = g_state.seq_counter++;

    int cells_packed = 0;
    uint8_t cx = g_state.terrain.pos_x;
    uint8_t cy = g_state.terrain.pos_y;

    /* Pack recently explored cells around current position */
    for (int dy = -2; dy <= 2 && cells_packed < 4; dy++) {
        for (int dx = -2; dx <= 2 && cells_packed < 4; dx++) {
            int nx = cx + dx;
            int ny = cy + dy;

            if (nx < 0 || nx >= TERRAIN_SIZE || ny < 0 || ny >= TERRAIN_SIZE) continue;
            if (!terrain_is_explored(nx, ny)) continue;

            int offset = 1 + cells_packed * 6;
            pkt.payload[offset + 0] = nx;
            pkt.payload[offset + 1] = ny;
            pkt.payload[offset + 2] = g_state.terrain.grid[ny][nx].base;
            pkt.payload[offset + 3] = g_state.terrain.grid[ny][nx].meta;
            pkt.payload[offset + 4] = 80;  /* Confidence */
            pkt.payload[offset + 5] = 0;   /* Reserved */
            cells_packed++;
        }
    }

    if (cells_packed > 0) {
        pkt.payload[0] = cells_packed;
        e1000_send(&pkt, sizeof(pkt));
        g_state.packets_tx++;
    }
}

/* Process terrain initialization from dashboard */
void terrain_process_init(struct nanos_pheromone* pkt) {
    /* Payload:
     * [0-3]: seed
     * [4]: difficulty
     * [5]: start_x
     * [6]: start_y
     * [7]: terrain_bias (unused for now)
     */
    terrain_init();

    g_state.terrain.seed = *(uint32_t*)(pkt->payload);

    /* Each node starts at a unique position based on node_id hash */
    /* This distributes any number of nodes across the terrain */
    uint32_t hash = g_state.node_id;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;

    /* Use hash to place node anywhere in terrain (with margin) */
    int start_x = 3 + (hash % (TERRAIN_SIZE - 6));
    int start_y = 3 + ((hash >> 8) % (TERRAIN_SIZE - 6));

    g_state.terrain.start_x = start_x;
    g_state.terrain.start_y = start_y;
    g_state.terrain.pos_x = start_x;
    g_state.terrain.pos_y = start_y;
    g_state.terrain.active = 1;
    g_state.terrain.mode = TERRAIN_MODE_EXPLORE;

    /* Generate starting area */
    terrain_sensor_scan();

    vga_set_color(0x0E);
    vga_puts(">> TERRAIN EXPLORATION: seed=");
    vga_put_hex(g_state.terrain.seed);
    vga_puts(" pos=");
    vga_put_dec(g_state.terrain.pos_x);
    vga_puts(",");
    vga_put_dec(g_state.terrain.pos_y);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[TERRAIN] Started exploration seed=");
    serial_put_hex(g_state.terrain.seed);
    serial_puts(" pos=");
    serial_put_dec(g_state.terrain.pos_x);
    serial_puts(",");
    serial_put_dec(g_state.terrain.pos_y);
    serial_puts("\n");

    /* Relay */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process terrain report from another node */
void terrain_process_report(struct nanos_pheromone* pkt) {
    if (!g_state.terrain.active) return;

    int count = pkt->payload[0];
    if (count > 4) count = 4;

    for (int i = 0; i < count; i++) {
        int offset = 1 + i * 6;
        uint8_t x = pkt->payload[offset + 0];
        uint8_t y = pkt->payload[offset + 1];
        uint8_t base = pkt->payload[offset + 2];
        uint8_t meta = pkt->payload[offset + 3];

        if (x >= TERRAIN_SIZE || y >= TERRAIN_SIZE) continue;

        /* Only update if we haven't explored this cell */
        if (!terrain_is_explored(x, y)) {
            g_state.terrain.grid[y][x].base = base;
            g_state.terrain.grid[y][x].meta = meta;
        } else {
            /* Merge threat info - take higher level */
            uint8_t their_threat = (meta >> TERRAIN_THREAT_SHIFT) & 0x07;
            uint8_t our_threat = terrain_get_threat(x, y);
            if (their_threat > our_threat) {
                terrain_set_threat(x, y, their_threat);
            }
        }
    }

    /* Relay */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process move update from another explorer */
void terrain_process_move(struct nanos_pheromone* pkt) {
    if (!g_state.terrain.active) return;

    uint32_t sender = pkt->node_id;
    uint8_t x = pkt->payload[0];
    uint8_t y = pkt->payload[1];
    uint8_t heading = pkt->payload[2];
    uint8_t role = pkt->payload[3];
    uint8_t sensor_range = pkt->payload[4];
    uint16_t cells = pkt->payload[6] | (pkt->payload[7] << 8);

    /* Update explorer tracking */
    int slot = -1;
    for (int i = 0; i < TERRAIN_MAX_EXPLORERS; i++) {
        if (g_state.terrain.explorers[i].node_id == sender) {
            slot = i;
            break;
        }
        if (slot < 0 && g_state.terrain.explorers[i].node_id == 0) {
            slot = i;
        }
    }

    if (slot >= 0) {
        g_state.terrain.explorers[slot].node_id = sender;
        g_state.terrain.explorers[slot].x = x;
        g_state.terrain.explorers[slot].y = y;
        g_state.terrain.explorers[slot].role = role;
        g_state.terrain.explorers[slot].sensor_range = sensor_range;
        g_state.terrain.explorers[slot].heading = heading;
        g_state.terrain.explorers[slot].last_seen = ticks;
        g_state.terrain.explorers[slot].cells_explored = cells;
    }

    /* Relay */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process threat report */
void terrain_process_threat(struct nanos_pheromone* pkt) {
    uint8_t x = pkt->payload[0];
    uint8_t y = pkt->payload[1];
    uint8_t level = pkt->payload[2];

    if (x < TERRAIN_SIZE && y < TERRAIN_SIZE) {
        uint8_t current = terrain_get_threat(x, y);
        if (level > current) {
            terrain_set_threat(x, y, level);
        }
    }

    /* Log if significant */
    if (level >= THREAT_DETECTED) {
        serial_puts("[TERRAIN] Threat Lv");
        serial_put_dec(level);
        serial_puts(" at ");
        serial_put_dec(x);
        serial_puts(",");
        serial_put_dec(y);
        serial_puts("\n");
    }

    /* Relay with high priority */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Process strategy command */
void terrain_process_strategy(struct nanos_pheromone* pkt) {
    if (!g_state.terrain.active) return;

    uint8_t cmd = pkt->payload[0];
    uint8_t target_x = pkt->payload[1];
    uint8_t target_y = pkt->payload[2];

    switch (cmd) {
        case STRATEGY_REGROUP:
            g_state.terrain.objective_x = target_x % TERRAIN_SIZE;
            g_state.terrain.objective_y = target_y % TERRAIN_SIZE;
            g_state.terrain.has_objective = 1;
            g_state.terrain.mode = TERRAIN_MODE_REGROUP;
            serial_puts("[TERRAIN] REGROUP to ");
            serial_put_dec(target_x);
            serial_puts(",");
            serial_put_dec(target_y);
            serial_puts("\n");
            break;

        case STRATEGY_SPREAD:
            g_state.terrain.has_objective = 0;
            g_state.terrain.mode = TERRAIN_MODE_EXPLORE;
            serial_puts("[TERRAIN] SPREAD - free exploration\n");
            break;

        case STRATEGY_RETREAT:
            g_state.terrain.objective_x = target_x % TERRAIN_SIZE;
            g_state.terrain.objective_y = target_y % TERRAIN_SIZE;
            g_state.terrain.has_objective = 1;
            g_state.terrain.mode = TERRAIN_MODE_RETREAT;
            serial_puts("[TERRAIN] RETREAT to ");
            serial_put_dec(target_x);
            serial_puts(",");
            serial_put_dec(target_y);
            serial_puts("\n");
            break;

        case STRATEGY_ADVANCE:
            g_state.terrain.objective_x = target_x % TERRAIN_SIZE;
            g_state.terrain.objective_y = target_y % TERRAIN_SIZE;
            g_state.terrain.has_objective = 1;
            g_state.terrain.mode = TERRAIN_MODE_ADVANCE;
            serial_puts("[TERRAIN] ADVANCE to ");
            serial_put_dec(target_x);
            serial_puts(",");
            serial_put_dec(target_y);
            serial_puts("\n");
            break;

        default:
            break;
    }

    /* Relay */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Integrate tactical DETECT events into terrain threat map */
void terrain_integrate_detections(void) {
    if (!g_state.terrain.active) return;

    /* Scale factor: map tactical coordinates to 32x32 grid */
    /* Assume tactical positions are in mm, world is ~3200m square */
    #define WORLD_SIZE_MM   3200000
    #define COORD_TO_GRID(c) (((c) + WORLD_SIZE_MM/2) / (WORLD_SIZE_MM / TERRAIN_SIZE))

    for (int i = 0; i < g_state.tactical.event_count; i++) {
        if (g_state.tactical.events[i].alert_level == 0) continue;

        /* Convert position to grid coordinates */
        int32_t ex = g_state.tactical.events[i].est_pos_x;
        int32_t ey = g_state.tactical.events[i].est_pos_y;

        int gx = COORD_TO_GRID(ex);
        int gy = COORD_TO_GRID(ey);

        if (gx < 0 || gx >= TERRAIN_SIZE || gy < 0 || gy >= TERRAIN_SIZE) continue;

        /* Map alert level to threat level */
        uint8_t threat = THREAT_SUSPECTED;
        uint8_t alert = g_state.tactical.events[i].alert_level;
        if (alert >= 4) threat = THREAT_CRITICAL;
        else if (alert >= 3) threat = THREAT_ACTIVE;
        else if (alert >= 2) threat = THREAT_CONFIRMED;
        else if (alert >= 1) threat = THREAT_DETECTED;

        /* Update if new threat is higher */
        uint8_t current = terrain_get_threat(gx, gy);
        if (threat > current) {
            terrain_set_threat(gx, gy, threat);

            /* Also track in threats array for dashboard */
            int slot = -1;
            for (int t = 0; t < TERRAIN_MAX_THREATS; t++) {
                if (g_state.terrain.threats[t].x == gx &&
                    g_state.terrain.threats[t].y == gy) {
                    slot = t;
                    break;
                }
                if (slot < 0 && g_state.terrain.threats[t].threat_level == 0) {
                    slot = t;
                }
            }
            if (slot >= 0) {
                g_state.terrain.threats[slot].x = gx;
                g_state.terrain.threats[slot].y = gy;
                g_state.terrain.threats[slot].threat_level = threat;
                g_state.terrain.threats[slot].detect_types =
                    g_state.tactical.events[i].detect_types;
                g_state.terrain.threats[slot].confidence =
                    g_state.tactical.events[i].reporter_count * 25;
                g_state.terrain.threats[slot].last_updated = ticks;
                if (g_state.terrain.threats[slot].first_seen == 0) {
                    g_state.terrain.threats[slot].first_seen = ticks;
                }
            }

            serial_puts("[TERRAIN] Threat from DETECT at ");
            serial_put_dec(gx);
            serial_puts(",");
            serial_put_dec(gy);
            serial_puts(" level=");
            serial_put_dec(threat);
            serial_puts("\n");
        }
    }

    #undef WORLD_SIZE_MM
    #undef COORD_TO_GRID
}
