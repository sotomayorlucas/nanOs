/*
 * NanOS - Core Types and Structures
 * The DNA of the swarm cell - v0.3 with collective intelligence
 */

#ifndef NANOS_H
#define NANOS_H

/* ==========================================================================
 * Freestanding Type Definitions (no libc dependency)
 * ========================================================================== */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;
typedef signed long long   int64_t;
typedef uint32_t           size_t;
typedef uint32_t           uintptr_t;
typedef _Bool              bool;
#define true  1
#define false 0
#define NULL  ((void*)0)

/* ==========================================================================
 * Magic Constants
 * ========================================================================== */
#define NANOS_MAGIC         0x4E414E4F  /* "NANO" in hex */
#define MULTIBOOT2_MAGIC    0x36D76289
#define NANOS_VERSION       0x0006      /* Protocol version 0.6 */

/* ==========================================================================
 * Pheromone Types - Extended language
 * ========================================================================== */
#define PHEROMONE_HELLO     0x01    /* Heartbeat with gradient info */
#define PHEROMONE_DATA      0x02    /* Information payload */
#define PHEROMONE_ALARM     0x03    /* Danger detected */
#define PHEROMONE_ECHO      0x04    /* Acknowledgment */
#define PHEROMONE_ELECTION  0x05    /* Queen election vote */
#define PHEROMONE_CORONATION 0x06   /* New queen announcement */
#define PHEROMONE_QUERY     0x07    /* Request for routing */
#define PHEROMONE_QUEEN_CMD 0x10    /* Command from queen */

/* Workload pheromones */
#define PHEROMONE_KV_SET    0x20    /* Key-Value store: SET */
#define PHEROMONE_KV_GET    0x21    /* Key-Value store: GET request */
#define PHEROMONE_KV_REPLY  0x22    /* Key-Value store: GET response */
#define PHEROMONE_TASK      0x30    /* Distributed task from queen */
#define PHEROMONE_RESULT    0x31    /* Task result from worker */
#define PHEROMONE_SENSOR    0x40    /* Sensor data report */
#define PHEROMONE_AGGREGATE 0x41    /* Aggregated sensor stats */

/* Global Compute pheromones - MapReduce style */
#define PHEROMONE_JOB_START 0x50    /* New global job announcement */
#define PHEROMONE_JOB_CHUNK 0x51    /* Work chunk assignment */
#define PHEROMONE_JOB_DONE  0x52    /* Chunk completion report */
#define PHEROMONE_JOB_RESULT 0x53   /* Final aggregated result */
#define PHEROMONE_JOB_STATUS 0x54   /* Job status query/response */

#define PHEROMONE_REBIRTH   0xFE    /* Cell death notification */
#define PHEROMONE_DIE       0xFF    /* Kill command */

/* ==========================================================================
 * Cell Roles
 * ========================================================================== */
#define ROLE_WORKER         0x01    /* Default: process data, relay */
#define ROLE_EXPLORER       0x02    /* Fast heartbeat, discovers */
#define ROLE_SENTINEL       0x03    /* Monitors anomalies */
#define ROLE_QUEEN          0x04    /* Issues authenticated commands */
#define ROLE_CANDIDATE      0x05    /* Running for queen election */

/* ==========================================================================
 * Quorum Sensing Constants
 * ========================================================================== */
#define NEIGHBOR_TABLE_SIZE 16      /* Track up to 16 neighbors */
#define NEIGHBOR_TIMEOUT    500     /* 5 seconds at 100Hz */
#define QUORUM_WINDOW       500     /* 5 seconds for role decisions */

/* Role balance thresholds */
#define MIN_SENTINEL_RATIO  10      /* Want at least 10% sentinels */
#define MIN_EXPLORER_RATIO  10      /* Want at least 10% explorers */
#define QUEEN_ABSENCE_TIME  1000    /* 10 seconds without queen = election */

/* Transition probabilities (out of 100) */
#define TRANSITION_PROB     50      /* 50% chance to transition */
#define ELECTION_VOTE_PROB  30      /* 30% chance to vote for self */

/* ==========================================================================
 * Gradient Routing Constants
 * ========================================================================== */
#define GRADIENT_INFINITY   255     /* Unknown distance to queen */
#define GRADIENT_MAX_HOPS   15      /* Maximum network diameter */
#define ROUTE_CACHE_SIZE    8       /* Remember routes to N destinations */

/* ==========================================================================
 * Security Constants
 * ========================================================================== */
#define HMAC_KEY_SIZE       16
#define HMAC_TAG_SIZE       8

#define SWARM_SECRET_0      0xDEADBEEF
#define SWARM_SECRET_1      0xCAFEBABE
#define SWARM_SECRET_2      0x8BADF00D
#define SWARM_SECRET_3      0xFEEDFACE

/* ==========================================================================
 * Gossip Protocol Constants
 * ========================================================================== */
#define GOSSIP_CACHE_SIZE   32
#define GOSSIP_IMMUNITY_MS  500
#define GOSSIP_PROB_BASE    100
#define GOSSIP_PROB_DECAY   20
#define ALARM_MAX_ECHOES    5

/* ==========================================================================
 * Bloom Filter - O(1) Deduplication
 * ========================================================================== */
#define BLOOM_BITS          256     /* 256 bits = 32 bytes */
#define BLOOM_BYTES         (BLOOM_BITS / 8)
#define BLOOM_HASH_K        3       /* Number of hash functions */
#define BLOOM_SLOTS         4       /* Rotating time windows */
#define BLOOM_WINDOW_MS     500     /* 500ms per window = 2s total */

/* ==========================================================================
 * Tactical Intelligence System
 * ========================================================================== */
/* Detection types */
#define DETECT_NONE         0x00
#define DETECT_MOTION       0x01    /* PIR, accelerometer */
#define DETECT_ACOUSTIC     0x02    /* Microphone, ultrasound */
#define DETECT_THERMAL      0x03    /* IR, temperature anomaly */
#define DETECT_RF           0x04    /* Radio emissions */
#define DETECT_MAGNETIC     0x05    /* Magnetometer (vehicles) */
#define DETECT_PRESSURE     0x06    /* Footsteps, vibrations */

/* Alert levels */
#define ALERT_NONE          0
#define ALERT_ANOMALY       1       /* Single node detection */
#define ALERT_CONTACT       2       /* 2+ nodes, low confidence */
#define ALERT_PROBABLE      3       /* 3+ nodes, temporal correlation */
#define ALERT_CONFIRMED     4       /* High confidence, multiple types */
#define ALERT_CRITICAL      5       /* Confirmed persistent threat */

/* Sectors (8 = 45 degrees each) */
#define SECTOR_COUNT        8

/* Tactical pheromones */
#define PHEROMONE_DETECT    0x60    /* Detection report */
#define PHEROMONE_CORRELATE 0x61    /* Correlated event */
#define PHEROMONE_TRACK     0x62    /* Target tracking */
#define PHEROMONE_CLEAR     0x63    /* Sector cleared */

/* Correlation settings */
#define CORRELATION_WINDOW_MS   3000    /* Temporal window */
#define CORRELATION_MIN_NODES   2       /* Min nodes for correlation */
#define MAX_ACTIVE_EVENTS       4       /* Simultaneous events */
#define EVENT_TIMEOUT_MS        10000   /* Event expires */

/* ==========================================================================
 * Maze Exploration - Collaborative Pathfinding
 * ========================================================================== */
#define MAZE_SIZE           16      /* 16x16 grid (256 cells) */
#define MAZE_CELLS          (MAZE_SIZE * MAZE_SIZE)

/* Cell states */
#define MAZE_WALL           0xFF    /* Impassable wall */
#define MAZE_UNEXPLORED     0x00    /* Not yet explored */
#define MAZE_EXPLORED       0x01    /* Explored by some node */
#define MAZE_PATH           0x02    /* Part of solution path */
#define MAZE_START          0x10    /* Start position */
#define MAZE_GOAL           0x20    /* Goal position */

/* Maze pheromones */
#define PHEROMONE_MAZE_INIT     0x70    /* Maze definition from dashboard */
#define PHEROMONE_MAZE_DISCOVER 0x71    /* Cell discovery report */
#define PHEROMONE_MAZE_PATH     0x72    /* Path segment found */
#define PHEROMONE_MAZE_SOLVED   0x73    /* Solution path announcement */
#define PHEROMONE_MAZE_MOVE     0x74    /* Node movement update */

/* Exploration settings */
#define MAZE_MOVE_INTERVAL      10      /* Ticks between moves (100ms) */
#define MAZE_SHARE_INTERVAL     50      /* Share discoveries every 500ms */
#define MAZE_MAX_EXPLORERS      8       /* Max simultaneous explorers */

/* Direction constants */
#define DIR_NORTH   0
#define DIR_EAST    1
#define DIR_SOUTH   2
#define DIR_WEST    3
#define DIR_COUNT   4

/* ==========================================================================
 * Tactical Terrain Exploration System
 * ========================================================================== */
#define TERRAIN_SIZE        32      /* 32x32 grid (1024 cells) */
#define TERRAIN_CELLS       (TERRAIN_SIZE * TERRAIN_SIZE)

/* Terrain Types (3 bits, stored in base[2:0]) */
#define TERRAIN_OPEN        0x00    /* Open ground, easy movement */
#define TERRAIN_FOREST      0x01    /* Trees, concealment, slower */
#define TERRAIN_URBAN       0x02    /* Buildings, high cover */
#define TERRAIN_WATER       0x03    /* Impassable or very slow */
#define TERRAIN_ROCKY       0x04    /* Difficult, elevation changes */
#define TERRAIN_MARSH       0x05    /* Very slow, low cover */
#define TERRAIN_ROAD        0x06    /* Fast movement, no cover */
#define TERRAIN_IMPASSABLE  0x07    /* Walls, cliffs - cannot traverse */

/* Elevation (3 bits, stored in base[5:3], 0-7 = 0m to 70m) */
#define TERRAIN_ELEV_SHIFT  3
#define TERRAIN_ELEV_MASK   0x38

/* Cover Rating (2 bits, stored in base[7:6]) */
#define COVER_NONE          0x00    /* No protection */
#define COVER_LOW           0x01    /* 25% protection */
#define COVER_MEDIUM        0x02    /* 50% protection */
#define COVER_HIGH          0x03    /* 75% protection */
#define TERRAIN_COVER_SHIFT 6
#define TERRAIN_COVER_MASK  0xC0

/* Threat Levels (3 bits, stored in meta[7:5]) */
#define THREAT_NONE         0x00    /* Area clear */
#define THREAT_UNKNOWN      0x01    /* Not yet assessed */
#define THREAT_SUSPECTED    0x02    /* Possible enemy presence */
#define THREAT_DETECTED     0x03    /* Single detection */
#define THREAT_CONFIRMED    0x04    /* Multiple confirmations */
#define THREAT_ACTIVE       0x05    /* Active engagement */
#define THREAT_CRITICAL     0x06    /* Overwhelming force */
#define TERRAIN_THREAT_SHIFT 5
#define TERRAIN_THREAT_MASK 0xE0

/* Strategic Value (2 bits, stored in meta[4:3]) */
#define STRATEGIC_NONE      0x00    /* No special value */
#define STRATEGIC_LOW       0x01    /* Minor objective */
#define STRATEGIC_MEDIUM    0x02    /* Important objective */
#define STRATEGIC_HIGH      0x03    /* Critical objective */
#define TERRAIN_STRAT_SHIFT 3
#define TERRAIN_STRAT_MASK  0x18

/* Passability (2 bits, stored in meta[2:1]) */
#define PASS_BLOCKED        0x00    /* Cannot traverse */
#define PASS_DIFFICULT      0x01    /* 3x movement cost */
#define PASS_SLOW           0x02    /* 2x movement cost */
#define PASS_NORMAL         0x03    /* 1x movement cost */
#define TERRAIN_PASS_SHIFT  1
#define TERRAIN_PASS_MASK   0x06

/* Explored flag (1 bit, stored in meta[0]) */
#define TERRAIN_EXPLORED    0x01

/* Terrain Pheromone Types (0x80-0x8F) */
#define PHEROMONE_TERRAIN_INIT      0x80    /* Map initialization from dashboard */
#define PHEROMONE_TERRAIN_REPORT    0x81    /* Cell discovery report */
#define PHEROMONE_TERRAIN_THREAT    0x82    /* Threat report */
#define PHEROMONE_TERRAIN_OBJECTIVE 0x83    /* Strategic point marking */
#define PHEROMONE_TERRAIN_MOVE      0x84    /* Explorer position update */
#define PHEROMONE_TERRAIN_STRATEGY  0x85    /* Formation/route commands */
#define PHEROMONE_TERRAIN_COMPLETE  0x86    /* Area fully explored */
#define PHEROMONE_TERRAIN_ROUTE     0x87    /* Optimal path segment */
#define PHEROMONE_STIGMERGIA        0x88    /* v0.5: Digital pheromone broadcast */
#define PHEROMONE_LAST_WILL         0x89    /* v0.5: Dying node's testament (Black Box) */
#define PHEROMONE_AIS_ALERT         0x8A    /* v0.6: AIS anomaly broadcast */
#define PHEROMONE_AIS_SIGNATURE     0x8B    /* v0.6: Share detector signature */
#define PHEROMONE_HWVAL_STATUS      0x8C    /* v0.6: Hardware validation status */
#define PHEROMONE_HWVAL_ALERT       0x8D    /* v0.6: Hardware integrity violation */

/* Sensor Ranges by Role */
#define SENSOR_RANGE_SCOUT      6   /* EXPLORER role: 6 cell radius */
#define SENSOR_RANGE_SENTINEL   4   /* SENTINEL role: 4 cell radius, high threat detect */
#define SENSOR_RANGE_WORKER     3   /* WORKER role: 3 cell radius */
#define SENSOR_RANGE_QUEEN      5   /* QUEEN role: 5 cell radius */

/* Movement Modes */
#define TERRAIN_MODE_EXPLORE    0   /* Free exploration */
#define TERRAIN_MODE_PATROL     1   /* Defined route patrol */
#define TERRAIN_MODE_RETREAT    2   /* Moving to safety */
#define TERRAIN_MODE_REGROUP    3   /* Moving to rally point */
#define TERRAIN_MODE_ADVANCE    4   /* Moving toward objective */

/* Strategy Commands */
#define STRATEGY_SPREAD         0x01    /* Expand coverage */
#define STRATEGY_REGROUP        0x02    /* Rally to point */
#define STRATEGY_PATROL         0x03    /* Define patrol route */
#define STRATEGY_RETREAT        0x04    /* Evacuation */
#define STRATEGY_ADVANCE        0x05    /* Move toward objective */
#define STRATEGY_HOLD           0x06    /* Defensive position */

/* Timing Intervals */
#define TERRAIN_MOVE_INTERVAL   15      /* 150ms between moves */
#define TERRAIN_SHARE_INTERVAL  30      /* 300ms between broadcasts */
#define TERRAIN_THREAT_INTERVAL 50      /* 500ms threat assessment */

/* Limits */
#define TERRAIN_MAX_EXPLORERS   8       /* Max tracked explorers */
#define TERRAIN_MAX_OBJECTIVES  4       /* Max objectives */
#define TERRAIN_MAX_THREATS     8       /* Max tracked threats */
#define TERRAIN_PATH_LEN        32      /* Breadcrumb path length */

/* ==========================================================================
 * Apoptosis Constants
 * ========================================================================== */
#define HEAP_CRITICAL_PCT   90
#define MAX_CELL_LIFETIME   360000

/* ==========================================================================
 * Workload Constants
 * ========================================================================== */
/* Key-Value Store */
#define KV_STORE_SIZE       8       /* Key-value pairs per node */
#define KV_KEY_SIZE         8       /* Max key length */
#define KV_VALUE_SIZE       16      /* Max value length */
#define KV_REPLICATION      2       /* Replicate to N neighbors */

/* Task Distribution */
#define TASK_PRIME_CHECK    0x01    /* Check if number is prime */
#define TASK_FACTORIAL      0x02    /* Calculate factorial */
#define TASK_FIBONACCI      0x03    /* Calculate fibonacci */
#define MAX_PENDING_TASKS   4       /* Tasks waiting for results */

/* Sensor Network */
#define SENSOR_INTERVAL     200     /* Generate sensor data every 2s */
#define SENSOR_TYPES        3       /* Temperature, humidity, pressure */
#define AGGREGATE_INTERVAL  500     /* Aggregate every 5s */

/* Global Compute - MapReduce style distributed computing */
#define JOB_PRIME_SEARCH    0x01    /* Find primes in range */
#define JOB_MONTE_CARLO_PI  0x02    /* Estimate Pi with Monte Carlo */
#define JOB_HASH_SEARCH     0x03    /* Find hash preimage (educational) */
#define JOB_REDUCE_SUM      0x04    /* Parallel sum reduction */
#define JOB_WORD_COUNT      0x05    /* Distributed word frequency */

#define MAX_ACTIVE_JOBS     2       /* Jobs in flight simultaneously */
#define MAX_JOB_CHUNKS      16      /* Chunks per job */
#define CHUNK_TIMEOUT       500     /* 5 seconds to complete chunk */

/* ==========================================================================
 * The Pheromone Packet v0.3 - 64 bytes with gradient support
 * ========================================================================== */
struct nanos_pheromone {
    /* Header - 16 bytes */
    uint32_t magic;         /* Must be NANOS_MAGIC */
    uint32_t node_id;       /* Sender's ID */
    uint8_t  type;          /* PHEROMONE_* constant */
    uint8_t  ttl;           /* Hops remaining */
    uint8_t  flags;         /* Bit 0: auth, Bit 1-3: role, Bit 4-7: reserved */
    uint8_t  version;       /* Protocol version */
    uint32_t seq;           /* Sequence number */

    /* Routing - 8 bytes */
    uint32_t dest_id;       /* Destination node (0 = broadcast) */
    uint8_t  distance;      /* Sender's distance to queen */
    uint8_t  hop_count;     /* Hops traveled so far */
    uint8_t  via_node_lo;   /* Low byte of best next-hop */
    uint8_t  via_node_hi;   /* High byte of best next-hop */

    /* Security - 8 bytes */
    uint8_t  hmac[HMAC_TAG_SIZE];

    /* Payload - 32 bytes */
    uint8_t  payload[32];
} __attribute__((packed));

_Static_assert(sizeof(struct nanos_pheromone) == 64, "Pheromone must be 64 bytes");

/* Flags bitfield */
#define FLAG_AUTHENTICATED  (1 << 0)
#define FLAG_ROLE_SHIFT     1
#define FLAG_ROLE_MASK      0x0E
#define FLAG_URGENT         (1 << 4)
#define FLAG_ROUTED         (1 << 5)  /* Packet is being routed, not broadcast */

#define PKT_GET_ROLE(pkt)   (((pkt)->flags & FLAG_ROLE_MASK) >> FLAG_ROLE_SHIFT)
#define PKT_SET_ROLE(pkt, r) ((pkt)->flags = ((pkt)->flags & ~FLAG_ROLE_MASK) | ((r) << FLAG_ROLE_SHIFT))

/* ==========================================================================
 * Neighbor Entry - For quorum sensing and Hebbian routing
 * ========================================================================== */
struct neighbor_entry {
    uint32_t node_id;       /* Neighbor's ID (0 = empty slot) */
    uint32_t last_seen;     /* Tick count when last heard */
    uint8_t  role;          /* Neighbor's role */
    uint8_t  distance;      /* Neighbor's distance to queen */
    uint16_t packets;       /* Packets received from this neighbor */

    /*
     * Hebbian Synaptic Weight (v0.5)
     * Implements "neurons that fire together, wire together"
     * Range: 0 (dead connection) to 255 (perfect connection)
     * Initial value: 128 (neutral)
     * LTP: Successful comms strengthen connection (+15)
     * LTD: Failed comms weaken connection (-40)
     */
    uint8_t  synaptic_weight;   /* Connection strength (0-255) */
};

/* ==========================================================================
 * Route Entry - For gradient routing
 * ========================================================================== */
struct route_entry {
    uint32_t dest_id;       /* Destination node ID */
    uint32_t via_id;        /* Next hop node ID */
    uint32_t updated;       /* When this route was updated */
    uint8_t  distance;      /* Hops to destination */
    uint8_t  valid;         /* Is this route still valid? */
};

/* ==========================================================================
 * Election State - For queen elections
 * ========================================================================== */
struct election_state {
    uint32_t election_id;       /* Current election ID (random) */
    uint32_t started_at;        /* When election started */
    uint32_t last_ended;        /* When last election ended (for cooldown) */
    uint32_t my_vote;           /* Who I voted for */
    uint32_t votes_received;    /* Votes for me */
    uint32_t highest_vote_id;   /* Highest ID seen in election */
    uint8_t  participating;     /* Am I in an election? */
    uint8_t  phase;             /* 0=none, 1=voting, 2=counting */
};

#define ELECTION_PHASE_NONE     0
#define ELECTION_PHASE_VOTING   1
#define ELECTION_PHASE_COUNTING 2
#define ELECTION_DURATION       500     /* 5 seconds to vote (longer for convergence) */
#define ELECTION_COOLDOWN       1000    /* 10 seconds cooldown after election */

/* ==========================================================================
 * Gossip Cache Entry
 * ========================================================================== */
struct gossip_entry {
    uint32_t hash;
    uint32_t timestamp;
    uint8_t  count;
    uint8_t  relayed;
};

/* ==========================================================================
 * Node State - Expanded for collective intelligence
 * ========================================================================== */
struct nanos_state {
    /* Identity */
    uint32_t node_id;
    uint8_t  role;
    uint8_t  previous_role;     /* Role before transition (for revert) */
    uint32_t generation;

    /* Timing */
    uint32_t boot_time;
    uint32_t last_heartbeat;
    uint32_t seq_counter;
    uint32_t last_role_check;   /* When we last evaluated role transition */

    /* Statistics */
    uint32_t packets_rx;
    uint32_t packets_tx;
    uint32_t packets_dropped;
    uint32_t packets_routed;    /* Packets forwarded via routing */
    uint32_t alarms_relayed;

    /* Neighbor tracking (Quorum Sensing) */
    struct neighbor_entry neighbors[NEIGHBOR_TABLE_SIZE];
    uint8_t  neighbor_count;            /* Active neighbors */
    uint8_t  role_counts[8];            /* Count per role type */
    uint32_t last_queen_seen;           /* Tick when we last heard a queen */
    uint32_t known_queen_id;            /* ID of the known queen */

    /* Gradient routing */
    uint8_t  distance_to_queen;         /* Our distance to queen */
    uint32_t gradient_via;              /* Next hop toward queen */
    struct route_entry routes[ROUTE_CACHE_SIZE];

    /* Election state */
    struct election_state election;

    /* Gossip cache */
    struct gossip_entry gossip_cache[GOSSIP_CACHE_SIZE];
    uint8_t gossip_index;

    /* Memory health */
    uint32_t heap_used;
    uint32_t heap_size;

    /* ==========================================================================
     * Workload State
     * ========================================================================== */
    /* Key-Value Store */
    struct {
        uint8_t  key[KV_KEY_SIZE];
        uint8_t  value[KV_VALUE_SIZE];
        uint8_t  valid;
    } kv_store[KV_STORE_SIZE];
    uint8_t kv_count;

    /* Task Distribution (queen only) */
    struct {
        uint32_t task_id;
        uint8_t  task_type;
        uint32_t input;
        uint32_t assigned_to;
        uint32_t sent_at;
        uint8_t  completed;
        uint32_t result;
    } pending_tasks[MAX_PENDING_TASKS];
    uint32_t tasks_sent;
    uint32_t tasks_completed;

    /* Sensor Network */
    uint32_t last_sensor_reading;
    uint32_t last_aggregate;
    struct {
        int32_t  value;          /* Current sensor value */
        int32_t  sum;            /* Sum for averaging */
        int32_t  min;
        int32_t  max;
        uint32_t count;          /* Readings received */
    } sensors[SENSOR_TYPES];     /* 0=temp, 1=humidity, 2=pressure */

    /* Global Compute - MapReduce Jobs */
    struct {
        uint32_t job_id;            /* Unique job identifier */
        uint8_t  job_type;          /* JOB_* constant */
        uint8_t  active;            /* Is this job running? */
        uint32_t param1;            /* Job-specific param (e.g., range start) */
        uint32_t param2;            /* Job-specific param (e.g., range end) */
        uint32_t chunks_total;      /* Total chunks in job */
        uint32_t chunks_done;       /* Completed chunks */
        uint64_t result;            /* Aggregated result */
        uint32_t started_at;        /* When job started */
        uint32_t coordinator_id;    /* Node responsible for aggregation */
    } active_jobs[MAX_ACTIVE_JOBS];

    /* Current chunk being processed */
    struct {
        uint32_t job_id;
        uint8_t  job_type;
        uint32_t chunk_id;
        uint32_t range_start;
        uint32_t range_end;
        uint8_t  processing;
    } current_chunk;

    uint32_t jobs_completed;
    uint32_t chunks_processed;

    /* ==========================================================================
     * Bloom Filter Deduplication State
     * ========================================================================== */
    struct {
        uint8_t  bits[BLOOM_SLOTS][BLOOM_BYTES];  /* Rotating bloom filters */
        uint8_t  current_slot;
        uint32_t slot_start_tick;
        uint32_t insertions;
        uint32_t duplicates_blocked;
    } bloom;

    /* ==========================================================================
     * Tactical Intelligence State
     * ========================================================================== */
    struct {
        /* Local detections pending correlation */
        struct {
            uint8_t  detect_type;
            uint8_t  confidence;
            uint8_t  sector;
            uint8_t  intensity;
            uint32_t timestamp;
            int16_t  pos_x, pos_y;
        } local_detections[4];
        uint8_t local_count;

        /* Active correlated events */
        struct {
            uint32_t event_id;
            uint8_t  alert_level;
            uint8_t  detect_types;      /* Bitmap of DETECT_* */
            uint8_t  sector;
            uint8_t  reporter_count;
            uint32_t first_seen;
            uint32_t last_seen;
            int32_t  est_pos_x, est_pos_y;
            uint32_t reporters[4];      /* Node IDs */
        } events[MAX_ACTIVE_EVENTS];
        uint8_t event_count;

        /* Node position (for correlation) */
        int32_t my_pos_x, my_pos_y;
        uint8_t my_sector;

        /* Stats */
        uint32_t detections_sent;
        uint32_t correlations_made;
        uint8_t  sector_activity[SECTOR_COUNT];
    } tactical;

    /* ==========================================================================
     * Maze Exploration State
     * ========================================================================== */
    struct {
        /* Shared maze knowledge (16x16 = 256 bytes) */
        uint8_t  grid[MAZE_SIZE][MAZE_SIZE];  /* Cell states */

        /* Explorer position */
        uint8_t  pos_x, pos_y;          /* Current position */
        uint8_t  start_x, start_y;      /* Start position */
        uint8_t  goal_x, goal_y;        /* Goal position */

        /* Exploration state */
        uint8_t  active;                /* Am I exploring? */
        uint8_t  solved;                /* Has maze been solved? */
        uint8_t  stuck_count;           /* Consecutive failed moves */
        uint32_t last_move;             /* Tick of last movement */
        uint32_t last_share;            /* Tick of last discovery share */

        /* Path tracking (breadcrumb trail) */
        struct {
            uint8_t x, y;
        } path[64];                     /* Path from start */
        uint8_t  path_len;

        /* Other explorers (collaborative) */
        struct {
            uint32_t node_id;
            uint8_t  x, y;
            uint32_t last_seen;
        } explorers[MAZE_MAX_EXPLORERS];

        /* Stats */
        uint32_t cells_explored;        /* Cells I discovered */
        uint32_t moves_made;
        uint32_t discoveries_shared;
    } maze;

    /* ==========================================================================
     * Tactical Terrain Exploration State
     * ========================================================================== */
    struct {
        /* Terrain grid (32x32 x 2 bytes = 2KB) */
        struct {
            uint8_t base;   /* [7:6]cover | [5:3]elevation | [2:0]terrain */
            uint8_t meta;   /* [7:5]threat | [4:3]strategic | [2:1]pass | [0]explored */
        } grid[TERRAIN_SIZE][TERRAIN_SIZE];

        /* Procedural generation seed */
        uint32_t seed;

        /* Explorer position and state */
        uint8_t  pos_x, pos_y;          /* Current position */
        uint8_t  start_x, start_y;      /* Starting position */
        uint8_t  heading;               /* 0-7 for 8 directions */
        uint8_t  sensor_range;          /* Based on role */
        uint8_t  active;                /* Exploration active? */
        uint8_t  mode;                  /* TERRAIN_MODE_* */
        uint8_t  stuck_count;           /* Consecutive failed moves */

        /* Timing */
        uint32_t last_move;             /* Tick of last movement */
        uint32_t last_share;            /* Tick of last broadcast */
        uint32_t last_threat_check;     /* Tick of last threat assessment */

        /* Path tracking (breadcrumb trail) */
        struct {
            uint8_t x, y;
        } path[TERRAIN_PATH_LEN];
        uint8_t  path_len;

        /* Visited history (circular buffer for anti-looping) */
        struct {
            uint8_t x, y;
        } visited[32];
        uint8_t  visited_head;              /* Next write index */
        uint8_t  visited_count;             /* Number of valid entries */

        /* Frontier tracking (unexplored cells on boundary) */
        uint8_t  frontier_x, frontier_y;    /* Current target frontier */
        uint8_t  has_frontier;              /* Valid frontier target? */
        uint32_t last_frontier_scan;        /* Tick of last frontier scan */

        /* Current objective */
        uint8_t  objective_x, objective_y;
        uint8_t  has_objective;
        uint8_t  objective_type;        /* 0=explore, 1=capture, 2=defend, 3=evacuate */

        /* Other explorers tracking */
        struct {
            uint32_t node_id;
            uint8_t  x, y;
            uint8_t  role;
            uint8_t  sensor_range;
            uint8_t  heading;
            uint32_t last_seen;
            uint16_t cells_explored;
        } explorers[TERRAIN_MAX_EXPLORERS];

        /* Objectives */
        struct {
            uint8_t  x, y;
            uint8_t  type;              /* 0=resource, 1=capture, 2=defend, 3=evacuate */
            uint8_t  priority;
            uint8_t  status;            /* 0=pending, 1=active, 2=complete, 3=failed */
            uint32_t marked_by;
        } objectives[TERRAIN_MAX_OBJECTIVES];
        uint8_t objective_count;

        /* Threat tracking */
        struct {
            uint8_t  x, y;
            uint8_t  threat_level;
            uint8_t  detect_types;      /* Bitmap from tactical system */
            uint8_t  confidence;
            uint8_t  reporter_count;
            uint32_t first_seen;
            uint32_t last_updated;
        } threats[TERRAIN_MAX_THREATS];
        uint8_t threat_count;

        /* Statistics */
        uint32_t cells_explored;
        uint32_t cells_generated;
        uint32_t threats_reported;
        uint32_t objectives_found;
        uint32_t moves_made;
        uint32_t reports_sent;

        /* =======================================================================
         * Stigmergia - Digital Pheromones (v0.5)
         * "Ants don't memorize the map; they leave chemicals that evaporate"
         *
         * Memory layout: 16x16 grid × 2 bytes = 512 bytes
         * Each byte stores 2 pheromone types as nibbles:
         *   pheromones[y][x][0] = [danger:4][queen:4]
         *   pheromones[y][x][1] = [resource:4][avoid:4]
         * ======================================================================= */
        #define STIGMERGIA_GRID_SIZE    16  /* 16x16 coarse grid */

        struct {
            uint8_t data[2];    /* [danger|queen], [resource|avoid] */
        } pheromones[16][16];   /* 512 bytes */

        uint32_t stigmergia_last_decay;     /* Tick of last decay */
        uint32_t stigmergia_last_share;     /* Tick of last broadcast */
        uint32_t stigmergia_marks_total;    /* Total marks emitted */
        uint32_t stigmergia_decays_total;   /* Total decay cycles */
    } terrain;

    /* ==========================================================================
     * Distributed Black Box (v0.5) - "El Último Aliento"
     *
     * When nodes die, they transmit a "Last Will" to trusted neighbors.
     * This creates a distributed forensic record of what happened to dead nodes.
     * "The dead speak through the living"
     * ========================================================================== */
    #define BLACKBOX_MAX_WILLS      8       /* Max last wills stored */
    #define BLACKBOX_MAX_EVENTS     5       /* Events per will */

    /* Death reasons */
    #define DEATH_NATURAL           0x00    /* Normal apoptosis (lifespan) */
    #define DEATH_HEAP_EXHAUSTED    0x01    /* Out of memory */
    #define DEATH_CORRUPTION        0x02    /* Detected memory corruption */
    #define DEATH_ATTACK_DETECTED   0x03    /* Security attack detected */
    #define DEATH_QUEEN_ORDER       0x04    /* Ordered to die by queen */
    #define DEATH_REPLACED          0x05    /* Replaced by new node */
    #define DEATH_ISOLATION         0x06    /* No neighbors for too long */
    #define DEATH_UNKNOWN           0xFF    /* Unknown cause */

    /* Security event types for forensics */
    #define EVENT_BAD_MAC           0x01    /* Failed MAC verification */
    #define EVENT_REPLAY            0x02    /* Replay attack blocked */
    #define EVENT_RATE_LIMIT        0x03    /* Rate limit triggered */
    #define EVENT_BLACKLIST         0x04    /* Node blacklisted */
    #define EVENT_JAMMING           0x05    /* Jamming detected */
    #define EVENT_CORRUPTION        0x06    /* Memory corruption */
    #define EVENT_KEY_ROTATE        0x07    /* Key rotation occurred */

    /* AIS (Artificial Immune System) events v0.6 */
    #define EVENT_AIS_DETECTOR_MATCH    0x10    /* Detector matched non-self */
    #define EVENT_AIS_THYMUS_COMPLETE   0x11    /* Maturation complete */
    #define EVENT_AIS_MEMORY_PROMOTE    0x12    /* Detector promoted to memory */
    #define EVENT_AIS_ANOMALY_ALERT     0x13    /* Anomaly threshold reached */
    #define EVENT_AIS_SELF_UPDATE       0x14    /* Self profile updated */

    /* Hardware Validation events v0.6 */
    #define EVENT_HWVAL_TEMP_VIOLATION  0x20    /* Temperature out of bounds */
    #define EVENT_HWVAL_VOLTAGE_GLITCH  0x21    /* Voltage glitch detected */
    #define EVENT_HWVAL_CLOCK_ANOMALY   0x22    /* Clock manipulation detected */
    #define EVENT_HWVAL_MEM_CORRUPT     0x23    /* Memory canary corrupted */
    #define EVENT_HWVAL_FLASH_TAMPER    0x24    /* Flash CRC mismatch */
    #define EVENT_HWVAL_SENSOR_STUCK    0x25    /* Sensor not responding */
    #define EVENT_HWVAL_COMPROMISED     0x2F    /* Hardware integrity failed */

    struct {
        /* Last will entries from dead neighbors */
        struct {
            uint32_t node_id;               /* Who died */
            uint32_t death_tick;            /* When received */
            uint8_t  death_reason;          /* DEATH_* */
            uint8_t  uptime_hours;          /* How long node lived */

            /* Security statistics at death */
            uint16_t bad_mac_count;
            uint16_t replay_count;
            uint16_t rate_limit_count;
            uint8_t  blacklist_count;

            /* Last security events (ring buffer) */
            struct {
                uint32_t tick;              /* When event occurred */
                uint8_t  type;              /* EVENT_* */
                uint16_t source_node;       /* Related node if any */
            } events[BLACKBOX_MAX_EVENTS];
            uint8_t event_count;

            /* Network state at death */
            uint8_t  neighbor_count;
            uint8_t  role;
            uint8_t  distance_to_queen;
        } wills[BLACKBOX_MAX_WILLS];

        uint8_t  will_count;                /* Number of stored wills */
        uint8_t  will_index;                /* Next write slot (circular) */
        uint32_t wills_received;            /* Total wills ever received */
        uint32_t wills_relayed;             /* Wills relayed to others */
    } blackbox;
};

extern struct nanos_state g_state;

/* ==========================================================================
 * Memory Functions
 * ========================================================================== */
void* bump_alloc(size_t size);
size_t heap_usage_percent(void);
void heap_reset(void);

/* ==========================================================================
 * Assembly Functions (x86)
 * ========================================================================== */
extern void gdt_load(void);
extern void idt_load(void* idt_ptr);
extern void cpu_halt(void);
extern void interrupts_enable(void);
extern void interrupts_disable(void);

/* ==========================================================================
 * Core Kernel Functions
 * ========================================================================== */
void kernel_main(uint32_t magic, void* mb_info);
void nanos_loop(void);
void process_pheromone(struct nanos_pheromone* pkt);
void emit_heartbeat(void);
void cell_apoptosis(void);

/* ==========================================================================
 * Quorum Sensing Functions
 * ========================================================================== */
void neighbor_update(struct nanos_pheromone* pkt);
void neighbor_expire(void);
void quorum_evaluate(void);
void role_transition(uint8_t new_role);
uint8_t quorum_suggest_role(void);

/* ==========================================================================
 * Queen Election Functions
 * ========================================================================== */
void election_start(void);
void election_vote(uint32_t election_id, uint32_t candidate_id);
void election_process(struct nanos_pheromone* pkt);
void election_check_timeout(void);
void coronation_announce(void);

/* ==========================================================================
 * Gradient Routing Functions
 * ========================================================================== */
void gradient_update(struct nanos_pheromone* pkt);
void gradient_propagate(void);
uint32_t route_next_hop(uint32_t dest_id);
int route_send(uint32_t dest_id, uint8_t type, uint8_t* data, uint8_t len);
void route_forward(struct nanos_pheromone* pkt);

/* ==========================================================================
 * Security Functions
 * ========================================================================== */
void compute_hmac(struct nanos_pheromone* pkt);
bool verify_hmac(struct nanos_pheromone* pkt);
bool is_authenticated_type(uint8_t type);

/* ==========================================================================
 * Gossip Protocol Functions
 * ========================================================================== */
bool gossip_should_relay(struct nanos_pheromone* pkt);
void gossip_record(struct nanos_pheromone* pkt);
uint32_t gossip_hash(struct nanos_pheromone* pkt);

/* ==========================================================================
 * Timer Functions
 * ========================================================================== */
void pit_init(uint32_t frequency);
uint32_t get_ticks(void);

/* ==========================================================================
 * Console Output
 * ========================================================================== */
void vga_clear(void);
void vga_puts(const char* str);
void vga_putchar(char c);
void vga_put_hex(uint32_t value);
void vga_put_dec(uint32_t value);
void vga_set_color(uint8_t color);

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */
uint32_t random(void);
void seed_random(void);

#endif /* NANOS_H */
