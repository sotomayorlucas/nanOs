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
#define NANOS_VERSION       0x0003      /* Protocol version 0.3 */

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
 * Neighbor Entry - For quorum sensing
 * ========================================================================== */
struct neighbor_entry {
    uint32_t node_id;       /* Neighbor's ID (0 = empty slot) */
    uint32_t last_seen;     /* Tick count when last heard */
    uint8_t  role;          /* Neighbor's role */
    uint8_t  distance;      /* Neighbor's distance to queen */
    uint16_t packets;       /* Packets received from this neighbor */
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
    uint32_t my_vote;           /* Who I voted for */
    uint32_t votes_received;    /* Votes for me */
    uint32_t highest_vote_id;   /* Highest ID seen in election */
    uint8_t  participating;     /* Am I in an election? */
    uint8_t  phase;             /* 0=none, 1=voting, 2=counting */
};

#define ELECTION_PHASE_NONE     0
#define ELECTION_PHASE_VOTING   1
#define ELECTION_PHASE_COUNTING 2
#define ELECTION_DURATION       300     /* 3 seconds to vote */

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

/* ==========================================================================
 * Random Number Generator
 * ========================================================================== */
uint32_t random(void);
void seed_random(void);

#endif /* NANOS_H */
