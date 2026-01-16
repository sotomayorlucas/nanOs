/*
 * NanOS - Core Types and Structures
 * The DNA of the swarm cell - v0.3 with collective intelligence
 */

#ifndef NANOS_H
#define NANOS_H

#include <stdint.h>
#include <stddef.h>

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
};

extern struct nanos_state g_state;

/* ==========================================================================
 * Simple Boolean Type
 * ========================================================================== */
typedef uint8_t bool;
#define true  1
#define false 0

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
