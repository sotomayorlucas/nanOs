/*
 * NanOS - Core Types and Structures
 * The DNA of the swarm cell - v0.2 with immune system
 */

#ifndef NANOS_H
#define NANOS_H

#include <stdint.h>
#include <stddef.h>

/* ==========================================================================
 * Magic Constants - The chemical signatures of our pheromones
 * ========================================================================== */
#define NANOS_MAGIC         0x4E414E4F  /* "NANO" in hex */
#define MULTIBOOT2_MAGIC    0x36D76289
#define NANOS_VERSION       0x0002      /* Protocol version 0.2 */

/* ==========================================================================
 * Pheromone Types - The language of the swarm
 * ========================================================================== */
#define PHEROMONE_HELLO     0x01    /* "I exist" - heartbeat */
#define PHEROMONE_DATA      0x02    /* "I have information" */
#define PHEROMONE_ALARM     0x03    /* "Danger detected" */
#define PHEROMONE_ECHO      0x04    /* "I heard you" - acknowledgment */
#define PHEROMONE_QUEEN_CMD 0x10    /* Command from queen (authenticated) */
#define PHEROMONE_REBIRTH   0xFE    /* "I'm dying, remember me" */
#define PHEROMONE_DIE       0xFF    /* "Kill yourself" - requires auth */

/* ==========================================================================
 * Cell Roles - Specialization through differentiation
 * ========================================================================== */
#define ROLE_WORKER         0x01    /* Default: process data, relay messages */
#define ROLE_EXPLORER       0x02    /* Fast heartbeat, discovers network */
#define ROLE_SENTINEL       0x03    /* Monitors for anomalies, raises alarms */
#define ROLE_QUEEN          0x04    /* Rare: can issue authenticated commands */

/* Queen probability: 1 in 256 nodes becomes a queen */
#define QUEEN_PROBABILITY   256

/* ==========================================================================
 * Security Constants - The immune system
 * ========================================================================== */
#define HMAC_KEY_SIZE       16      /* 128-bit shared secret */
#define HMAC_TAG_SIZE       8       /* Truncated HMAC for space */

/* Hardcoded swarm secret (in production, derive from boot params) */
#define SWARM_SECRET_0      0xDEADBEEF
#define SWARM_SECRET_1      0xCAFEBABE
#define SWARM_SECRET_2      0x8BADF00D
#define SWARM_SECRET_3      0xFEEDFACE

/* ==========================================================================
 * Gossip Protocol Constants - Prevent broadcast storms
 * ========================================================================== */
#define GOSSIP_CACHE_SIZE   32      /* Remember last N message hashes */
#define GOSSIP_IMMUNITY_MS  500     /* Ignore repeated messages for 500ms */
#define GOSSIP_PROB_BASE    100     /* Base probability (100 = always relay) */
#define GOSSIP_PROB_DECAY   20      /* Reduce probability by 20% per duplicate */
#define ALARM_MAX_ECHOES    5       /* Stop relaying after seeing 5 copies */

/* ==========================================================================
 * Apoptosis - Programmed cell death
 * ========================================================================== */
#define HEAP_CRITICAL_PCT   90      /* Trigger apoptosis at 90% heap usage */
#define MAX_CELL_LIFETIME   360000  /* Max lifetime in ticks (~1 hour at 100Hz) */

/* ==========================================================================
 * The Pheromone Packet - 64 bytes, fits in one cache line
 * Now with security and version fields
 * ========================================================================== */
struct nanos_pheromone {
    uint32_t magic;         /* Must be NANOS_MAGIC */
    uint32_t node_id;       /* Random ID assigned at boot */
    uint8_t  type;          /* PHEROMONE_* constant */
    uint8_t  ttl;           /* Hops remaining before death */
    uint8_t  flags;         /* Bit 0: authenticated, Bit 1-3: role */
    uint8_t  version;       /* Protocol version for compatibility */
    uint32_t seq;           /* Sequence number for deduplication */
    uint8_t  hmac[HMAC_TAG_SIZE]; /* Truncated HMAC for critical msgs */
    uint8_t  payload[40];   /* Reduced payload (40 + 24 header = 64) */
} __attribute__((packed));

_Static_assert(sizeof(struct nanos_pheromone) == 64, "Pheromone must be 64 bytes");

/* Flags bitfield helpers */
#define FLAG_AUTHENTICATED  (1 << 0)
#define FLAG_ROLE_SHIFT     1
#define FLAG_ROLE_MASK      0x0E

#define PKT_GET_ROLE(pkt)   (((pkt)->flags & FLAG_ROLE_MASK) >> FLAG_ROLE_SHIFT)
#define PKT_SET_ROLE(pkt, r) ((pkt)->flags = ((pkt)->flags & ~FLAG_ROLE_MASK) | ((r) << FLAG_ROLE_SHIFT))

/* ==========================================================================
 * Gossip Cache Entry - For deduplication
 * ========================================================================== */
struct gossip_entry {
    uint32_t hash;          /* Hash of (node_id, seq, type) */
    uint32_t timestamp;     /* When first seen (ticks) */
    uint8_t  count;         /* How many times we've seen this */
    uint8_t  relayed;       /* Did we relay it? */
};

/* ==========================================================================
 * Node State - The cell's memory (expanded)
 * ========================================================================== */
struct nanos_state {
    /* Identity */
    uint32_t node_id;           /* Our unique (random) identifier */
    uint8_t  role;              /* ROLE_* constant */
    uint32_t generation;        /* Increments on rebirth (apoptosis) */

    /* Timing */
    uint32_t boot_time;         /* Ticks since boot */
    uint32_t last_heartbeat;    /* When we last said "hello" */
    uint32_t seq_counter;       /* Sequence number for our messages */

    /* Statistics */
    uint32_t packets_rx;        /* Received packet counter */
    uint32_t packets_tx;        /* Transmitted packet counter */
    uint32_t packets_dropped;   /* Dropped by gossip filter */
    uint32_t neighbors_seen;    /* Unique node_ids heard */
    uint32_t alarms_relayed;    /* Alarms propagated */

    /* Gossip cache */
    struct gossip_entry gossip_cache[GOSSIP_CACHE_SIZE];
    uint8_t gossip_index;       /* Next slot to use (circular) */

    /* Memory health */
    uint32_t heap_used;         /* Current heap usage */
    uint32_t heap_size;         /* Total heap size */
};

/* Global state - one per cell */
extern struct nanos_state g_state;

/* ==========================================================================
 * Simple Boolean Type
 * ========================================================================== */
typedef uint8_t bool;
#define true  1
#define false 0

/* ==========================================================================
 * Bump Allocator - Memory that never frees (like biological growth)
 * ========================================================================== */
void* bump_alloc(size_t size);
size_t heap_usage_percent(void);
void heap_reset(void);  /* For apoptosis - dangerous! */

/* ==========================================================================
 * Assembly Functions - Declared in boot.asm
 * ========================================================================== */
extern void gdt_load(void);
extern void idt_load(void* idt_ptr);
extern void cpu_halt(void);
extern void interrupts_enable(void);
extern void interrupts_disable(void);

/* ==========================================================================
 * Kernel Functions
 * ========================================================================== */
void kernel_main(uint32_t magic, void* mb_info);
void nanos_loop(void);
void process_pheromone(struct nanos_pheromone* pkt);
void emit_heartbeat(void);
void cell_apoptosis(void);  /* Programmed death and rebirth */

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
 * Console Output - For debugging only
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
