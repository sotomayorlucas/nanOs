/*
 * NanOS - Core Types and Structures
 * The DNA of the swarm cell
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

/* ==========================================================================
 * Pheromone Types - The language of the swarm
 * ========================================================================== */
#define PHEROMONE_HELLO     0x01    /* "I exist" - heartbeat */
#define PHEROMONE_DATA      0x02    /* "I have information" */
#define PHEROMONE_ALARM     0x03    /* "Danger detected" */
#define PHEROMONE_ECHO      0x04    /* "I heard you" - acknowledgment */
#define PHEROMONE_DIE       0xFF    /* "Kill yourself" - graceful shutdown */

/* ==========================================================================
 * The Pheromone Packet - 64 bytes, fits in one cache line
 * This is the ONLY data structure that travels between nodes
 * ========================================================================== */
struct nanos_pheromone {
    uint32_t magic;         /* Must be NANOS_MAGIC */
    uint32_t node_id;       /* Random ID assigned at boot */
    uint8_t  type;          /* PHEROMONE_* constant */
    uint8_t  ttl;           /* Hops remaining before death */
    uint8_t  flags;         /* Reserved for future pheromone variants */
    uint8_t  checksum;      /* Simple XOR checksum */
    uint8_t  payload[52];   /* The actual data (52 + 12 header = 64) */
} __attribute__((packed));

_Static_assert(sizeof(struct nanos_pheromone) == 64, "Pheromone must be 64 bytes");

/* ==========================================================================
 * Node State - The cell's memory
 * ========================================================================== */
struct nanos_state {
    uint32_t node_id;           /* Our unique (random) identifier */
    uint32_t boot_time;         /* Ticks since boot */
    uint32_t last_heartbeat;    /* When we last said "hello" */
    uint32_t packets_rx;        /* Received packet counter */
    uint32_t packets_tx;        /* Transmitted packet counter */
    uint32_t neighbors_seen;    /* Unique node_ids heard */
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
void vga_put_hex(uint32_t value);

#endif /* NANOS_H */
