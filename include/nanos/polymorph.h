/*
 * NanOS Code Polymorphism - "El Camaleón" (v0.6)
 *
 * Defense evasion through runtime diversity. Each node in the swarm has
 * a unique binary fingerprint, making mass exploitation impossible.
 *
 * Key concepts:
 * - ASLR: Randomize stack, heap, and data segment locations
 * - Poly-Packing: Mutate binary signature at boot
 * - Stack Canaries: Randomized canary values per node
 * - NOP Sledge Variation: Random NOPs to change code layout
 *
 * "If an attacker exploits one node, they cannot replay
 *  the same exploit on another - each node is unique."
 */
#ifndef NANOS_POLYMORPH_H
#define NANOS_POLYMORPH_H

#include <nanos.h>

/* ==========================================================================
 * Polymorphism Constants
 * ========================================================================== */

/* ASLR entropy bits (limited by MCU memory constraints) */
#define POLY_ASLR_STACK_BITS        8       /* 256 possible stack bases */
#define POLY_ASLR_HEAP_BITS         6       /* 64 possible heap bases */
#define POLY_ASLR_ENTROPY_MAX       ((1 << POLY_ASLR_STACK_BITS) * (1 << POLY_ASLR_HEAP_BITS))

/* Memory alignment requirements */
#define POLY_ASLR_ALIGNMENT         16      /* 16-byte alignment for ARM */
#define POLY_STACK_OFFSET_MAX       4096    /* Max stack randomization (bytes) */
#define POLY_HEAP_OFFSET_MAX        1024    /* Max heap randomization (bytes) */

/* Stack canary configuration */
#define POLY_CANARY_SIZE            4       /* 4 bytes = 32-bit canary */
#define POLY_CANARY_CHECK_INTERVAL  100     /* Check every 100 ticks */

/* Binary mutation parameters */
#define POLY_SIGNATURE_SIZE         16      /* 16-byte unique signature */
#define POLY_NOP_REGIONS            4       /* Number of NOP sled regions */
#define POLY_NOP_MAX_SIZE           8       /* Max NOPs per region */

/* Function pointer table shuffling */
#define POLY_SHUFFLE_TABLE_SIZE     8       /* Shuffleable function pointers */

/* Timing jitter for side-channel resistance */
#define POLY_JITTER_MIN_US          10      /* Min timing jitter */
#define POLY_JITTER_MAX_US          100     /* Max timing jitter */

/* Refresh intervals */
#define POLY_CANARY_REFRESH_MS      60000   /* Refresh canary every 60s */
#define POLY_SIGNATURE_REFRESH_MS   300000  /* Refresh signature every 5min */

/* ==========================================================================
 * Polymorphism States
 * ========================================================================== */

#define POLY_STATE_UNINITIALIZED    0x00
#define POLY_STATE_INITIALIZING     0x01
#define POLY_STATE_ACTIVE           0x02
#define POLY_STATE_COMPROMISED      0xFF    /* Canary violation detected */

/* ==========================================================================
 * Data Structures
 * ========================================================================== */

/**
 * Memory layout after ASLR
 */
struct poly_memory_layout {
    uint32_t stack_base;            /* Randomized stack base address */
    uint32_t stack_offset;          /* Offset from original base */
    uint32_t heap_base;             /* Randomized heap base address */
    uint32_t heap_offset;           /* Offset from original base */
    uint32_t data_offset;           /* Static data offset (if supported) */
    uint32_t entropy_seed;          /* Seed used for this layout */
};

/**
 * Stack canary state
 */
struct poly_canary_state {
    uint32_t value;                 /* Current canary value */
    uint32_t backup;                /* Backup for verification */
    uint32_t violations;            /* Violation count */
    uint32_t last_check;            /* Last verification tick */
    uint32_t last_refresh;          /* Last refresh tick */
};

/**
 * Binary signature (unique per node)
 */
struct poly_signature {
    uint8_t  bytes[POLY_SIGNATURE_SIZE];    /* Unique binary fingerprint */
    uint32_t created_tick;                   /* When generated */
    uint32_t node_id;                        /* Associated node ID */
    uint8_t  version;                        /* Signature version */
};

/**
 * NOP sled region descriptor
 */
struct poly_nop_region {
    uint32_t address;               /* Start address of NOP region */
    uint8_t  length;                /* Number of NOPs (1-8) */
    uint8_t  pattern;               /* NOP pattern index */
};

/**
 * Complete polymorphism state
 */
struct poly_state {
    uint8_t  state;                 /* POLY_STATE_* */

    /* Memory layout */
    struct poly_memory_layout layout;

    /* Stack protection */
    struct poly_canary_state canary;

    /* Binary identity */
    struct poly_signature signature;

    /* NOP regions (code diversity) */
    struct poly_nop_region nop_regions[POLY_NOP_REGIONS];
    uint8_t nop_region_count;

    /* Timing jitter */
    uint16_t jitter_us;             /* Current jitter value */

    /* Statistics */
    uint32_t canary_checks;         /* Total canary verifications */
    uint32_t canary_refreshes;      /* Total canary refreshes */
    uint32_t timing_variations;     /* Timing jitter applications */
};

/* ==========================================================================
 * Polymorphism API
 * ========================================================================== */

/**
 * Initialize polymorphism system
 * Must be called very early in boot process
 *
 * @return 0 on success, -1 on failure
 */
int poly_init(void);

/**
 * Apply ASLR to memory layout
 * Randomizes stack and heap base addresses
 *
 * @param entropy  Random seed (use hardware RNG if available)
 * @return Pointer to resulting layout
 */
struct poly_memory_layout* poly_apply_aslr(uint32_t entropy);

/**
 * Get current memory layout
 * @return Pointer to current layout (NULL if not initialized)
 */
struct poly_memory_layout* poly_get_layout(void);

/**
 * Generate unique binary signature
 * Creates a fingerprint that identifies this specific node instance
 */
void poly_generate_signature(void);

/**
 * Get current binary signature
 * @return Pointer to signature (NULL if not generated)
 */
struct poly_signature* poly_get_signature(void);

/**
 * Verify signature matches node identity
 * @param sig  Signature to verify
 * @return true if valid, false if mismatch
 */
bool poly_verify_signature(struct poly_signature* sig);

/* ==========================================================================
 * Stack Canary API
 * ========================================================================== */

/**
 * Initialize stack canary with random value
 * Places canary at critical stack locations
 */
void poly_canary_init(void);

/**
 * Get current canary value (for function prologue)
 * @return Current canary value
 */
uint32_t poly_canary_get(void);

/**
 * Verify canary hasn't been corrupted
 * Call this periodically and in critical function epilogues
 *
 * @return true if canary is intact, false if corrupted
 */
bool poly_canary_check(void);

/**
 * Refresh canary with new random value
 * Should be called periodically for additional security
 */
void poly_canary_refresh(void);

/**
 * Handle canary violation
 * Called when corruption is detected
 * Triggers security response (alarm, apoptosis)
 */
void poly_canary_violated(void);

/* ==========================================================================
 * Timing Jitter API (Side-Channel Resistance)
 * ========================================================================== */

/**
 * Apply random timing jitter
 * Inserts random delay to prevent timing attacks
 */
void poly_apply_jitter(void);

/**
 * Get current jitter value
 * @return Jitter in microseconds
 */
uint16_t poly_get_jitter(void);

/**
 * Randomize jitter for next operation
 */
void poly_randomize_jitter(void);

/* ==========================================================================
 * NOP Sled API (Code Layout Diversity)
 * ========================================================================== */

/**
 * Register a NOP sled region
 * Regions will be filled with random NOPs at boot
 *
 * @param address  Start address of region
 * @param max_len  Maximum length (will be randomized)
 * @return Region index, or -1 if full
 */
int poly_register_nop_region(uint32_t address, uint8_t max_len);

/**
 * Randomize all registered NOP regions
 * Changes code layout without affecting functionality
 */
void poly_randomize_nop_regions(void);

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * Periodic maintenance tick
 * Call from main loop to handle canary checks and refreshes
 */
void poly_tick(void);

/**
 * Check if polymorphism is fully active
 * @return true if system is operational
 */
bool poly_is_active(void);

/**
 * Get polymorphism statistics
 * @return Pointer to state structure
 */
struct poly_state* poly_get_state(void);

/**
 * Print polymorphism status to serial
 */
void poly_print_status(void);

/**
 * Calculate diversity score
 * Estimates how different this node is from a "standard" build
 *
 * @return Score 0-255 (higher = more diverse)
 */
uint8_t poly_diversity_score(void);

/* ==========================================================================
 * Compiler Macros for Code Instrumentation
 * ========================================================================== */

/**
 * POLY_PROTECTED_FUNC - Mark function for canary protection
 * Usage: POLY_PROTECTED_FUNC void my_critical_function(void) { ... }
 */
#ifdef POLY_ENABLE_INSTRUMENTATION
#define POLY_PROTECTED_FUNC __attribute__((stack_protect))
#define POLY_CANARY_PROLOGUE() uint32_t __canary = poly_canary_get()
#define POLY_CANARY_EPILOGUE() if (__canary != poly_canary_get()) poly_canary_violated()
#else
#define POLY_PROTECTED_FUNC
#define POLY_CANARY_PROLOGUE()
#define POLY_CANARY_EPILOGUE()
#endif

/**
 * POLY_NOP_REGION - Insert randomizable NOP sled
 * Compiler will place NOPs here that can be varied at runtime
 */
#define POLY_NOP_REGION(n) \
    __asm__ volatile( \
        ".rept " #n "\n\t" \
        "nop\n\t" \
        ".endr\n\t" \
    )

/**
 * POLY_TIMING_SAFE - Execute with timing jitter
 * Wraps critical operations with random delays
 */
#define POLY_TIMING_SAFE(code) do { \
    poly_apply_jitter(); \
    code; \
    poly_apply_jitter(); \
} while(0)

#endif /* NANOS_POLYMORPH_H */
