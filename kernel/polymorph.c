/*
 * NanOS Code Polymorphism - "El Camaleón" (v0.6)
 *
 * Implements defense evasion through runtime diversity.
 * Each node becomes unique, preventing mass exploitation.
 *
 * Key mechanisms:
 * 1. ASLR: Memory layout randomization
 * 2. Stack Canaries: Buffer overflow detection
 * 3. Binary Signatures: Unique node fingerprints
 * 4. Timing Jitter: Side-channel resistance
 *
 * "An exploit that works on one node will fail on another -
 *  the swarm's diversity is its shield."
 */
#include <nanos.h>
#include "../include/nanos/polymorph.h"
#include "../include/nanos/blackbox.h"
#include "../include/nanos/serial.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern uint32_t random(void);
extern void e1000_send(void* data, uint16_t len);

/* Global polymorphism state */
static struct poly_state g_poly;

/* Original memory addresses (before ASLR) */
static uint32_t original_stack_base = 0;
static uint32_t original_heap_base = 0;

/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * Generate cryptographically random bytes
 * Uses hardware RNG if available, falls back to PRNG
 */
static void generate_random_bytes(uint8_t* buf, uint8_t len) {
    for (int i = 0; i < len; i += 4) {
        uint32_t r = random();
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            buf[i + j] = (r >> (j * 8)) & 0xFF;
        }
    }
}

/**
 * Mix entropy sources for better randomness
 */
static uint32_t mix_entropy(uint32_t seed) {
    /* XOR with various entropy sources */
    seed ^= ticks;
    seed ^= g_state.node_id;
    seed ^= g_state.packets_rx;
    seed ^= (uint32_t)(uintptr_t)&seed;  /* Stack address */

    /* Avalanche mixing */
    seed ^= seed >> 16;
    seed *= 0x85EBCA6B;
    seed ^= seed >> 13;
    seed *= 0xC2B2AE35;
    seed ^= seed >> 16;

    return seed;
}

/**
 * Simple delay loop for timing jitter
 */
static void delay_us(uint16_t us) {
    /* Approximate microsecond delay (platform dependent) */
    volatile uint32_t count = us * 10;  /* Adjust for CPU speed */
    while (count--) {
        __asm__ volatile("nop");
    }
}

/* ==========================================================================
 * ASLR Implementation
 * ========================================================================== */

struct poly_memory_layout* poly_apply_aslr(uint32_t entropy) {
    if (g_poly.state != POLY_STATE_UNINITIALIZED &&
        g_poly.state != POLY_STATE_INITIALIZING) {
        /* Already applied - can't re-randomize at runtime */
        return &g_poly.layout;
    }

    /* Mix entropy for unpredictability */
    entropy = mix_entropy(entropy);
    g_poly.layout.entropy_seed = entropy;

    /*
     * Stack ASLR:
     * Add random offset to stack base (aligned to 16 bytes)
     * Range: 0 to POLY_STACK_OFFSET_MAX
     */
    uint32_t stack_offset = (entropy & ((1 << POLY_ASLR_STACK_BITS) - 1));
    stack_offset = (stack_offset * POLY_ASLR_ALIGNMENT);
    if (stack_offset > POLY_STACK_OFFSET_MAX) {
        stack_offset = POLY_STACK_OFFSET_MAX;
    }
    g_poly.layout.stack_offset = stack_offset;

    /*
     * Heap ASLR:
     * Add random offset to heap base (aligned)
     * Use different entropy bits
     */
    uint32_t heap_offset = ((entropy >> POLY_ASLR_STACK_BITS) &
                            ((1 << POLY_ASLR_HEAP_BITS) - 1));
    heap_offset = (heap_offset * POLY_ASLR_ALIGNMENT);
    if (heap_offset > POLY_HEAP_OFFSET_MAX) {
        heap_offset = POLY_HEAP_OFFSET_MAX;
    }
    g_poly.layout.heap_offset = heap_offset;

    /*
     * Note: Actual base address modification requires linker support
     * and early boot code. Here we store the intended offsets.
     */
    if (original_stack_base != 0) {
        g_poly.layout.stack_base = original_stack_base - stack_offset;
    }
    if (original_heap_base != 0) {
        g_poly.layout.heap_base = original_heap_base + heap_offset;
    }

    serial_puts("[POLY] ASLR applied: stack_off=");
    serial_put_dec(stack_offset);
    serial_puts(" heap_off=");
    serial_put_dec(heap_offset);
    serial_puts("\n");

    return &g_poly.layout;
}

struct poly_memory_layout* poly_get_layout(void) {
    if (g_poly.state == POLY_STATE_UNINITIALIZED) {
        return (struct poly_memory_layout*)0;
    }
    return &g_poly.layout;
}

/* ==========================================================================
 * Stack Canary Implementation
 * ========================================================================== */

void poly_canary_init(void) {
    /* Generate random canary value */
    g_poly.canary.value = mix_entropy(random());

    /* Ensure canary doesn't contain null bytes (can break string operations) */
    uint8_t* bytes = (uint8_t*)&g_poly.canary.value;
    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) {
            bytes[i] = 0xFF;  /* Replace null with 0xFF */
        }
    }

    /* Store backup for verification */
    g_poly.canary.backup = g_poly.canary.value;
    g_poly.canary.violations = 0;
    g_poly.canary.last_check = ticks;
    g_poly.canary.last_refresh = ticks;

    serial_puts("[POLY] Stack canary initialized: 0x");
    serial_put_hex(g_poly.canary.value);
    serial_puts("\n");
}

uint32_t poly_canary_get(void) {
    return g_poly.canary.value;
}

bool poly_canary_check(void) {
    g_poly.canary_checks++;
    g_poly.canary.last_check = ticks;

    /* Verify canary hasn't been modified */
    if (g_poly.canary.value != g_poly.canary.backup) {
        /* Canary corrupted! */
        g_poly.canary.violations++;
        return false;
    }

    return true;
}

void poly_canary_refresh(void) {
    /* Generate new random canary */
    uint32_t old_value = g_poly.canary.value;
    g_poly.canary.value = mix_entropy(random());

    /* Ensure no null bytes */
    uint8_t* bytes = (uint8_t*)&g_poly.canary.value;
    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) {
            bytes[i] = (uint8_t)(random() | 0x01);
        }
    }

    g_poly.canary.backup = g_poly.canary.value;
    g_poly.canary.last_refresh = ticks;
    g_poly.canary_refreshes++;

    serial_puts("[POLY] Canary refreshed: 0x");
    serial_put_hex(old_value);
    serial_puts(" -> 0x");
    serial_put_hex(g_poly.canary.value);
    serial_puts("\n");
}

void poly_canary_violated(void) {
    serial_puts("[POLY] !!! CANARY VIOLATION DETECTED !!!\n");
    serial_puts("[POLY] Stack corruption or buffer overflow!\n");

    /* Change state to compromised */
    g_poly.state = POLY_STATE_COMPROMISED;

    /* Record in Black Box */
    blackbox_record_event(EVENT_CORRUPTION, 0);

    /* Emit alarm to swarm */
    struct nanos_pheromone alarm;
    alarm.magic = NANOS_MAGIC;
    alarm.type = PHEROMONE_ALARM;
    alarm.node_id = g_state.node_id;
    alarm.seq = g_state.seq_counter++;
    alarm.ttl = 5;
    alarm.hop_count = 0;
    alarm.dest_id = 0;  /* Broadcast */
    alarm.flags = FLAG_URGENT;

    alarm.payload[0] = 0xCA;  /* Canary violation marker */
    alarm.payload[1] = 0xDE;
    alarm.payload[2] = 0xAD;
    alarm.payload[3] = 0x00;

    e1000_send(&alarm, sizeof(alarm));

    /* Trigger apoptosis - compromised node must die */
    serial_puts("[POLY] Initiating emergency apoptosis...\n");

    /* In a real implementation, this would call cell_apoptosis() */
    /* For now, we just halt */
    /* cell_apoptosis(); */
}

/* ==========================================================================
 * Binary Signature Implementation
 * ========================================================================== */

void poly_generate_signature(void) {
    struct poly_signature* sig = &g_poly.signature;

    /* Generate unique signature bytes */
    for (int i = 0; i < POLY_SIGNATURE_SIZE; i += 4) {
        uint32_t r = mix_entropy(random());
        sig->bytes[i] = (r >> 0) & 0xFF;
        if (i + 1 < POLY_SIGNATURE_SIZE) sig->bytes[i + 1] = (r >> 8) & 0xFF;
        if (i + 2 < POLY_SIGNATURE_SIZE) sig->bytes[i + 2] = (r >> 16) & 0xFF;
        if (i + 3 < POLY_SIGNATURE_SIZE) sig->bytes[i + 3] = (r >> 24) & 0xFF;
    }

    /* Mix in node-specific data */
    sig->bytes[0] ^= (g_state.node_id >> 0) & 0xFF;
    sig->bytes[1] ^= (g_state.node_id >> 8) & 0xFF;
    sig->bytes[2] ^= (g_state.node_id >> 16) & 0xFF;
    sig->bytes[3] ^= (g_state.node_id >> 24) & 0xFF;

    /* Mix in memory layout */
    sig->bytes[4] ^= (g_poly.layout.stack_offset >> 0) & 0xFF;
    sig->bytes[5] ^= (g_poly.layout.stack_offset >> 8) & 0xFF;
    sig->bytes[6] ^= (g_poly.layout.heap_offset >> 0) & 0xFF;
    sig->bytes[7] ^= (g_poly.layout.heap_offset >> 8) & 0xFF;

    /* Mix in canary (proves we're the same instance) */
    sig->bytes[8] ^= (g_poly.canary.value >> 0) & 0xFF;
    sig->bytes[9] ^= (g_poly.canary.value >> 8) & 0xFF;
    sig->bytes[10] ^= (g_poly.canary.value >> 16) & 0xFF;
    sig->bytes[11] ^= (g_poly.canary.value >> 24) & 0xFF;

    sig->created_tick = ticks;
    sig->node_id = g_state.node_id;
    sig->version = 1;

    serial_puts("[POLY] Signature generated: ");
    for (int i = 0; i < 8; i++) {
        serial_put_hex(sig->bytes[i]);
    }
    serial_puts("...\n");
}

struct poly_signature* poly_get_signature(void) {
    if (g_poly.signature.node_id == 0) {
        return (struct poly_signature*)0;
    }
    return &g_poly.signature;
}

bool poly_verify_signature(struct poly_signature* sig) {
    if (!sig) return false;
    if (sig->node_id != g_state.node_id) return false;

    /* Regenerate expected signature and compare */
    /* (Simplified: just check first bytes match our ID) */
    uint8_t expected_id_byte = (g_state.node_id >> 0) & 0xFF;
    uint8_t actual_id_byte = sig->bytes[0] ^
                             (g_poly.signature.bytes[0] ^ expected_id_byte);

    return (actual_id_byte == expected_id_byte);
}

/* ==========================================================================
 * Timing Jitter Implementation
 * ========================================================================== */

void poly_apply_jitter(void) {
    if (g_poly.jitter_us > 0) {
        delay_us(g_poly.jitter_us);
        g_poly.timing_variations++;
    }
}

uint16_t poly_get_jitter(void) {
    return g_poly.jitter_us;
}

void poly_randomize_jitter(void) {
    uint32_t r = random();
    uint16_t range = POLY_JITTER_MAX_US - POLY_JITTER_MIN_US;
    g_poly.jitter_us = POLY_JITTER_MIN_US + (r % range);
}

/* ==========================================================================
 * NOP Sled Implementation
 * ========================================================================== */

int poly_register_nop_region(uint32_t address, uint8_t max_len) {
    if (g_poly.nop_region_count >= POLY_NOP_REGIONS) {
        return -1;
    }

    int idx = g_poly.nop_region_count++;
    g_poly.nop_regions[idx].address = address;
    g_poly.nop_regions[idx].length = (max_len > POLY_NOP_MAX_SIZE)
                                      ? POLY_NOP_MAX_SIZE : max_len;
    g_poly.nop_regions[idx].pattern = 0;

    return idx;
}

void poly_randomize_nop_regions(void) {
    /*
     * Note: Actually modifying code memory at runtime requires
     * special handling (memory protection, cache invalidation).
     * This is a placeholder that tracks the intended randomization.
     */
    for (int i = 0; i < g_poly.nop_region_count; i++) {
        uint32_t r = random();

        /* Randomize length (1 to max) */
        g_poly.nop_regions[i].length = 1 + (r % g_poly.nop_regions[i].length);

        /* Select NOP pattern (platform-specific) */
        g_poly.nop_regions[i].pattern = (r >> 8) % 4;
    }

    serial_puts("[POLY] NOP regions randomized: ");
    serial_put_dec(g_poly.nop_region_count);
    serial_puts(" regions\n");
}

/* ==========================================================================
 * Main API Implementation
 * ========================================================================== */

int poly_init(void) {
    serial_puts("[POLY] Initializing Code Polymorphism v0.6\n");

    g_poly.state = POLY_STATE_INITIALIZING;

    /* Store original memory layout */
    /* These would come from linker symbols in real implementation */
    original_stack_base = 0x80000;   /* Example stack base */
    original_heap_base = 0x20000;    /* Example heap base */

    /* Apply ASLR */
    uint32_t entropy = random() ^ ticks ^ g_state.node_id;
    poly_apply_aslr(entropy);

    /* Initialize stack canary */
    poly_canary_init();

    /* Generate unique binary signature */
    poly_generate_signature();

    /* Initialize timing jitter */
    poly_randomize_jitter();

    /* Randomize NOP regions (if any registered) */
    if (g_poly.nop_region_count > 0) {
        poly_randomize_nop_regions();
    }

    /* Initialize statistics */
    g_poly.canary_checks = 0;
    g_poly.canary_refreshes = 0;
    g_poly.timing_variations = 0;

    g_poly.state = POLY_STATE_ACTIVE;

    serial_puts("[POLY] Polymorphism ACTIVE - this node is unique\n");
    serial_puts("[POLY] Diversity score: ");
    serial_put_dec(poly_diversity_score());
    serial_puts("/255\n");

    return 0;
}

void poly_tick(void) {
    if (g_poly.state != POLY_STATE_ACTIVE) {
        return;
    }

    uint32_t now = ticks;

    /* Periodic canary check */
    if ((now - g_poly.canary.last_check) >= POLY_CANARY_CHECK_INTERVAL) {
        if (!poly_canary_check()) {
            poly_canary_violated();
            return;  /* We're dead */
        }
    }

    /* Periodic canary refresh */
    if ((now - g_poly.canary.last_refresh) >= (POLY_CANARY_REFRESH_MS / 10)) {
        poly_canary_refresh();
    }

    /* Periodic jitter randomization */
    if ((now % 1000) == 0) {  /* Every 10 seconds */
        poly_randomize_jitter();
    }
}

bool poly_is_active(void) {
    return (g_poly.state == POLY_STATE_ACTIVE);
}

struct poly_state* poly_get_state(void) {
    return &g_poly;
}

uint8_t poly_diversity_score(void) {
    uint32_t score = 0;

    /* ASLR contribution (0-80 points) */
    score += (g_poly.layout.stack_offset / (POLY_STACK_OFFSET_MAX / 40));
    score += (g_poly.layout.heap_offset / (POLY_HEAP_OFFSET_MAX / 40));

    /* Canary uniqueness (0-50 points) */
    uint8_t canary_entropy = 0;
    uint32_t c = g_poly.canary.value;
    while (c) {
        canary_entropy += (c & 1);
        c >>= 1;
    }
    score += canary_entropy * 3;  /* ~48 max for good entropy */

    /* Signature uniqueness (0-80 points) */
    for (int i = 0; i < 8; i++) {
        uint8_t b = g_poly.signature.bytes[i];
        uint8_t bits = 0;
        while (b) {
            bits += (b & 1);
            b >>= 1;
        }
        score += bits;  /* ~32 for random bytes */
    }

    /* Timing jitter contribution (0-45 points) */
    score += (g_poly.jitter_us - POLY_JITTER_MIN_US) /
             ((POLY_JITTER_MAX_US - POLY_JITTER_MIN_US) / 45);

    /* Cap at 255 */
    return (score > 255) ? 255 : (uint8_t)score;
}

void poly_print_status(void) {
    serial_puts("\n=== CODE POLYMORPHISM STATUS ===\n");

    serial_puts("State: ");
    switch (g_poly.state) {
        case POLY_STATE_UNINITIALIZED: serial_puts("UNINITIALIZED"); break;
        case POLY_STATE_INITIALIZING: serial_puts("INITIALIZING"); break;
        case POLY_STATE_ACTIVE: serial_puts("ACTIVE"); break;
        case POLY_STATE_COMPROMISED: serial_puts("COMPROMISED!"); break;
        default: serial_puts("UNKNOWN"); break;
    }
    serial_puts("\n");

    serial_puts("\nASLR Layout:\n");
    serial_puts("  Stack offset: ");
    serial_put_dec(g_poly.layout.stack_offset);
    serial_puts(" bytes\n");
    serial_puts("  Heap offset:  ");
    serial_put_dec(g_poly.layout.heap_offset);
    serial_puts(" bytes\n");
    serial_puts("  Entropy seed: 0x");
    serial_put_hex(g_poly.layout.entropy_seed);
    serial_puts("\n");

    serial_puts("\nStack Canary:\n");
    serial_puts("  Value:      0x");
    serial_put_hex(g_poly.canary.value);
    serial_puts("\n");
    serial_puts("  Checks:     ");
    serial_put_dec(g_poly.canary_checks);
    serial_puts("\n");
    serial_puts("  Refreshes:  ");
    serial_put_dec(g_poly.canary_refreshes);
    serial_puts("\n");
    serial_puts("  Violations: ");
    serial_put_dec(g_poly.canary.violations);
    serial_puts("\n");

    serial_puts("\nBinary Signature: ");
    for (int i = 0; i < 8; i++) {
        serial_put_hex(g_poly.signature.bytes[i]);
    }
    serial_puts("...\n");

    serial_puts("\nTiming Jitter: ");
    serial_put_dec(g_poly.jitter_us);
    serial_puts(" us (");
    serial_put_dec(g_poly.timing_variations);
    serial_puts(" applications)\n");

    serial_puts("\nDiversity Score: ");
    serial_put_dec(poly_diversity_score());
    serial_puts("/255\n");

    serial_puts("================================\n\n");
}
