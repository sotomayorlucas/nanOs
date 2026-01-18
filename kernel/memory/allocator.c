/*
 * NanOS Bump Allocator - Simple memory allocation with apoptosis support
 *
 * A simple bump allocator that tracks heap usage for apoptosis decisions.
 * When memory runs out, returns NULL to trigger cell death/rebirth.
 */
#include <nanos.h>

/* ==========================================================================
 * Heap Storage
 * ========================================================================== */
#define HEAP_SIZE 65536
static uint8_t heap[HEAP_SIZE];
static size_t heap_ptr = 0;

/* ==========================================================================
 * Public API
 * ========================================================================== */

void* bump_alloc(size_t size) {
    size = (size + 15) & ~15;  /* 16-byte align */

    if (heap_ptr + size > HEAP_SIZE) {
        return (void*)0;  /* Trigger apoptosis check */
    }

    void* ptr = &heap[heap_ptr];
    heap_ptr += size;
    g_state.heap_used = heap_ptr;
    return ptr;
}

size_t heap_usage_percent(void) {
    return (heap_ptr * 100) / HEAP_SIZE;
}

void heap_reset(void) {
    heap_ptr = 0;
    g_state.heap_used = 0;
}

size_t heap_used_bytes(void) {
    return heap_ptr;
}

size_t heap_total_bytes(void) {
    return HEAP_SIZE;
}
