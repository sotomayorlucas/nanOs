/*
 * NanOS Bump Allocator - Simple memory allocation with apoptosis support
 * When memory is exhausted, the cell can trigger apoptosis (controlled death)
 */
#ifndef NANOS_ALLOCATOR_H
#define NANOS_ALLOCATOR_H

#include <nanos.h>

/* Allocate memory from the heap (16-byte aligned)
 * Returns NULL if heap is exhausted
 */
void* bump_alloc(size_t size);

/* Get current heap usage as percentage (0-100) */
size_t heap_usage_percent(void);

/* Reset heap (clear all allocations) */
void heap_reset(void);

/* Get current heap usage in bytes */
size_t heap_used_bytes(void);

/* Get total heap size in bytes */
size_t heap_total_bytes(void);

#endif /* NANOS_ALLOCATOR_H */
