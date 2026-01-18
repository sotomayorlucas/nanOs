/*
 * NanOS Bloom Filter - O(1) Deduplication
 * Prevents duplicate pheromone processing using probabilistic data structure
 */
#ifndef NANOS_BLOOM_H
#define NANOS_BLOOM_H

#include <nanos.h>

/* Initialize bloom filter state */
void bloom_init(void);

/* Check and add packet to bloom filter
 * Returns true if NEW packet (should process)
 * Returns false if DUPLICATE (should ignore)
 */
bool bloom_check_and_add(struct nanos_pheromone* pkt);

#endif /* NANOS_BLOOM_H */
