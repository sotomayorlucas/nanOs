/*
 * NanOS Gossip Protocol - Prevent Broadcast Storms
 * Probabilistic relay with exponential decay to prevent network flooding
 */
#ifndef NANOS_GOSSIP_H
#define NANOS_GOSSIP_H

#include <nanos.h>

/* Hash a pheromone packet for cache lookup */
uint32_t gossip_hash(struct nanos_pheromone* pkt);

/* Record a pheromone in the gossip cache */
void gossip_record(struct nanos_pheromone* pkt);

/* Determine if this pheromone should be relayed
 * Returns true if should relay, false if should suppress
 */
bool gossip_should_relay(struct nanos_pheromone* pkt);

#endif /* NANOS_GOSSIP_H */
