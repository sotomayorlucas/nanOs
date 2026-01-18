/*
 * NanOS HMAC Authentication - SipHash-inspired simplified HMAC
 * Provides message authentication for critical pheromone types
 */
#ifndef NANOS_HMAC_H
#define NANOS_HMAC_H

#include <nanos.h>

/* Compute HMAC for a pheromone packet
 * Fills pkt->hmac with computed tag and sets FLAG_AUTHENTICATED
 */
void compute_hmac(struct nanos_pheromone* pkt);

/* Verify HMAC of a pheromone packet
 * Returns true if HMAC is valid, false otherwise
 */
bool verify_hmac(struct nanos_pheromone* pkt);

/* Check if pheromone type requires authentication */
bool is_authenticated_type(uint8_t type);

#endif /* NANOS_HMAC_H */
