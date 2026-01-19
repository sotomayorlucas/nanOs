/*
 * NanOS Distributed Black Box - "El Último Aliento" (v0.5)
 *
 * When nodes die, they transmit a "Last Will" to trusted neighbors.
 * This creates a distributed forensic record - even if a node was
 * hacked and suicided, its evidence survives in the swarm.
 *
 * "The dead speak through the living"
 */
#ifndef NANOS_BLACKBOX_H
#define NANOS_BLACKBOX_H

#include <nanos.h>

/* ==========================================================================
 * Black Box API
 * ========================================================================== */

/**
 * Initialize black box system
 * Clears all stored wills
 */
void blackbox_init(void);

/**
 * Record a security event for potential last will
 * Call this when significant security events occur
 *
 * @param event_type  EVENT_* type
 * @param source_node Related node ID (0 if none)
 */
void blackbox_record_event(uint8_t event_type, uint16_t source_node);

/**
 * Emit last will before death
 * Call this from cell_apoptosis() before dying
 *
 * @param death_reason  DEATH_* reason code
 */
void blackbox_emit_last_will(uint8_t death_reason);

/**
 * Process received last will from dying node
 * Called when PHEROMONE_LAST_WILL is received
 *
 * @param pkt  Received pheromone packet
 */
void blackbox_process_last_will(struct nanos_pheromone* pkt);

/**
 * Query stored last will by node ID
 * For forensic investigation
 *
 * @param node_id  Dead node to query
 * @param death_reason  Out: death reason (or NULL)
 * @param bad_mac_count Out: bad MAC count (or NULL)
 * @param uptime_hours  Out: uptime in hours (or NULL)
 * @return 0 if found, -1 if not found
 */
int blackbox_query_death(uint32_t node_id,
                         uint8_t *death_reason,
                         uint16_t *bad_mac_count,
                         uint8_t *uptime_hours);

/**
 * Get count of stored last wills
 */
uint8_t blackbox_get_will_count(void);

/**
 * Relay high-priority last wills to neighbors
 * Called periodically to ensure critical forensic data propagates
 */
void blackbox_relay_critical(void);

/**
 * Print forensic summary to serial
 * For debugging and investigation
 */
void blackbox_print_summary(void);

#endif /* NANOS_BLACKBOX_H */
