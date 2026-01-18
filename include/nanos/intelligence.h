/*
 * NanOS Tactical Intelligence System
 * Sensor correlation and threat detection
 */
#ifndef NANOS_INTELLIGENCE_H
#define NANOS_INTELLIGENCE_H

#include <nanos.h>

/* Initialize tactical intelligence state */
void tactical_init(void);

/* Process incoming detection pheromone */
void tactical_process_detection(struct nanos_pheromone* pkt);

/* Helper functions for display */
const char* detect_type_name(uint8_t type);
const char* alert_level_name(uint8_t level);

#endif /* NANOS_INTELLIGENCE_H */
