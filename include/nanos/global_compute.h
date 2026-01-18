/*
 * NanOS Global Compute - MapReduce Style Distributed Computing
 * Distributed job processing across the swarm
 */
#ifndef NANOS_GLOBAL_COMPUTE_H
#define NANOS_GLOBAL_COMPUTE_H

#include <nanos.h>

/* Process pending job chunk if any */
void job_process_chunk(void);

/* Handle incoming job pheromones */
void process_job_start(struct nanos_pheromone* pkt);
void process_job_done(struct nanos_pheromone* pkt);
void process_job_result(struct nanos_pheromone* pkt);

/* Command to start a global compute job (queen only) */
void cmd_start_job(void);

#endif /* NANOS_GLOBAL_COMPUTE_H */
