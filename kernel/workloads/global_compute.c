/*
 * NanOS Global Compute - MapReduce Style Distributed Computing
 * Distributed job processing across the swarm
 */
#include <nanos.h>
#include "../../include/nanos/global_compute.h"
#include "../../include/nanos/gossip.h"
#include "../../include/nanos/serial.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern void e1000_send(void* data, uint16_t len);
extern void vga_set_color(uint8_t color);
extern void vga_puts(const char* str);
extern void vga_put_hex(uint32_t value);
extern void vga_put_dec(uint32_t value);

/* Prime number check */
static uint32_t is_prime(uint32_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (uint32_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

/* ==========================================================================
 * Internal Helper Functions
 * ========================================================================== */

/* Count primes in a range (for prime search job) */
static uint32_t count_primes_in_range(uint32_t start, uint32_t end) {
    uint32_t count = 0;
    for (uint32_t n = start; n <= end; n++) {
        if (is_prime(n)) count++;
    }
    return count;
}

/* Monte Carlo Pi estimation - random points in unit square */
static uint32_t monte_carlo_pi_samples(uint32_t samples) {
    uint32_t inside = 0;
    for (uint32_t i = 0; i < samples; i++) {
        /* Generate random point in [0,1000) x [0,1000) */
        uint32_t x = random() % 1000;
        uint32_t y = random() % 1000;
        /* Check if inside quarter circle: x^2 + y^2 < 1000^2 */
        if (x * x + y * y < 1000000) {
            inside++;
        }
    }
    return inside;  /* Pi ~= 4 * inside / samples */
}

/* Sum numbers in a range (for parallel sum job) */
static uint64_t sum_range(uint32_t start, uint32_t end) {
    uint64_t sum = 0;
    for (uint32_t n = start; n <= end; n++) {
        sum += n;
    }
    return sum;
}

/* ==========================================================================
 * Public API Implementation
 * ========================================================================== */

/* Process a job chunk */
void job_process_chunk(void) {
    if (!g_state.current_chunk.processing) return;

    uint32_t job_id = g_state.current_chunk.job_id;
    uint8_t job_type = g_state.current_chunk.job_type;
    uint32_t start = g_state.current_chunk.range_start;
    uint32_t end = g_state.current_chunk.range_end;
    uint64_t result = 0;

    vga_set_color(0x0E);
    vga_puts("[JOB] Processing chunk ");
    vga_put_dec(g_state.current_chunk.chunk_id);
    vga_puts(" (");
    vga_put_dec(start);
    vga_puts("-");
    vga_put_dec(end);
    vga_puts(")\n");
    vga_set_color(0x0A);

    switch (job_type) {
        case JOB_PRIME_SEARCH:
            result = count_primes_in_range(start, end);
            break;
        case JOB_MONTE_CARLO_PI:
            result = monte_carlo_pi_samples(end - start);
            break;
        case JOB_REDUCE_SUM:
            result = sum_range(start, end);
            break;
        default:
            result = 0;
    }

    /* Send result back */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_JOB_DONE;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast to queen */
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    /* Payload: job_id(4) + chunk_id(4) + result_lo(4) + result_hi(4) */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = job_id; p += 4;
    *(uint32_t*)p = g_state.current_chunk.chunk_id; p += 4;
    *(uint32_t*)p = (uint32_t)(result & 0xFFFFFFFF); p += 4;
    *(uint32_t*)p = (uint32_t)(result >> 32); p += 4;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    vga_set_color(0x0B);
    vga_puts("[JOB] Chunk ");
    vga_put_dec(g_state.current_chunk.chunk_id);
    vga_puts(" done: result=");
    vga_put_dec((uint32_t)result);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[JOB] Chunk ");
    serial_put_dec(g_state.current_chunk.chunk_id);
    serial_puts(" done: ");
    serial_put_dec((uint32_t)result);
    serial_puts("\n");

    g_state.current_chunk.processing = 0;
    g_state.chunks_processed++;
}

/* Handle JOB_START pheromone */
void process_job_start(struct nanos_pheromone* pkt) {
    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint8_t job_type = pkt->payload[4];
    uint32_t param1 = *(uint32_t*)(pkt->payload + 5);
    uint32_t param2 = *(uint32_t*)(pkt->payload + 9);
    uint32_t num_chunks = *(uint32_t*)(pkt->payload + 13);

    /* Check if we're already processing this job (deduplication) */
    int slot = job_id % MAX_ACTIVE_JOBS;
    if (g_state.active_jobs[slot].job_id == job_id && g_state.active_jobs[slot].active) {
        /* Already processing - just relay if needed */
        if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
            pkt->ttl--;
            e1000_send(pkt, sizeof(*pkt));
        }
        return;
    }

    /* Also check if we're currently processing a chunk from this job */
    if (g_state.current_chunk.job_id == job_id && g_state.current_chunk.processing) {
        if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
            pkt->ttl--;
            e1000_send(pkt, sizeof(*pkt));
        }
        return;
    }

    /* New job - display it */
    vga_set_color(0x0D);
    vga_puts(">> JOB #");
    vga_put_dec(job_id);
    vga_puts(" type=");
    vga_put_dec(job_type);
    vga_puts(" range=");
    vga_put_dec(param1);
    vga_puts("-");
    vga_put_dec(param2);
    vga_puts(" chunks=");
    vga_put_dec(num_chunks);
    vga_puts("\n");
    vga_set_color(0x0A);

    serial_puts("[JOB] Received job ");
    serial_put_dec(job_id);
    serial_puts(" type=");
    serial_put_dec(job_type);
    serial_puts("\n");

    /* Calculate which chunk this node should process based on node_id */
    uint32_t my_chunk = g_state.node_id % num_chunks;
    uint32_t range_size = (param2 - param1) / num_chunks;
    uint32_t chunk_start = param1 + (my_chunk * range_size);
    uint32_t chunk_end = (my_chunk == num_chunks - 1) ? param2 : chunk_start + range_size - 1;

    /* Record the job */
    g_state.active_jobs[slot].job_id = job_id;
    g_state.active_jobs[slot].job_type = job_type;
    g_state.active_jobs[slot].active = 1;
    g_state.active_jobs[slot].param1 = param1;
    g_state.active_jobs[slot].param2 = param2;
    g_state.active_jobs[slot].chunks_total = num_chunks;
    g_state.active_jobs[slot].chunks_done = 0;
    g_state.active_jobs[slot].result = 0;
    g_state.active_jobs[slot].started_at = ticks;
    g_state.active_jobs[slot].coordinator_id = pkt->node_id;  /* Sender aggregates results */

    /* Set current chunk to process */
    g_state.current_chunk.job_id = job_id;
    g_state.current_chunk.job_type = job_type;
    g_state.current_chunk.chunk_id = my_chunk;
    g_state.current_chunk.range_start = chunk_start;
    g_state.current_chunk.range_end = chunk_end;
    g_state.current_chunk.processing = 1;

    /* Relay the job announcement (gossip) */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Handle JOB_DONE pheromone (chunk result from worker) */
void process_job_done(struct nanos_pheromone* pkt) {
    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint32_t chunk_id = *(uint32_t*)(pkt->payload + 4);
    uint32_t result_lo = *(uint32_t*)(pkt->payload + 8);
    uint32_t result_hi = *(uint32_t*)(pkt->payload + 12);
    uint64_t result = ((uint64_t)result_hi << 32) | result_lo;

    int slot = job_id % MAX_ACTIVE_JOBS;

    /* Check if we should aggregate results */
    int should_aggregate = 0;

    if (g_state.role == ROLE_QUEEN) {
        /* Queens always aggregate */
        should_aggregate = 1;
    } else if (g_state.active_jobs[slot].coordinator_id == g_state.node_id) {
        /* We are the designated coordinator */
        should_aggregate = 1;
    } else if (g_state.current_chunk.chunk_id == 0 &&
               g_state.current_chunk.job_id == job_id) {
        /* Fallback: node processing chunk 0 aggregates (for external coordinators like dashboard) */
        should_aggregate = 1;
    }

    if (should_aggregate) {
        if (g_state.active_jobs[slot].job_id == job_id && g_state.active_jobs[slot].active) {
            g_state.active_jobs[slot].result += result;
            g_state.active_jobs[slot].chunks_done++;

            vga_set_color(0x0B);
            vga_puts("<< CHUNK ");
            vga_put_dec(chunk_id);
            vga_puts(" result=");
            vga_put_dec((uint32_t)result);
            vga_puts(" (");
            vga_put_dec(g_state.active_jobs[slot].chunks_done);
            vga_puts("/");
            vga_put_dec(g_state.active_jobs[slot].chunks_total);
            vga_puts(")\n");
            vga_set_color(0x0A);

            /* Check if job is complete */
            if (g_state.active_jobs[slot].chunks_done >= g_state.active_jobs[slot].chunks_total) {
                vga_set_color(0x0D);
                vga_puts(">> JOB #");
                vga_put_dec(job_id);
                vga_puts(" COMPLETE! Total result: ");
                vga_put_dec((uint32_t)g_state.active_jobs[slot].result);
                vga_puts("\n");
                vga_set_color(0x0A);

                serial_puts("[JOB] Job ");
                serial_put_dec(job_id);
                serial_puts(" complete: result=");
                serial_put_dec((uint32_t)g_state.active_jobs[slot].result);
                serial_puts("\n");

                g_state.active_jobs[slot].active = 0;
                g_state.jobs_completed++;

                /* Broadcast final result */
                struct nanos_pheromone result_pkt;
                result_pkt.magic = NANOS_MAGIC;
                result_pkt.node_id = g_state.node_id;
                result_pkt.type = PHEROMONE_JOB_RESULT;
                result_pkt.ttl = GRADIENT_MAX_HOPS;
                result_pkt.flags = 0;
                result_pkt.version = NANOS_VERSION;
                result_pkt.seq = g_state.seq_counter++;
                result_pkt.dest_id = 0;
                result_pkt.distance = 0;
                result_pkt.hop_count = 0;
                PKT_SET_ROLE(&result_pkt, ROLE_QUEEN);

                uint8_t* p = result_pkt.payload;
                *(uint32_t*)p = job_id; p += 4;
                *(uint32_t*)p = (uint32_t)(g_state.active_jobs[slot].result & 0xFFFFFFFF); p += 4;
                *(uint32_t*)p = (uint32_t)(g_state.active_jobs[slot].result >> 32);

                for (int i = 0; i < HMAC_TAG_SIZE; i++) result_pkt.hmac[i] = 0;
                e1000_send(&result_pkt, sizeof(result_pkt));
                g_state.packets_tx++;
            }
        }
    }

    /* Relay result (gossip toward queen) */
    if (pkt->ttl > 0 && gossip_should_relay(pkt)) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Handle JOB_RESULT pheromone (final result broadcast) */
void process_job_result(struct nanos_pheromone* pkt) {
    /* Deduplicate using gossip cache */
    if (!gossip_should_relay(pkt)) {
        return;  /* Already seen this result */
    }

    uint32_t job_id = *(uint32_t*)(pkt->payload);
    uint32_t result_lo = *(uint32_t*)(pkt->payload + 4);
    uint32_t result_hi = *(uint32_t*)(pkt->payload + 8);
    uint64_t result = ((uint64_t)result_hi << 32) | result_lo;

    vga_set_color(0x0D);
    vga_puts(">> FINAL RESULT Job #");
    vga_put_dec(job_id);
    vga_puts(": ");
    vga_put_dec((uint32_t)result);
    vga_puts("\n");
    vga_set_color(0x0A);

    /* Clear our active job state for this job */
    int slot = job_id % MAX_ACTIVE_JOBS;
    if (g_state.active_jobs[slot].job_id == job_id) {
        g_state.active_jobs[slot].active = 0;
    }

    /* Relay the result */
    if (pkt->ttl > 0) {
        pkt->ttl--;
        e1000_send(pkt, sizeof(*pkt));
    }
}

/* Command to start a global compute job (queen only) */
void cmd_start_job(void) {
    if (g_state.role != ROLE_QUEEN) {
        vga_puts("! Only QUEEN can start global jobs\n");
        return;
    }

    static uint32_t job_counter = 0;
    uint32_t job_id = job_counter++;

    /* Create a prime search job */
    uint32_t range_start = 1 + (random() % 1000);
    uint32_t range_end = range_start + 1000 + (random() % 5000);
    uint32_t num_chunks = g_state.neighbor_count > 0 ? g_state.neighbor_count + 1 : 1;
    if (num_chunks > MAX_JOB_CHUNKS) num_chunks = MAX_JOB_CHUNKS;

    vga_set_color(0x0D);
    vga_puts(">> Starting PRIME SEARCH job #");
    vga_put_dec(job_id);
    vga_puts("\n   Range: ");
    vga_put_dec(range_start);
    vga_puts(" - ");
    vga_put_dec(range_end);
    vga_puts("\n   Chunks: ");
    vga_put_dec(num_chunks);
    vga_puts("\n");
    vga_set_color(0x0A);

    /* Build and send JOB_START */
    struct nanos_pheromone pkt;
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_JOB_START;
    pkt.ttl = GRADIENT_MAX_HOPS;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;  /* Broadcast */
    pkt.distance = 0;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, ROLE_QUEEN);

    /* Payload: job_id(4) + job_type(1) + param1(4) + param2(4) + num_chunks(4) */
    uint8_t* p = pkt.payload;
    *(uint32_t*)p = job_id; p += 4;
    *p++ = JOB_PRIME_SEARCH;
    *(uint32_t*)p = range_start; p += 4;
    *(uint32_t*)p = range_end; p += 4;
    *(uint32_t*)p = num_chunks;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;

    /* Record the job locally */
    int slot = job_id % MAX_ACTIVE_JOBS;
    g_state.active_jobs[slot].job_id = job_id;
    g_state.active_jobs[slot].job_type = JOB_PRIME_SEARCH;
    g_state.active_jobs[slot].active = 1;
    g_state.active_jobs[slot].param1 = range_start;
    g_state.active_jobs[slot].param2 = range_end;
    g_state.active_jobs[slot].chunks_total = num_chunks;
    g_state.active_jobs[slot].chunks_done = 0;
    g_state.active_jobs[slot].result = 0;
    g_state.active_jobs[slot].started_at = ticks;
    g_state.active_jobs[slot].coordinator_id = g_state.node_id;  /* We are coordinator */

    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;

    /* Also process our own chunk */
    process_job_start(&pkt);

    serial_puts("[JOB] Started global job ");
    serial_put_dec(job_id);
    serial_puts("\n");
}
