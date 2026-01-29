/**
 * NanOS Task Handler - Worker-side task execution (v1.0)
 *
 * Receives computational tasks from Queen (micrOS),
 * executes them locally, and sends results back.
 *
 * Uses raw nanos_pheromone format for compatibility with micrOS native mode.
 * Sends complete Ethernet frames with proper headers.
 *
 * Copyright (c) 2026 SymbiOS Project
 */

#include <nanos/task_handler.h>
#include <nanos.h>
#include <string.h>

/* External kernel state and functions */
extern struct nanos_state g_state;
extern volatile uint32_t ticks;

/* e1000 driver functions */
extern int e1000_send(const void *data, uint16_t len);
extern void e1000_get_mac(uint8_t *mac);

/* Serial output for debugging */
extern void serial_puts(const char *s);
extern void serial_put_hex(uint32_t val);
extern void serial_put_dec(uint32_t val);

/* Ethernet constants - must match micrOS */
#define ETH_ALEN            6
#define NERT_ETH_TYPE       0x4F4E  /* Must match micrOS */

/* NERT multicast MAC address - must match micrOS */
static const uint8_t NERT_MULTICAST_MAC[ETH_ALEN] = {
    0x01, 0x00, 0x5E, 0x4E, 0x45, 0x52
};

/* Wrapper to match expected naming */
static inline uint32_t nert_get_ticks(void) { return ticks; }
static inline uint16_t nert_get_node_id(void) { return (uint16_t)g_state.node_id; }

/**
 * Send raw pheromone packet with Ethernet frame (compatible with micrOS native mode)
 * Builds complete Ethernet frame: [DST MAC][SRC MAC][EtherType][nanos_pheromone]
 */
static void send_raw_pheromone(uint8_t type, const void *data, uint8_t len) {
    /* Ethernet frame buffer: 14 byte header + 64 byte payload */
    uint8_t frame[14 + sizeof(struct nanos_pheromone)];
    struct nanos_pheromone *pkt = (struct nanos_pheromone *)(frame + 14);

    /* Build Ethernet header */
    /* Destination: multicast MAC */
    for (int i = 0; i < ETH_ALEN; i++) {
        frame[i] = NERT_MULTICAST_MAC[i];
    }
    /* Source: our MAC */
    e1000_get_mac(frame + ETH_ALEN);
    /* EtherType (big-endian on wire) */
    frame[12] = (NERT_ETH_TYPE >> 8) & 0xFF;
    frame[13] = NERT_ETH_TYPE & 0xFF;

    /* Clear pheromone payload */
    for (int i = 0; i < (int)sizeof(struct nanos_pheromone); i++) {
        ((uint8_t*)pkt)[i] = 0;
    }

    /* Build pheromone header */
    pkt->magic = NANOS_MAGIC;
    pkt->node_id = g_state.node_id;
    pkt->type = type;
    pkt->ttl = 1;
    pkt->flags = 0;
    pkt->version = NANOS_VERSION;
    pkt->seq = g_state.seq_counter++;

    PKT_SET_ROLE(pkt, g_state.role);

    /* Routing fields */
    pkt->dest_id = 0;  /* Broadcast */
    pkt->distance = g_state.distance_to_queen;
    pkt->hop_count = 0;
    pkt->via_node_lo = g_state.gradient_via & 0xFF;
    pkt->via_node_hi = (g_state.gradient_via >> 8) & 0xFF;

    /* Copy payload data (max 32 bytes) */
    if (data && len > 0) {
        if (len > 32) len = 32;
        for (int i = 0; i < len; i++) {
            pkt->payload[i] = ((const uint8_t*)data)[i];
        }
    }

    /* Send complete Ethernet frame */
    if (e1000_send(frame, sizeof(frame)) == 0) {
        g_state.packets_tx++;
    }
}

/* Wrapper for pheromone sending (uses raw format for micrOS compatibility) */
static inline void nert_send_pheromone(uint8_t type, const void *data, uint8_t len) {
    send_raw_pheromone(type, data, len);
}

/* Global handler state */
static struct task_handler_state g_task_handler;

/* =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * CRC16 calculation
 */
static uint16_t task_calc_crc16(const void *data, uint16_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t crc = 0xFFFF;

    for (uint16_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

/* =============================================================================
 * Task Implementations
 * =============================================================================
 */

/**
 * Check if a number is prime
 */
uint32_t task_compute_prime(uint32_t n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;

    for (uint32_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return 0;
        }
    }

    return 1;
}

/**
 * Compute factorial (limited to prevent overflow)
 */
uint32_t task_compute_factorial(uint32_t n) {
    if (n > 12) return 0;  /* 13! overflows 32-bit */

    uint32_t result = 1;
    for (uint32_t i = 2; i <= n; i++) {
        result *= i;
    }

    return result;
}

/**
 * FNV-1a hash
 */
uint32_t task_compute_hash(uint32_t input) {
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    const uint8_t *bytes = (const uint8_t *)&input;

    for (int i = 0; i < 4; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;  /* FNV prime */
    }

    return hash;
}

/**
 * Fibonacci number (iterative)
 */
uint32_t task_compute_fibonacci(uint32_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    if (n > 46) return 0;  /* Fib(47) overflows 32-bit */

    uint32_t prev = 0, curr = 1;
    for (uint32_t i = 2; i <= n; i++) {
        uint32_t next = prev + curr;
        prev = curr;
        curr = next;
    }

    return curr;
}

/**
 * GCD using Euclidean algorithm
 */
uint32_t task_compute_gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/* =============================================================================
 * Task Execution
 * =============================================================================
 */

/**
 * Execute a task and store result
 */
static void task_execute(struct worker_task *task) {
    serial_puts("[TASK_EXEC] Executing task type=");
    serial_put_dec(task->task_type);
    serial_puts(" input=");
    serial_put_dec(task->input);
    serial_puts("\n");

    task->status = TASK_STATUS_RUNNING;
    task->started_tick = nert_get_ticks();
    task->error_code = TASK_ERR_NONE;

    switch (task->task_type) {
        case TASK_TYPE_PRIME_CHECK:
            task->result = task_compute_prime(task->input);
            task->status = TASK_STATUS_COMPLETE;
            serial_puts("[TASK_EXEC] Prime(");
            serial_put_dec(task->input);
            serial_puts(") = ");
            serial_put_dec(task->result);
            serial_puts("\n");
            break;

        case TASK_TYPE_FACTORIAL:
            task->result = task_compute_factorial(task->input);
            if (task->input > 12) {
                task->error_code = TASK_ERR_OVERFLOW;
                task->status = TASK_STATUS_FAILED;
            } else {
                task->status = TASK_STATUS_COMPLETE;
            }
            break;

        case TASK_TYPE_HASH:
            task->result = task_compute_hash(task->input);
            task->status = TASK_STATUS_COMPLETE;
            break;

        case TASK_TYPE_FIBONACCI:
            task->result = task_compute_fibonacci(task->input);
            if (task->input > 46) {
                task->error_code = TASK_ERR_OVERFLOW;
                task->status = TASK_STATUS_FAILED;
            } else {
                task->status = TASK_STATUS_COMPLETE;
            }
            break;

        case TASK_TYPE_GCD:
            if (task->input == 0 && task->input2 == 0) {
                task->error_code = TASK_ERR_INVALID_INPUT;
                task->status = TASK_STATUS_FAILED;
            } else {
                task->result = task_compute_gcd(task->input, task->input2);
                task->status = TASK_STATUS_COMPLETE;
            }
            break;

        default:
            task->error_code = TASK_ERR_UNKNOWN_TYPE;
            task->status = TASK_STATUS_FAILED;
            break;
    }
}

/**
 * Send task result to Queen
 */
static void task_send_result(struct worker_task *task) {
    serial_puts("[TASK_RESULT] Sending result: task_id=");
    serial_put_dec(task->task_id);
    serial_puts(" result=");
    serial_put_dec(task->result);
    serial_puts(" status=");
    serial_put_dec(task->status);
    serial_puts("\n");

    struct task_result_payload result;
    memset(&result, 0, sizeof(result));

    result.task_id = task->task_id;
    result.node_id = g_task_handler.local_node_id;
    result.status = task->status;
    result.error_code = task->error_code;

    /* Calculate execution time */
    uint32_t now = nert_get_ticks();
    uint32_t elapsed = now - task->started_tick;
    result.execution_ms = (elapsed > 0xFFFF) ? 0xFFFF : (uint16_t)elapsed;

    result.result = task->result;
    result.result2 = task->result2;

    /* Calculate checksum */
    result.checksum = task_calc_crc16(&result, sizeof(result) - sizeof(result.padding) - 2);

    /* Send via NERT */
    serial_puts("[TASK_RESULT] Calling nert_send_pheromone(0xA1)\n");
    nert_send_pheromone(PHEROMONE_TASK_RESULT, &result, sizeof(result));

    /* Update statistics */
    if (task->status == TASK_STATUS_COMPLETE) {
        g_task_handler.tasks_completed++;
    } else {
        g_task_handler.tasks_failed++;
    }

    /* Free the slot */
    task->active = 0;
    g_task_handler.active_count--;
}

/* =============================================================================
 * Task Queue Management
 * =============================================================================
 */

/**
 * Find a free task slot
 */
static struct worker_task* task_find_free_slot(void) {
    for (uint8_t i = 0; i < TASK_HANDLER_MAX_PENDING; i++) {
        if (!g_task_handler.tasks[i].active) {
            return &g_task_handler.tasks[i];
        }
    }
    return NULL;
}

/**
 * Find a task by ID
 */
static struct worker_task* task_find_by_id(uint16_t task_id) {
    for (uint8_t i = 0; i < TASK_HANDLER_MAX_PENDING; i++) {
        if (g_task_handler.tasks[i].active &&
            g_task_handler.tasks[i].task_id == task_id) {
            return &g_task_handler.tasks[i];
        }
    }
    return NULL;
}

/* =============================================================================
 * Public API
 * =============================================================================
 */

void task_handler_init(uint16_t node_id) {
    memset(&g_task_handler, 0, sizeof(g_task_handler));

    g_task_handler.local_node_id = node_id;
    g_task_handler.initialized = 1;
}

void task_handler_process_pheromone(const struct task_payload *payload) {
    serial_puts("[TASK_HANDLER] process_pheromone called\n");

    if (!g_task_handler.initialized) {
        serial_puts("[TASK_HANDLER] ERROR: not initialized!\n");
        return;
    }

    /* Validate checksum */
    uint16_t calc_checksum = task_calc_crc16(payload,
        sizeof(*payload) - sizeof(payload->padding) - 2);
    serial_puts("[TASK_HANDLER] checksum: calc=0x");
    serial_put_hex(calc_checksum);
    serial_puts(" pkt=0x");
    serial_put_hex(payload->checksum);
    serial_puts(" cmd=0x");
    serial_put_hex(payload->command);
    serial_puts("\n");

    if (calc_checksum != payload->checksum) {
        /* Invalid checksum - ignore */
        serial_puts("[TASK_HANDLER] ERROR: checksum mismatch!\n");
        return;
    }

    serial_puts("[TASK_HANDLER] checksum OK, processing command\n");

    switch (payload->command) {
        case TASK_CMD_ASSIGN: {
            serial_puts("[TASK_HANDLER] TASK_CMD_ASSIGN: type=");
            serial_put_dec(payload->task_type);
            serial_puts(" input=");
            serial_put_dec(payload->input);
            serial_puts("\n");
            /* Find a free slot */
            struct worker_task *task = task_find_free_slot();
            if (!task) {
                /* Queue full - send failure */
                struct task_result_payload result;
                memset(&result, 0, sizeof(result));
                result.task_id = payload->task_id;
                result.node_id = g_task_handler.local_node_id;
                result.status = TASK_STATUS_FAILED;
                result.error_code = TASK_ERR_INTERNAL;
                result.checksum = task_calc_crc16(&result,
                    sizeof(result) - sizeof(result.padding) - 2);
                nert_send_pheromone(PHEROMONE_TASK_RESULT, &result, sizeof(result));
                return;
            }

            /* Store task */
            memset(task, 0, sizeof(*task));
            task->task_id = payload->task_id;
            task->task_type = payload->task_type;
            task->input = payload->input;
            task->input2 = payload->input2;
            task->timeout_ms = payload->timeout_ms;
            task->status = TASK_STATUS_PENDING;
            task->active = 1;

            g_task_handler.active_count++;
            g_task_handler.tasks_received++;
            break;
        }

        case TASK_CMD_CANCEL: {
            struct worker_task *task = task_find_by_id(payload->task_id);
            if (task) {
                task->active = 0;
                g_task_handler.active_count--;
            }
            break;
        }

        case TASK_CMD_STATUS: {
            /* Could send back status for specific task */
            break;
        }

        default:
            break;
    }
}

void task_handler_tick(void) {
    if (!g_task_handler.initialized) return;

    uint32_t now = nert_get_ticks();
    g_task_handler.last_tick = now;

    /* Process pending tasks */
    for (uint8_t i = 0; i < TASK_HANDLER_MAX_PENDING; i++) {
        struct worker_task *task = &g_task_handler.tasks[i];

        if (!task->active) continue;

        switch (task->status) {
            case TASK_STATUS_PENDING:
                /* Execute the task */
                task_execute(task);

                /* Send result immediately */
                task_send_result(task);
                break;

            case TASK_STATUS_RUNNING:
                /* Check for timeout (shouldn't happen with sync execution) */
                if (now - task->started_tick > task->timeout_ms) {
                    task->status = TASK_STATUS_TIMEOUT;
                    task->error_code = TASK_ERR_TIMEOUT;
                    task_send_result(task);
                }
                break;

            default:
                break;
        }
    }
}

struct task_handler_state* task_handler_get_state(void) {
    return &g_task_handler;
}
