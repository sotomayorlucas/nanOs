/**
 * NanOS Task Handler - Worker-side task execution
 *
 * Receives tasks from Queen, executes them, and returns results.
 *
 * Copyright (c) 2026 SymbiOS Project
 */

#ifndef NANOS_TASK_HANDLER_H
#define NANOS_TASK_HANDLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * Configuration
 * =============================================================================
 */

#define TASK_HANDLER_MAX_PENDING    4       /* Max concurrent tasks */
#define TASK_HANDLER_TICK_MS        50      /* Handler tick interval */

/* =============================================================================
 * Task Pheromone Types (must match Queen-side micrOS)
 * Range 0xA0-0xAF reserved for task distribution
 * =============================================================================
 */

#define PHEROMONE_TASK_ASSIGN       0xA0    /* Task from Queen → Worker */
#define PHEROMONE_TASK_RESULT       0xA1    /* Result from Worker → Queen */
#define PHEROMONE_TASK_STATUS       0xA2    /* Status query/response */
#define PHEROMONE_TASK_CANCEL       0xA3    /* Cancel task */

/* =============================================================================
 * Task Types (must match Queen-side)
 * =============================================================================
 */

#define TASK_TYPE_NONE              0x00
#define TASK_TYPE_PRIME_CHECK       0x01
#define TASK_TYPE_FACTORIAL         0x02
#define TASK_TYPE_HASH              0x03
#define TASK_TYPE_FIBONACCI         0x04
#define TASK_TYPE_GCD               0x05
#define TASK_TYPE_CUSTOM            0x80

/* =============================================================================
 * Task Status
 * =============================================================================
 */

#define TASK_STATUS_FREE            0
#define TASK_STATUS_PENDING         1
#define TASK_STATUS_ASSIGNED        2
#define TASK_STATUS_RUNNING         3
#define TASK_STATUS_COMPLETE        4
#define TASK_STATUS_FAILED          5
#define TASK_STATUS_TIMEOUT         6

/* =============================================================================
 * Task Commands
 * =============================================================================
 */

#define TASK_CMD_ASSIGN             0x01
#define TASK_CMD_CANCEL             0x02
#define TASK_CMD_STATUS             0x03

/* =============================================================================
 * Error Codes
 * =============================================================================
 */

#define TASK_ERR_NONE               0x00
#define TASK_ERR_UNKNOWN_TYPE       0x01
#define TASK_ERR_INVALID_INPUT      0x02
#define TASK_ERR_OVERFLOW           0x03
#define TASK_ERR_TIMEOUT            0x04
#define TASK_ERR_INTERNAL           0xFF

/* =============================================================================
 * Task Assignment Payload (from Queen)
 * =============================================================================
 */

struct task_payload {
    uint8_t  command;           /* TASK_CMD_* */
    uint8_t  priority;          /* 0=critical, 1-9=normal */
    uint16_t task_id;           /* Unique identifier */
    uint8_t  task_type;         /* TASK_TYPE_* */
    uint8_t  reserved;
    uint16_t timeout_ms;        /* Execution timeout */
    uint32_t input;             /* Primary input value */
    uint32_t input2;            /* Secondary input (optional) */
    uint16_t checksum;          /* CRC16 */
    uint8_t  padding[14];       /* Pad to 32 bytes */
} __attribute__((packed));

/* =============================================================================
 * Task Result Payload (to Queen)
 * =============================================================================
 */

struct task_result_payload {
    uint16_t task_id;           /* Task identifier */
    uint16_t node_id;           /* Our node ID */
    uint8_t  status;            /* TASK_STATUS_* */
    uint8_t  error_code;        /* TASK_ERR_* */
    uint16_t execution_ms;      /* Time to complete */
    uint32_t result;            /* Primary result */
    uint32_t result2;           /* Secondary result */
    uint16_t checksum;          /* CRC16 */
    uint8_t  padding[14];       /* Pad to 32 bytes */
} __attribute__((packed));

/* =============================================================================
 * Worker Task State
 * =============================================================================
 */

struct worker_task {
    uint16_t task_id;           /* Task identifier */
    uint8_t  task_type;         /* TASK_TYPE_* */
    uint8_t  status;            /* Current status */
    uint32_t input;             /* Primary input */
    uint32_t input2;            /* Secondary input */
    uint32_t result;            /* Computed result */
    uint32_t result2;           /* Secondary result */
    uint32_t started_tick;      /* When execution started */
    uint16_t timeout_ms;        /* Timeout setting */
    uint8_t  error_code;        /* Error if failed */
    uint8_t  active;            /* Slot in use */
};

/* =============================================================================
 * Handler State
 * =============================================================================
 */

struct task_handler_state {
    uint8_t  initialized;
    uint16_t local_node_id;

    /* Active tasks */
    struct worker_task tasks[TASK_HANDLER_MAX_PENDING];
    uint8_t  active_count;

    /* Statistics */
    uint32_t tasks_received;
    uint32_t tasks_completed;
    uint32_t tasks_failed;

    /* Timing */
    uint32_t last_tick;
};

/* =============================================================================
 * Public API
 * =============================================================================
 */

/**
 * Initialize the task handler
 * @param node_id  Local node identifier
 */
void task_handler_init(uint16_t node_id);

/**
 * Process incoming task pheromone
 * Called by NERT callback dispatcher
 */
void task_handler_process_pheromone(const struct task_payload *payload);

/**
 * Run one tick of the task handler
 * Call periodically from main kernel loop
 */
void task_handler_tick(void);

/**
 * Get handler state for debugging
 */
struct task_handler_state* task_handler_get_state(void);

/* =============================================================================
 * Task Implementation Functions
 * =============================================================================
 */

/**
 * Check if a number is prime
 * @param n  Number to check
 * @return 1 if prime, 0 otherwise
 */
uint32_t task_compute_prime(uint32_t n);

/**
 * Compute factorial
 * @param n  Number (limited to avoid overflow)
 * @return n! or 0 on overflow
 */
uint32_t task_compute_factorial(uint32_t n);

/**
 * Compute FNV-1a hash
 * @param input  Value to hash
 * @return 32-bit hash
 */
uint32_t task_compute_hash(uint32_t input);

/**
 * Compute Fibonacci number
 * @param n  Index
 * @return Fibonacci(n)
 */
uint32_t task_compute_fibonacci(uint32_t n);

/**
 * Compute GCD (Greatest Common Divisor)
 * @param a  First number
 * @param b  Second number
 * @return GCD(a, b)
 */
uint32_t task_compute_gcd(uint32_t a, uint32_t b);

#ifdef __cplusplus
}
#endif

#endif /* NANOS_TASK_HANDLER_H */
