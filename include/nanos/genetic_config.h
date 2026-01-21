/*
 * NanOS Genetic Configuration Receiver - "El Genoma del Trabajador" (v0.7)
 *
 * Workers receive optimized configurations from the Queen via
 * PHEROMONE_CONFIG_UPDATE and apply them to their NERT stack.
 *
 * "Each worker carries the evolved DNA of the swarm."
 */
#ifndef NANOS_GENETIC_CONFIG_H
#define NANOS_GENETIC_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* ==========================================================================
 * Shared Constants (must match genetic_tuning.h)
 * ========================================================================== */

#define GENETIC_GENOME_VERSION      1

/* Pheromone types */
#define PHEROMONE_CONFIG_UPDATE     0x14
#define PHEROMONE_TELEMETRY_REPORT  0x15

/* Config commands */
#define CONFIG_CMD_APPLY        0x01
#define CONFIG_CMD_TEST         0x02
#define CONFIG_CMD_REVERT       0x03
#define CONFIG_CMD_REPORT       0x04

/* ==========================================================================
 * Genome Structure (must match Queen's structure exactly)
 * ========================================================================== */

struct nert_genome {
    /* Identity */
    uint16_t genome_id;
    uint8_t  generation;
    uint8_t  version;

    /* Timing Genes */
    uint16_t tick_interval_ms;
    uint16_t retry_timeout_ms;
    uint8_t  max_retries;
    uint8_t  window_size;
    uint16_t connection_timeout_cs;

    /* Security Genes */
    uint16_t key_grace_window_cs;
    uint8_t  rate_bucket_capacity;
    uint8_t  rate_refill_tokens;
    uint16_t rate_refill_ms;

    /* Gossip Genes */
    uint8_t  gossip_prob_base;
    uint8_t  gossip_prob_decay;
    uint8_t  jitter_min_ms;
    uint8_t  jitter_max_ms;

    /* Behavioral Genes */
    uint8_t  reputation_warn;
    uint8_t  reputation_ban;
    uint8_t  cover_mode;
    uint8_t  cover_interval_scale;

    /* Evaluation (local use) */
    uint16_t fitness_score;
    uint16_t sample_count;

    /* Checksum */
    uint16_t checksum;
} __attribute__((packed));

/* ==========================================================================
 * Payload Structures
 * ========================================================================== */

struct config_update_payload {
    uint8_t  command;
    uint8_t  sub_swarm_id;
    uint16_t apply_delay_ms;
    struct nert_genome genome;
} __attribute__((packed));

struct telemetry_report_payload {
    uint16_t genome_id;
    uint16_t node_id;
    uint16_t avg_rtt;
    uint16_t throughput;
    uint16_t success_rate;
    uint16_t uptime_minutes;
    uint8_t  neighbor_count;
    uint8_t  alarm_count;
    uint16_t bad_mac_count;
    uint16_t replay_blocked;
    uint16_t rate_limited;
    uint8_t  heap_usage_pct;
    uint8_t  queue_depth;
    uint32_t report_tick;
} __attribute__((packed));

/* ==========================================================================
 * Worker Genetic State
 * ========================================================================== */

struct genetic_worker_state {
    /* Active configuration */
    uint16_t active_genome_id;      /* Currently applied genome */
    uint8_t  active_generation;     /* Generation of active genome */
    uint32_t genome_applied_tick;   /* When genome was applied */

    /* Sub-swarm membership */
    uint8_t  sub_swarm_id;          /* Assigned sub-swarm */

    /* Test mode */
    uint8_t  in_test_mode;          /* 1 if in test mode (auto-revert) */
    uint32_t test_timeout_tick;     /* When test mode expires */

    /* Backup for revert */
    struct nert_genome backup_genome;
    uint8_t  has_backup;            /* 1 if backup is valid */

    /* Telemetry collection */
    uint32_t telemetry_start_tick;  /* Start of current measurement period */
    uint32_t tx_at_start;           /* TX packets at start */
    uint32_t tx_success_at_start;   /* Successful TX at start */

    /* Rate limiting for config updates */
    uint32_t last_config_tick;      /* Last config update received */
    uint8_t  config_count;          /* Config updates this minute */
};

/* ==========================================================================
 * Public API
 * ========================================================================== */

/**
 * Initialize genetic config subsystem
 */
void genetic_config_init(void);

/**
 * Process received CONFIG_UPDATE pheromone
 * Called from main pheromone handler
 *
 * @param pkt  Received pheromone packet
 */
void genetic_process_config_update(struct nanos_pheromone *pkt);

/**
 * Apply a genome to the NERT configuration
 *
 * @param genome     Genome to apply
 * @param delay_ms   Delay before applying (for sync)
 * @param test_mode  If true, auto-revert on timeout
 * @return 0 on success, -1 on error
 */
int genetic_apply_genome(const struct nert_genome *genome,
                         uint16_t delay_ms,
                         bool test_mode);

/**
 * Revert to default/backup configuration
 */
void genetic_revert_to_default(void);

/**
 * Generate and send telemetry report to Queen
 */
void genetic_send_telemetry_report(void);

/**
 * Periodic tick - handles test mode timeout
 * Call from main loop
 */
void genetic_config_tick(void);

/**
 * Get current active genome ID
 */
uint16_t genetic_get_active_genome_id(void);

/**
 * Check if currently in test mode
 */
bool genetic_is_test_mode(void);

/* ==========================================================================
 * Internal Helpers (exposed for testing)
 * ========================================================================== */

/**
 * Calculate CRC16 checksum
 */
uint16_t genetic_calc_crc16(const void *data, uint16_t len);

/**
 * Verify genome checksum
 */
bool genetic_verify_genome(const struct nert_genome *genome);

/**
 * Save current config as backup
 */
void genetic_save_backup(void);

/**
 * Restore from backup
 */
void genetic_restore_backup(void);

/**
 * Collect current telemetry metrics
 */
void genetic_collect_metrics(struct telemetry_report_payload *report);

#endif /* NANOS_GENETIC_CONFIG_H */
