/*
 * NanOS Genetic Configuration Receiver - "El Adaptador del Trabajador" (v0.7)
 *
 * Receives genetic configurations from the Queen and applies them
 * to the local NERT stack. Reports telemetry for fitness evaluation.
 *
 * "Each worker adapts to the swarm's evolved parameters."
 */
#include <nanos.h>
#include <nanos/genetic_config.h>
#include <nanos/blackbox.h>
#include <nanos/serial.h>
#include "../include/nert.h"
#include <string.h>

/* External globals */
extern volatile uint32_t ticks;
extern struct nanos_state g_state;
extern uint32_t random(void);

/* External NERT functions (signatures must match kernel/protocol/nert.c) */
extern const struct nert_stats* nert_get_stats(void);
extern void nert_set_jitter_params(uint16_t min_ms, uint16_t max_ms);
extern void nert_rate_limit_configure(const struct nert_rate_limit_config *config);
extern void nert_blacklist_configure(const struct nert_behavior_config *config);
extern void nert_cover_set_mode(uint8_t mode);
extern size_t heap_usage_percent(void);
extern uint8_t nert_get_tx_queue_count(void);
extern const struct nert_rate_limit_config *nert_rate_limit_get_config(void);
extern const struct nert_behavior_config *nert_blacklist_get_config(void);

/* Worker genetic state */
static struct genetic_worker_state g_genetic_worker;

/* Rate limiting for config updates */
#define CONFIG_RATE_LIMIT_MS        60000   /* 1 minute */
#define CONFIG_RATE_LIMIT_COUNT     10      /* Max config APPLY/TEST per minute */

/* Test mode timeout */
#define TEST_MODE_TIMEOUT_MS        120000  /* 2 minutes */

/* Max caller-supplied apply delay. The sync wait below spins on the worker's single
 * cooperative loop, and apply_delay_ms comes from the (authenticated but trusted)
 * payload; cap it so a buggy/hostile Queen cannot stall RX/telemetry/task processing. */
#define GENETIC_MAX_APPLY_DELAY_MS  500

/* ==========================================================================
 * CRC16 Calculation (must match Queen's implementation)
 * ========================================================================== */

static uint16_t crc16_update(uint16_t crc, uint8_t byte) {
    crc ^= (uint16_t)byte << 8;
    for (int i = 0; i < 8; i++) {
        if (crc & 0x8000) {
            crc = (crc << 1) ^ 0x1021;
        } else {
            crc <<= 1;
        }
    }
    return crc;
}

uint16_t genetic_calc_crc16(const void *data, uint16_t len) {
    uint16_t crc = 0xFFFF;
    const uint8_t *bytes = (const uint8_t *)data;

    for (uint16_t i = 0; i < len; i++) {
        crc = crc16_update(crc, bytes[i]);
    }

    return crc;
}

bool genetic_verify_genome(const struct nert_genome *genome) {
    /* Calculate CRC over all bytes except checksum field */
    uint16_t expected = genetic_calc_crc16(genome,
        sizeof(struct nert_genome) - sizeof(uint16_t));
    return genome->checksum == expected;
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

void genetic_config_init(void) {
    memset(&g_genetic_worker, 0, sizeof(g_genetic_worker));

    g_genetic_worker.active_genome_id = 0;
    g_genetic_worker.sub_swarm_id = 0;
    g_genetic_worker.in_test_mode = 0;
    g_genetic_worker.has_backup = 0;

    g_genetic_worker.telemetry_start_tick = ticks;
    g_genetic_worker.tx_at_start = 0;
    g_genetic_worker.tx_success_at_start = 0;

    serial_puts("[GENETIC] Config receiver initialized\n");
}

/* ==========================================================================
 * Backup/Restore
 * ========================================================================== */

void genetic_save_backup(void) {
    /* Save current configuration as backup */
    struct nert_genome *backup = &g_genetic_worker.backup_genome;

    backup->version = GENETIC_GENOME_VERSION;
    backup->genome_id = g_genetic_worker.active_genome_id;
    backup->generation = g_genetic_worker.active_generation;

    /* Read current NERT config (these would need getters in real impl) */
    backup->tick_interval_ms = NERT_TICK_INTERVAL_MS;
    backup->retry_timeout_ms = NERT_RETRY_TIMEOUT_MS;
    backup->max_retries = NERT_MAX_RETRIES;
    backup->window_size = NERT_WINDOW_SIZE;
    backup->connection_timeout_cs = NERT_CONNECTION_TIMEOUT_MS / 100;
    backup->key_grace_window_cs = NERT_KEY_GRACE_WINDOW_MS / 100;

    /* These are default values */
    backup->rate_bucket_capacity = 10;
    backup->rate_refill_tokens = 5;
    backup->rate_refill_ms = 1000;
    backup->gossip_prob_base = 80;
    backup->gossip_prob_decay = 40;
    backup->jitter_min_ms = NERT_JITTER_MIN_MS;
    backup->jitter_max_ms = NERT_JITTER_MAX_MS;
    backup->reputation_warn = 70;
    backup->reputation_ban = 20;
    backup->cover_mode = 0;
    backup->cover_interval_scale = 5;

    g_genetic_worker.has_backup = 1;

    serial_puts("[GENETIC] Backup saved\n");
}

void genetic_restore_backup(void) {
    if (!g_genetic_worker.has_backup) {
        serial_puts("[GENETIC] No backup to restore\n");
        return;
    }

    /* Apply backup genome */
    genetic_apply_genome(&g_genetic_worker.backup_genome, 0, false);
    g_genetic_worker.in_test_mode = 0;

    serial_puts("[GENETIC] Backup restored\n");
}

/* ==========================================================================
 * Genome Application
 * ========================================================================== */

int genetic_apply_genome(const struct nert_genome *genome,
                         uint16_t delay_ms,
                         bool test_mode) {
    /* Verify genome version */
    if (genome->version != GENETIC_GENOME_VERSION) {
        serial_puts("[GENETIC] Invalid genome version\n");
        blackbox_record_event(EVENT_CORRUPTION, 0);
        return -1;
    }

    /* Save backup if entering test mode */
    if (test_mode && !g_genetic_worker.has_backup) {
        genetic_save_backup();
    }

    /* Clamp payload-supplied delay (see GENETIC_MAX_APPLY_DELAY_MS). */
    if (delay_ms > GENETIC_MAX_APPLY_DELAY_MS) {
        delay_ms = GENETIC_MAX_APPLY_DELAY_MS;
    }

    /* Wait for sync delay */
    if (delay_ms > 0) {
        uint32_t target = ticks + (delay_ms / 10);
        while (ticks < target) {
            /* Spin wait */
        }
    }

    /* Apply timing genes */
    /* Note: In real implementation, these would modify runtime config */
    /* g_nert_config.tick_interval_ms = genome->tick_interval_ms; */
    /* g_nert_config.retry_timeout_ms = genome->retry_timeout_ms; */
    /* etc. */

    /* Apply jitter parameters */
    nert_set_jitter_params(genome->jitter_min_ms, genome->jitter_max_ms);

    /* Apply rate limiting: read current config, override genome-controlled genes. */
    struct nert_rate_limit_config rl = *nert_rate_limit_get_config();
    rl.bucket_capacity     = genome->rate_bucket_capacity;
    rl.refill_tokens       = genome->rate_refill_tokens;
    rl.refill_interval_ms  = genome->rate_refill_ms;
    nert_rate_limit_configure(&rl);

    /* Apply behavioral blacklist thresholds: read current config, override genes. */
    struct nert_behavior_config bh = *nert_blacklist_get_config();
    bh.warn_threshold = genome->reputation_warn;
    bh.ban_threshold  = genome->reputation_ban;
    nert_blacklist_configure(&bh);

    /* Apply cover traffic mode */
    nert_cover_set_mode(genome->cover_mode);

    /* Update state */
    g_genetic_worker.active_genome_id = genome->genome_id;
    g_genetic_worker.active_generation = genome->generation;
    g_genetic_worker.genome_applied_tick = ticks;

    /* Reset telemetry collection */
    g_genetic_worker.telemetry_start_tick = ticks;
    const struct nert_stats *stats = nert_get_stats();
    if (stats) {
        g_genetic_worker.tx_at_start = stats->tx_packets;
        g_genetic_worker.tx_success_at_start = stats->tx_packets - stats->tx_retransmits;
    }

    /* Set test mode if requested */
    if (test_mode) {
        g_genetic_worker.in_test_mode = 1;
        g_genetic_worker.test_timeout_tick = ticks + (TEST_MODE_TIMEOUT_MS / 10);
    } else {
        g_genetic_worker.in_test_mode = 0;
    }

    serial_puts("[GENETIC] Applied genome 0x");
    serial_put_hex(genome->genome_id);
    serial_puts(" gen=");
    serial_put_dec(genome->generation);
    if (test_mode) serial_puts(" (TEST MODE)");
    serial_puts("\n");

    /* Record in BlackBox */
    blackbox_record_event(EVENT_CONFIG_APPLIED, genome->genome_id);

    return 0;
}

void genetic_revert_to_default(void) {
    if (g_genetic_worker.has_backup) {
        genetic_restore_backup();
    } else {
        /* Create default genome and apply */
        struct nert_genome default_genome;
        memset(&default_genome, 0, sizeof(default_genome));

        default_genome.version = GENETIC_GENOME_VERSION;
        default_genome.tick_interval_ms = 50;
        default_genome.retry_timeout_ms = 200;
        default_genome.max_retries = 5;
        default_genome.window_size = 2;
        default_genome.connection_timeout_cs = 300;
        default_genome.key_grace_window_cs = 300;
        default_genome.rate_bucket_capacity = 10;
        default_genome.rate_refill_tokens = 5;
        default_genome.rate_refill_ms = 1000;
        default_genome.gossip_prob_base = 80;
        default_genome.gossip_prob_decay = 40;
        default_genome.jitter_min_ms = 10;
        default_genome.jitter_max_ms = 100;
        default_genome.reputation_warn = 70;
        default_genome.reputation_ban = 20;
        default_genome.cover_mode = 0;
        default_genome.cover_interval_scale = 5;

        genetic_apply_genome(&default_genome, 0, false);
    }

    g_genetic_worker.active_genome_id = 0;
    g_genetic_worker.in_test_mode = 0;

    serial_puts("[GENETIC] Reverted to default config\n");
}

/* ==========================================================================
 * Telemetry Collection and Reporting
 * ========================================================================== */

void genetic_collect_metrics(struct telemetry_report_payload *report) {
    const struct nert_stats *stats = nert_get_stats();

    report->genome_id = g_genetic_worker.active_genome_id;
    report->node_id = (uint16_t)g_state.node_id;

    /* Performance metrics */
    if (stats) {
        report->avg_rtt = stats->avg_rtt;

        /* Calculate throughput (packets per second) */
        uint32_t elapsed_ticks = ticks - g_genetic_worker.telemetry_start_tick;
        uint32_t elapsed_ms = elapsed_ticks * 10;  /* Assuming 10ms tick */
        if (elapsed_ms > 0) {
            uint32_t tx_delta = stats->tx_packets - g_genetic_worker.tx_at_start;
            report->throughput = (uint16_t)((tx_delta * 1000) / elapsed_ms);
        } else {
            report->throughput = 0;
        }

        /* Calculate success rate */
        uint32_t total_tx = stats->tx_packets - g_genetic_worker.tx_at_start;
        uint32_t retx = stats->tx_retransmits;
        if (total_tx > 0) {
            uint32_t success = total_tx - retx;
            report->success_rate = (uint16_t)((success * 10000) / total_tx);
        } else {
            report->success_rate = 10000;  /* Assume perfect if no traffic */
        }

        /* Security metrics */
        report->bad_mac_count = (uint16_t)stats->rx_bad_mac;
        report->replay_blocked = (uint16_t)stats->rx_replay_blocked;
        report->rate_limited = (uint16_t)stats->rx_rate_limited;
    } else {
        report->avg_rtt = 0;
        report->throughput = 0;
        report->success_rate = 10000;
        report->bad_mac_count = 0;
        report->replay_blocked = 0;
        report->rate_limited = 0;
    }

    /* Survival metrics */
    uint32_t uptime_ticks = ticks - g_state.boot_time;
    report->uptime_minutes = (uint16_t)(uptime_ticks / 6000);  /* ticks to minutes */
    report->neighbor_count = g_state.neighbor_count;
    report->alarm_count = (uint8_t)g_state.alarms_relayed;

    /* Resource metrics */
    report->heap_usage_pct = (uint8_t)heap_usage_percent();
    report->queue_depth = nert_get_tx_queue_count();

    report->report_tick = ticks;
}

void genetic_send_telemetry_report(void) {
    struct telemetry_report_payload report;
    genetic_collect_metrics(&report);

    /* Send to Queen (node with distance 0, or use known queen ID) */
    uint32_t queen_id = g_state.known_queen_id;
    if (queen_id == 0) {
        /* No known queen - broadcast */
        queen_id = 0;
    }

    int result = nert_send_unreliable(queen_id, PHEROMONE_TELEMETRY_REPORT,
                                      &report, sizeof(report));

    if (result >= 0) {
        serial_puts("[GENETIC] Telemetry sent: fitness metrics for genome 0x");
        serial_put_hex(report.genome_id);
        serial_puts("\n");
    } else {
        serial_puts("[GENETIC] Failed to send telemetry\n");
    }
}

/* ==========================================================================
 * Pheromone Processing
 * ========================================================================== */

/* Shared command core. sender_id is the authenticated NERT sender (or the raw
 * pheromone node_id). Applies rate-limit to reconfiguring commands only. */
static void genetic_apply_config_payload(uint16_t sender_id,
                                         const struct config_update_payload *payload) {
    /* Sub-swarm targeting (0 = all) */
    if (payload->sub_swarm_id != 0 &&
        payload->sub_swarm_id != g_genetic_worker.sub_swarm_id) {
        return;  /* Not for us */
    }

    /* Rate limiting applies only to reconfiguring commands (APPLY/TEST). REPORT and
     * REVERT do not reconfigure and must not consume the budget. */
    if (payload->command == CONFIG_CMD_APPLY || payload->command == CONFIG_CMD_TEST) {
        uint32_t now = ticks;
        if (now - g_genetic_worker.last_config_tick < (CONFIG_RATE_LIMIT_MS / 10)) {
            g_genetic_worker.config_count++;
            if (g_genetic_worker.config_count > CONFIG_RATE_LIMIT_COUNT) {
                serial_puts("[GENETIC] Rate limited - too many config updates\n");
                return;
            }
        } else {
            g_genetic_worker.last_config_tick = now;
            g_genetic_worker.config_count = 1;
        }
    }

    switch (payload->command) {
        case CONFIG_CMD_APPLY:
            if (!genetic_verify_genome(&payload->genome)) {
                serial_puts("[GENETIC] Invalid genome checksum\n");
                blackbox_record_event(EVENT_CORRUPTION, sender_id);
                return;
            }
            genetic_apply_genome(&payload->genome, payload->apply_delay_ms, false);
            break;

        case CONFIG_CMD_TEST:
            if (!genetic_verify_genome(&payload->genome)) {
                serial_puts("[GENETIC] Invalid genome checksum\n");
                blackbox_record_event(EVENT_CORRUPTION, sender_id);
                return;
            }
            genetic_apply_genome(&payload->genome, payload->apply_delay_ms, true);
            break;

        case CONFIG_CMD_REVERT:
            genetic_revert_to_default();
            break;

        case CONFIG_CMD_REPORT:
            genetic_send_telemetry_report();
            break;

        default:
            serial_puts("[GENETIC] Unknown command: ");
            serial_put_hex(payload->command);
            serial_puts("\n");
            break;
    }
}

/* NERT dispatch entry for PHEROMONE_CONFIG_UPDATE (0x14). The decrypted payload is
 * delivered as (sender_id, data, len) -- NOT a nanos_pheromone. */
void genetic_process_config_nert(uint16_t sender_id, const void *data, uint8_t len) {
    if (data == NULL || len < sizeof(struct config_update_payload)) {
        serial_puts("[GENETIC] Config payload too short\n");
        return;
    }

    /* Accept only from the known Queen. If we have not yet learned the Queen's id
     * (known_queen_id == 0), accept: NERT authentication already proves the sender
     * is a swarm member holding the PSK. */
    uint16_t queen = (uint16_t)g_state.known_queen_id;
    if (queen != 0 && sender_id != queen) {
        serial_puts("[GENETIC] Rejected config from non-Queen\n");
        blackbox_record_event(EVENT_BAD_MAC, sender_id);
        return;
    }

    genetic_apply_config_payload(sender_id, (const struct config_update_payload *)data);
}

/* ==========================================================================
 * Periodic Tick
 * ========================================================================== */

void genetic_config_tick(void) {
    /* Check test mode timeout */
    if (g_genetic_worker.in_test_mode) {
        if (ticks >= g_genetic_worker.test_timeout_tick) {
            serial_puts("[GENETIC] Test mode timeout - reverting\n");
            genetic_restore_backup();
        }
    }
}

/* ==========================================================================
 * Status Queries
 * ========================================================================== */

uint16_t genetic_get_active_genome_id(void) {
    return g_genetic_worker.active_genome_id;
}

bool genetic_is_test_mode(void) {
    return g_genetic_worker.in_test_mode != 0;
}
