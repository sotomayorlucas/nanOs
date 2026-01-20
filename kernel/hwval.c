/*
 * NanOS Hardware Validation - "El Centinela del Silicio" (v0.6)
 *
 * Implementation of hardware integrity monitoring for detecting
 * physical attacks, sensor manipulation, and hardware compromise.
 */

#include <nanos/hwval.h>

/* ==========================================================================
 * Module State
 * ========================================================================== */

static struct hwval_state hwval_state;

/* Calibration parameters */
#define HWVAL_CALIBRATION_SAMPLES   50      /* Samples for baseline */
#define HWVAL_CALIBRATION_TIME_MS   5000    /* Max calibration time */

/* Memory regions */
#define HWVAL_REGION_RAM            0x01
#define HWVAL_REGION_FLASH          0x02
#define HWVAL_REGION_PERIPHERAL     0x03

/* ==========================================================================
 * Internal Helper Functions
 * ========================================================================== */

/**
 * Simple CRC32 implementation (if HAL doesn't provide one)
 */
static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void crc32_init_table(void) {
    if (crc32_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = true;
}

static uint32_t calculate_crc32(uint8_t *data, uint32_t size) {
    crc32_init_table();

    uint32_t crc = 0xFFFFFFFF;
    for (uint32_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

/**
 * Find violation slot (existing or new)
 */
static struct hwval_violation* find_violation_slot(uint8_t type) {
    /* Look for existing violation of same type */
    for (int i = 0; i < hwval_state.violation_count; i++) {
        if (hwval_state.violations[i].type == type) {
            return &hwval_state.violations[i];
        }
    }

    /* Add new if space available */
    if (hwval_state.violation_count < 8) {
        return &hwval_state.violations[hwval_state.violation_count++];
    }

    /* Replace oldest low-severity violation */
    uint32_t oldest_tick = 0xFFFFFFFF;
    int oldest_idx = 0;
    for (int i = 0; i < 8; i++) {
        if (hwval_state.violations[i].severity < HWVAL_SEVERITY_CRITICAL &&
            hwval_state.violations[i].first_tick < oldest_tick) {
            oldest_tick = hwval_state.violations[i].first_tick;
            oldest_idx = i;
        }
    }

    return &hwval_state.violations[oldest_idx];
}

/**
 * Update anomaly score based on violation severity
 */
static void update_anomaly_score(uint8_t severity) {
    switch (severity) {
        case HWVAL_SEVERITY_INFO:
            hwval_state.anomaly_score += 1;
            break;
        case HWVAL_SEVERITY_WARNING:
            hwval_state.anomaly_score += 5;
            break;
        case HWVAL_SEVERITY_CRITICAL:
            hwval_state.anomaly_score += 20;
            break;
        case HWVAL_SEVERITY_FATAL:
            hwval_state.anomaly_score = 255;
            break;
    }

    /* Cap at 255 */
    if (hwval_state.anomaly_score > 255) {
        hwval_state.anomaly_score = 255;
    }

    /* Update state based on anomaly level */
    if (hwval_state.anomaly_score >= 200) {
        hwval_state.state = HWVAL_STATE_COMPROMISED;
    } else if (hwval_state.anomaly_score >= 50) {
        hwval_state.state = HWVAL_STATE_SUSPICIOUS;
    }
}

/**
 * Decay anomaly score over time
 */
static void decay_anomaly_score(void) {
    if (hwval_state.anomaly_score > 0) {
        hwval_state.anomaly_score--;

        /* Restore state if anomalies cleared */
        if (hwval_state.anomaly_score < 50 &&
            hwval_state.state == HWVAL_STATE_SUSPICIOUS) {
            hwval_state.state = HWVAL_STATE_ACTIVE;
        }
    }
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

int hwval_init(void) {
    /* Clear state */
    for (int i = 0; i < (int)sizeof(hwval_state); i++) {
        ((uint8_t*)&hwval_state)[i] = 0;
    }

    hwval_state.state = HWVAL_STATE_CALIBRATING;
    hwval_state.calibration_start = hal_timer_ticks();

    /* Initialize memory canaries with magic values */
    for (int i = 0; i < HWVAL_MEM_CANARY_COUNT; i++) {
        hwval_state.canaries[i].expected = HWVAL_MEM_CANARY_MAGIC ^ (i * 0x12345678);
        hwval_state.canaries[i].address = NULL;
        hwval_state.canaries[i].violated = 0;
    }

    /* Take initial sensor readings */
    hwval_state.current.temperature = hal_read_temperature();
    hwval_state.current.temp_prev = hwval_state.current.temperature;
    hwval_state.current.voltage = hal_read_voltage();
    hwval_state.current.voltage_prev = hwval_state.current.voltage;
    hwval_state.current.clock_ticks = hal_get_hires_ticks();
    hwval_state.current.last_update = hal_timer_ticks();

    /* Initialize baseline accumulators */
    hwval_state.baseline.temp_avg = hwval_state.current.temperature;
    hwval_state.baseline.voltage_avg = hwval_state.current.voltage;
    hwval_state.baseline.samples = 1;

    return 0;
}

/* ==========================================================================
 * Calibration
 * ========================================================================== */

bool hwval_is_calibrated(void) {
    return hwval_state.state != HWVAL_STATE_CALIBRATING &&
           hwval_state.state != HWVAL_STATE_UNINITIALIZED;
}

uint8_t hwval_calibration_progress(void) {
    if (hwval_is_calibrated()) return 100;
    if (hwval_state.state == HWVAL_STATE_UNINITIALIZED) return 0;

    uint32_t progress = (hwval_state.calibration_samples * 100) / HWVAL_CALIBRATION_SAMPLES;
    return (progress > 100) ? 100 : progress;
}

void hwval_recalibrate(void) {
    hwval_state.state = HWVAL_STATE_CALIBRATING;
    hwval_state.calibration_start = hal_timer_ticks();
    hwval_state.calibration_samples = 0;
    hwval_state.baseline.samples = 0;
    hwval_state.anomaly_score = 0;
}

static void calibration_tick(void) {
    int16_t temp = hal_read_temperature();
    uint16_t voltage = hal_read_voltage();

    /* Accumulate baseline using running average */
    uint32_t n = hwval_state.baseline.samples;
    if (n > 0) {
        /* Running average: avg = avg + (new - avg) / n */
        hwval_state.baseline.temp_avg +=
            (temp - hwval_state.baseline.temp_avg) / (int)(n + 1);
        hwval_state.baseline.voltage_avg +=
            (voltage - hwval_state.baseline.voltage_avg) / (n + 1);

        /* Update variance estimate */
        int16_t temp_diff = temp - hwval_state.baseline.temp_avg;
        int16_t volt_diff = voltage - hwval_state.baseline.voltage_avg;

        if (temp_diff < 0) temp_diff = -temp_diff;
        if (volt_diff < 0) volt_diff = -volt_diff;

        if (temp_diff > hwval_state.baseline.temp_variance) {
            hwval_state.baseline.temp_variance = temp_diff;
        }
        if ((uint16_t)volt_diff > hwval_state.baseline.voltage_variance) {
            hwval_state.baseline.voltage_variance = volt_diff;
        }
    }

    hwval_state.baseline.samples++;
    hwval_state.calibration_samples++;

    /* Check if calibration complete */
    uint32_t elapsed = hal_timer_ticks() - hwval_state.calibration_start;
    if (hwval_state.calibration_samples >= HWVAL_CALIBRATION_SAMPLES ||
        elapsed >= HWVAL_CALIBRATION_TIME_MS) {

        /* Set minimum variance thresholds */
        if (hwval_state.baseline.temp_variance < 10) {
            hwval_state.baseline.temp_variance = 10;  /* 1.0C minimum */
        }
        if (hwval_state.baseline.voltage_variance < 50) {
            hwval_state.baseline.voltage_variance = 50;  /* 50mV minimum */
        }

        /* Calculate expected clock frequency */
        uint32_t ticks = hal_get_hires_ticks() - hwval_state.current.clock_ticks;
        hwval_state.baseline.clock_freq = (ticks * 1000) / elapsed;

        hwval_state.state = HWVAL_STATE_ACTIVE;

        /* Record calibration complete event */
        blackbox_record_event(EVENT_KEY_ROTATE, 0, 0, hwval_state.baseline.samples);
    }
}

/* ==========================================================================
 * Sensor Validation
 * ========================================================================== */

uint8_t hwval_update_temperature(int16_t temp_c) {
    uint8_t violation = HWVAL_VIOLATION_NONE;

    hwval_state.current.temp_prev = hwval_state.current.temperature;
    hwval_state.current.temperature = temp_c;

    if (!hwval_is_calibrated()) return HWVAL_VIOLATION_NONE;

    /* Check absolute bounds */
    if (temp_c < HWVAL_TEMP_MIN_C * 10 || temp_c > HWVAL_TEMP_MAX_C * 10) {
        violation = HWVAL_VIOLATION_TEMP_RANGE;
        hwval_record_violation(violation, HWVAL_SEVERITY_CRITICAL, temp_c);
    }

    /* Check rate of change (thermal attacks) */
    int16_t delta = temp_c - hwval_state.current.temp_prev;
    if (delta < 0) delta = -delta;

    if (delta > HWVAL_TEMP_DELTA_MAX * 10) {
        violation = HWVAL_VIOLATION_TEMP_SPIKE;
        hwval_record_violation(violation, HWVAL_SEVERITY_WARNING, delta);
    }

    /* Check against baseline */
    int16_t diff_from_baseline = temp_c - hwval_state.baseline.temp_avg;
    if (diff_from_baseline < 0) diff_from_baseline = -diff_from_baseline;

    if (diff_from_baseline > hwval_state.baseline.temp_variance * 5) {
        if (violation == HWVAL_VIOLATION_NONE) {
            violation = HWVAL_VIOLATION_TEMP_RANGE;
        }
        hwval_record_violation(HWVAL_VIOLATION_TEMP_RANGE,
                               HWVAL_SEVERITY_WARNING, temp_c);
    }

    return violation;
}

uint8_t hwval_update_voltage(uint16_t voltage_mv) {
    uint8_t violation = HWVAL_VIOLATION_NONE;

    hwval_state.current.voltage_prev = hwval_state.current.voltage;
    hwval_state.current.voltage = voltage_mv;

    if (!hwval_is_calibrated()) return HWVAL_VIOLATION_NONE;

    /* Check absolute bounds */
    if (voltage_mv < HWVAL_VOLTAGE_MIN_MV || voltage_mv > HWVAL_VOLTAGE_MAX_MV) {
        violation = HWVAL_VIOLATION_VOLTAGE_RANGE;
        hwval_record_violation(violation, HWVAL_SEVERITY_CRITICAL, voltage_mv);
    }

    /* Check for voltage glitches (fault injection) */
    int16_t delta = voltage_mv - hwval_state.current.voltage_prev;
    if (delta < 0) delta = -delta;

    if ((uint16_t)delta > HWVAL_VOLTAGE_DELTA_MAX) {
        violation = HWVAL_VIOLATION_VOLTAGE_SPIKE;
        hwval_record_violation(violation, HWVAL_SEVERITY_CRITICAL, delta);
    }

    /* Check for brownout pattern */
    if (voltage_mv < HWVAL_VOLTAGE_MIN_MV + 200) {
        hwval_record_violation(HWVAL_VIOLATION_BROWNOUT,
                               HWVAL_SEVERITY_WARNING, voltage_mv);
    }

    return violation;
}

uint8_t hwval_validate_clock(uint32_t actual_ticks, uint32_t interval_ms) {
    if (!hwval_is_calibrated() || interval_ms == 0) {
        return HWVAL_VIOLATION_NONE;
    }

    /* Calculate expected ticks */
    uint32_t expected_ticks = (hwval_state.baseline.clock_freq * interval_ms) / 1000;
    hwval_state.current.clock_expected = expected_ticks;
    hwval_state.current.clock_ticks = actual_ticks;

    /* Calculate drift percentage */
    int32_t diff = actual_ticks - expected_ticks;
    if (diff < 0) diff = -diff;

    uint32_t drift_pct = (diff * 100) / expected_ticks;

    /* Check for excessive drift */
    if (drift_pct > HWVAL_CLOCK_TOLERANCE_PCT) {
        hwval_state.clock_glitches++;

        if (hwval_state.clock_glitches >= HWVAL_CLOCK_GLITCH_THRESH) {
            hwval_record_violation(HWVAL_VIOLATION_CLOCK_GLITCH,
                                   HWVAL_SEVERITY_CRITICAL, drift_pct);
            return HWVAL_VIOLATION_CLOCK_GLITCH;
        } else {
            hwval_record_violation(HWVAL_VIOLATION_CLOCK_DRIFT,
                                   HWVAL_SEVERITY_WARNING, drift_pct);
            return HWVAL_VIOLATION_CLOCK_DRIFT;
        }
    } else {
        /* Reset glitch counter on good reading */
        if (hwval_state.clock_glitches > 0) {
            hwval_state.clock_glitches--;
        }
    }

    return HWVAL_VIOLATION_NONE;
}

/* ==========================================================================
 * Memory Integrity
 * ========================================================================== */

int hwval_register_canary(uint32_t *address, uint8_t region) {
    if (hwval_state.canary_count >= HWVAL_MEM_CANARY_COUNT) {
        return -1;
    }

    int idx = hwval_state.canary_count++;
    hwval_state.canaries[idx].address = address;
    hwval_state.canaries[idx].region = region;
    hwval_state.canaries[idx].expected = HWVAL_MEM_CANARY_MAGIC ^ (uint32_t)address;
    hwval_state.canaries[idx].violated = 0;

    /* Write canary value to memory */
    *address = hwval_state.canaries[idx].expected;

    return idx;
}

uint8_t hwval_check_canaries(void) {
    uint8_t corrupted = 0;

    for (int i = 0; i < hwval_state.canary_count; i++) {
        if (hwval_state.canaries[i].address == NULL) continue;

        uint32_t current = *hwval_state.canaries[i].address;
        if (current != hwval_state.canaries[i].expected) {
            corrupted++;
            hwval_state.canaries[i].violated = 1;

            hwval_record_violation(HWVAL_VIOLATION_MEM_CANARY,
                                   HWVAL_SEVERITY_FATAL,
                                   (uint32_t)hwval_state.canaries[i].address);
        }
    }

    return corrupted;
}

int hwval_register_flash_block(uint32_t start_addr, uint32_t size) {
    if (hwval_state.flash_block_count >= HWVAL_FLASH_CRC_BLOCKS) {
        return -1;
    }

    int idx = hwval_state.flash_block_count++;
    hwval_state.flash_blocks[idx].start_addr = start_addr;
    hwval_state.flash_blocks[idx].size = size;
    hwval_state.flash_blocks[idx].crc = calculate_crc32((uint8_t*)start_addr, size);
    hwval_state.flash_blocks[idx].last_check = hal_timer_ticks();

    return idx;
}

bool hwval_verify_flash_block(uint8_t block_idx) {
    if (block_idx >= hwval_state.flash_block_count) {
        return false;
    }

    struct hwval_flash_block *block = &hwval_state.flash_blocks[block_idx];
    uint32_t crc = calculate_crc32((uint8_t*)block->start_addr, block->size);
    block->last_check = hal_timer_ticks();

    if (crc != block->crc) {
        hwval_record_violation(HWVAL_VIOLATION_FLASH_CRC,
                               HWVAL_SEVERITY_FATAL, block->start_addr);
        return false;
    }

    return true;
}

uint8_t hwval_verify_all_flash(void) {
    uint8_t failed = 0;

    for (int i = 0; i < hwval_state.flash_block_count; i++) {
        if (!hwval_verify_flash_block(i)) {
            failed++;
        }
    }

    return failed;
}

/* ==========================================================================
 * Violation Handling
 * ========================================================================== */

void hwval_record_violation(uint8_t type, uint8_t severity, uint32_t data) {
    struct hwval_violation *v = find_violation_slot(type);
    uint32_t now = hal_timer_ticks();

    if (v->type != type) {
        /* New violation */
        v->type = type;
        v->severity = severity;
        v->count = 1;
        v->first_tick = now;
        v->last_tick = now;
        v->data = data;
    } else {
        /* Existing violation - update */
        v->count++;
        v->last_tick = now;
        if (severity > v->severity) {
            v->severity = severity;
        }
        v->data = data;
    }

    hwval_state.total_violations++;
    update_anomaly_score(severity);

    /* Record to black box */
    blackbox_record_event(EVENT_CORRUPTION, type, data, severity);

    /* Report to AIS for correlation */
    hwval_report_to_ais(v);

    /* Handle critical/fatal violations immediately */
    if (severity >= HWVAL_SEVERITY_FATAL) {
        hwval_compromised();
    }
}

struct hwval_violation* hwval_get_violations(void) {
    return hwval_state.violations;
}

void hwval_clear_violations(void) {
    for (int i = 0; i < 8; i++) {
        hwval_state.violations[i].type = HWVAL_VIOLATION_NONE;
        hwval_state.violations[i].count = 0;
    }
    hwval_state.violation_count = 0;
    hwval_state.false_positives += hwval_state.total_violations;
    hwval_state.total_violations = 0;
}

void hwval_compromised(void) {
    hwval_state.state = HWVAL_STATE_COMPROMISED;

    /* Record final state to black box */
    blackbox_record_event(EVENT_CORRUPTION, 0xFF,
                          hwval_state.anomaly_score,
                          hwval_state.total_violations);

    /* Emit DANGER pheromone */
    stigmergia_emit_danger(swarm_state.terrain_x, swarm_state.terrain_y, 15);

    /* Broadcast alarm to swarm */
    uint32_t alarm_data = 0xBADHARD0;  /* "Bad Hardware" marker */
    nert_send_critical(0x0000, PHEROMONE_ALARM, &alarm_data, 4);

    /* Trigger apoptosis - hardware cannot be trusted */
    hal_trigger_apoptosis();
}

/* ==========================================================================
 * Integration with Other Systems
 * ========================================================================== */

void hwval_report_to_ais(struct hwval_violation *violation) {
    /* Create antigen from hardware violation */
    struct ais_antigen antigen;

    antigen.features[0] = violation->type;
    antigen.features[1] = violation->severity;
    antigen.features[2] = (violation->data >> 24) & 0xFF;
    antigen.features[3] = (violation->data >> 16) & 0xFF;
    antigen.features[4] = (violation->data >> 8) & 0xFF;
    antigen.features[5] = violation->data & 0xFF;
    antigen.features[6] = hwval_state.anomaly_score;
    antigen.features[7] = hwval_state.state;

    antigen.source_node = swarm_state.node_id;
    antigen.pheromone_type = PHEROMONE_ALARM;
    antigen.context_flags = 0x80;  /* Hardware source flag */

    /* Let AIS process this as potential attack indicator */
    ais_process_antigen(&antigen);
}

void hwval_emit_status(void) {
    struct {
        uint8_t  state;
        uint8_t  anomaly_score;
        uint8_t  trust_score;
        uint8_t  violations;
        uint16_t temp_c;
        uint16_t voltage_mv;
    } status;

    status.state = hwval_state.state;
    status.anomaly_score = hwval_state.anomaly_score;
    status.trust_score = hwval_trust_score();
    status.violations = hwval_state.total_violations;
    status.temp_c = hwval_state.current.temperature;
    status.voltage_mv = hwval_state.current.voltage;

    /* Broadcast to swarm - use pheromone system */
    nert_send_unreliable(0x0000, PHEROMONE_SENSOR, &status, sizeof(status));
}

/* ==========================================================================
 * Main Tick Handler
 * ========================================================================== */

void hwval_tick(void) {
    hwval_state.total_checks++;

    /* Handle calibration phase */
    if (hwval_state.state == HWVAL_STATE_CALIBRATING) {
        calibration_tick();
        return;
    }

    /* Not initialized */
    if (hwval_state.state == HWVAL_STATE_UNINITIALIZED) {
        return;
    }

    /* Update sensor readings */
    int16_t temp = hal_read_temperature();
    uint16_t voltage = hal_read_voltage();

    hwval_update_temperature(temp);
    hwval_update_voltage(voltage);

    /* Clock validation every few ticks */
    if (hwval_state.total_checks % HWVAL_CLOCK_CHECK_SAMPLES == 0) {
        uint32_t now = hal_get_hires_ticks();
        uint32_t elapsed = now - hwval_state.clock_last_check;
        uint32_t interval = (hwval_state.total_checks - hwval_state.clock_last_check) *
                           HWVAL_TICK_INTERVAL_MS / HWVAL_CLOCK_CHECK_SAMPLES;

        hwval_validate_clock(elapsed, interval);
        hwval_state.clock_last_check = now;
    }

    /* Full check periodically */
    if (hwval_state.total_checks % HWVAL_FULL_CHECK_INTERVAL == 0) {
        hwval_check_now();
    }

    /* Decay anomaly score */
    if (hwval_state.total_checks % HWVAL_ANOMALY_DECAY_TICKS == 0) {
        decay_anomaly_score();
    }

    /* Handle compromised state */
    if (hwval_state.state == HWVAL_STATE_COMPROMISED) {
        hwval_compromised();
    }
}

uint8_t hwval_check_now(void) {
    uint8_t violations = 0;

    /* Check memory canaries */
    violations += hwval_check_canaries();

    /* Verify flash integrity */
    violations += hwval_verify_all_flash();

    /* Sensor sanity checks */
    if (hwval_state.current.temperature == hwval_state.current.temp_prev) {
        /* Sensor might be stuck */
        static uint8_t stuck_count = 0;
        stuck_count++;
        if (stuck_count > 10) {
            hwval_record_violation(HWVAL_VIOLATION_SENSOR_STUCK,
                                   HWVAL_SEVERITY_WARNING,
                                   hwval_state.current.temperature);
            violations++;
            stuck_count = 0;
        }
    }

    return violations;
}

/* ==========================================================================
 * Query Functions
 * ========================================================================== */

bool hwval_is_trusted(void) {
    return hwval_state.state == HWVAL_STATE_ACTIVE &&
           hwval_state.anomaly_score < 50;
}

struct hwval_state* hwval_get_state(void) {
    return &hwval_state;
}

uint8_t hwval_trust_score(void) {
    /* Inverse of anomaly score, scaled */
    if (hwval_state.state == HWVAL_STATE_COMPROMISED) {
        return 0;
    }
    if (hwval_state.state == HWVAL_STATE_CALIBRATING) {
        return 128;  /* Neutral during calibration */
    }

    /* 255 - anomaly_score, but with some floor */
    uint8_t score = 255 - hwval_state.anomaly_score;

    /* Penalize for recent violations */
    if (hwval_state.total_violations > 0) {
        uint8_t penalty = hwval_state.total_violations * 10;
        if (penalty > score) {
            score = 0;
        } else {
            score -= penalty;
        }
    }

    return score;
}

/* ==========================================================================
 * Debug Functions
 * ========================================================================== */

void hwval_print_status(void) {
    const char *state_names[] = {
        "UNINITIALIZED", "CALIBRATING", "ACTIVE",
        "SUSPICIOUS", "COMPROMISED"
    };

    uint8_t state_idx = hwval_state.state;
    if (state_idx > 4) state_idx = 4;  /* COMPROMISED */

    hal_debug_printf("\n=== Hardware Validation Status ===\n");
    hal_debug_printf("State: %s\n", state_names[state_idx]);
    hal_debug_printf("Trust Score: %u/255\n", hwval_trust_score());
    hal_debug_printf("Anomaly Score: %u\n", hwval_state.anomaly_score);
    hal_debug_printf("\n");

    hal_debug_printf("Sensors:\n");
    hal_debug_printf("  Temperature: %d.%dC (baseline: %d.%dC)\n",
                    hwval_state.current.temperature / 10,
                    hwval_state.current.temperature % 10,
                    hwval_state.baseline.temp_avg / 10,
                    hwval_state.baseline.temp_avg % 10);
    hal_debug_printf("  Voltage: %umV (baseline: %umV)\n",
                    hwval_state.current.voltage,
                    hwval_state.baseline.voltage_avg);
    hal_debug_printf("\n");

    hal_debug_printf("Integrity:\n");
    hal_debug_printf("  Memory canaries: %u registered\n", hwval_state.canary_count);
    hal_debug_printf("  Flash blocks: %u registered\n", hwval_state.flash_block_count);
    hal_debug_printf("  Clock glitches: %lu\n", hwval_state.clock_glitches);
    hal_debug_printf("\n");

    hal_debug_printf("Statistics:\n");
    hal_debug_printf("  Total checks: %lu\n", hwval_state.total_checks);
    hal_debug_printf("  Total violations: %lu\n", hwval_state.total_violations);
    hal_debug_printf("  Active violations: %u\n", hwval_state.violation_count);
    hal_debug_printf("\n");

    if (hwval_state.violation_count > 0) {
        hal_debug_printf("Recent Violations:\n");
        for (int i = 0; i < hwval_state.violation_count; i++) {
            struct hwval_violation *v = &hwval_state.violations[i];
            hal_debug_printf("  [%u] Type=0x%02X Sev=%u Count=%u\n",
                            i, v->type, v->severity, v->count);
        }
    }
}

void hwval_simulate_violation(uint8_t type) {
    hwval_record_violation(type, HWVAL_SEVERITY_WARNING, 0xDEADBEEF);
}

/* ==========================================================================
 * Weak HAL Implementations (platform should override)
 * ========================================================================== */

__attribute__((weak))
int16_t hal_read_temperature(void) {
    /* Default: return room temperature (25.0C) */
    return 250;
}

__attribute__((weak))
uint16_t hal_read_voltage(void) {
    /* Default: return nominal 3.3V */
    return 3300;
}

__attribute__((weak))
uint32_t hal_get_hires_ticks(void) {
    return hal_timer_ticks();
}

__attribute__((weak))
uint32_t hal_crc32(uint32_t *addr, uint32_t size) {
    return calculate_crc32((uint8_t*)addr, size);
}

__attribute__((weak))
bool hal_is_flash_addr(uint32_t addr) {
    /* Default: addresses below 0x20000000 are flash (ARM convention) */
    return addr < 0x20000000;
}

__attribute__((weak))
void hal_trigger_watchdog_reset(void) {
    /* Platform should implement hardware watchdog reset */
    while(1);  /* Hang if not implemented */
}
