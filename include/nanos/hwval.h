/*
 * NanOS Hardware Validation - "El Centinela del Silicio" (v0.6)
 *
 * Physical layer security through continuous hardware integrity monitoring.
 * Detects tampered sensors, manipulated clocks, fault injection, and
 * compromised firmware before they can affect the swarm.
 *
 * Key concepts:
 * - Sensor Bounds: Physical limits on sensor readings
 * - Clock Watchdog: Detect glitching/frequency manipulation
 * - Voltage Monitor: Detect power analysis or fault injection
 * - Memory Canaries: Detect unauthorized flash/RAM modifications
 * - Thermal Guard: Detect freeze/heat attacks for fault injection
 *
 * "The hardware cannot lie - but it can be tortured into false confessions.
 *  Our job is to detect the torture."
 */
#ifndef NANOS_HWVAL_H
#define NANOS_HWVAL_H

#include <nanos.h>

/* ==========================================================================
 * Hardware Validation Constants
 * ========================================================================== */

/* Validation check intervals */
#define HWVAL_TICK_INTERVAL_MS      100     /* Check every 100ms */
#define HWVAL_FULL_CHECK_INTERVAL   10      /* Full check every 10 ticks (1s) */

/* Sensor bounds (physical limits) */
#define HWVAL_TEMP_MIN_C            (-40)   /* Min operating temp */
#define HWVAL_TEMP_MAX_C            85      /* Max operating temp */
#define HWVAL_TEMP_DELTA_MAX        10      /* Max change per second */

#define HWVAL_VOLTAGE_MIN_MV        2700    /* Min VCC (2.7V) */
#define HWVAL_VOLTAGE_MAX_MV        3600    /* Max VCC (3.6V) */
#define HWVAL_VOLTAGE_DELTA_MAX     100     /* Max change per tick (mV) */

/* Clock validation */
#define HWVAL_CLOCK_TOLERANCE_PCT   5       /* 5% clock drift tolerance */
#define HWVAL_CLOCK_CHECK_SAMPLES   4       /* Samples for clock check */
#define HWVAL_CLOCK_GLITCH_THRESH   3       /* Glitches before alarm */

/* Memory integrity */
#define HWVAL_MEM_CANARY_COUNT      4       /* Memory canary locations */
#define HWVAL_MEM_CANARY_MAGIC      0xC0DEBABE  /* Canary magic value */
#define HWVAL_FLASH_CRC_BLOCKS      8       /* Flash blocks to CRC */

/* Anomaly thresholds */
#define HWVAL_ANOMALY_THRESHOLD     3       /* Anomalies before critical */
#define HWVAL_ANOMALY_DECAY_TICKS   100     /* Decay anomaly counter */

/* Violation severity levels */
#define HWVAL_SEVERITY_INFO         0       /* Informational */
#define HWVAL_SEVERITY_WARNING      1       /* Suspicious but not critical */
#define HWVAL_SEVERITY_CRITICAL     2       /* Likely attack in progress */
#define HWVAL_SEVERITY_FATAL        3       /* Hardware compromised */

/* ==========================================================================
 * Hardware Validation States
 * ========================================================================== */

#define HWVAL_STATE_UNINITIALIZED   0x00
#define HWVAL_STATE_CALIBRATING     0x01    /* Learning baseline */
#define HWVAL_STATE_ACTIVE          0x02    /* Normal monitoring */
#define HWVAL_STATE_SUSPICIOUS      0x03    /* Anomalies detected */
#define HWVAL_STATE_COMPROMISED     0xFF    /* Hardware integrity failed */

/* ==========================================================================
 * Violation Types
 * ========================================================================== */

#define HWVAL_VIOLATION_NONE            0x00
#define HWVAL_VIOLATION_TEMP_RANGE      0x01    /* Temperature out of bounds */
#define HWVAL_VIOLATION_TEMP_SPIKE      0x02    /* Sudden temperature change */
#define HWVAL_VIOLATION_VOLTAGE_RANGE   0x03    /* Voltage out of bounds */
#define HWVAL_VIOLATION_VOLTAGE_SPIKE   0x04    /* Voltage glitch detected */
#define HWVAL_VIOLATION_CLOCK_DRIFT     0x05    /* Clock frequency anomaly */
#define HWVAL_VIOLATION_CLOCK_GLITCH    0x06    /* Clock glitching detected */
#define HWVAL_VIOLATION_MEM_CANARY      0x07    /* Memory canary corrupted */
#define HWVAL_VIOLATION_FLASH_CRC       0x08    /* Flash CRC mismatch */
#define HWVAL_VIOLATION_REGISTER_MOD    0x09    /* Critical register modified */
#define HWVAL_VIOLATION_SENSOR_STUCK    0x0A    /* Sensor not changing */
#define HWVAL_VIOLATION_SENSOR_NOISE    0x0B    /* Excessive sensor noise */
#define HWVAL_VIOLATION_BROWNOUT        0x0C    /* Power brownout detected */
#define HWVAL_VIOLATION_WATCHDOG        0x0D    /* Watchdog anomaly */
#define HWVAL_VIOLATION_TIMING          0x0E    /* Timing attack pattern */

/* ==========================================================================
 * Data Structures
 * ========================================================================== */

/**
 * Sensor baseline (learned during calibration)
 */
struct hwval_sensor_baseline {
    int16_t  temp_avg;              /* Average temperature (0.1C units) */
    int16_t  temp_variance;         /* Expected variance */
    uint16_t voltage_avg;           /* Average voltage (mV) */
    uint16_t voltage_variance;      /* Expected variance */
    uint32_t clock_freq;            /* Expected clock frequency */
    uint32_t samples;               /* Calibration samples collected */
};

/**
 * Current sensor readings
 */
struct hwval_sensor_current {
    int16_t  temperature;           /* Current temp (0.1C units) */
    int16_t  temp_prev;             /* Previous reading */
    uint16_t voltage;               /* Current VCC (mV) */
    uint16_t voltage_prev;          /* Previous reading */
    uint32_t clock_ticks;           /* Clock ticks in interval */
    uint32_t clock_expected;        /* Expected ticks */
    uint32_t last_update;           /* Last sensor update tick */
};

/**
 * Memory canary location
 */
struct hwval_mem_canary {
    uint32_t *address;              /* Canary location */
    uint32_t expected;              /* Expected value */
    uint8_t  region;                /* Memory region (FLASH/RAM/etc) */
    uint8_t  violated;              /* Violation detected */
};

/**
 * Flash integrity block
 */
struct hwval_flash_block {
    uint32_t start_addr;            /* Block start address */
    uint32_t size;                  /* Block size */
    uint32_t crc;                   /* Expected CRC */
    uint32_t last_check;            /* Last check tick */
};

/**
 * Violation record
 */
struct hwval_violation {
    uint8_t  type;                  /* HWVAL_VIOLATION_* */
    uint8_t  severity;              /* HWVAL_SEVERITY_* */
    uint16_t count;                 /* Occurrence count */
    uint32_t first_tick;            /* First occurrence */
    uint32_t last_tick;             /* Last occurrence */
    uint32_t data;                  /* Violation-specific data */
};

/**
 * Complete hardware validation state
 */
struct hwval_state {
    uint8_t state;                  /* HWVAL_STATE_* */

    /* Sensor data */
    struct hwval_sensor_baseline baseline;
    struct hwval_sensor_current current;

    /* Memory integrity */
    struct hwval_mem_canary canaries[HWVAL_MEM_CANARY_COUNT];
    struct hwval_flash_block flash_blocks[HWVAL_FLASH_CRC_BLOCKS];
    uint8_t canary_count;
    uint8_t flash_block_count;

    /* Violation tracking */
    struct hwval_violation violations[8];  /* Recent violations */
    uint8_t violation_count;
    uint8_t anomaly_score;          /* Current anomaly level */

    /* Clock validation */
    uint32_t clock_glitches;        /* Consecutive glitch count */
    uint32_t clock_last_check;      /* Last clock check tick */

    /* Calibration */
    uint32_t calibration_start;     /* Calibration start tick */
    uint16_t calibration_samples;   /* Samples collected */

    /* Statistics */
    uint32_t total_checks;          /* Total validation checks */
    uint32_t total_violations;      /* Total violations detected */
    uint32_t false_positives;       /* Violations later cleared */
};

/* ==========================================================================
 * Hardware Validation API
 * ========================================================================== */

/**
 * Initialize hardware validation system
 * Begins calibration phase to learn baseline
 *
 * @return 0 on success, -1 on failure
 */
int hwval_init(void);

/**
 * Periodic validation tick
 * Call from main loop every HWVAL_TICK_INTERVAL_MS
 */
void hwval_tick(void);

/**
 * Force immediate full hardware check
 * Use when suspicious activity detected
 *
 * @return Number of violations found
 */
uint8_t hwval_check_now(void);

/**
 * Check if hardware is trusted
 * @return true if no critical violations
 */
bool hwval_is_trusted(void);

/**
 * Get current validation state
 * @return Pointer to state structure
 */
struct hwval_state* hwval_get_state(void);

/* ==========================================================================
 * Sensor Validation API
 * ========================================================================== */

/**
 * Update temperature reading
 * Call when new temperature data available
 *
 * @param temp_c Temperature in 0.1C units (e.g., 250 = 25.0C)
 * @return Violation type if out of bounds, 0 otherwise
 */
uint8_t hwval_update_temperature(int16_t temp_c);

/**
 * Update voltage reading
 * Call when new voltage data available
 *
 * @param voltage_mv Voltage in millivolts
 * @return Violation type if out of bounds, 0 otherwise
 */
uint8_t hwval_update_voltage(uint16_t voltage_mv);

/**
 * Validate clock frequency
 * Compares actual ticks against expected
 *
 * @param actual_ticks Ticks measured in interval
 * @param interval_ms Measurement interval
 * @return Violation type if anomaly, 0 otherwise
 */
uint8_t hwval_validate_clock(uint32_t actual_ticks, uint32_t interval_ms);

/* ==========================================================================
 * Memory Integrity API
 * ========================================================================== */

/**
 * Register a memory canary location
 * Canary will be checked periodically
 *
 * @param address Memory address for canary
 * @param region Memory region identifier
 * @return Canary index, or -1 if full
 */
int hwval_register_canary(uint32_t *address, uint8_t region);

/**
 * Check all memory canaries
 * @return Number of corrupted canaries
 */
uint8_t hwval_check_canaries(void);

/**
 * Register a flash block for CRC checking
 *
 * @param start_addr Block start address
 * @param size Block size in bytes
 * @return Block index, or -1 if full
 */
int hwval_register_flash_block(uint32_t start_addr, uint32_t size);

/**
 * Verify flash block integrity
 * @param block_idx Block index to check
 * @return true if CRC matches
 */
bool hwval_verify_flash_block(uint8_t block_idx);

/**
 * Verify all registered flash blocks
 * @return Number of failed blocks
 */
uint8_t hwval_verify_all_flash(void);

/* ==========================================================================
 * Violation Handling API
 * ========================================================================== */

/**
 * Record a hardware violation
 *
 * @param type HWVAL_VIOLATION_* type
 * @param severity HWVAL_SEVERITY_* level
 * @param data Violation-specific data
 */
void hwval_record_violation(uint8_t type, uint8_t severity, uint32_t data);

/**
 * Get recent violations
 * @return Pointer to violations array
 */
struct hwval_violation* hwval_get_violations(void);

/**
 * Clear violation history
 * Use after investigation/remediation
 */
void hwval_clear_violations(void);

/**
 * Handle critical hardware compromise
 * Triggers security response
 */
void hwval_compromised(void);

/* ==========================================================================
 * Calibration API
 * ========================================================================== */

/**
 * Check if calibration is complete
 * @return true if baseline established
 */
bool hwval_is_calibrated(void);

/**
 * Force recalibration
 * Use if environment changed significantly
 */
void hwval_recalibrate(void);

/**
 * Get calibration progress
 * @return Percentage complete (0-100)
 */
uint8_t hwval_calibration_progress(void);

/* ==========================================================================
 * Integration API
 * ========================================================================== */

/**
 * Report violation to AIS
 * Allows AIS to correlate hardware events with network anomalies
 *
 * @param violation Violation details
 */
void hwval_report_to_ais(struct hwval_violation *violation);

/**
 * Emit hardware status pheromone
 * Broadcasts hardware health to swarm
 */
void hwval_emit_status(void);

/* ==========================================================================
 * Debug API
 * ========================================================================== */

/**
 * Print hardware validation status
 */
void hwval_print_status(void);

/**
 * Get hardware trust score
 * @return Score 0-255 (higher = more trusted)
 */
uint8_t hwval_trust_score(void);

/**
 * Simulate hardware violation (testing only)
 * @param type Violation type to simulate
 */
void hwval_simulate_violation(uint8_t type);

/* ==========================================================================
 * Platform-Specific HAL Functions (to be implemented per platform)
 * ========================================================================== */

/**
 * Read internal temperature sensor
 * @return Temperature in 0.1C units
 */
int16_t hal_read_temperature(void);

/**
 * Read supply voltage
 * @return Voltage in millivolts
 */
uint16_t hal_read_voltage(void);

/**
 * Get high-resolution timer ticks
 * @return Current tick count
 */
uint32_t hal_get_hires_ticks(void);

/**
 * Calculate CRC32 of memory region
 * @param addr Start address
 * @param size Size in bytes
 * @return CRC32 value
 */
uint32_t hal_crc32(uint32_t *addr, uint32_t size);

/**
 * Check if address is in flash
 * @return true if flash address
 */
bool hal_is_flash_addr(uint32_t addr);

/**
 * Trigger hardware watchdog reset
 */
void hal_trigger_watchdog_reset(void);

#endif /* NANOS_HWVAL_H */
