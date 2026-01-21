/*
 * NanOS Judas Node System - "El Traidor Estratégico" (v0.7)
 *
 * Implements active defense honeypots that:
 * 1. Detect intrusion attempts
 * 2. Feign vulnerability to engage attackers
 * 3. Capture attacker payloads
 * 4. Transmit forensic data to Queen before detonating
 *
 * "The swarm sacrifices pawns to capture kings."
 */
#ifndef NANOS_JUDAS_H
#define NANOS_JUDAS_H

#include <nanos.h>

/* ==========================================================================
 * Judas State Machine
 * ========================================================================== */

typedef enum {
    JUDAS_STATE_DORMANT,        /* Normal operation, monitoring */
    JUDAS_STATE_SUSPICIOUS,     /* Intrusion detected, evaluating */
    JUDAS_STATE_ENGAGING,       /* Feigning vulnerability */
    JUDAS_STATE_CAPTURING,      /* Recording attacker payload */
    JUDAS_STATE_DETONATING      /* Transmitting forensics, then apoptosis */
} judas_state_t;

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define JUDAS_MAX_CAPTURE_SIZE      512     /* Max bytes to capture */
#define JUDAS_ENGAGE_TIMEOUT_MS     30000   /* Max time in ENGAGING state */
#define JUDAS_CAPTURE_TIMEOUT_MS    10000   /* Max time in CAPTURING state */
#define JUDAS_FORENSICS_RETRIES     3       /* Retries for forensics TX */

/* Trigger thresholds */
#define JUDAS_BAD_MAC_THRESHOLD     5       /* Bad MACs to trigger */
#define JUDAS_REPLAY_THRESHOLD      3       /* Replay attempts to trigger */
#define JUDAS_PROBE_THRESHOLD       8       /* Probes to trigger */

/* ==========================================================================
 * Trigger Configuration
 * ========================================================================== */

struct judas_trigger_config {
    uint8_t  bad_mac_threshold;      /* Bad MACs before activation [1-20] */
    uint8_t  replay_threshold;       /* Replay attempts before activation [1-10] */
    uint8_t  probe_threshold;        /* Anomalous probes before activation [1-20] */
    uint16_t engage_timeout_ms;      /* Timeout in ENGAGING state */
    uint16_t capture_timeout_ms;     /* Timeout in CAPTURING state */
    uint16_t capture_max_bytes;      /* Max payload bytes to capture */
    uint8_t  auto_detonate;          /* 1 = auto-detonate after capture */
    uint8_t  enabled;                /* 1 = Judas mode enabled */
};

/* ==========================================================================
 * Attacker Profile
 * ========================================================================== */

struct judas_attacker_profile {
    uint32_t attacker_id;           /* Node ID (if known) */
    uint8_t  attacker_mac[6];       /* MAC address */
    uint8_t  first_detection_type;  /* What triggered suspicion */
    uint8_t  confidence;            /* Confidence level [0-255] */

    /* Observed techniques */
    uint16_t bad_mac_count;         /* Failed MAC verifications */
    uint16_t replay_count;          /* Replay attempts */
    uint16_t probe_count;           /* Anomalous probes */
    uint16_t injection_attempts;    /* Injection attempts */

    /* Timing */
    uint32_t first_seen_tick;       /* When first detected */
    uint32_t last_activity_tick;    /* Last suspicious activity */
};

/* ==========================================================================
 * Capture Record
 * ========================================================================== */

struct judas_capture {
    /* Identity */
    uint32_t capture_id;            /* Unique capture identifier */
    uint32_t node_id;               /* This node's ID */

    /* Attacker info */
    struct judas_attacker_profile attacker;

    /* State at capture */
    uint32_t engage_tick;           /* When ENGAGING started */
    uint32_t capture_tick;          /* When payload captured */
    judas_state_t state_at_capture;

    /* Captured payload */
    uint16_t payload_len;           /* Actual payload length */
    uint8_t  payload[JUDAS_MAX_CAPTURE_SIZE];

    /* Payload analysis */
    uint32_t payload_hash;          /* FNV-1a hash for dedup */
    uint8_t  payload_type;          /* Detected payload type */
    uint8_t  is_encrypted;          /* 1 if appears encrypted */
    uint8_t  has_shellcode;         /* 1 if shellcode patterns found */
    uint8_t  entropy_score;         /* 0-255, high = encrypted/compressed */

    /* Checksum */
    uint16_t checksum;              /* CRC16 for integrity */
};

/* Payload type classifications */
#define JUDAS_PAYLOAD_UNKNOWN       0x00
#define JUDAS_PAYLOAD_PROBE         0x01    /* Reconnaissance */
#define JUDAS_PAYLOAD_EXPLOIT       0x02    /* Attempted exploit */
#define JUDAS_PAYLOAD_INJECTION     0x03    /* Command injection */
#define JUDAS_PAYLOAD_MALWARE       0x04    /* Likely malware */
#define JUDAS_PAYLOAD_EXFIL         0x05    /* Data exfiltration attempt */

/* ==========================================================================
 * Judas State
 * ========================================================================== */

struct judas_state {
    /* Current state */
    judas_state_t state;
    uint32_t state_enter_tick;

    /* Configuration */
    struct judas_trigger_config config;

    /* Current target */
    struct judas_attacker_profile current_attacker;
    uint8_t  has_target;            /* 1 if tracking an attacker */

    /* Capture buffer */
    struct judas_capture capture;
    uint8_t  capture_started;

    /* Statistics */
    uint32_t activations_total;     /* Times activated */
    uint32_t captures_total;        /* Successful captures */
    uint32_t detonations_total;     /* Detonations performed */
    uint32_t forensics_sent;        /* Forensics successfully sent */

    /* Counters for trigger evaluation */
    uint16_t window_bad_mac;        /* Bad MACs in current window */
    uint16_t window_replay;         /* Replays in current window */
    uint16_t window_probe;          /* Probes in current window */
    uint32_t window_start_tick;     /* Window start time */
};

/* ==========================================================================
 * Public API - Initialization
 * ========================================================================== */

/**
 * Initialize Judas subsystem
 */
void judas_init(void);

/**
 * Configure Judas triggers and behavior
 * @param config  Configuration structure
 */
void judas_configure(const struct judas_trigger_config *config);

/**
 * Enable/disable Judas mode
 */
void judas_enable(bool enable);

/**
 * Check if Judas mode is enabled
 */
bool judas_is_enabled(void);

/* ==========================================================================
 * Public API - State Machine
 * ========================================================================== */

/**
 * Periodic tick - call from main loop
 * Handles state transitions and timeouts
 */
void judas_tick(void);

/**
 * Get current Judas state
 */
judas_state_t judas_get_state(void);

/**
 * Check if currently engaged with an attacker
 */
bool judas_is_engaged(void);

/* ==========================================================================
 * Public API - Threat Detection (called from AIS/NERT)
 * ========================================================================== */

/**
 * Report a security event for Judas evaluation
 * Call this from AIS or NERT security handlers
 *
 * @param event_type  Type of event (EVENT_BAD_MAC, EVENT_REPLAY, etc.)
 * @param source_id   Source node ID
 * @param source_mac  Source MAC address (6 bytes, or NULL)
 * @param confidence  Detection confidence [0-255]
 */
void judas_report_event(uint8_t event_type, uint32_t source_id,
                        const uint8_t *source_mac, uint8_t confidence);

/**
 * Called when AIS detects anomaly - check if should enter Judas mode
 * Returns 1 if Judas takes over (don't reject the packet)
 */
int judas_intercept_anomaly(uint8_t detect_type, uint16_t source_node,
                            uint8_t confidence);

/* ==========================================================================
 * Public API - Capture
 * ========================================================================== */

/**
 * Capture incoming payload from suspected attacker
 * Call this when receiving packets from engaged attacker
 *
 * @param data  Packet data
 * @param len   Packet length
 */
void judas_capture_payload(const void *data, uint16_t len);

/**
 * Analyze captured payload
 * Sets payload_type, entropy_score, has_shellcode flags
 */
void judas_analyze_capture(struct judas_capture *capture);

/* ==========================================================================
 * Public API - Detonation
 * ========================================================================== */

/**
 * Trigger detonation sequence
 * 1. Finalize capture
 * 2. Send forensics to Queen
 * 3. Trigger apoptosis
 */
void judas_detonate(void);

/**
 * Send forensics to Queen (can retry)
 * @return 0 on success, -1 on failure
 */
int judas_send_forensics(void);

/* ==========================================================================
 * Public API - Debug
 * ========================================================================== */

/**
 * Print Judas status to serial
 */
void judas_print_status(void);

/**
 * Get pointer to Judas state (for inspection)
 */
struct judas_state* judas_get_state_ptr(void);

#endif /* NANOS_JUDAS_H */
