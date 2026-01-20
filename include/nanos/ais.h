/*
 * NanOS Artificial Immune System (AIS) - "El Sistema Inmune" (v0.6)
 *
 * Implements Negative Selection Algorithm inspired by the biological immune system.
 * The swarm learns to distinguish "self" from "non-self" without prior attack signatures.
 *
 * Key concepts:
 * - Thymus Phase: Generate detectors at boot, mature by removing self-reactive ones
 * - Negative Selection: Detectors that don't match "self" survive to detect "non-self"
 * - Clonal Selection: Successful detectors can be amplified
 * - Danger Theory: Combine detector match with context (damage signals)
 *
 * "The immune system doesn't need to know what attacks look like -
 *  it only needs to know what 'healthy' looks like."
 */
#ifndef NANOS_AIS_H
#define NANOS_AIS_H

#include <nanos.h>

/* ==========================================================================
 * AIS Constants
 * ========================================================================== */

/* Detector configuration */
#define AIS_DETECTOR_COUNT          16      /* Number of active detectors */
#define AIS_DETECTOR_SIZE           8       /* Bytes per detector pattern */
#define AIS_AFFINITY_THRESHOLD      6       /* Min matching bits to trigger (r-contiguous) */
#define AIS_MATURATION_SAMPLES      32      /* Self samples needed for maturation */

/* Thymus phase timing */
#define AIS_THYMUS_DURATION_MS      5000    /* 5 seconds to mature detectors */
#define AIS_THYMUS_SAMPLE_INTERVAL  100     /* Sample self every 100ms */

/* Detector lifecycle */
#define AIS_DETECTOR_LIFESPAN_MS    300000  /* 5 minutes before replacement */
#define AIS_DETECTOR_REFRESH_MS     60000   /* Check for refresh every 60s */

/* Detection sensitivity */
#define AIS_ANOMALY_THRESHOLD       3       /* Detectors must match to raise alarm */
#define AIS_COOLDOWN_MS             1000    /* Min time between same-type alerts */

/* Memory cell (successful detectors) */
#define AIS_MEMORY_CELLS            4       /* Detectors promoted to memory */
#define AIS_MEMORY_BOOST            2       /* Weight multiplier for memory cells */

/* Self profile dimensions */
#define AIS_SELF_PROFILE_SIZE       8       /* Number of behavioral features */

/* ==========================================================================
 * Feature Extraction (What defines "self"?)
 * ========================================================================== */

/* Behavioral features extracted from traffic (normalized 0-255) */
#define AIS_FEATURE_PKT_RATE        0       /* Packets per second */
#define AIS_FEATURE_AVG_SIZE        1       /* Average packet size */
#define AIS_FEATURE_TYPE_ENTROPY    2       /* Entropy of pheromone types */
#define AIS_FEATURE_SRC_DIVERSITY   3       /* Unique sources seen */
#define AIS_FEATURE_HMAC_FAIL_RATE  4       /* Failed HMACs per window */
#define AIS_FEATURE_REPLAY_RATE     5       /* Replay attempts per window */
#define AIS_FEATURE_NEIGHBOR_CHURN  6       /* Neighbor table changes */
#define AIS_FEATURE_ROUTE_STABILITY 7       /* Route change frequency */

/* Feature thresholds for "normal" behavior (configurable) */
#define AIS_NORMAL_PKT_RATE_MIN     1       /* At least 1 pkt/s */
#define AIS_NORMAL_PKT_RATE_MAX     50      /* At most 50 pkt/s */
#define AIS_NORMAL_HMAC_FAIL_MAX    5       /* Max 5 failures/window */
#define AIS_NORMAL_REPLAY_MAX       2       /* Max 2 replays/window */

/* ==========================================================================
 * Detector States
 * ========================================================================== */

#define AIS_DETECTOR_EMPTY          0x00    /* Slot available */
#define AIS_DETECTOR_IMMATURE       0x01    /* In thymus, learning self */
#define AIS_DETECTOR_MATURE         0x02    /* Active, can detect non-self */
#define AIS_DETECTOR_MEMORY         0x03    /* Promoted to memory (proven) */
#define AIS_DETECTOR_ANERGIC        0x04    /* Disabled (matched self) */

/* ==========================================================================
 * Detection Types (what the AIS can identify)
 * ========================================================================== */

#define AIS_DETECT_NONE             0x00
#define AIS_DETECT_FLOOD            0x01    /* DoS/flooding pattern */
#define AIS_DETECT_PROBE            0x02    /* Reconnaissance/scanning */
#define AIS_DETECT_REPLAY           0x03    /* Replay attack pattern */
#define AIS_DETECT_INJECTION        0x04    /* Malicious packet injection */
#define AIS_DETECT_BEHAVIORAL       0x05    /* Anomalous node behavior */
#define AIS_DETECT_SYBIL            0x06    /* Multiple identities from one source */
#define AIS_DETECT_UNKNOWN          0xFF    /* Unknown anomaly (0-day) */

/* ==========================================================================
 * AIS Event Types (for Black Box integration)
 * ========================================================================== */

#define EVENT_AIS_DETECTOR_MATCH    0x10    /* Detector matched non-self */
#define EVENT_AIS_THYMUS_COMPLETE   0x11    /* Maturation complete */
#define EVENT_AIS_MEMORY_PROMOTE    0x12    /* Detector promoted to memory */
#define EVENT_AIS_ANOMALY_ALERT     0x13    /* Anomaly threshold reached */
#define EVENT_AIS_SELF_UPDATE       0x14    /* Self profile updated */

/* ==========================================================================
 * Data Structures
 * ========================================================================== */

/**
 * Single detector (antibody)
 * Represents a pattern that should NOT match normal traffic
 */
struct ais_detector {
    uint8_t  pattern[AIS_DETECTOR_SIZE];    /* The detector pattern */
    uint8_t  mask[AIS_DETECTOR_SIZE];       /* Which bits to compare */
    uint8_t  state;                         /* AIS_DETECTOR_* state */
    uint8_t  detect_type;                   /* What it detects (if known) */
    uint16_t matches;                       /* Times this detector matched */
    uint16_t false_positives;               /* Times it matched self (bad) */
    uint32_t created_tick;                  /* When detector was created */
    uint32_t last_match_tick;               /* Last successful match */
};

/**
 * Self profile - what "normal" looks like
 * Updated during thymus phase and periodically
 */
struct ais_self_profile {
    uint8_t  features[AIS_SELF_PROFILE_SIZE];   /* Current feature values */
    uint8_t  min[AIS_SELF_PROFILE_SIZE];        /* Observed minimums */
    uint8_t  max[AIS_SELF_PROFILE_SIZE];        /* Observed maximums */
    uint8_t  variance[AIS_SELF_PROFILE_SIZE];   /* Acceptable variance */
    uint32_t samples;                            /* Number of samples */
    uint32_t last_update;                        /* Last update tick */
};

/**
 * Antigen - extracted features from a packet/event
 * This is what detectors try to match against
 */
struct ais_antigen {
    uint8_t  features[AIS_DETECTOR_SIZE];   /* Extracted features */
    uint16_t source_node;                    /* Source of the antigen */
    uint8_t  pheromone_type;                 /* Packet type if applicable */
    uint8_t  context_flags;                  /* Additional context */
};

/* Context flags for antigens */
#define AIS_CTX_HMAC_FAILED     (1 << 0)    /* HMAC verification failed */
#define AIS_CTX_REPLAY_ATTEMPT  (1 << 1)    /* Replay was attempted */
#define AIS_CTX_RATE_LIMITED    (1 << 2)    /* Sender was rate limited */
#define AIS_CTX_BLACKLISTED     (1 << 3)    /* Sender is blacklisted */
#define AIS_CTX_NEW_NODE        (1 << 4)    /* Never seen this node */
#define AIS_CTX_RAPID_CHANGE    (1 << 5)    /* Rapid behavior change */

/* ==========================================================================
 * AIS API
 * ========================================================================== */

/**
 * Initialize the Artificial Immune System
 * Starts the "thymus phase" for detector maturation
 */
void ais_init(void);

/**
 * Called periodically from main loop
 * Handles thymus phase, detector lifecycle, and anomaly response
 */
void ais_tick(void);

/**
 * Extract antigen (features) from a received packet
 * Used to create input for detector matching
 *
 * @param pkt       Received pheromone packet
 * @param antigen   Output: extracted antigen
 * @param ctx_flags Context flags (AIS_CTX_*)
 */
void ais_extract_antigen(struct nanos_pheromone* pkt,
                         struct ais_antigen* antigen,
                         uint8_t ctx_flags);

/**
 * Check if antigen matches any detector (non-self detection)
 * Returns detection type if match found, AIS_DETECT_NONE otherwise
 *
 * @param antigen   Antigen to check
 * @return Detection type (AIS_DETECT_*)
 */
uint8_t ais_detect(struct ais_antigen* antigen);

/**
 * Process a packet through the immune system
 * Convenience function that extracts antigen and checks detection
 *
 * @param pkt       Received packet
 * @param ctx_flags Context from NERT layer (HMAC fail, replay, etc.)
 * @return Detection type if anomaly, AIS_DETECT_NONE if normal
 */
uint8_t ais_process_packet(struct nanos_pheromone* pkt, uint8_t ctx_flags);

/**
 * Update self profile with current behavioral snapshot
 * Call periodically during normal operation to adapt to environment
 */
void ais_update_self_profile(void);

/**
 * Record a sample during thymus phase
 * Helps detectors learn what "self" looks like
 *
 * @param antigen   A "self" antigen (known good traffic)
 */
void ais_thymus_sample(struct ais_antigen* antigen);

/**
 * Generate a new random detector
 * Used during initialization and to replace expired detectors
 *
 * @return Index of new detector, or -1 if no slots available
 */
int ais_generate_detector(void);

/**
 * Mature a detector (negative selection)
 * Checks if detector matches self; if so, marks as anergic
 *
 * @param detector_idx  Index of detector to mature
 * @return true if detector survived (doesn't match self)
 */
bool ais_mature_detector(int detector_idx);

/**
 * Promote a detector to memory cell
 * Called when detector successfully identifies real threats
 *
 * @param detector_idx  Index of detector to promote
 */
void ais_promote_to_memory(int detector_idx);

/**
 * Check if thymus phase is complete
 * @return true if maturation is done
 */
bool ais_is_mature(void);

/**
 * Get number of active (mature) detectors
 */
uint8_t ais_get_active_detector_count(void);

/**
 * Get number of detections since boot
 */
uint32_t ais_get_detection_count(void);

/**
 * Print AIS status summary to serial
 */
void ais_print_status(void);

/* ==========================================================================
 * Integration Callbacks
 * ========================================================================== */

/**
 * Called when AIS detects an anomaly
 * Integrates with Stigmergia (emit DANGER) and Black Box (record event)
 *
 * @param detect_type   Type of detection (AIS_DETECT_*)
 * @param source_node   Source node ID (if applicable)
 * @param confidence    Detection confidence (0-255)
 */
void ais_on_anomaly(uint8_t detect_type, uint16_t source_node, uint8_t confidence);

/**
 * Callback for NERT layer to report security events
 * Feeds the AIS with context about packet handling
 *
 * @param event_type    EVENT_* type from nanos.h
 * @param source_node   Related node
 */
void ais_report_security_event(uint8_t event_type, uint16_t source_node);

#endif /* NANOS_AIS_H */
