/*
 * NanOS Artificial Immune System (AIS) - "El Sistema Inmune" (v0.6)
 *
 * Implements bio-inspired Negative Selection Algorithm for 0-day detection.
 * The system learns what "normal" looks like and flags anything else.
 *
 * Algorithm overview:
 * 1. THYMUS PHASE (boot): Generate random detectors, remove those matching "self"
 * 2. DETECTION PHASE: Match incoming traffic against mature detectors
 * 3. RESPONSE: Emit DANGER pheromones, record in Black Box, alert neighbors
 *
 * "The swarm's immune system doesn't need attack signatures -
 *  it learns to recognize 'healthy' and rejects everything else."
 */
#include <nanos.h>
#include "../include/nanos/ais.h"
#include "../include/nanos/blackbox.h"
#include "../include/nanos/gossip.h"
#include "../include/nanos/terrain.h"
#include "../include/nanos/serial.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern uint32_t random(void);
extern void e1000_send(void* data, uint16_t len);

/* ==========================================================================
 * AIS State
 * ========================================================================== */

/* Detector pool */
static struct ais_detector detectors[AIS_DETECTOR_COUNT];

/* Self profile (what "normal" looks like) */
static struct ais_self_profile self_profile;

/* Self samples collected during thymus phase */
#define SELF_SAMPLE_BUFFER_SIZE 16
static struct {
    uint8_t features[AIS_DETECTOR_SIZE];
} self_samples[SELF_SAMPLE_BUFFER_SIZE];
static uint8_t self_sample_count = 0;

/* State tracking */
static struct {
    bool     thymus_complete;           /* Maturation phase done? */
    uint32_t thymus_start_tick;         /* When thymus phase started */
    uint32_t last_refresh_tick;         /* Last detector refresh */
    uint32_t last_self_update;          /* Last self profile update */

    /* Statistics */
    uint32_t detections_total;          /* Total anomalies detected */
    uint32_t false_positives;           /* Known false positives */
    uint32_t detectors_generated;       /* Total detectors created */
    uint32_t detectors_culled;          /* Detectors removed (matched self) */

    /* Recent detection cooldown */
    uint32_t last_detection_tick;
    uint8_t  last_detection_type;

    /* Rolling window statistics for feature extraction */
    struct {
        uint32_t packets_received;
        uint32_t bytes_received;
        uint32_t unique_sources;
        uint32_t hmac_failures;
        uint32_t replay_attempts;
        uint32_t window_start;
        uint8_t  source_bitmap[32];     /* Bloom filter for unique sources */
    } window;
} ais_state;

/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * Simple hash for source tracking
 */
static uint8_t source_hash(uint16_t node_id) {
    uint32_t h = node_id * 0x9E3779B9;
    return (uint8_t)(h ^ (h >> 8)) % 256;
}

/**
 * Check if source was seen in current window
 */
static bool source_seen(uint16_t node_id) {
    uint8_t h = source_hash(node_id);
    uint8_t byte_idx = h / 8;
    uint8_t bit_idx = h % 8;
    return (ais_state.window.source_bitmap[byte_idx] & (1 << bit_idx)) != 0;
}

/**
 * Mark source as seen
 */
static void source_mark(uint16_t node_id) {
    uint8_t h = source_hash(node_id);
    uint8_t byte_idx = h / 8;
    uint8_t bit_idx = h % 8;
    if (!(ais_state.window.source_bitmap[byte_idx] & (1 << bit_idx))) {
        ais_state.window.source_bitmap[byte_idx] |= (1 << bit_idx);
        ais_state.window.unique_sources++;
    }
}

/**
 * Reset sliding window
 */
static void window_reset(void) {
    ais_state.window.packets_received = 0;
    ais_state.window.bytes_received = 0;
    ais_state.window.unique_sources = 0;
    ais_state.window.hmac_failures = 0;
    ais_state.window.replay_attempts = 0;
    ais_state.window.window_start = ticks;

    for (int i = 0; i < 32; i++) {
        ais_state.window.source_bitmap[i] = 0;
    }
}

/**
 * Calculate r-contiguous matching bits between pattern and antigen
 * Returns the longest run of matching bits
 */
static uint8_t calculate_affinity(const uint8_t* pattern, const uint8_t* mask,
                                   const uint8_t* antigen, uint8_t size) {
    uint8_t max_run = 0;
    uint8_t current_run = 0;

    for (int i = 0; i < size; i++) {
        /* XOR to find differences, AND with mask */
        uint8_t diff = (pattern[i] ^ antigen[i]) & mask[i];

        /* Count contiguous matching bits in this byte */
        for (int bit = 7; bit >= 0; bit--) {
            if ((diff & (1 << bit)) == 0) {
                /* Bit matches */
                current_run++;
                if (current_run > max_run) {
                    max_run = current_run;
                }
            } else {
                /* Bit differs - reset run */
                current_run = 0;
            }
        }
    }

    return max_run;
}

/**
 * Check if detector matches any self sample (should be culled)
 */
static bool detector_matches_self(int detector_idx) {
    struct ais_detector* d = &detectors[detector_idx];

    for (int i = 0; i < self_sample_count; i++) {
        uint8_t affinity = calculate_affinity(
            d->pattern, d->mask,
            self_samples[i].features, AIS_DETECTOR_SIZE);

        if (affinity >= AIS_AFFINITY_THRESHOLD) {
            return true;  /* Matches self - bad detector */
        }
    }

    return false;  /* Doesn't match self - good detector */
}

/**
 * Generate random detector pattern
 */
static void generate_random_pattern(uint8_t* pattern, uint8_t* mask, uint8_t size) {
    for (int i = 0; i < size; i++) {
        pattern[i] = (uint8_t)(random() & 0xFF);
        /* Mask: some bits are "don't care" for flexibility */
        mask[i] = (uint8_t)((random() & 0xFF) | 0x0F);  /* At least low nibble active */
    }
}

/* ==========================================================================
 * Feature Extraction
 * ========================================================================== */

/**
 * Extract behavioral features from current state
 * Returns normalized values (0-255) for each feature dimension
 */
static void extract_current_features(uint8_t* features) {
    uint32_t elapsed = ticks - ais_state.window.window_start;
    if (elapsed < 10) elapsed = 10;  /* Avoid division by zero */

    /* Feature 0: Packet rate (packets per 100 ticks) */
    uint32_t pkt_rate = (ais_state.window.packets_received * 100) / elapsed;
    features[AIS_FEATURE_PKT_RATE] = (pkt_rate > 255) ? 255 : (uint8_t)pkt_rate;

    /* Feature 1: Average packet size (simplified) */
    uint32_t avg_size = (ais_state.window.packets_received > 0)
        ? ais_state.window.bytes_received / ais_state.window.packets_received
        : 64;
    features[AIS_FEATURE_AVG_SIZE] = (avg_size > 255) ? 255 : (uint8_t)avg_size;

    /* Feature 2: Type entropy (approximated by packet count variance) */
    features[AIS_FEATURE_TYPE_ENTROPY] = 128;  /* Placeholder - would need type histogram */

    /* Feature 3: Source diversity */
    features[AIS_FEATURE_SRC_DIVERSITY] =
        (ais_state.window.unique_sources > 255) ? 255 : (uint8_t)ais_state.window.unique_sources;

    /* Feature 4: HMAC failure rate */
    uint32_t hmac_rate = (ais_state.window.hmac_failures * 100) /
                         (ais_state.window.packets_received + 1);
    features[AIS_FEATURE_HMAC_FAIL_RATE] = (hmac_rate > 255) ? 255 : (uint8_t)hmac_rate;

    /* Feature 5: Replay attempt rate */
    uint32_t replay_rate = (ais_state.window.replay_attempts * 100) /
                           (ais_state.window.packets_received + 1);
    features[AIS_FEATURE_REPLAY_RATE] = (replay_rate > 255) ? 255 : (uint8_t)replay_rate;

    /* Feature 6: Neighbor churn (use neighbor_count as proxy) */
    features[AIS_FEATURE_NEIGHBOR_CHURN] = g_state.neighbor_count * 16;

    /* Feature 7: Route stability (use distance variance as proxy) */
    features[AIS_FEATURE_ROUTE_STABILITY] =
        (g_state.distance_to_queen < 255) ? g_state.distance_to_queen * 10 : 255;
}

/* ==========================================================================
 * Public API Implementation
 * ========================================================================== */

void ais_init(void) {
    serial_puts("[AIS] Initializing Artificial Immune System v0.6\n");

    /* Clear all detectors */
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        detectors[i].state = AIS_DETECTOR_EMPTY;
        detectors[i].matches = 0;
        detectors[i].false_positives = 0;
    }

    /* Clear self profile */
    for (int i = 0; i < AIS_SELF_PROFILE_SIZE; i++) {
        self_profile.features[i] = 128;  /* Neutral starting point */
        self_profile.min[i] = 255;
        self_profile.max[i] = 0;
        self_profile.variance[i] = 32;   /* Default tolerance */
    }
    self_profile.samples = 0;
    self_profile.last_update = ticks;

    /* Reset state */
    ais_state.thymus_complete = false;
    ais_state.thymus_start_tick = ticks;
    ais_state.last_refresh_tick = ticks;
    ais_state.last_self_update = ticks;
    ais_state.detections_total = 0;
    ais_state.false_positives = 0;
    ais_state.detectors_generated = 0;
    ais_state.detectors_culled = 0;
    ais_state.last_detection_tick = 0;
    ais_state.last_detection_type = AIS_DETECT_NONE;

    self_sample_count = 0;
    window_reset();

    /* Generate initial detector pool */
    serial_puts("[AIS] Generating initial detectors...\n");
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        ais_generate_detector();
    }

    serial_puts("[AIS] THYMUS PHASE started - collecting self samples\n");
}

void ais_tick(void) {
    uint32_t now = ticks;

    /* === THYMUS PHASE === */
    if (!ais_state.thymus_complete) {
        uint32_t elapsed = now - ais_state.thymus_start_tick;

        /* Collect self sample periodically */
        if ((now % (AIS_THYMUS_SAMPLE_INTERVAL / 10)) == 0) {
            if (self_sample_count < SELF_SAMPLE_BUFFER_SIZE) {
                extract_current_features(self_samples[self_sample_count].features);
                self_sample_count++;
            }
        }

        /* Check if thymus phase complete */
        if (elapsed >= (AIS_THYMUS_DURATION_MS / 10) &&
            self_sample_count >= AIS_MATURATION_SAMPLES / 2) {

            serial_puts("[AIS] THYMUS PHASE complete - maturing detectors\n");

            /* Mature all detectors (negative selection) */
            int mature_count = 0;
            for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
                if (detectors[i].state == AIS_DETECTOR_IMMATURE) {
                    if (ais_mature_detector(i)) {
                        mature_count++;
                    }
                }
            }

            serial_puts("[AIS] Mature detectors: ");
            serial_put_dec(mature_count);
            serial_puts("/");
            serial_put_dec(AIS_DETECTOR_COUNT);
            serial_puts("\n");

            ais_state.thymus_complete = true;

            /* Record in Black Box */
            blackbox_record_event(EVENT_AIS_THYMUS_COMPLETE, 0);
        }

        return;  /* Don't do detection during thymus phase */
    }

    /* === DETECTION PHASE === */

    /* Periodic self profile update */
    if (now - ais_state.last_self_update >= (60000 / 10)) {  /* Every 60s */
        ais_update_self_profile();
        ais_state.last_self_update = now;
    }

    /* Periodic detector refresh (replace expired detectors) */
    if (now - ais_state.last_refresh_tick >= (AIS_DETECTOR_REFRESH_MS / 10)) {
        for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
            if (detectors[i].state == AIS_DETECTOR_MATURE) {
                uint32_t age = now - detectors[i].created_tick;
                if (age >= (AIS_DETECTOR_LIFESPAN_MS / 10)) {
                    /* Detector expired - replace unless it's productive */
                    if (detectors[i].matches < 2) {
                        detectors[i].state = AIS_DETECTOR_EMPTY;
                        ais_generate_detector();
                        if (detectors[i].state == AIS_DETECTOR_IMMATURE) {
                            ais_mature_detector(i);
                        }
                    }
                }
            }
        }
        ais_state.last_refresh_tick = now;
    }

    /* Reset window periodically */
    if (now - ais_state.window.window_start >= 100) {  /* Every 1 second */
        window_reset();
    }
}

void ais_extract_antigen(struct nanos_pheromone* pkt,
                         struct ais_antigen* antigen,
                         uint8_t ctx_flags) {
    /* Update window statistics */
    ais_state.window.packets_received++;
    ais_state.window.bytes_received += 64;  /* Fixed packet size */
    source_mark((uint16_t)pkt->node_id);

    if (ctx_flags & AIS_CTX_HMAC_FAILED) {
        ais_state.window.hmac_failures++;
    }
    if (ctx_flags & AIS_CTX_REPLAY_ATTEMPT) {
        ais_state.window.replay_attempts++;
    }

    /* Extract features into antigen */
    antigen->source_node = (uint16_t)pkt->node_id;
    antigen->pheromone_type = pkt->type;
    antigen->context_flags = ctx_flags;

    /* Build feature vector from packet */
    antigen->features[0] = pkt->type;                    /* Packet type */
    antigen->features[1] = pkt->ttl;                     /* TTL */
    antigen->features[2] = pkt->hop_count;               /* Hop count */
    antigen->features[3] = (uint8_t)(pkt->node_id & 0xFF);  /* Source low byte */
    antigen->features[4] = pkt->distance;                /* Distance to queen */
    antigen->features[5] = ctx_flags;                    /* Context flags */
    antigen->features[6] = (uint8_t)(pkt->seq & 0xFF);   /* Seq low byte */
    antigen->features[7] = (pkt->flags & 0xF0) | (pkt->version & 0x0F);  /* Flags+version */
}

uint8_t ais_detect(struct ais_antigen* antigen) {
    if (!ais_state.thymus_complete) {
        return AIS_DETECT_NONE;  /* Still learning */
    }

    int match_count = 0;
    uint8_t detected_type = AIS_DETECT_NONE;
    uint8_t highest_affinity = 0;

    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        if (detectors[i].state != AIS_DETECTOR_MATURE &&
            detectors[i].state != AIS_DETECTOR_MEMORY) {
            continue;
        }

        uint8_t affinity = calculate_affinity(
            detectors[i].pattern, detectors[i].mask,
            antigen->features, AIS_DETECTOR_SIZE);

        /* Memory cells get boost */
        if (detectors[i].state == AIS_DETECTOR_MEMORY) {
            affinity += AIS_MEMORY_BOOST;
        }

        if (affinity >= AIS_AFFINITY_THRESHOLD) {
            match_count++;
            detectors[i].matches++;
            detectors[i].last_match_tick = ticks;

            if (affinity > highest_affinity) {
                highest_affinity = affinity;
                detected_type = detectors[i].detect_type;
            }
        }
    }

    /* Only raise alarm if multiple detectors match (reduces false positives) */
    if (match_count >= AIS_ANOMALY_THRESHOLD) {
        /* Cooldown check */
        if (ticks - ais_state.last_detection_tick < (AIS_COOLDOWN_MS / 10) &&
            ais_state.last_detection_type == detected_type) {
            return AIS_DETECT_NONE;  /* In cooldown */
        }

        ais_state.last_detection_tick = ticks;
        ais_state.last_detection_type = detected_type;
        ais_state.detections_total++;

        /* If no specific type, classify based on context */
        if (detected_type == AIS_DETECT_NONE) {
            if (antigen->context_flags & AIS_CTX_HMAC_FAILED) {
                detected_type = AIS_DETECT_INJECTION;
            } else if (antigen->context_flags & AIS_CTX_REPLAY_ATTEMPT) {
                detected_type = AIS_DETECT_REPLAY;
            } else if (antigen->context_flags & AIS_CTX_RATE_LIMITED) {
                detected_type = AIS_DETECT_FLOOD;
            } else {
                detected_type = AIS_DETECT_UNKNOWN;  /* 0-day! */
            }
        }

        return detected_type;
    }

    return AIS_DETECT_NONE;
}

uint8_t ais_process_packet(struct nanos_pheromone* pkt, uint8_t ctx_flags) {
    struct ais_antigen antigen;
    ais_extract_antigen(pkt, &antigen, ctx_flags);

    uint8_t detection = ais_detect(&antigen);

    if (detection != AIS_DETECT_NONE) {
        /* Calculate confidence based on how many detectors matched */
        uint8_t confidence = 128;  /* Base confidence */
        if (ctx_flags & (AIS_CTX_HMAC_FAILED | AIS_CTX_REPLAY_ATTEMPT)) {
            confidence += 64;  /* Higher confidence with context evidence */
        }

        ais_on_anomaly(detection, antigen.source_node, confidence);
    }

    return detection;
}

void ais_update_self_profile(void) {
    uint8_t features[AIS_SELF_PROFILE_SIZE];
    extract_current_features(features);

    for (int i = 0; i < AIS_SELF_PROFILE_SIZE; i++) {
        /* Update min/max bounds */
        if (features[i] < self_profile.min[i]) {
            self_profile.min[i] = features[i];
        }
        if (features[i] > self_profile.max[i]) {
            self_profile.max[i] = features[i];
        }

        /* Exponential moving average */
        self_profile.features[i] =
            (self_profile.features[i] * 7 + features[i]) / 8;

        /* Update variance estimate */
        uint8_t range = self_profile.max[i] - self_profile.min[i];
        self_profile.variance[i] = (range / 4) + 8;  /* Min variance of 8 */
    }

    self_profile.samples++;
    self_profile.last_update = ticks;
}

void ais_thymus_sample(struct ais_antigen* antigen) {
    if (self_sample_count >= SELF_SAMPLE_BUFFER_SIZE) return;

    for (int i = 0; i < AIS_DETECTOR_SIZE; i++) {
        self_samples[self_sample_count].features[i] = antigen->features[i];
    }
    self_sample_count++;
}

int ais_generate_detector(void) {
    /* Find empty slot */
    int slot = -1;
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        if (detectors[i].state == AIS_DETECTOR_EMPTY) {
            slot = i;
            break;
        }
    }

    if (slot < 0) return -1;

    /* Generate random pattern */
    generate_random_pattern(detectors[slot].pattern, detectors[slot].mask,
                           AIS_DETECTOR_SIZE);

    detectors[slot].state = AIS_DETECTOR_IMMATURE;
    detectors[slot].detect_type = AIS_DETECT_UNKNOWN;
    detectors[slot].matches = 0;
    detectors[slot].false_positives = 0;
    detectors[slot].created_tick = ticks;
    detectors[slot].last_match_tick = 0;

    ais_state.detectors_generated++;

    return slot;
}

bool ais_mature_detector(int detector_idx) {
    if (detector_idx < 0 || detector_idx >= AIS_DETECTOR_COUNT) {
        return false;
    }

    struct ais_detector* d = &detectors[detector_idx];
    if (d->state != AIS_DETECTOR_IMMATURE) {
        return false;
    }

    /* Negative selection: check if detector matches self */
    if (detector_matches_self(detector_idx)) {
        /* Detector is self-reactive - cull it */
        d->state = AIS_DETECTOR_ANERGIC;
        ais_state.detectors_culled++;

        /* Try to generate a replacement */
        d->state = AIS_DETECTOR_EMPTY;
        int new_slot = ais_generate_detector();
        if (new_slot == detector_idx) {
            /* Re-check the new detector (recursive maturation) */
            /* Limit recursion depth implicitly by sample size */
            if (!detector_matches_self(new_slot)) {
                detectors[new_slot].state = AIS_DETECTOR_MATURE;
                return true;
            } else {
                detectors[new_slot].state = AIS_DETECTOR_ANERGIC;
                ais_state.detectors_culled++;
                return false;
            }
        }
        return false;
    }

    /* Detector passed negative selection - promote to mature */
    d->state = AIS_DETECTOR_MATURE;
    return true;
}

void ais_promote_to_memory(int detector_idx) {
    if (detector_idx < 0 || detector_idx >= AIS_DETECTOR_COUNT) {
        return;
    }

    struct ais_detector* d = &detectors[detector_idx];
    if (d->state != AIS_DETECTOR_MATURE) {
        return;
    }

    /* Count current memory cells */
    int memory_count = 0;
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        if (detectors[i].state == AIS_DETECTOR_MEMORY) {
            memory_count++;
        }
    }

    /* Only promote if we have room */
    if (memory_count < AIS_MEMORY_CELLS) {
        d->state = AIS_DETECTOR_MEMORY;

        serial_puts("[AIS] Detector ");
        serial_put_dec(detector_idx);
        serial_puts(" promoted to MEMORY CELL\n");

        blackbox_record_event(EVENT_AIS_MEMORY_PROMOTE, 0);
    }
}

bool ais_is_mature(void) {
    return ais_state.thymus_complete;
}

uint8_t ais_get_active_detector_count(void) {
    uint8_t count = 0;
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        if (detectors[i].state == AIS_DETECTOR_MATURE ||
            detectors[i].state == AIS_DETECTOR_MEMORY) {
            count++;
        }
    }
    return count;
}

uint32_t ais_get_detection_count(void) {
    return ais_state.detections_total;
}

void ais_print_status(void) {
    serial_puts("\n=== ARTIFICIAL IMMUNE SYSTEM STATUS ===\n");

    serial_puts("Phase: ");
    if (ais_state.thymus_complete) {
        serial_puts("DETECTION (mature)\n");
    } else {
        serial_puts("THYMUS (learning)\n");
        serial_puts("Self samples: ");
        serial_put_dec(self_sample_count);
        serial_puts("/");
        serial_put_dec(SELF_SAMPLE_BUFFER_SIZE);
        serial_puts("\n");
    }

    /* Detector stats */
    uint8_t mature = 0, memory = 0, immature = 0;
    for (int i = 0; i < AIS_DETECTOR_COUNT; i++) {
        switch (detectors[i].state) {
            case AIS_DETECTOR_MATURE: mature++; break;
            case AIS_DETECTOR_MEMORY: memory++; break;
            case AIS_DETECTOR_IMMATURE: immature++; break;
        }
    }

    serial_puts("Detectors: ");
    serial_put_dec(mature);
    serial_puts(" mature, ");
    serial_put_dec(memory);
    serial_puts(" memory, ");
    serial_put_dec(immature);
    serial_puts(" immature\n");

    serial_puts("Generated: ");
    serial_put_dec(ais_state.detectors_generated);
    serial_puts(", Culled: ");
    serial_put_dec(ais_state.detectors_culled);
    serial_puts("\n");

    serial_puts("Detections: ");
    serial_put_dec(ais_state.detections_total);
    serial_puts(", False positives: ");
    serial_put_dec(ais_state.false_positives);
    serial_puts("\n");

    /* Self profile */
    serial_puts("Self profile: [");
    for (int i = 0; i < AIS_SELF_PROFILE_SIZE; i++) {
        serial_put_dec(self_profile.features[i]);
        if (i < AIS_SELF_PROFILE_SIZE - 1) serial_puts(",");
    }
    serial_puts("]\n");

    serial_puts("==========================================\n\n");
}

/* ==========================================================================
 * Integration Callbacks
 * ========================================================================== */

void ais_on_anomaly(uint8_t detect_type, uint16_t source_node, uint8_t confidence) {
    serial_puts("[AIS] ANOMALY DETECTED: type=");
    switch (detect_type) {
        case AIS_DETECT_FLOOD: serial_puts("FLOOD"); break;
        case AIS_DETECT_PROBE: serial_puts("PROBE"); break;
        case AIS_DETECT_REPLAY: serial_puts("REPLAY"); break;
        case AIS_DETECT_INJECTION: serial_puts("INJECTION"); break;
        case AIS_DETECT_BEHAVIORAL: serial_puts("BEHAVIORAL"); break;
        case AIS_DETECT_SYBIL: serial_puts("SYBIL"); break;
        case AIS_DETECT_UNKNOWN: serial_puts("UNKNOWN (0-day?)"); break;
        default: serial_puts("???"); break;
    }
    serial_puts(" source=");
    serial_put_hex(source_node);
    serial_puts(" confidence=");
    serial_put_dec(confidence);
    serial_puts("\n");

    /* === STIGMERGIA INTEGRATION === */
    /* Emit DANGER pheromone at current location */
    uint8_t intensity = STIGMERGIA_INTENSITY_MEDIUM;
    if (confidence >= 192) {
        intensity = STIGMERGIA_INTENSITY_HIGH;
    } else if (confidence < 128) {
        intensity = STIGMERGIA_INTENSITY_LOW;
    }
    stigmergia_emit_danger(intensity);

    /* === BLACK BOX INTEGRATION === */
    blackbox_record_event(EVENT_AIS_ANOMALY_ALERT, source_node);
    blackbox_record_event(EVENT_AIS_DETECTOR_MATCH, source_node);

    /* === HEBBIAN INTEGRATION === */
    /* Penalize the source node's synaptic weight */
    nert_synapse_update(source_node, false);  /* LTD - depression */

    /* === ALERT SWARM === */
    /* Send alarm pheromone to neighbors */
    struct nanos_pheromone alarm_pkt;
    alarm_pkt.magic = NANOS_MAGIC;
    alarm_pkt.type = PHEROMONE_ALARM;
    alarm_pkt.node_id = g_state.node_id;
    alarm_pkt.seq = g_state.seq_counter++;
    alarm_pkt.ttl = 3;
    alarm_pkt.hop_count = 0;
    alarm_pkt.dest_id = 0;  /* Broadcast */
    alarm_pkt.distance = g_state.distance_to_queen;
    alarm_pkt.flags = (g_state.role << FLAG_ROLE_SHIFT) | FLAG_URGENT;
    alarm_pkt.version = NANOS_VERSION;

    /* Payload: detection info */
    alarm_pkt.payload[0] = detect_type;
    alarm_pkt.payload[1] = confidence;
    alarm_pkt.payload[2] = (source_node >> 0) & 0xFF;
    alarm_pkt.payload[3] = (source_node >> 8) & 0xFF;

    e1000_send(&alarm_pkt, sizeof(alarm_pkt));
}

void ais_report_security_event(uint8_t event_type, uint16_t source_node) {
    /* Feed security events into the AIS for context */
    switch (event_type) {
        case EVENT_BAD_MAC:
            ais_state.window.hmac_failures++;
            break;
        case EVENT_REPLAY:
            ais_state.window.replay_attempts++;
            break;
        default:
            break;
    }

    /* Also record in Black Box */
    blackbox_record_event(event_type, source_node);
}
