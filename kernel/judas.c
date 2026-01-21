/*
 * NanOS Judas Node Implementation - "La Trampa Mortal" (v0.7)
 *
 * Active defense honeypot that sacrifices itself to capture
 * attacker payloads and transmit forensics to the Queen.
 *
 * "Better to die with intelligence than live in ignorance."
 */
#include <nanos.h>
#include <nanos/judas.h>
#include <nanos/blackbox.h>
#include <nanos/serial.h>
#include <string.h>

/* External globals */
extern volatile uint32_t ticks;
extern struct nanos_state g_state;
extern uint32_t random(void);

/* External functions */
extern int route_send(uint32_t dest_id, uint8_t type, const uint8_t *data, uint8_t len);
extern void cell_apoptosis(void);
extern void e1000_send(void *data, uint16_t len);

/* Global Judas state */
static struct judas_state g_judas;

/* Sliding window duration */
#define JUDAS_WINDOW_MS         30000   /* 30 second window */

/* ==========================================================================
 * Hash and Entropy Functions
 * ========================================================================== */

/**
 * FNV-1a hash for payload deduplication
 */
static uint32_t fnv1a_hash(const uint8_t *data, uint16_t len) {
    uint32_t hash = 0x811c9dc5;
    for (uint16_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

/**
 * Calculate Shannon entropy (simplified, returns 0-255)
 */
static uint8_t calculate_entropy(const uint8_t *data, uint16_t len) {
    if (len == 0) return 0;

    /* Count byte frequencies */
    uint16_t freq[256];
    for (int i = 0; i < 256; i++) freq[i] = 0;

    for (uint16_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    /* Calculate entropy approximation */
    /* High entropy = more unique bytes = likely encrypted/compressed */
    uint16_t unique = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) unique++;
    }

    /* Scale: 256 unique bytes = 255 entropy */
    return (uint8_t)((unique * 255) / 256);
}

/**
 * Simple shellcode pattern detection
 */
static bool detect_shellcode_patterns(const uint8_t *data, uint16_t len) {
    /* Look for common shellcode patterns */
    /* NOP sled */
    uint8_t nop_count = 0;
    for (uint16_t i = 0; i < len; i++) {
        if (data[i] == 0x90) {  /* x86 NOP */
            nop_count++;
            if (nop_count >= 10) return true;
        } else {
            nop_count = 0;
        }
    }

    /* Look for syscall patterns */
    for (uint16_t i = 0; i < len - 2; i++) {
        /* int 0x80 (Linux syscall) */
        if (data[i] == 0xCD && data[i+1] == 0x80) return true;
        /* syscall (x64) */
        if (data[i] == 0x0F && data[i+1] == 0x05) return true;
    }

    /* Look for /bin/sh string */
    const uint8_t binsh[] = "/bin/sh";
    for (uint16_t i = 0; i < len - 7; i++) {
        bool match = true;
        for (int j = 0; j < 7 && match; j++) {
            if (data[i+j] != binsh[j]) match = false;
        }
        if (match) return true;
    }

    return false;
}

/**
 * CRC16 calculation
 */
static uint16_t crc16(const void *data, uint16_t len) {
    uint16_t crc = 0xFFFF;
    const uint8_t *bytes = (const uint8_t *)data;

    for (uint16_t i = 0; i < len; i++) {
        crc ^= (uint16_t)bytes[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

void judas_init(void) {
    memset(&g_judas, 0, sizeof(g_judas));

    g_judas.state = JUDAS_STATE_DORMANT;
    g_judas.state_enter_tick = ticks;

    /* Default configuration */
    g_judas.config.bad_mac_threshold = JUDAS_BAD_MAC_THRESHOLD;
    g_judas.config.replay_threshold = JUDAS_REPLAY_THRESHOLD;
    g_judas.config.probe_threshold = JUDAS_PROBE_THRESHOLD;
    g_judas.config.engage_timeout_ms = JUDAS_ENGAGE_TIMEOUT_MS;
    g_judas.config.capture_timeout_ms = JUDAS_CAPTURE_TIMEOUT_MS;
    g_judas.config.capture_max_bytes = JUDAS_MAX_CAPTURE_SIZE;
    g_judas.config.auto_detonate = 1;
    g_judas.config.enabled = 0;  /* Disabled by default */

    g_judas.window_start_tick = ticks;

    serial_puts("[JUDAS] Initialized - DORMANT\n");
}

void judas_configure(const struct judas_trigger_config *config) {
    memcpy(&g_judas.config, config, sizeof(struct judas_trigger_config));

    serial_puts("[JUDAS] Configured: bad_mac=");
    serial_put_dec(config->bad_mac_threshold);
    serial_puts(" replay=");
    serial_put_dec(config->replay_threshold);
    serial_puts(" probe=");
    serial_put_dec(config->probe_threshold);
    serial_puts("\n");
}

void judas_enable(bool enable) {
    g_judas.config.enabled = enable ? 1 : 0;

    if (enable) {
        serial_puts("[JUDAS] ENABLED - Active defense mode\n");
        blackbox_record_event(EVENT_JUDAS_ENABLED, 0);
    } else {
        serial_puts("[JUDAS] DISABLED\n");
        /* Reset to dormant if was active */
        if (g_judas.state != JUDAS_STATE_DORMANT) {
            g_judas.state = JUDAS_STATE_DORMANT;
            g_judas.has_target = 0;
        }
    }
}

bool judas_is_enabled(void) {
    return g_judas.config.enabled != 0;
}

/* ==========================================================================
 * State Machine
 * ========================================================================== */

/**
 * Transition to new state
 */
static void judas_transition(judas_state_t new_state) {
    judas_state_t old_state = g_judas.state;
    g_judas.state = new_state;
    g_judas.state_enter_tick = ticks;

    const char *state_names[] = {
        "DORMANT", "SUSPICIOUS", "ENGAGING", "CAPTURING", "DETONATING"
    };

    serial_puts("[JUDAS] ");
    serial_puts(state_names[old_state]);
    serial_puts(" -> ");
    serial_puts(state_names[new_state]);
    serial_puts("\n");

    /* State entry actions */
    switch (new_state) {
        case JUDAS_STATE_SUSPICIOUS:
            g_judas.activations_total++;
            blackbox_record_event(EVENT_JUDAS_SUSPICIOUS, g_judas.current_attacker.attacker_id);
            break;

        case JUDAS_STATE_ENGAGING:
            /* Send ENGAGE notification to Queen */
            {
                uint8_t engage_data[8];
                engage_data[0] = (g_judas.current_attacker.attacker_id >> 0) & 0xFF;
                engage_data[1] = (g_judas.current_attacker.attacker_id >> 8) & 0xFF;
                engage_data[2] = (g_judas.current_attacker.attacker_id >> 16) & 0xFF;
                engage_data[3] = (g_judas.current_attacker.attacker_id >> 24) & 0xFF;
                engage_data[4] = g_judas.current_attacker.confidence;
                engage_data[5] = g_judas.current_attacker.first_detection_type;
                engage_data[6] = 0;
                engage_data[7] = 0;

                route_send(g_state.known_queen_id, PHEROMONE_JUDAS_ENGAGE,
                          engage_data, sizeof(engage_data));
            }
            blackbox_record_event(EVENT_JUDAS_ENGAGING, g_judas.current_attacker.attacker_id);
            break;

        case JUDAS_STATE_CAPTURING:
            g_judas.capture_started = 1;
            g_judas.capture.capture_tick = ticks;
            g_judas.capture.engage_tick = g_judas.state_enter_tick;
            break;

        case JUDAS_STATE_DETONATING:
            g_judas.detonations_total++;
            blackbox_record_event(EVENT_JUDAS_DETONATING, g_judas.current_attacker.attacker_id);
            break;

        default:
            break;
    }
}

/**
 * Check if should transition to suspicious
 */
static bool judas_should_activate(void) {
    if (g_judas.window_bad_mac >= g_judas.config.bad_mac_threshold) {
        return true;
    }
    if (g_judas.window_replay >= g_judas.config.replay_threshold) {
        return true;
    }
    if (g_judas.window_probe >= g_judas.config.probe_threshold) {
        return true;
    }
    return false;
}

void judas_tick(void) {
    if (!g_judas.config.enabled) return;

    uint32_t now = ticks;
    uint32_t state_age_ms = (now - g_judas.state_enter_tick) * 10;

    /* Reset window if expired */
    if ((now - g_judas.window_start_tick) * 10 >= JUDAS_WINDOW_MS) {
        g_judas.window_bad_mac = 0;
        g_judas.window_replay = 0;
        g_judas.window_probe = 0;
        g_judas.window_start_tick = now;
    }

    /* State machine */
    switch (g_judas.state) {
        case JUDAS_STATE_DORMANT:
            /* Check if should activate */
            if (judas_should_activate()) {
                judas_transition(JUDAS_STATE_SUSPICIOUS);
            }
            break;

        case JUDAS_STATE_SUSPICIOUS:
            /* Wait for more activity or timeout */
            /* Move to ENGAGING after brief evaluation */
            if (state_age_ms >= 2000) {  /* 2 second evaluation */
                if (g_judas.current_attacker.confidence >= 128) {
                    judas_transition(JUDAS_STATE_ENGAGING);
                } else {
                    /* Not enough confidence, return to dormant */
                    judas_transition(JUDAS_STATE_DORMANT);
                    g_judas.has_target = 0;
                }
            }
            break;

        case JUDAS_STATE_ENGAGING:
            /* Timeout check */
            if (state_age_ms >= g_judas.config.engage_timeout_ms) {
                serial_puts("[JUDAS] Engage timeout - no payload received\n");
                if (g_judas.capture.payload_len > 0) {
                    judas_transition(JUDAS_STATE_DETONATING);
                } else {
                    judas_transition(JUDAS_STATE_DORMANT);
                    g_judas.has_target = 0;
                }
            }
            break;

        case JUDAS_STATE_CAPTURING:
            /* Timeout check */
            if (state_age_ms >= g_judas.config.capture_timeout_ms) {
                serial_puts("[JUDAS] Capture timeout\n");
                if (g_judas.config.auto_detonate) {
                    judas_transition(JUDAS_STATE_DETONATING);
                }
            }
            break;

        case JUDAS_STATE_DETONATING:
            /* Send forensics and die */
            if (state_age_ms < 100) {
                /* First tick - finalize capture */
                judas_analyze_capture(&g_judas.capture);
                g_judas.capture.node_id = g_state.node_id;
                g_judas.capture.capture_id = fnv1a_hash(
                    (uint8_t*)&g_judas.capture, sizeof(g_judas.capture) - 2);
                g_judas.capture.checksum = crc16(&g_judas.capture,
                    sizeof(g_judas.capture) - sizeof(uint16_t));
            } else if (state_age_ms < 1000) {
                /* Send forensics (retry up to JUDAS_FORENSICS_RETRIES) */
                static uint8_t retries = 0;
                if (retries < JUDAS_FORENSICS_RETRIES) {
                    if (judas_send_forensics() == 0) {
                        g_judas.forensics_sent++;
                        retries = JUDAS_FORENSICS_RETRIES;  /* Success - stop retrying */
                    } else {
                        retries++;
                    }
                }
            } else {
                /* BOOM */
                serial_puts("[JUDAS] === DETONATING ===\n");
                cell_apoptosis();
            }
            break;
    }
}

judas_state_t judas_get_state(void) {
    return g_judas.state;
}

bool judas_is_engaged(void) {
    return g_judas.state == JUDAS_STATE_ENGAGING ||
           g_judas.state == JUDAS_STATE_CAPTURING;
}

/* ==========================================================================
 * Threat Detection
 * ========================================================================== */

void judas_report_event(uint8_t event_type, uint32_t source_id,
                        const uint8_t *source_mac, uint8_t confidence) {
    if (!g_judas.config.enabled) return;

    /* Update window counters */
    switch (event_type) {
        case EVENT_BAD_MAC:
            g_judas.window_bad_mac++;
            break;
        case EVENT_REPLAY:
            g_judas.window_replay++;
            break;
        case EVENT_PROBE:
        case EVENT_AIS_ANOMALY_ALERT:
            g_judas.window_probe++;
            break;
    }

    /* Update attacker profile if tracking */
    if (g_judas.has_target && g_judas.current_attacker.attacker_id == source_id) {
        switch (event_type) {
            case EVENT_BAD_MAC:
                g_judas.current_attacker.bad_mac_count++;
                break;
            case EVENT_REPLAY:
                g_judas.current_attacker.replay_count++;
                break;
            case EVENT_PROBE:
                g_judas.current_attacker.probe_count++;
                break;
        }
        g_judas.current_attacker.last_activity_tick = ticks;

        /* Update confidence */
        if (confidence > g_judas.current_attacker.confidence) {
            g_judas.current_attacker.confidence = confidence;
        }
    } else if (!g_judas.has_target && g_judas.state == JUDAS_STATE_DORMANT) {
        /* Start tracking new potential attacker */
        if (judas_should_activate()) {
            memset(&g_judas.current_attacker, 0, sizeof(g_judas.current_attacker));
            g_judas.current_attacker.attacker_id = source_id;
            if (source_mac) {
                memcpy(g_judas.current_attacker.attacker_mac, source_mac, 6);
            }
            g_judas.current_attacker.first_detection_type = event_type;
            g_judas.current_attacker.confidence = confidence;
            g_judas.current_attacker.first_seen_tick = ticks;
            g_judas.current_attacker.last_activity_tick = ticks;
            g_judas.has_target = 1;
        }
    }
}

int judas_intercept_anomaly(uint8_t detect_type, uint16_t source_node,
                            uint8_t confidence) {
    if (!g_judas.config.enabled) return 0;

    /* Only intercept injection and probe attempts */
    if (detect_type != AIS_DETECT_INJECTION &&
        detect_type != AIS_DETECT_PROBE &&
        detect_type != AIS_DETECT_UNKNOWN) {
        return 0;
    }

    /* Start or update tracking */
    if (g_judas.state == JUDAS_STATE_DORMANT ||
        g_judas.state == JUDAS_STATE_SUSPICIOUS) {

        /* Set/update target */
        if (!g_judas.has_target) {
            memset(&g_judas.current_attacker, 0, sizeof(g_judas.current_attacker));
            g_judas.current_attacker.attacker_id = source_node;
            g_judas.current_attacker.first_detection_type = detect_type;
            g_judas.current_attacker.first_seen_tick = ticks;
            g_judas.has_target = 1;
        }

        g_judas.current_attacker.confidence = confidence;
        g_judas.current_attacker.last_activity_tick = ticks;

        if (g_judas.state == JUDAS_STATE_DORMANT) {
            judas_transition(JUDAS_STATE_SUSPICIOUS);
        }

        serial_puts("[JUDAS] Intercepting anomaly from 0x");
        serial_put_hex(source_node);
        serial_puts("\n");

        return 1;  /* We're handling it */
    }

    return 0;
}

/* ==========================================================================
 * Capture
 * ========================================================================== */

void judas_capture_payload(const void *data, uint16_t len) {
    if (g_judas.state != JUDAS_STATE_ENGAGING &&
        g_judas.state != JUDAS_STATE_CAPTURING) {
        return;
    }

    /* Transition to capturing if needed */
    if (g_judas.state == JUDAS_STATE_ENGAGING) {
        judas_transition(JUDAS_STATE_CAPTURING);
    }

    /* Append to capture buffer */
    uint16_t remaining = g_judas.config.capture_max_bytes - g_judas.capture.payload_len;
    uint16_t to_copy = (len < remaining) ? len : remaining;

    if (to_copy > 0) {
        memcpy(&g_judas.capture.payload[g_judas.capture.payload_len],
               data, to_copy);
        g_judas.capture.payload_len += to_copy;
    }

    serial_puts("[JUDAS] Captured ");
    serial_put_dec(to_copy);
    serial_puts(" bytes (total: ");
    serial_put_dec(g_judas.capture.payload_len);
    serial_puts(")\n");

    /* Copy attacker profile */
    memcpy(&g_judas.capture.attacker, &g_judas.current_attacker,
           sizeof(struct judas_attacker_profile));

    /* Check if buffer full */
    if (g_judas.capture.payload_len >= g_judas.config.capture_max_bytes) {
        serial_puts("[JUDAS] Capture buffer full\n");
        if (g_judas.config.auto_detonate) {
            judas_transition(JUDAS_STATE_DETONATING);
        }
    }
}

void judas_analyze_capture(struct judas_capture *capture) {
    if (capture->payload_len == 0) {
        capture->payload_type = JUDAS_PAYLOAD_UNKNOWN;
        return;
    }

    /* Calculate hash */
    capture->payload_hash = fnv1a_hash(capture->payload, capture->payload_len);

    /* Calculate entropy */
    capture->entropy_score = calculate_entropy(capture->payload, capture->payload_len);

    /* High entropy suggests encryption/compression */
    capture->is_encrypted = (capture->entropy_score > 200) ? 1 : 0;

    /* Check for shellcode */
    capture->has_shellcode = detect_shellcode_patterns(capture->payload,
                                                        capture->payload_len) ? 1 : 0;

    /* Classify payload */
    if (capture->has_shellcode) {
        capture->payload_type = JUDAS_PAYLOAD_EXPLOIT;
    } else if (capture->is_encrypted) {
        capture->payload_type = JUDAS_PAYLOAD_MALWARE;
    } else if (capture->attacker.probe_count > capture->attacker.injection_attempts) {
        capture->payload_type = JUDAS_PAYLOAD_PROBE;
    } else if (capture->attacker.injection_attempts > 0) {
        capture->payload_type = JUDAS_PAYLOAD_INJECTION;
    } else {
        capture->payload_type = JUDAS_PAYLOAD_UNKNOWN;
    }

    serial_puts("[JUDAS] Analysis: type=");
    serial_put_dec(capture->payload_type);
    serial_puts(" entropy=");
    serial_put_dec(capture->entropy_score);
    serial_puts(" shellcode=");
    serial_puts(capture->has_shellcode ? "YES" : "NO");
    serial_puts("\n");
}

/* ==========================================================================
 * Detonation
 * ========================================================================== */

void judas_detonate(void) {
    if (g_judas.state != JUDAS_STATE_CAPTURING &&
        g_judas.state != JUDAS_STATE_ENGAGING) {
        serial_puts("[JUDAS] Cannot detonate in current state\n");
        return;
    }

    judas_transition(JUDAS_STATE_DETONATING);
}

int judas_send_forensics(void) {
    /* Prepare forensics packet */
    /* Due to size constraints, send in chunks */

    /* First packet: capture metadata */
    uint8_t meta_packet[32];
    meta_packet[0] = (g_judas.capture.capture_id >> 0) & 0xFF;
    meta_packet[1] = (g_judas.capture.capture_id >> 8) & 0xFF;
    meta_packet[2] = (g_judas.capture.capture_id >> 16) & 0xFF;
    meta_packet[3] = (g_judas.capture.capture_id >> 24) & 0xFF;
    meta_packet[4] = (g_judas.capture.attacker.attacker_id >> 0) & 0xFF;
    meta_packet[5] = (g_judas.capture.attacker.attacker_id >> 8) & 0xFF;
    meta_packet[6] = (g_judas.capture.attacker.attacker_id >> 16) & 0xFF;
    meta_packet[7] = (g_judas.capture.attacker.attacker_id >> 24) & 0xFF;
    memcpy(&meta_packet[8], g_judas.capture.attacker.attacker_mac, 6);
    meta_packet[14] = g_judas.capture.attacker.confidence;
    meta_packet[15] = g_judas.capture.payload_type;
    meta_packet[16] = (g_judas.capture.payload_len >> 0) & 0xFF;
    meta_packet[17] = (g_judas.capture.payload_len >> 8) & 0xFF;
    meta_packet[18] = (g_judas.capture.payload_hash >> 0) & 0xFF;
    meta_packet[19] = (g_judas.capture.payload_hash >> 8) & 0xFF;
    meta_packet[20] = (g_judas.capture.payload_hash >> 16) & 0xFF;
    meta_packet[21] = (g_judas.capture.payload_hash >> 24) & 0xFF;
    meta_packet[22] = g_judas.capture.entropy_score;
    meta_packet[23] = g_judas.capture.has_shellcode;
    meta_packet[24] = g_judas.capture.is_encrypted;
    meta_packet[25] = (g_judas.capture.attacker.bad_mac_count >> 0) & 0xFF;
    meta_packet[26] = (g_judas.capture.attacker.bad_mac_count >> 8) & 0xFF;
    meta_packet[27] = (g_judas.capture.attacker.replay_count >> 0) & 0xFF;
    meta_packet[28] = (g_judas.capture.attacker.replay_count >> 8) & 0xFF;
    meta_packet[29] = g_judas.capture.attacker.first_detection_type;
    meta_packet[30] = 0;  /* Packet number (0 = metadata) */
    meta_packet[31] = (g_judas.capture.payload_len + 31) / 32;  /* Total packets */

    int result = route_send(g_state.known_queen_id, PHEROMONE_JUDAS_FORENSICS,
                            meta_packet, sizeof(meta_packet));

    if (result < 0) {
        serial_puts("[JUDAS] Failed to send forensics metadata\n");
        return -1;
    }

    /* Send payload in 32-byte chunks */
    uint16_t offset = 0;
    uint8_t packet_num = 1;
    uint8_t payload_chunk[32];

    while (offset < g_judas.capture.payload_len) {
        uint16_t chunk_len = g_judas.capture.payload_len - offset;
        if (chunk_len > 31) chunk_len = 31;

        payload_chunk[0] = packet_num;
        memcpy(&payload_chunk[1], &g_judas.capture.payload[offset], chunk_len);

        /* Pad with zeros */
        for (int i = chunk_len + 1; i < 32; i++) {
            payload_chunk[i] = 0;
        }

        route_send(g_state.known_queen_id, PHEROMONE_JUDAS_CAPTURE,
                   payload_chunk, 32);

        offset += chunk_len;
        packet_num++;
    }

    serial_puts("[JUDAS] Forensics sent: ");
    serial_put_dec(packet_num);
    serial_puts(" packets\n");

    g_judas.captures_total++;

    return 0;
}

/* ==========================================================================
 * Debug
 * ========================================================================== */

void judas_print_status(void) {
    const char *state_names[] = {
        "DORMANT", "SUSPICIOUS", "ENGAGING", "CAPTURING", "DETONATING"
    };

    serial_puts("\n=== JUDAS NODE STATUS ===\n");
    serial_puts("Enabled: ");
    serial_puts(g_judas.config.enabled ? "YES" : "NO");
    serial_puts("\nState: ");
    serial_puts(state_names[g_judas.state]);
    serial_puts("\n");

    if (g_judas.has_target) {
        serial_puts("Target: 0x");
        serial_put_hex(g_judas.current_attacker.attacker_id);
        serial_puts(" conf=");
        serial_put_dec(g_judas.current_attacker.confidence);
        serial_puts("\n");
    }

    serial_puts("Window: bad_mac=");
    serial_put_dec(g_judas.window_bad_mac);
    serial_puts("/");
    serial_put_dec(g_judas.config.bad_mac_threshold);
    serial_puts(" replay=");
    serial_put_dec(g_judas.window_replay);
    serial_puts("/");
    serial_put_dec(g_judas.config.replay_threshold);
    serial_puts("\n");

    serial_puts("Stats: activations=");
    serial_put_dec(g_judas.activations_total);
    serial_puts(" captures=");
    serial_put_dec(g_judas.captures_total);
    serial_puts(" detonations=");
    serial_put_dec(g_judas.detonations_total);
    serial_puts("\n");

    if (g_judas.capture.payload_len > 0) {
        serial_puts("Capture: ");
        serial_put_dec(g_judas.capture.payload_len);
        serial_puts(" bytes, hash=0x");
        serial_put_hex(g_judas.capture.payload_hash);
        serial_puts("\n");
    }

    serial_puts("=========================\n\n");
}

struct judas_state* judas_get_state_ptr(void) {
    return &g_judas;
}
