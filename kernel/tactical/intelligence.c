/*
 * NanOS Tactical Intelligence System
 * Sensor correlation and threat detection
 */
#include <nanos.h>
#include "../include/nanos/intelligence.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern struct nanos_state g_state;
extern void vga_set_color(uint8_t color);
extern void vga_puts(const char* s);
extern void vga_put_dec(uint32_t n);
extern void vga_put_hex(uint32_t n);
extern void serial_puts(const char* s);
extern void serial_put_dec(uint32_t n);
extern void e1000_send(void* data, uint32_t len);
extern uint32_t random(void);

/* Detection type names */
const char* detect_type_name(uint8_t type) {
    switch (type) {
        case DETECT_MOTION:   return "MOTION";
        case DETECT_ACOUSTIC: return "ACOUSTIC";
        case DETECT_THERMAL:  return "THERMAL";
        case DETECT_RF:       return "RF";
        case DETECT_MAGNETIC: return "MAGNETIC";
        case DETECT_PRESSURE: return "PRESSURE";
        default:              return "UNKNOWN";
    }
}

/* Alert level names */
const char* alert_level_name(uint8_t level) {
    switch (level) {
        case ALERT_ANOMALY:   return "ANOMALY";
        case ALERT_CONTACT:   return "CONTACT";
        case ALERT_PROBABLE:  return "PROBABLE";
        case ALERT_CONFIRMED: return "CONFIRMED";
        case ALERT_CRITICAL:  return "CRITICAL";
        default:              return "NONE";
    }
}

/* Initialize tactical system */
void tactical_init(void) {
    g_state.tactical.local_count = 0;
    g_state.tactical.event_count = 0;
    g_state.tactical.my_pos_x = (random() % 1000) - 500;  /* Random position -500 to 500 */
    g_state.tactical.my_pos_y = (random() % 1000) - 500;
    g_state.tactical.my_sector = random() % SECTOR_COUNT;
    g_state.tactical.detections_sent = 0;
    g_state.tactical.correlations_made = 0;
    for (int i = 0; i < SECTOR_COUNT; i++) {
        g_state.tactical.sector_activity[i] = 0;
    }
}

#if 0 /* Tactical send functions disabled - too spammy */
/* Calculate sector from relative position */
static uint8_t calc_sector(int16_t dx, int16_t dy) {
    if (dy > 0) {
        if (dx > dy) return 2;        /* E */
        if (dx < -dy) return 6;       /* W */
        if (dx > 0) return 1;         /* NE */
        if (dx < 0) return 7;         /* NW */
        return 0;                      /* N */
    } else {
        if (dx > -dy) return 2;       /* E */
        if (dx < dy) return 6;        /* W */
        if (dx > 0) return 3;         /* SE */
        if (dx < 0) return 5;         /* SW */
        return 4;                      /* S */
    }
}

/* Send detection to swarm */
static void tactical_send_detection(uint8_t type, uint8_t intensity,
                                     int16_t rel_x, int16_t rel_y) {
    struct nanos_pheromone pkt;

    pkt.magic = NANOS_MAGIC;
    pkt.node_id = g_state.node_id;
    pkt.type = PHEROMONE_DETECT;
    pkt.ttl = 5;
    pkt.flags = 0;
    pkt.version = NANOS_VERSION;
    pkt.seq = g_state.seq_counter++;
    pkt.dest_id = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.hop_count = 0;
    PKT_SET_ROLE(&pkt, g_state.role);

    uint8_t confidence = 50 + (intensity / 5);
    if (confidence > 100) confidence = 100;
    uint8_t sector = calc_sector(rel_x, rel_y);

    uint8_t* p = pkt.payload;
    *p++ = type;
    *p++ = confidence;
    *p++ = sector;
    *p++ = intensity;
    *(uint32_t*)p = ticks; p += 4;
    *(int16_t*)p = g_state.tactical.my_pos_x + rel_x; p += 2;
    *(int16_t*)p = g_state.tactical.my_pos_y + rel_y; p += 2;

    for (int i = 0; i < HMAC_TAG_SIZE; i++) pkt.hmac[i] = 0;
    e1000_send(&pkt, sizeof(pkt));
    g_state.packets_tx++;
    g_state.tactical.detections_sent++;
}
#endif

/* Find matching event for correlation */
static int find_matching_event(uint8_t sector, int32_t pos_x, int32_t pos_y) {
    for (int i = 0; i < g_state.tactical.event_count; i++) {
        /* Check timeout */
        if (ticks - g_state.tactical.events[i].last_seen > (EVENT_TIMEOUT_MS / 10)) {
            continue;
        }
        /* Check sector match (adjacent sectors OK) */
        int8_t sd = g_state.tactical.events[i].sector - sector;
        if (sd < 0) sd = -sd;
        if (sd > 1 && sd < 7) continue;

        /* Check distance */
        int32_t dx = pos_x - g_state.tactical.events[i].est_pos_x;
        int32_t dy = pos_y - g_state.tactical.events[i].est_pos_y;
        if (dx < 0) dx = -dx;
        if (dy < 0) dy = -dy;
        if (dx + dy < 500) {  /* Within 5m */
            return i;
        }
    }
    return -1;
}

/* Process incoming detection */
void tactical_process_detection(struct nanos_pheromone* pkt) {
    uint8_t* p = pkt->payload;
    uint8_t det_type = *p++;
    uint8_t confidence = *p++;
    uint8_t sector = *p++;
    (void)*p++;  /* intensity - skip */
    p += 4;      /* timestamp - skip */
    int16_t pos_x = *(int16_t*)p; p += 2;
    int16_t pos_y = *(int16_t*)p;

    /* Update sector activity */
    g_state.tactical.sector_activity[sector % SECTOR_COUNT]++;

    /* Try to correlate with existing event */
    int evt_idx = find_matching_event(sector, pos_x, pos_y);

    if (evt_idx >= 0) {
        /* Update existing event */
        g_state.tactical.events[evt_idx].detect_types |= (1 << det_type);
        g_state.tactical.events[evt_idx].last_seen = ticks;

        /* Check if new reporter */
        int is_new = 1;
        for (int i = 0; i < g_state.tactical.events[evt_idx].reporter_count && i < 4; i++) {
            if (g_state.tactical.events[evt_idx].reporters[i] == pkt->node_id) {
                is_new = 0;
                break;
            }
        }
        if (is_new && g_state.tactical.events[evt_idx].reporter_count < 4) {
            g_state.tactical.events[evt_idx].reporters[
                g_state.tactical.events[evt_idx].reporter_count++] = pkt->node_id;
        }

        /* Update alert level based on reporters and types */
        uint8_t type_count = 0;
        for (int i = 0; i < 8; i++) {
            if (g_state.tactical.events[evt_idx].detect_types & (1 << i)) type_count++;
        }

        if (g_state.tactical.events[evt_idx].reporter_count >= 4 && type_count >= 2) {
            g_state.tactical.events[evt_idx].alert_level = ALERT_CONFIRMED;
        } else if (g_state.tactical.events[evt_idx].reporter_count >= 3 || type_count >= 2) {
            g_state.tactical.events[evt_idx].alert_level = ALERT_PROBABLE;
        } else if (g_state.tactical.events[evt_idx].reporter_count >= 2) {
            g_state.tactical.events[evt_idx].alert_level = ALERT_CONTACT;
        }

        /* Elevation to CRITICAL after 5 seconds persistence */
        if (ticks - g_state.tactical.events[evt_idx].first_seen > 500 &&
            g_state.tactical.events[evt_idx].alert_level >= ALERT_PROBABLE) {
            g_state.tactical.events[evt_idx].alert_level = ALERT_CRITICAL;
        }
    } else if (g_state.tactical.event_count < MAX_ACTIVE_EVENTS) {
        /* Create new event */
        evt_idx = g_state.tactical.event_count++;
        g_state.tactical.events[evt_idx].event_id = random();
        g_state.tactical.events[evt_idx].alert_level = ALERT_ANOMALY;
        g_state.tactical.events[evt_idx].detect_types = (1 << det_type);
        g_state.tactical.events[evt_idx].sector = sector;
        g_state.tactical.events[evt_idx].reporter_count = 1;
        g_state.tactical.events[evt_idx].reporters[0] = pkt->node_id;
        g_state.tactical.events[evt_idx].first_seen = ticks;
        g_state.tactical.events[evt_idx].last_seen = ticks;
        g_state.tactical.events[evt_idx].est_pos_x = pos_x;
        g_state.tactical.events[evt_idx].est_pos_y = pos_y;
    }

    /* Display on screen */
    if (g_state.role == ROLE_QUEEN || g_state.role == ROLE_SENTINEL) {
        vga_set_color(0x0E);
        vga_puts("[DETECT] ");
        vga_puts(detect_type_name(det_type));
        vga_puts(" from ");
        vga_put_hex(pkt->node_id);
        vga_puts(" sector=");
        vga_put_dec(sector);
        vga_puts(" conf=");
        vga_put_dec(confidence);
        if (evt_idx >= 0 && g_state.tactical.events[evt_idx].alert_level >= ALERT_CONTACT) {
            vga_set_color(0x0C);
            vga_puts(" >> ");
            vga_puts(alert_level_name(g_state.tactical.events[evt_idx].alert_level));
        }
        vga_puts("\n");
        vga_set_color(0x0A);

        serial_puts("[DETECT] type=");
        serial_puts(detect_type_name(det_type));
        serial_puts(" sector=");
        serial_put_dec(sector);
        serial_puts(" alert=");
        if (evt_idx >= 0) {
            serial_puts(alert_level_name(g_state.tactical.events[evt_idx].alert_level));
        } else {
            serial_puts("NEW");
        }
        serial_puts("\n");
    }
}

/* Simulate sensor detections for testing (DISABLED - too spammy) */
#if 0
static void tactical_simulate(void) {
    static uint32_t last_sim = 0;
    if (ticks - last_sim < 300) return;  /* Every 3 seconds */
    last_sim = ticks;

    /* 20% chance of detection */
    if ((random() % 100) > 20) return;

    uint8_t type = (random() % 4) + 1;  /* MOTION to RF */
    uint8_t intensity = 50 + (random() % 150);
    int16_t rel_x = (random() % 400) - 200;
    int16_t rel_y = (random() % 400) - 200;

    tactical_send_detection(type, intensity, rel_x, rel_y);

    vga_set_color(0x0D);
    vga_puts("[SIM] Detected ");
    vga_puts(detect_type_name(type));
    vga_puts(" intensity=");
    vga_put_dec(intensity);
    vga_puts("\n");
    vga_set_color(0x0A);
}

/* Clean up expired events */
static void tactical_maintenance(void) {
    int write_idx = 0;
    for (int i = 0; i < g_state.tactical.event_count; i++) {
        if (ticks - g_state.tactical.events[i].last_seen < (EVENT_TIMEOUT_MS / 10)) {
            if (write_idx != i) {
                g_state.tactical.events[write_idx] = g_state.tactical.events[i];
            }
            write_idx++;
        }
    }
    g_state.tactical.event_count = write_idx;

    /* Decay sector activity */
    for (int i = 0; i < SECTOR_COUNT; i++) {
        if (g_state.tactical.sector_activity[i] > 0) {
            g_state.tactical.sector_activity[i]--;
        }
    }
}
#endif /* Tactical simulation disabled */
