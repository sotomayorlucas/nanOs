/*
 * NanOS Distributed Black Box - "El Último Aliento" (v0.5)
 *
 * Implements distributed forensic evidence preservation.
 * Dying nodes transmit their security state to trusted neighbors,
 * creating a distributed record that survives individual node deaths.
 *
 * Key insight: In swarm systems, nodes die frequently. Without this
 * system, forensic evidence dies with them. The Black Box ensures
 * that critical security events are preserved in the collective memory.
 */
#include <nanos.h>
#include "../include/nanos/blackbox.h"
#include "../include/nanos/gossip.h"
#include "../include/nanos/serial.h"

/* External dependencies */
extern volatile uint32_t ticks;
extern void e1000_send(void* data, uint16_t len);

/* Local event ring buffer for our own events (before death) */
#define LOCAL_EVENT_BUFFER_SIZE 8
static struct {
    uint32_t tick;
    uint8_t  type;
    uint16_t source_node;
} local_events[LOCAL_EVENT_BUFFER_SIZE];
static uint8_t local_event_head = 0;
static uint8_t local_event_count = 0;

/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * Find a trusted neighbor to receive our last will
 * Uses Hebbian weights to select reliable recipients
 */
static uint32_t find_trusted_recipient(uint32_t exclude) {
    return nert_synapse_select_best(exclude);
}

/**
 * Pack last will into pheromone payload
 * Payload format (48 bytes max):
 *   [0-3]:   node_id (dying node)
 *   [4]:     death_reason
 *   [5]:     uptime_hours
 *   [6-7]:   bad_mac_count
 *   [8-9]:   replay_count
 *   [10-11]: rate_limit_count
 *   [12]:    blacklist_count
 *   [13]:    neighbor_count
 *   [14]:    role
 *   [15]:    distance_to_queen
 *   [16]:    event_count (0-5)
 *   [17+]:   events (7 bytes each: tick[4], type[1], source[2])
 */
static int pack_last_will(uint8_t* payload, uint8_t death_reason) {
    int offset = 0;

    /* Node identification */
    payload[offset++] = (g_state.node_id >> 0) & 0xFF;
    payload[offset++] = (g_state.node_id >> 8) & 0xFF;
    payload[offset++] = (g_state.node_id >> 16) & 0xFF;
    payload[offset++] = (g_state.node_id >> 24) & 0xFF;

    /* Death info */
    payload[offset++] = death_reason;
    payload[offset++] = (uint8_t)(ticks / 360000);  /* Approx hours */

    /* Security statistics (from NERT if available) */
    uint32_t bad_mac = 0, replay = 0, invalid = 0;
    /* Note: These would come from nert_security_get_stats in full impl */
    payload[offset++] = bad_mac & 0xFF;
    payload[offset++] = (bad_mac >> 8) & 0xFF;
    payload[offset++] = replay & 0xFF;
    payload[offset++] = (replay >> 8) & 0xFF;
    payload[offset++] = 0;  /* rate_limit_count low */
    payload[offset++] = 0;  /* rate_limit_count high */
    payload[offset++] = 0;  /* blacklist_count */

    /* Network state */
    payload[offset++] = g_state.neighbor_count;
    payload[offset++] = g_state.role;
    payload[offset++] = g_state.distance_to_queen;

    /* Recent security events (up to 5) */
    uint8_t events_to_pack = local_event_count;
    if (events_to_pack > BLACKBOX_MAX_EVENTS) {
        events_to_pack = BLACKBOX_MAX_EVENTS;
    }
    payload[offset++] = events_to_pack;

    /* Pack events (most recent first) */
    for (int i = 0; i < events_to_pack; i++) {
        int idx = (local_event_head - 1 - i + LOCAL_EVENT_BUFFER_SIZE)
                  % LOCAL_EVENT_BUFFER_SIZE;

        /* Pack tick (4 bytes) */
        payload[offset++] = (local_events[idx].tick >> 0) & 0xFF;
        payload[offset++] = (local_events[idx].tick >> 8) & 0xFF;
        payload[offset++] = (local_events[idx].tick >> 16) & 0xFF;
        payload[offset++] = (local_events[idx].tick >> 24) & 0xFF;

        /* Pack type (1 byte) */
        payload[offset++] = local_events[idx].type;

        /* Pack source node (2 bytes) */
        payload[offset++] = (local_events[idx].source_node >> 0) & 0xFF;
        payload[offset++] = (local_events[idx].source_node >> 8) & 0xFF;
    }

    return offset;
}

/**
 * Unpack received last will from payload
 */
static void unpack_last_will(const uint8_t* payload, uint8_t len,
                             uint32_t* node_id, uint8_t* death_reason,
                             uint8_t* uptime_hours, uint16_t* bad_mac_count,
                             uint8_t* neighbor_count, uint8_t* role,
                             uint8_t* distance) {
    if (len < 17) return;

    *node_id = payload[0] | (payload[1] << 8) |
               (payload[2] << 16) | (payload[3] << 24);
    *death_reason = payload[4];
    *uptime_hours = payload[5];
    *bad_mac_count = payload[6] | (payload[7] << 8);
    *neighbor_count = payload[13];
    *role = payload[14];
    *distance = payload[15];
}

/* ==========================================================================
 * Public API Implementation
 * ========================================================================== */

void blackbox_init(void) {
    /* Clear local event buffer */
    local_event_head = 0;
    local_event_count = 0;

    /* Clear stored wills */
    for (int i = 0; i < BLACKBOX_MAX_WILLS; i++) {
        g_state.blackbox.wills[i].node_id = 0;
    }

    g_state.blackbox.will_count = 0;
    g_state.blackbox.will_index = 0;
    g_state.blackbox.wills_received = 0;
    g_state.blackbox.wills_relayed = 0;

    serial_puts("[BLACKBOX] Forensic system initialized\n");
}

void blackbox_record_event(uint8_t event_type, uint16_t source_node) {
    /* Add to local ring buffer */
    local_events[local_event_head].tick = ticks;
    local_events[local_event_head].type = event_type;
    local_events[local_event_head].source_node = source_node;

    local_event_head = (local_event_head + 1) % LOCAL_EVENT_BUFFER_SIZE;
    if (local_event_count < LOCAL_EVENT_BUFFER_SIZE) {
        local_event_count++;
    }
}

void blackbox_emit_last_will(uint8_t death_reason) {
    serial_puts("[BLACKBOX] Emitting LAST WILL, reason=");
    serial_put_dec(death_reason);
    serial_puts("\n");

    struct nanos_pheromone pkt;

    pkt.magic = NANOS_MAGIC;
    pkt.type = PHEROMONE_LAST_WILL;
    pkt.node_id = g_state.node_id;
    pkt.seq = g_state.seq_num++;
    pkt.ttl = 2;  /* Limited propagation - only trusted neighbors */
    pkt.hop_count = 0;
    pkt.distance = g_state.distance_to_queen;
    pkt.reserved = PKT_MAKE_ROLE(g_state.role);

    /* Pack our testament */
    pkt.payload_len = pack_last_will(pkt.payload, death_reason);

    /* Send to multiple trusted neighbors */
    uint32_t sent_to[3] = {0, 0, 0};
    int sent_count = 0;

    for (int i = 0; i < 3 && sent_count < 3; i++) {
        uint32_t recipient = find_trusted_recipient(
            sent_count > 0 ? sent_to[sent_count - 1] : 0);

        if (recipient == 0) break;

        /* Avoid duplicates */
        int dup = 0;
        for (int j = 0; j < sent_count; j++) {
            if (sent_to[j] == recipient) { dup = 1; break; }
        }
        if (dup) continue;

        pkt.dest_id = (uint16_t)recipient;
        e1000_send(&pkt, sizeof(pkt));
        sent_to[sent_count++] = recipient;

        serial_puts("[BLACKBOX] Will sent to ");
        serial_put_hex(recipient);
        serial_puts("\n");
    }

    /* Also broadcast once for general awareness */
    pkt.dest_id = 0;
    pkt.ttl = 1;  /* Single hop broadcast */
    e1000_send(&pkt, sizeof(pkt));
}

void blackbox_process_last_will(struct nanos_pheromone* pkt) {
    if (pkt->payload_len < 17) return;

    uint32_t dead_node_id;
    uint8_t death_reason, uptime_hours, neighbor_count, role, distance;
    uint16_t bad_mac_count;

    unpack_last_will(pkt->payload, pkt->payload_len,
                     &dead_node_id, &death_reason, &uptime_hours,
                     &bad_mac_count, &neighbor_count, &role, &distance);

    /* Ignore our own will (shouldn't happen but be safe) */
    if (dead_node_id == g_state.node_id) return;

    /* Check if we already have this will */
    for (int i = 0; i < BLACKBOX_MAX_WILLS; i++) {
        if (g_state.blackbox.wills[i].node_id == dead_node_id) {
            /* Already recorded, update if newer info */
            return;
        }
    }

    /* Store in circular buffer */
    int slot = g_state.blackbox.will_index;
    g_state.blackbox.will_index =
        (g_state.blackbox.will_index + 1) % BLACKBOX_MAX_WILLS;

    if (g_state.blackbox.will_count < BLACKBOX_MAX_WILLS) {
        g_state.blackbox.will_count++;
    }

    /* Store the will */
    g_state.blackbox.wills[slot].node_id = dead_node_id;
    g_state.blackbox.wills[slot].death_tick = ticks;
    g_state.blackbox.wills[slot].death_reason = death_reason;
    g_state.blackbox.wills[slot].uptime_hours = uptime_hours;
    g_state.blackbox.wills[slot].bad_mac_count = bad_mac_count;
    g_state.blackbox.wills[slot].replay_count =
        pkt->payload[8] | (pkt->payload[9] << 8);
    g_state.blackbox.wills[slot].rate_limit_count =
        pkt->payload[10] | (pkt->payload[11] << 8);
    g_state.blackbox.wills[slot].blacklist_count = pkt->payload[12];
    g_state.blackbox.wills[slot].neighbor_count = neighbor_count;
    g_state.blackbox.wills[slot].role = role;
    g_state.blackbox.wills[slot].distance_to_queen = distance;

    /* Store events from will */
    uint8_t event_count = pkt->payload[16];
    if (event_count > BLACKBOX_MAX_EVENTS) event_count = BLACKBOX_MAX_EVENTS;
    g_state.blackbox.wills[slot].event_count = event_count;

    for (int i = 0; i < event_count; i++) {
        int base = 17 + (i * 7);
        if (base + 7 > pkt->payload_len) break;

        g_state.blackbox.wills[slot].events[i].tick =
            pkt->payload[base] | (pkt->payload[base + 1] << 8) |
            (pkt->payload[base + 2] << 16) | (pkt->payload[base + 3] << 24);
        g_state.blackbox.wills[slot].events[i].type = pkt->payload[base + 4];
        g_state.blackbox.wills[slot].events[i].source_node =
            pkt->payload[base + 5] | (pkt->payload[base + 6] << 8);
    }

    g_state.blackbox.wills_received++;

    serial_puts("[BLACKBOX] Received LAST WILL from ");
    serial_put_hex(dead_node_id);
    serial_puts(" reason=");
    serial_put_dec(death_reason);
    serial_puts(" uptime=");
    serial_put_dec(uptime_hours);
    serial_puts("h\n");

    /* Relay to other neighbors if critical (attack-related death) */
    if (death_reason == DEATH_ATTACK_DETECTED ||
        death_reason == DEATH_CORRUPTION ||
        bad_mac_count > 10) {

        if (pkt->ttl > 0) {
            pkt->ttl--;
            e1000_send(pkt, sizeof(*pkt));
            g_state.blackbox.wills_relayed++;
        }
    }
}

int blackbox_query_death(uint32_t node_id,
                         uint8_t *death_reason,
                         uint16_t *bad_mac_count,
                         uint8_t *uptime_hours) {
    for (int i = 0; i < BLACKBOX_MAX_WILLS; i++) {
        if (g_state.blackbox.wills[i].node_id == node_id) {
            if (death_reason) *death_reason = g_state.blackbox.wills[i].death_reason;
            if (bad_mac_count) *bad_mac_count = g_state.blackbox.wills[i].bad_mac_count;
            if (uptime_hours) *uptime_hours = g_state.blackbox.wills[i].uptime_hours;
            return 0;
        }
    }
    return -1;
}

uint8_t blackbox_get_will_count(void) {
    return g_state.blackbox.will_count;
}

void blackbox_relay_critical(void) {
    /* Relay any critical wills (attack deaths) that we haven't relayed recently */
    for (int i = 0; i < BLACKBOX_MAX_WILLS; i++) {
        if (g_state.blackbox.wills[i].node_id == 0) continue;

        uint8_t reason = g_state.blackbox.wills[i].death_reason;
        if (reason == DEATH_ATTACK_DETECTED || reason == DEATH_CORRUPTION) {
            /* This is critical - relay it */
            struct nanos_pheromone pkt;
            pkt.magic = NANOS_MAGIC;
            pkt.type = PHEROMONE_LAST_WILL;
            pkt.node_id = g_state.blackbox.wills[i].node_id;
            pkt.ttl = 1;
            pkt.dest_id = 0;  /* Broadcast */

            /* Simplified relay - just essential info */
            pkt.payload[0] = (g_state.blackbox.wills[i].node_id >> 0) & 0xFF;
            pkt.payload[1] = (g_state.blackbox.wills[i].node_id >> 8) & 0xFF;
            pkt.payload[2] = (g_state.blackbox.wills[i].node_id >> 16) & 0xFF;
            pkt.payload[3] = (g_state.blackbox.wills[i].node_id >> 24) & 0xFF;
            pkt.payload[4] = reason;
            pkt.payload[5] = g_state.blackbox.wills[i].uptime_hours;
            pkt.payload[6] = g_state.blackbox.wills[i].bad_mac_count & 0xFF;
            pkt.payload[7] = (g_state.blackbox.wills[i].bad_mac_count >> 8) & 0xFF;
            pkt.payload_len = 17;  /* Minimum */

            e1000_send(&pkt, sizeof(pkt));
            g_state.blackbox.wills_relayed++;
        }
    }
}

void blackbox_print_summary(void) {
    serial_puts("\n=== DISTRIBUTED BLACK BOX SUMMARY ===\n");
    serial_puts("Wills stored: ");
    serial_put_dec(g_state.blackbox.will_count);
    serial_puts("/");
    serial_put_dec(BLACKBOX_MAX_WILLS);
    serial_puts("\n");
    serial_puts("Total received: ");
    serial_put_dec(g_state.blackbox.wills_received);
    serial_puts(", relayed: ");
    serial_put_dec(g_state.blackbox.wills_relayed);
    serial_puts("\n\n");

    for (int i = 0; i < BLACKBOX_MAX_WILLS; i++) {
        if (g_state.blackbox.wills[i].node_id == 0) continue;

        serial_puts("Node ");
        serial_put_hex(g_state.blackbox.wills[i].node_id);
        serial_puts(": ");

        switch (g_state.blackbox.wills[i].death_reason) {
            case DEATH_NATURAL: serial_puts("NATURAL"); break;
            case DEATH_HEAP_EXHAUSTED: serial_puts("HEAP_EXHAUSTED"); break;
            case DEATH_CORRUPTION: serial_puts("CORRUPTION"); break;
            case DEATH_ATTACK_DETECTED: serial_puts("ATTACK"); break;
            case DEATH_QUEEN_ORDER: serial_puts("QUEEN_ORDER"); break;
            case DEATH_REPLACED: serial_puts("REPLACED"); break;
            case DEATH_ISOLATION: serial_puts("ISOLATION"); break;
            default: serial_puts("UNKNOWN"); break;
        }

        serial_puts(", lived ");
        serial_put_dec(g_state.blackbox.wills[i].uptime_hours);
        serial_puts("h, bad_mac=");
        serial_put_dec(g_state.blackbox.wills[i].bad_mac_count);
        serial_puts("\n");
    }

    serial_puts("=====================================\n\n");
}
