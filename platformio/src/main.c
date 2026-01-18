/*
 * NanOS ESP32 - PlatformIO Entry Point
 *
 * Build:   pio run
 * Upload:  pio run -t upload
 * Monitor: pio device monitor
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define LED_PIN             2       /* Built-in LED */
#define ESPNOW_CHANNEL      1
#define TICK_INTERVAL_MS    10
#define HEARTBEAT_MS        1000
#define MAX_NEIGHBORS       8
#define GOSSIP_CACHE_SIZE   32

/* Packet magic */
#define NANOS_MAGIC         0xAA
#define PKT_SIZE            24

/* Pheromone types */
#define PHEROMONE_HEARTBEAT 0x01
#define PHEROMONE_DATA      0x02
#define PHEROMONE_ALARM     0x03

/* Roles */
#define ROLE_WORKER         0
#define ROLE_EXPLORER       1
#define ROLE_SENTINEL       2
#define ROLE_QUEEN          3

static const char* TAG = "NanOS";

/* ==========================================================================
 * Compact Packet Structure (24 bytes)
 * ========================================================================== */

typedef struct __attribute__((packed)) {
    uint8_t  magic;         /* 0xAA */
    uint16_t node_id;       /* Truncated ID */
    uint8_t  type;          /* Pheromone type */
    uint8_t  ttl_flags;     /* TTL(4) + flags(4) */
    uint8_t  seq;           /* Sequence */
    uint16_t dest_id;       /* Destination */
    uint8_t  dist_hop;      /* distance(4) + hop(4) */
    uint8_t  payload[8];    /* Compact payload */
    uint8_t  hmac[4];       /* Truncated HMAC */
    uint8_t  reserved[3];
} nanos_packet_t;

/* ==========================================================================
 * State
 * ========================================================================== */

static struct {
    uint32_t node_id;
    uint8_t  role;
    uint8_t  mac[6];

    uint32_t packets_rx;
    uint32_t packets_tx;
    uint16_t seq_counter;

    uint32_t boot_time;
    uint32_t last_heartbeat;

    uint16_t known_queen_id;
    uint8_t  distance_to_queen;
    uint32_t last_queen_seen;

    struct {
        uint16_t node_id;
        uint8_t  role;
        uint32_t last_seen;
    } neighbors[MAX_NEIGHBORS];
    uint8_t neighbor_count;

    uint32_t gossip_cache[GOSSIP_CACHE_SIZE];
    uint8_t  gossip_idx;
} state;

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static const char* role_name(uint8_t role) {
    switch (role) {
        case ROLE_WORKER:   return "WORKER";
        case ROLE_EXPLORER: return "EXPLORER";
        case ROLE_SENTINEL: return "SENTINEL";
        case ROLE_QUEEN:    return "QUEEN";
        default:            return "?";
    }
}

static uint32_t get_ticks(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static uint32_t packet_hash(const nanos_packet_t* pkt) {
    uint32_t hash = 0x811c9dc5;
    const uint8_t* data = (const uint8_t*)pkt;
    for (int i = 0; i < PKT_SIZE; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

static int is_duplicate(const nanos_packet_t* pkt) {
    uint32_t hash = packet_hash(pkt);
    for (int i = 0; i < GOSSIP_CACHE_SIZE; i++) {
        if (state.gossip_cache[i] == hash) return 1;
    }
    state.gossip_cache[state.gossip_idx] = hash;
    state.gossip_idx = (state.gossip_idx + 1) % GOSSIP_CACHE_SIZE;
    return 0;
}

/* ==========================================================================
 * ESP-NOW Callbacks
 * ========================================================================== */

static QueueHandle_t rx_queue = NULL;

static void espnow_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (rx_queue && len == PKT_SIZE) {
        nanos_packet_t pkt;
        memcpy(&pkt, data, PKT_SIZE);
        xQueueSendFromISR(rx_queue, &pkt, NULL);
    }
}

static void espnow_send_cb(const uint8_t *mac, esp_now_send_status_t status) {
    (void)mac;
    (void)status;
}

/* ==========================================================================
 * Network
 * ========================================================================== */

static void net_init(void) {
    /* Init WiFi in STA mode (required for ESP-NOW) */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);

    /* Get MAC */
    esp_wifi_get_mac(WIFI_IF_STA, state.mac);

    /* Init ESP-NOW */
    esp_now_init();
    esp_now_register_recv_cb(espnow_recv_cb);
    esp_now_register_send_cb(espnow_send_cb);

    /* Add broadcast peer */
    esp_now_peer_info_t peer = {
        .channel = ESPNOW_CHANNEL,
        .ifidx = WIFI_IF_STA,
        .encrypt = false,
    };
    memset(peer.peer_addr, 0xFF, 6);
    esp_now_add_peer(&peer);

    ESP_LOGI(TAG, "ESP-NOW initialized on channel %d", ESPNOW_CHANNEL);
}

static void net_send(const nanos_packet_t* pkt) {
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    esp_now_send(broadcast, (uint8_t*)pkt, PKT_SIZE);
    state.packets_tx++;
}

/* ==========================================================================
 * Heartbeat
 * ========================================================================== */

static void send_heartbeat(void) {
    nanos_packet_t pkt = {0};
    pkt.magic = NANOS_MAGIC;
    pkt.node_id = (uint16_t)(state.node_id & 0xFFFF);
    pkt.type = PHEROMONE_HEARTBEAT;
    pkt.ttl_flags = (15 << 4) | 0;  /* TTL=15, flags=0 */
    pkt.seq = (uint8_t)(state.seq_counter++ & 0xFF);
    pkt.dist_hop = (state.distance_to_queen << 4) | 0;

    /* Payload: role, neighbors, uptime */
    pkt.payload[0] = state.role;
    pkt.payload[1] = state.neighbor_count;
    uint16_t uptime_min = (get_ticks() - state.boot_time) / 60000;
    pkt.payload[2] = uptime_min & 0xFF;
    pkt.payload[3] = (uptime_min >> 8) & 0xFF;

    net_send(&pkt);
    state.last_heartbeat = get_ticks();

    /* Toggle LED */
    static int led_state = 0;
    gpio_set_level(LED_PIN, led_state);
    led_state = !led_state;
}

/* ==========================================================================
 * Packet Processing
 * ========================================================================== */

static void update_neighbor(uint16_t node_id, uint8_t role) {
    uint32_t now = get_ticks();

    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (state.neighbors[i].node_id == node_id) {
            state.neighbors[i].last_seen = now;
            return;
        }
    }

    /* Find empty slot */
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (state.neighbors[i].node_id == 0 ||
            (now - state.neighbors[i].last_seen) > 30000) {
            state.neighbors[i].node_id = node_id;
            state.neighbors[i].role = role;
            state.neighbors[i].last_seen = now;

            /* Recount */
            state.neighbor_count = 0;
            for (int j = 0; j < MAX_NEIGHBORS; j++) {
                if (state.neighbors[j].node_id != 0 &&
                    (now - state.neighbors[j].last_seen) < 10000) {
                    state.neighbor_count++;
                }
            }
            return;
        }
    }
}

static void process_packet(nanos_packet_t* pkt) {
    if (pkt->magic != NANOS_MAGIC) return;
    if (pkt->node_id == (uint16_t)(state.node_id & 0xFFFF)) return;
    if (is_duplicate(pkt)) return;

    state.packets_rx++;

    switch (pkt->type) {
        case PHEROMONE_HEARTBEAT: {
            uint8_t role = pkt->payload[0];
            update_neighbor(pkt->node_id, role);

            if (role == ROLE_QUEEN) {
                uint8_t dist = (pkt->dist_hop >> 4) & 0x0F;
                if (dist < state.distance_to_queen || state.known_queen_id == 0) {
                    state.known_queen_id = pkt->node_id;
                    state.distance_to_queen = dist + 1;
                    state.last_queen_seen = get_ticks();
                }
            }
            break;
        }

        case PHEROMONE_ALARM:
            ESP_LOGW(TAG, "ALARM from %04X!", pkt->node_id);
            /* Blink LED rapidly */
            for (int i = 0; i < 5; i++) {
                gpio_set_level(LED_PIN, 1);
                vTaskDelay(pdMS_TO_TICKS(50));
                gpio_set_level(LED_PIN, 0);
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            break;

        case PHEROMONE_DATA:
            ESP_LOGI(TAG, "DATA from %04X: %.*s", pkt->node_id, 8, pkt->payload);
            break;
    }
}

/* ==========================================================================
 * Main Task
 * ========================================================================== */

static void nanos_task(void* arg) {
    nanos_packet_t pkt;

    while (1) {
        /* Process received packets */
        while (xQueueReceive(rx_queue, &pkt, 0) == pdTRUE) {
            process_packet(&pkt);
        }

        /* Periodic heartbeat */
        if ((get_ticks() - state.last_heartbeat) >= HEARTBEAT_MS) {
            send_heartbeat();

            /* Status every 10 heartbeats */
            static int status_counter = 0;
            if (++status_counter >= 10) {
                status_counter = 0;
                ESP_LOGI(TAG, "Node %08X [%s] neighbors=%d rx=%lu tx=%lu",
                         (unsigned)state.node_id,
                         role_name(state.role),
                         state.neighbor_count,
                         state.packets_rx,
                         state.packets_tx);
            }
        }

        /* Queen timeout check */
        if (state.role != ROLE_QUEEN &&
            state.known_queen_id != 0 &&
            (get_ticks() - state.last_queen_seen) > 30000) {
            ESP_LOGW(TAG, "Queen timeout - promoting to QUEEN");
            state.role = ROLE_QUEEN;
            state.distance_to_queen = 0;
        }

        vTaskDelay(pdMS_TO_TICKS(TICK_INTERVAL_MS));
    }
}

/* ==========================================================================
 * App Main
 * ========================================================================== */

void app_main(void) {
    /* Init NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* Init LED */
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 1);

    /* Init state */
    memset(&state, 0, sizeof(state));
    state.node_id = esp_random();
    state.role = (state.node_id & 0x03);  /* Role from random bits */
    state.boot_time = get_ticks();
    state.distance_to_queen = (state.role == ROLE_QUEEN) ? 0 : 15;

    /* Create RX queue */
    rx_queue = xQueueCreate(16, sizeof(nanos_packet_t));

    /* Init network */
    net_init();

    /* Banner */
    printf("\n");
    printf("========================================\n");
    printf("  NanOS ESP32 - The Swarm Awakens\n");
    printf("========================================\n");
    printf("Node ID:   %08X\n", (unsigned)state.node_id);
    printf("Role:      %s\n", role_name(state.role));
    printf("MAC:       %02X:%02X:%02X:%02X:%02X:%02X\n",
           state.mac[0], state.mac[1], state.mac[2],
           state.mac[3], state.mac[4], state.mac[5]);
    printf("Free heap: %lu bytes\n", (unsigned long)esp_get_free_heap_size());
    printf("========================================\n\n");

    /* Start main task */
    xTaskCreate(nanos_task, "nanos", 4096, NULL, 5, NULL);
}
