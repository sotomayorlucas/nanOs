/*
 * NERT HAL Implementation for ESP32
 *
 * Uses WiFi broadcast or ESP-NOW for communication
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert.h"
#include <string.h>

#if defined(ESP_PLATFORM)

#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define NERT_ESP_USE_ESPNOW     1   /* Use ESP-NOW (1) or UDP broadcast (0) */
#define NERT_RX_QUEUE_SIZE      8
#define NERT_MAX_FRAME_SIZE     100 /* Compact mode */

/* ============================================================================
 * Local State
 * ============================================================================ */

static uint16_t local_node_id = 0;
static uint8_t local_mac[6];
static QueueHandle_t rx_queue = NULL;

/* RX queue entry */
struct rx_entry {
    uint8_t data[NERT_MAX_FRAME_SIZE];
    uint16_t len;
};

/* ESP-NOW broadcast address */
static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ============================================================================
 * ESP-NOW Callbacks
 * ============================================================================ */

#if NERT_ESP_USE_ESPNOW

static void espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status) {
    /* Send callback - can be used for statistics */
    (void)mac_addr;
    (void)status;
}

static void espnow_recv_cb(const esp_now_recv_info_t *recv_info,
                           const uint8_t *data, int len) {
    if (!rx_queue || len <= 0 || len > NERT_MAX_FRAME_SIZE) return;

    /* Skip packets from ourselves */
    if (memcmp(recv_info->src_addr, local_mac, 6) == 0) return;

    /* Check NERT magic byte */
    if (data[0] != 0x4E) return; /* Not NERT */

    struct rx_entry entry;
    memcpy(entry.data, data, len);
    entry.len = len;

    /* Non-blocking queue send */
    xQueueSendFromISR(rx_queue, &entry, NULL);
}

static int espnow_init(void) {
    esp_err_t ret;

    /* Initialize ESP-NOW */
    ret = esp_now_init();
    if (ret != ESP_OK) return -1;

    /* Register callbacks */
    esp_now_register_send_cb(espnow_send_cb);
    esp_now_register_recv_cb(espnow_recv_cb);

    /* Add broadcast peer */
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;

    ret = esp_now_add_peer(&peer);
    if (ret != ESP_OK) return -1;

    return 0;
}

#else /* UDP Broadcast */

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#define NERT_UDP_PORT       4E52    /* Port 20050 */

static int udp_socket = -1;

static int udp_init(void) {
    struct sockaddr_in addr;

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0) return -1;

    /* Enable broadcast */
    int broadcast = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    /* Non-blocking */
    int flags = fcntl(udp_socket, F_GETFL, 0);
    fcntl(udp_socket, F_SETFL, flags | O_NONBLOCK);

    /* Bind to receive */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NERT_UDP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(udp_socket);
        udp_socket = -1;
        return -1;
    }

    return 0;
}

#endif /* NERT_ESP_USE_ESPNOW */

/* ============================================================================
 * HAL Implementation
 * ============================================================================ */

int nert_hal_send(const void *data, uint16_t len) {
    if (len > NERT_MAX_FRAME_SIZE) return -1;

#if NERT_ESP_USE_ESPNOW
    esp_err_t ret = esp_now_send(BROADCAST_MAC, (const uint8_t*)data, len);
    return (ret == ESP_OK) ? 0 : -1;
#else
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(NERT_UDP_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    int sent = sendto(udp_socket, data, len, 0,
                      (struct sockaddr*)&dest, sizeof(dest));
    return (sent == len) ? 0 : -1;
#endif
}

int nert_hal_receive(void *buffer, uint16_t max_len) {
#if NERT_ESP_USE_ESPNOW
    if (!rx_queue) return 0;

    struct rx_entry entry;
    if (xQueueReceive(rx_queue, &entry, 0) != pdTRUE) {
        return 0;
    }

    uint16_t copy_len = (entry.len < max_len) ? entry.len : max_len;
    memcpy(buffer, entry.data, copy_len);
    return copy_len;
#else
    if (udp_socket < 0) return 0;

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    int received = recvfrom(udp_socket, buffer, max_len, 0,
                            (struct sockaddr*)&src, &src_len);

    if (received <= 0) return 0;

    /* Check NERT magic */
    uint8_t *data = (uint8_t*)buffer;
    if (data[0] != 0x4E) return 0;

    return received;
#endif
}

uint32_t nert_hal_get_ticks(void) {
    return (uint32_t)(esp_timer_get_time() / 1000); /* Convert us to ms */
}

uint32_t nert_hal_random(void) {
    return esp_random();
}

uint16_t nert_hal_get_node_id(void) {
    if (local_node_id == 0) {
        local_node_id = (local_mac[4] << 8) | local_mac[5];
        if (local_node_id == 0) {
            local_node_id = (uint16_t)esp_random();
        }
    }
    return local_node_id;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void nert_hal_init(void) {
    /* Get MAC address */
    esp_read_mac(local_mac, ESP_MAC_WIFI_STA);

    /* Create RX queue */
    rx_queue = xQueueCreate(NERT_RX_QUEUE_SIZE, sizeof(struct rx_entry));

#if NERT_ESP_USE_ESPNOW
    espnow_init();
#else
    udp_init();
#endif

    /* Pre-compute node ID */
    nert_hal_get_node_id();
}

/* ============================================================================
 * Power Management Hooks
 * ============================================================================ */

void nert_hal_enter_light_sleep(uint32_t duration_ms) {
    /* Enter light sleep for power saving */
    esp_sleep_enable_timer_wakeup(duration_ms * 1000);
    esp_light_sleep_start();
}

void nert_hal_set_tx_power(int8_t power_dbm) {
    /* Adjust TX power (-127 to 127 corresponds to -0.25 to 31.75 dBm) */
    esp_wifi_set_max_tx_power(power_dbm * 4);
}

#endif /* ESP_PLATFORM */
