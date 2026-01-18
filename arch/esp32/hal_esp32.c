/*
 * NanOS ESP32 Hardware Abstraction Layer
 * Implementation using ESP-IDF and ESP-NOW
 */
#ifdef NANOS_PLATFORM_ESP32

#include "nanos_config.h"
#include "hal_portable.h"
#include "hal_esp32.h"
#include <string.h>

/* ESP-IDF includes */
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

/* ==========================================================================
 * Global Variables
 * ========================================================================== */

static uint8_t esp32_mac[6];
static SemaphoreHandle_t critical_mutex = NULL;
static nvs_handle_t nvs_handle;

/* RX queue for incoming packets */
#define RX_QUEUE_SIZE   16
QueueHandle_t nanos_rx_queue = NULL;

/* Packet buffer for RX queue */
typedef struct {
    uint8_t data[NANOS_PKT_TOTAL_SIZE];
    uint16_t len;
    uint8_t src_mac[6];
} rx_packet_t;

/* Task handles */
TaskHandle_t nanos_main_task = NULL;
TaskHandle_t nanos_net_task = NULL;

/* ==========================================================================
 * ESP-NOW Callbacks
 * ========================================================================== */

static void espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status) {
    /* Send complete - could track statistics here */
    (void)mac_addr;
    (void)status;
}

static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
    if (nanos_rx_queue == NULL || len <= 0 || len > NANOS_PKT_TOTAL_SIZE) {
        return;
    }

    rx_packet_t pkt;
    memcpy(pkt.data, data, len);
    pkt.len = (uint16_t)len;
    memcpy(pkt.src_mac, recv_info->src_addr, 6);

    /* Non-blocking queue send */
    xQueueSendFromISR(nanos_rx_queue, &pkt, NULL);
}

/* ==========================================================================
 * Core System Functions
 * ========================================================================== */

void hal_init(void) {
    /* Initialize NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* Open NVS namespace */
    nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);

    /* Create mutex for critical sections */
    critical_mutex = xSemaphoreCreateMutex();

    /* Create RX queue */
    nanos_rx_queue = xQueueCreate(RX_QUEUE_SIZE, sizeof(rx_packet_t));

    /* Initialize WiFi in station mode (required for ESP-NOW) */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    /* Get MAC address */
    esp_wifi_get_mac(WIFI_IF_STA, esp32_mac);

    /* Set channel for ESP-NOW */
    esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);

    /* Initialize LED */
#ifdef NANOS_HAS_LED
    gpio_set_direction(ESP32_LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(ESP32_LED_PIN, 0);
#endif

    hal_print("[HAL] ESP32 initialized\n");
}

uint32_t hal_get_ticks(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);  /* Convert us to ms */
}

void hal_delay_ms(uint32_t ms) {
    vTaskDelay(pdMS_TO_TICKS(ms));
}

uint32_t hal_random(void) {
    return esp_random();
}

void hal_random_seed(uint32_t seed) {
    /* ESP32 has hardware RNG, seed is ignored */
    (void)seed;
}

void hal_critical_enter(void) {
    if (critical_mutex) {
        xSemaphoreTake(critical_mutex, portMAX_DELAY);
    }
}

void hal_critical_exit(void) {
    if (critical_mutex) {
        xSemaphoreGive(critical_mutex);
    }
}

/* ==========================================================================
 * Console Output
 * ========================================================================== */

void hal_print(const char* str) {
    printf("%s", str);
}

void hal_print_hex(uint32_t value) {
    printf("%08X", (unsigned int)value);
}

void hal_print_dec(uint32_t value) {
    printf("%u", (unsigned int)value);
}

void hal_set_color(uint8_t color) {
    /* ANSI color codes for terminal */
    static const char* colors[] = {
        "\033[30m", /* 0: Black */
        "\033[34m", /* 1: Blue */
        "\033[32m", /* 2: Green */
        "\033[36m", /* 3: Cyan */
        "\033[31m", /* 4: Red */
        "\033[35m", /* 5: Magenta */
        "\033[33m", /* 6: Brown/Yellow */
        "\033[37m", /* 7: Light Gray */
        "\033[90m", /* 8: Dark Gray */
        "\033[94m", /* 9: Light Blue */
        "\033[92m", /* A: Light Green */
        "\033[96m", /* B: Light Cyan */
        "\033[91m", /* C: Light Red */
        "\033[95m", /* D: Light Magenta */
        "\033[93m", /* E: Yellow */
        "\033[97m"  /* F: White */
    };

    if (color < 16) {
        printf("%s", colors[color]);
    }
}

/* ==========================================================================
 * Network Functions (ESP-NOW)
 * ========================================================================== */

void hal_net_init(void) {
    /* Initialize ESP-NOW */
    esp_now_init();

    /* Register callbacks */
    esp_now_register_send_cb(espnow_send_cb);
    esp_now_register_recv_cb(espnow_recv_cb);

    /* Add broadcast peer */
    esp_now_peer_info_t broadcast_peer = {
        .channel = ESPNOW_CHANNEL,
        .ifidx = WIFI_IF_STA,
        .encrypt = false,
    };
    memset(broadcast_peer.peer_addr, 0xFF, 6);  /* Broadcast MAC */
    esp_now_add_peer(&broadcast_peer);

    hal_print("[NET] ESP-NOW initialized on channel ");
    hal_print_dec(ESPNOW_CHANNEL);
    hal_print("\n");
}

void hal_net_send(const void* data, uint16_t len) {
    /* Broadcast to all peers */
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    esp_now_send(broadcast_mac, data, len);
}

bool hal_net_available(void) {
    return (nanos_rx_queue != NULL && uxQueueMessagesWaiting(nanos_rx_queue) > 0);
}

uint16_t hal_net_recv(void* buffer, uint16_t max_len) {
    if (nanos_rx_queue == NULL) {
        return 0;
    }

    rx_packet_t pkt;
    if (xQueueReceive(nanos_rx_queue, &pkt, 0) == pdTRUE) {
        uint16_t copy_len = (pkt.len < max_len) ? pkt.len : max_len;
        memcpy(buffer, pkt.data, copy_len);
        return copy_len;
    }

    return 0;
}

void hal_net_get_addr(uint8_t* addr) {
    memcpy(addr, esp32_mac, 6);
}

/* ==========================================================================
 * Storage Functions (NVS)
 * ========================================================================== */

void hal_storage_init(void) {
    /* Already initialized in hal_init() */
}

uint16_t hal_storage_read(const char* key, void* data, uint16_t max_len) {
    size_t len = max_len;
    esp_err_t err = nvs_get_blob(nvs_handle, key, data, &len);
    return (err == ESP_OK) ? (uint16_t)len : 0;
}

int hal_storage_write(const char* key, const void* data, uint16_t len) {
    esp_err_t err = nvs_set_blob(nvs_handle, key, data, len);
    if (err == ESP_OK) {
        nvs_commit(nvs_handle);
    }
    return (err == ESP_OK) ? 0 : -1;
}

void hal_storage_erase(const char* key) {
    nvs_erase_key(nvs_handle, key);
    nvs_commit(nvs_handle);
}

/* ==========================================================================
 * Power Management
 * ========================================================================== */

#ifdef NANOS_DEEP_SLEEP

void hal_sleep_light(uint32_t ms) {
    /* Light sleep - wakes on any interrupt */
    esp_sleep_enable_timer_wakeup(ms * 1000);
    esp_light_sleep_start();
}

void hal_sleep_deep(uint32_t ms) {
    /* Deep sleep - full power off, wake on timer */
    esp_sleep_enable_timer_wakeup(ms * 1000);
    esp_deep_sleep_start();
}

uint8_t hal_battery_level(void) {
    /* TODO: Read from ADC if battery monitoring circuit present */
    return 100;  /* Default: assume powered */
}

bool hal_on_battery(void) {
    /* TODO: Check USB power detection */
    return false;
}

#endif /* NANOS_DEEP_SLEEP */

/* ==========================================================================
 * GPIO Functions
 * ========================================================================== */

#ifdef NANOS_HAS_GPIO

void hal_gpio_mode(uint8_t pin, gpio_mode_t mode) {
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << pin),
        .mode = (mode == GPIO_OUTPUT) ? GPIO_MODE_OUTPUT : GPIO_MODE_INPUT,
        .pull_up_en = (mode == GPIO_INPUT_PULLUP) ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
        .pull_down_en = (mode == GPIO_INPUT_PULLDOWN) ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
}

void hal_gpio_write(uint8_t pin, bool value) {
    gpio_set_level(pin, value ? 1 : 0);
}

bool hal_gpio_read(uint8_t pin) {
    return gpio_get_level(pin) != 0;
}

#endif /* NANOS_HAS_GPIO */

/* ==========================================================================
 * LED Indicator
 * ========================================================================== */

#ifdef NANOS_HAS_LED

void hal_led_init(void) {
    gpio_set_direction(ESP32_LED_PIN, GPIO_MODE_OUTPUT);
}

void hal_led_set(uint8_t led, bool on) {
    if (led == LED_STATUS) {
        gpio_set_level(ESP32_LED_PIN, on ? 1 : 0);
    }
}

void hal_led_toggle(uint8_t led) {
    if (led == LED_STATUS) {
        int level = gpio_get_level(ESP32_LED_PIN);
        gpio_set_level(ESP32_LED_PIN, level ? 0 : 1);
    }
}

void hal_led_blink(uint8_t led, uint16_t on_ms, uint16_t off_ms) {
    hal_led_set(led, true);
    hal_delay_ms(on_ms);
    hal_led_set(led, false);
    hal_delay_ms(off_ms);
}

#endif /* NANOS_HAS_LED */

/* ==========================================================================
 * System Functions
 * ========================================================================== */

void hal_reboot(void) {
    esp_restart();
}

void hal_panic(const char* msg) {
    hal_set_color(0x0C);  /* Red */
    hal_print("\n!!! PANIC: ");
    hal_print(msg);
    hal_print(" !!!\n");

    /* Blink LED rapidly */
#ifdef NANOS_HAS_LED
    for (int i = 0; i < 10; i++) {
        hal_led_toggle(LED_STATUS);
        hal_delay_ms(100);
    }
#endif

    esp_restart();
}

uint32_t hal_get_chip_id(void) {
    /* Use last 4 bytes of MAC as unique ID */
    return (esp32_mac[2] << 24) | (esp32_mac[3] << 16) |
           (esp32_mac[4] << 8) | esp32_mac[5];
}

uint32_t hal_get_free_heap(void) {
    return esp_get_free_heap_size();
}

/* ==========================================================================
 * ESP32-Specific Functions
 * ========================================================================== */

void esp32_espnow_add_peer(const uint8_t* mac) {
    esp_now_peer_info_t peer = {
        .channel = ESPNOW_CHANNEL,
        .ifidx = WIFI_IF_STA,
        .encrypt = false,
    };
    memcpy(peer.peer_addr, mac, 6);
    esp_now_add_peer(&peer);
}

void esp32_espnow_remove_peer(const uint8_t* mac) {
    esp_now_del_peer(mac);
}

bool esp32_espnow_is_peer(const uint8_t* mac) {
    return esp_now_is_peer_exist(mac);
}

void esp32_deep_sleep_timer(uint32_t seconds) {
    esp_sleep_enable_timer_wakeup(seconds * 1000000ULL);
    esp_deep_sleep_start();
}

void esp32_deep_sleep_gpio(uint8_t pin, bool level) {
    esp_sleep_enable_ext0_wakeup(pin, level ? 1 : 0);
    esp_deep_sleep_start();
}

int8_t esp32_internal_temp(void) {
    /* Note: ESP32 internal temp sensor has limited accuracy */
    /* Returns approximate die temperature in Celsius */
    return 25;  /* TODO: Implement with temp sensor API */
}

#endif /* NANOS_PLATFORM_ESP32 */
