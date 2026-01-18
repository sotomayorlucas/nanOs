/*
 * NanOS ESP32 HAL Header
 * Platform-specific definitions for ESP32
 */
#ifndef HAL_ESP32_H
#define HAL_ESP32_H

#ifdef NANOS_PLATFORM_ESP32

/* ESP-IDF includes */
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_sleep.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

/* ==========================================================================
 * ESP32-Specific Configuration
 * ========================================================================== */

/* GPIO Pins - default for ESP32 DevKit */
#define ESP32_LED_PIN           2       /* Built-in LED */
#define ESP32_BTN_PIN           0       /* Boot button */
#define ESP32_UART_TX           1
#define ESP32_UART_RX           3
#define ESP32_I2C_SDA           21
#define ESP32_I2C_SCL           22
#define ESP32_SPI_MOSI          23
#define ESP32_SPI_MISO          19
#define ESP32_SPI_SCK           18
#define ESP32_SPI_CS            5

/* LoRa pins (if using SX1276 module) */
#define ESP32_LORA_CS           18
#define ESP32_LORA_RST          14
#define ESP32_LORA_DIO0         26

/* ESP-NOW configuration */
#define ESPNOW_CHANNEL          1
#define ESPNOW_PMK              "nanos_swarm_key!"
#define ESPNOW_LMK              "nanos_local_key!"

/* NVS namespace for NanOS state */
#define NVS_NAMESPACE           "nanos"

/* ==========================================================================
 * ESP32-Specific Functions
 * ========================================================================== */

/* ESP-NOW peer management */
void esp32_espnow_add_peer(const uint8_t* mac);
void esp32_espnow_remove_peer(const uint8_t* mac);
bool esp32_espnow_is_peer(const uint8_t* mac);

/* WiFi station mode (for hybrid ESP-NOW + WiFi) */
void esp32_wifi_connect(const char* ssid, const char* password);
bool esp32_wifi_connected(void);
void esp32_wifi_disconnect(void);

/* OTA update support */
void esp32_ota_begin(const char* url);
bool esp32_ota_in_progress(void);

/* Deep sleep with wake sources */
void esp32_deep_sleep_timer(uint32_t seconds);
void esp32_deep_sleep_gpio(uint8_t pin, bool level);

/* Temperature sensor (internal) */
int8_t esp32_internal_temp(void);

/* ==========================================================================
 * Task Handles
 * ========================================================================== */

extern TaskHandle_t nanos_main_task;
extern TaskHandle_t nanos_net_task;
extern QueueHandle_t nanos_rx_queue;

#endif /* NANOS_PLATFORM_ESP32 */
#endif /* HAL_ESP32_H */
