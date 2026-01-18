/*
 * NanOS Portable Hardware Abstraction Layer
 * Platform-independent interface for all HAL implementations
 *
 * Each platform (x86, ESP32, RP2040, etc.) must implement these functions
 */
#ifndef HAL_PORTABLE_H
#define HAL_PORTABLE_H

#include "nanos_config.h"
#include <stdint.h>
#include <stddef.h>

/* Boolean type for platforms without stdbool */
#ifndef __cplusplus
#ifndef bool
typedef uint8_t bool;
#define true  1
#define false 0
#endif
#endif

/* ==========================================================================
 * Core System Functions (REQUIRED)
 * ========================================================================== */

/* Initialize hardware - called once at startup */
void hal_init(void);

/* Get current tick count (milliseconds since boot) */
uint32_t hal_get_ticks(void);

/* Delay for specified milliseconds */
void hal_delay_ms(uint32_t ms);

/* Generate random number */
uint32_t hal_random(void);

/* Seed random number generator */
void hal_random_seed(uint32_t seed);

/* Critical section - disable/enable interrupts */
void hal_critical_enter(void);
void hal_critical_exit(void);

/* ==========================================================================
 * Console Output (REQUIRED - at least one)
 * ========================================================================== */

/* Print string to console */
void hal_print(const char* str);

/* Print hexadecimal number */
void hal_print_hex(uint32_t value);

/* Print decimal number */
void hal_print_dec(uint32_t value);

/* Set console color (if supported, otherwise no-op) */
void hal_set_color(uint8_t color);

/* ==========================================================================
 * Network Functions (REQUIRED)
 * ========================================================================== */

/* Initialize network hardware */
void hal_net_init(void);

/* Send packet (broadcast) */
void hal_net_send(const void* data, uint16_t len);

/* Check if packet available */
bool hal_net_available(void);

/* Receive packet - returns bytes received, 0 if none */
uint16_t hal_net_recv(void* buffer, uint16_t max_len);

/* Get this node's MAC/address (6 bytes for compatibility) */
void hal_net_get_addr(uint8_t* addr);

/* ==========================================================================
 * Storage Functions (OPTIONAL - for persistence)
 * ========================================================================== */

#if defined(NANOS_HAS_NVS) || defined(NANOS_HAS_FLASH)

/* Initialize persistent storage */
void hal_storage_init(void);

/* Read blob from storage - returns bytes read */
uint16_t hal_storage_read(const char* key, void* data, uint16_t max_len);

/* Write blob to storage - returns 0 on success */
int hal_storage_write(const char* key, const void* data, uint16_t len);

/* Erase key from storage */
void hal_storage_erase(const char* key);

#endif

/* ==========================================================================
 * Power Management (OPTIONAL - for battery devices)
 * ========================================================================== */

#ifdef NANOS_DEEP_SLEEP

/* Enter light sleep - wake on timer or interrupt */
void hal_sleep_light(uint32_t ms);

/* Enter deep sleep - wake on timer or external event */
void hal_sleep_deep(uint32_t ms);

/* Get battery level (0-100%) */
uint8_t hal_battery_level(void);

/* Check if running on battery */
bool hal_on_battery(void);

#endif

/* ==========================================================================
 * GPIO Functions (OPTIONAL - for sensors/actuators)
 * ========================================================================== */

#ifdef NANOS_HAS_GPIO

typedef enum {
    GPIO_INPUT,
    GPIO_OUTPUT,
    GPIO_INPUT_PULLUP,
    GPIO_INPUT_PULLDOWN
} gpio_mode_t;

void hal_gpio_mode(uint8_t pin, gpio_mode_t mode);
void hal_gpio_write(uint8_t pin, bool value);
bool hal_gpio_read(uint8_t pin);

#endif

/* ==========================================================================
 * I2C Functions (OPTIONAL - for sensors)
 * ========================================================================== */

#ifdef NANOS_HAS_I2C

void hal_i2c_init(uint8_t sda, uint8_t scl, uint32_t freq);
int hal_i2c_write(uint8_t addr, const uint8_t* data, uint16_t len);
int hal_i2c_read(uint8_t addr, uint8_t* data, uint16_t len);
int hal_i2c_write_reg(uint8_t addr, uint8_t reg, uint8_t value);
uint8_t hal_i2c_read_reg(uint8_t addr, uint8_t reg);

#endif

/* ==========================================================================
 * SPI Functions (OPTIONAL - for radio modules)
 * ========================================================================== */

#ifdef NANOS_HAS_SPI

void hal_spi_init(uint8_t mosi, uint8_t miso, uint8_t sck, uint32_t freq);
uint8_t hal_spi_transfer(uint8_t data);
void hal_spi_transfer_buf(const uint8_t* tx, uint8_t* rx, uint16_t len);
void hal_spi_cs(uint8_t pin, bool active);

#endif

/* ==========================================================================
 * ADC Functions (OPTIONAL - for analog sensors)
 * ========================================================================== */

#ifdef NANOS_HAS_ADC

void hal_adc_init(void);
uint16_t hal_adc_read(uint8_t channel);  /* Returns 12-bit value */
uint16_t hal_adc_read_mv(uint8_t channel);  /* Returns millivolts */

#endif

/* ==========================================================================
 * PWM Functions (OPTIONAL - for motors/LEDs)
 * ========================================================================== */

#ifdef NANOS_HAS_PWM

void hal_pwm_init(uint8_t pin, uint32_t freq);
void hal_pwm_duty(uint8_t pin, uint8_t duty);  /* 0-255 */
void hal_pwm_stop(uint8_t pin);

#endif

/* ==========================================================================
 * LED Indicator (OPTIONAL - for status)
 * ========================================================================== */

#ifdef NANOS_HAS_LED

void hal_led_init(void);
void hal_led_set(uint8_t led, bool on);
void hal_led_toggle(uint8_t led);
void hal_led_blink(uint8_t led, uint16_t on_ms, uint16_t off_ms);

/* Standard LED meanings */
#define LED_STATUS      0   /* General status */
#define LED_NETWORK     1   /* Network activity */
#define LED_ERROR       2   /* Error indicator */

#endif

/* ==========================================================================
 * Watchdog Timer (OPTIONAL - for reliability)
 * ========================================================================== */

#ifdef NANOS_HAS_WATCHDOG

void hal_watchdog_init(uint32_t timeout_ms);
void hal_watchdog_feed(void);
void hal_watchdog_disable(void);

#endif

/* ==========================================================================
 * System Functions
 * ========================================================================== */

/* Reboot the system */
void hal_reboot(void);

/* Panic - unrecoverable error */
void hal_panic(const char* msg);

/* Get unique chip ID (for node ID generation) */
uint32_t hal_get_chip_id(void);

/* Get free heap memory */
uint32_t hal_get_free_heap(void);

/* ==========================================================================
 * Platform-Specific Includes
 * ========================================================================== */

#if defined(NANOS_PLATFORM_X86)
/* x86 uses existing hal.h */
#include "hal.h"

#elif defined(NANOS_PLATFORM_ESP32)
#include "hal_esp32.h"

#elif defined(NANOS_PLATFORM_RP2040)
#include "hal_rp2040.h"

#elif defined(NANOS_PLATFORM_STM32)
#include "hal_stm32.h"

#elif defined(NANOS_PLATFORM_NRF52)
#include "hal_nrf52.h"

#endif

#endif /* HAL_PORTABLE_H */
