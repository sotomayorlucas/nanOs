/*
 * NanOS Covert Channels - "El Susurro en la Oscuridad" (v0.7)
 *
 * Implements physical side-channel communication for air-gapped networks:
 * - Optical: LED modulation → Light sensor
 * - Acoustic: Buzzer/PWM → Microphone/ADC
 *
 * "When radio is silent, light and sound still speak."
 */
#ifndef NANOS_COVERT_H
#define NANOS_COVERT_H

#include <nanos.h>

/* ==========================================================================
 * Channel Types
 * ========================================================================== */

#define COVERT_CHANNEL_OPTICAL      0x01    /* LED → Photoresistor */
#define COVERT_CHANNEL_ACOUSTIC     0x02    /* Buzzer → Microphone */

/* ==========================================================================
 * Modulation Modes
 * ========================================================================== */

#define COVERT_MOD_OOK              0x01    /* On-Off Keying */
#define COVERT_MOD_FSK              0x02    /* Frequency Shift Keying */
#define COVERT_MOD_MANCHESTER       0x03    /* Manchester Encoding (self-clocking) */

/* ==========================================================================
 * Configuration
 * ========================================================================== */

/* Optical channel defaults */
#define COVERT_OPTICAL_LED_PIN      2       /* ESP32 built-in LED */
#define COVERT_OPTICAL_ADC_CHANNEL  0       /* Light sensor ADC channel */
#define COVERT_OPTICAL_BIT_TIME_MS  10      /* 100 bps */
#define COVERT_OPTICAL_THRESHOLD    512     /* ADC threshold for 1 vs 0 */

/* Acoustic channel defaults */
#define COVERT_ACOUSTIC_PWM_PIN     25      /* Buzzer PWM pin */
#define COVERT_ACOUSTIC_ADC_CHANNEL 1       /* Microphone ADC channel */
#define COVERT_ACOUSTIC_FREQ_0      1000    /* FSK frequency for 0 */
#define COVERT_ACOUSTIC_FREQ_1      2000    /* FSK frequency for 1 */
#define COVERT_ACOUSTIC_BIT_TIME_MS 5       /* 200 bps */

/* Frame structure */
#define COVERT_SYNC_PATTERN         0xAA    /* Sync byte */
#define COVERT_MAX_PAYLOAD          16      /* Max payload bytes */
#define COVERT_FRAME_OVERHEAD       4       /* sync + channel + len + crc */

/* Error codes */
#define COVERT_OK                   0
#define COVERT_ERR_TIMEOUT          -1
#define COVERT_ERR_CRC              -2
#define COVERT_ERR_NOSYNC           -3
#define COVERT_ERR_OVERFLOW         -4
#define COVERT_ERR_DISABLED         -5

/* ==========================================================================
 * Frame Structure
 * ========================================================================== */

struct covert_frame {
    uint8_t  sync;                  /* Sync pattern (0xAA) */
    uint8_t  channel_type;          /* COVERT_CHANNEL_* */
    uint8_t  payload_len;           /* Payload length (1-16) */
    uint8_t  payload[COVERT_MAX_PAYLOAD];
    uint8_t  crc8;                  /* CRC-8 checksum */
};

/* ==========================================================================
 * Channel Configuration
 * ========================================================================== */

struct covert_optical_config {
    uint8_t  led_pin;               /* GPIO for LED output */
    uint8_t  adc_channel;           /* ADC channel for light sensor */
    uint16_t bit_time_ms;           /* Time per bit in ms */
    uint16_t threshold;             /* ADC threshold for 1 vs 0 */
    uint8_t  modulation;            /* COVERT_MOD_* */
    uint8_t  enabled;
};

struct covert_acoustic_config {
    uint8_t  pwm_pin;               /* GPIO for buzzer PWM */
    uint8_t  adc_channel;           /* ADC channel for microphone */
    uint16_t freq_0;                /* FSK frequency for 0 */
    uint16_t freq_1;                /* FSK frequency for 1 */
    uint16_t bit_time_ms;           /* Time per bit in ms */
    uint8_t  modulation;            /* COVERT_MOD_* */
    uint8_t  enabled;
};

/* ==========================================================================
 * Channel State
 * ========================================================================== */

struct covert_state {
    /* Configuration */
    struct covert_optical_config optical;
    struct covert_acoustic_config acoustic;

    /* TX state */
    uint8_t  tx_active;
    uint8_t  tx_channel;
    uint16_t tx_bit_index;
    struct covert_frame tx_frame;

    /* RX state */
    uint8_t  rx_active;
    uint8_t  rx_channel;
    uint8_t  rx_synced;
    uint16_t rx_bit_index;
    struct covert_frame rx_frame;
    uint32_t rx_last_sample_tick;

    /* Manchester decoder state */
    uint8_t  manchester_last_bit;
    uint8_t  manchester_phase;

    /* Statistics */
    uint32_t tx_frames;
    uint32_t tx_bytes;
    uint32_t rx_frames;
    uint32_t rx_bytes;
    uint32_t rx_crc_errors;
    uint32_t rx_sync_lost;
};

/* ==========================================================================
 * Public API - Initialization
 * ========================================================================== */

/**
 * Initialize covert channel subsystem
 */
void covert_init(void);

/**
 * Configure optical channel
 */
void covert_optical_configure(const struct covert_optical_config *config);

/**
 * Configure acoustic channel
 */
void covert_acoustic_configure(const struct covert_acoustic_config *config);

/**
 * Enable/disable channel
 */
void covert_enable(uint8_t channel, bool enable);

/* ==========================================================================
 * Public API - Transmission
 * ========================================================================== */

/**
 * Initialize TX on specified channel
 * @param channel  COVERT_CHANNEL_OPTICAL or COVERT_CHANNEL_ACOUSTIC
 * @return 0 on success, negative on error
 */
int covert_tx_init(uint8_t channel);

/**
 * Send data over covert channel (blocking)
 * @param data  Data to send
 * @param len   Data length (1-16 bytes)
 * @return Bytes sent, or negative error code
 */
int covert_tx_send(const void *data, uint8_t len);

/**
 * Send data over covert channel (non-blocking)
 * Call covert_tx_tick() to drive transmission
 * @return 0 on success, negative on error
 */
int covert_tx_send_async(const void *data, uint8_t len);

/**
 * Check if TX is complete
 */
bool covert_tx_complete(void);

/**
 * TX tick - call periodically to drive async transmission
 */
void covert_tx_tick(void);

/* ==========================================================================
 * Public API - Reception
 * ========================================================================== */

/**
 * Initialize RX on specified channel
 * @param channel  COVERT_CHANNEL_OPTICAL or COVERT_CHANNEL_ACOUSTIC
 * @return 0 on success, negative on error
 */
int covert_rx_init(uint8_t channel);

/**
 * Receive data from covert channel (blocking)
 * @param buffer    Output buffer
 * @param max_len   Buffer size
 * @param timeout_ms  Timeout in milliseconds
 * @return Bytes received, or negative error code
 */
int covert_rx_receive(void *buffer, uint8_t max_len, uint32_t timeout_ms);

/**
 * RX tick - call periodically to sample and decode
 */
void covert_rx_tick(void);

/**
 * Check if RX has complete frame
 */
bool covert_rx_available(void);

/**
 * Read received frame (non-blocking)
 * @param buffer   Output buffer
 * @param max_len  Buffer size
 * @return Bytes copied, or negative if no frame
 */
int covert_rx_read(void *buffer, uint8_t max_len);

/* ==========================================================================
 * Public API - Manchester Encoding
 * ========================================================================== */

/**
 * Manchester encode a byte array
 * @param input    Input data
 * @param in_len   Input length
 * @param output   Output buffer (must be 2x input length)
 * @return Output length
 */
uint16_t covert_manchester_encode(const uint8_t *input, uint16_t in_len,
                                   uint8_t *output);

/**
 * Manchester decode a byte array
 * @param input    Input data (manchester encoded)
 * @param in_len   Input length
 * @param output   Output buffer
 * @return Output length, or negative on error
 */
int16_t covert_manchester_decode(const uint8_t *input, uint16_t in_len,
                                  uint8_t *output);

/* ==========================================================================
 * Public API - Low-Level
 * ========================================================================== */

/**
 * Send single bit over optical channel
 */
void covert_optical_tx_bit(uint8_t bit);

/**
 * Sample optical channel
 * @return ADC value
 */
uint16_t covert_optical_sample(void);

/**
 * Send single bit over acoustic channel
 */
void covert_acoustic_tx_bit(uint8_t bit);

/**
 * Sample acoustic channel
 * @return ADC value
 */
uint16_t covert_acoustic_sample(void);

/* ==========================================================================
 * Public API - Debug
 * ========================================================================== */

/**
 * Print covert channel status
 */
void covert_print_status(void);

/**
 * Get covert channel state (for inspection)
 */
struct covert_state* covert_get_state(void);

/* ==========================================================================
 * Internal - CRC8
 * ========================================================================== */

/**
 * Calculate CRC-8 (polynomial 0x07)
 */
uint8_t covert_crc8(const void *data, uint8_t len);

#endif /* NANOS_COVERT_H */
