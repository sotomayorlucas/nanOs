/*
 * Optical Covert Channel - "El Ojo que Todo lo Ve" (v0.7)
 *
 * Implements LED-to-Photoresistor communication:
 * TX: Modulate LED brightness/on-off state
 * RX: Sample light sensor ADC
 *
 * "In darkness, a single photon can carry secrets."
 */
#include <nanos.h>
#include <nanos/covert.h>
#include <nanos/serial.h>
#include <string.h>

/* External HAL functions */
extern void hal_gpio_write(uint8_t pin, bool value);
extern void hal_gpio_mode(uint8_t pin, uint8_t mode);
extern uint16_t hal_adc_read(uint8_t channel);
extern void hal_pwm_init(uint8_t pin, uint32_t freq);
extern void hal_pwm_duty(uint8_t pin, uint8_t duty);
extern void hal_delay_ms(uint32_t ms);
extern volatile uint32_t ticks;

/* GPIO modes */
#define GPIO_MODE_OUTPUT    0x01

/* Global covert state */
static struct covert_state g_covert;

/* ==========================================================================
 * CRC-8 Calculation (polynomial 0x07)
 * ========================================================================== */

static const uint8_t crc8_table[256] = {
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
    0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
    0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
    0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
    0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
    0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
    0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
    0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
    0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
    0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
    0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
    0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
};

uint8_t covert_crc8(const void *data, uint8_t len) {
    uint8_t crc = 0x00;
    const uint8_t *bytes = (const uint8_t *)data;

    for (uint8_t i = 0; i < len; i++) {
        crc = crc8_table[crc ^ bytes[i]];
    }

    return crc;
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

void covert_init(void) {
    memset(&g_covert, 0, sizeof(g_covert));

    /* Default optical config */
    g_covert.optical.led_pin = COVERT_OPTICAL_LED_PIN;
    g_covert.optical.adc_channel = COVERT_OPTICAL_ADC_CHANNEL;
    g_covert.optical.bit_time_ms = COVERT_OPTICAL_BIT_TIME_MS;
    g_covert.optical.threshold = COVERT_OPTICAL_THRESHOLD;
    g_covert.optical.modulation = COVERT_MOD_MANCHESTER;
    g_covert.optical.enabled = 0;

    /* Default acoustic config */
    g_covert.acoustic.pwm_pin = COVERT_ACOUSTIC_PWM_PIN;
    g_covert.acoustic.adc_channel = COVERT_ACOUSTIC_ADC_CHANNEL;
    g_covert.acoustic.freq_0 = COVERT_ACOUSTIC_FREQ_0;
    g_covert.acoustic.freq_1 = COVERT_ACOUSTIC_FREQ_1;
    g_covert.acoustic.bit_time_ms = COVERT_ACOUSTIC_BIT_TIME_MS;
    g_covert.acoustic.modulation = COVERT_MOD_FSK;
    g_covert.acoustic.enabled = 0;

    serial_puts("[COVERT] Initialized\n");
}

void covert_optical_configure(const struct covert_optical_config *config) {
    memcpy(&g_covert.optical, config, sizeof(struct covert_optical_config));
}

void covert_acoustic_configure(const struct covert_acoustic_config *config) {
    memcpy(&g_covert.acoustic, config, sizeof(struct covert_acoustic_config));
}

void covert_enable(uint8_t channel, bool enable) {
    if (channel == COVERT_CHANNEL_OPTICAL) {
        g_covert.optical.enabled = enable ? 1 : 0;
        if (enable) {
            hal_gpio_mode(g_covert.optical.led_pin, GPIO_MODE_OUTPUT);
            hal_gpio_write(g_covert.optical.led_pin, false);
        }
    } else if (channel == COVERT_CHANNEL_ACOUSTIC) {
        g_covert.acoustic.enabled = enable ? 1 : 0;
        if (enable) {
            hal_pwm_init(g_covert.acoustic.pwm_pin, 1000);
            hal_pwm_duty(g_covert.acoustic.pwm_pin, 0);
        }
    }
}

/* ==========================================================================
 * Low-Level Optical TX/RX
 * ========================================================================== */

void covert_optical_tx_bit(uint8_t bit) {
    if (g_covert.optical.modulation == COVERT_MOD_OOK) {
        /* On-Off Keying: 1=on, 0=off */
        hal_gpio_write(g_covert.optical.led_pin, bit ? true : false);
        hal_delay_ms(g_covert.optical.bit_time_ms);
    } else if (g_covert.optical.modulation == COVERT_MOD_MANCHESTER) {
        /* Manchester: 0=LOW→HIGH, 1=HIGH→LOW */
        if (bit) {
            hal_gpio_write(g_covert.optical.led_pin, true);
            hal_delay_ms(g_covert.optical.bit_time_ms / 2);
            hal_gpio_write(g_covert.optical.led_pin, false);
            hal_delay_ms(g_covert.optical.bit_time_ms / 2);
        } else {
            hal_gpio_write(g_covert.optical.led_pin, false);
            hal_delay_ms(g_covert.optical.bit_time_ms / 2);
            hal_gpio_write(g_covert.optical.led_pin, true);
            hal_delay_ms(g_covert.optical.bit_time_ms / 2);
        }
    }
}

uint16_t covert_optical_sample(void) {
    return hal_adc_read(g_covert.optical.adc_channel);
}

/* ==========================================================================
 * Low-Level Acoustic TX/RX
 * ========================================================================== */

void covert_acoustic_tx_bit(uint8_t bit) {
    if (g_covert.acoustic.modulation == COVERT_MOD_FSK) {
        /* FSK: different frequency for 0 and 1 */
        uint16_t freq = bit ? g_covert.acoustic.freq_1 : g_covert.acoustic.freq_0;
        hal_pwm_init(g_covert.acoustic.pwm_pin, freq);
        hal_pwm_duty(g_covert.acoustic.pwm_pin, 128);  /* 50% duty */
        hal_delay_ms(g_covert.acoustic.bit_time_ms);
        hal_pwm_duty(g_covert.acoustic.pwm_pin, 0);    /* Silent between bits */
    } else if (g_covert.acoustic.modulation == COVERT_MOD_OOK) {
        /* OOK: tone on/off */
        if (bit) {
            hal_pwm_init(g_covert.acoustic.pwm_pin, g_covert.acoustic.freq_1);
            hal_pwm_duty(g_covert.acoustic.pwm_pin, 128);
        } else {
            hal_pwm_duty(g_covert.acoustic.pwm_pin, 0);
        }
        hal_delay_ms(g_covert.acoustic.bit_time_ms);
    }
}

uint16_t covert_acoustic_sample(void) {
    return hal_adc_read(g_covert.acoustic.adc_channel);
}

/* ==========================================================================
 * Frame TX
 * ========================================================================== */

/**
 * Transmit a byte over the active channel
 */
static void tx_byte(uint8_t byte) {
    for (int bit = 7; bit >= 0; bit--) {
        uint8_t b = (byte >> bit) & 0x01;
        if (g_covert.tx_channel == COVERT_CHANNEL_OPTICAL) {
            covert_optical_tx_bit(b);
        } else {
            covert_acoustic_tx_bit(b);
        }
    }
}

int covert_tx_init(uint8_t channel) {
    if (channel == COVERT_CHANNEL_OPTICAL && !g_covert.optical.enabled) {
        return COVERT_ERR_DISABLED;
    }
    if (channel == COVERT_CHANNEL_ACOUSTIC && !g_covert.acoustic.enabled) {
        return COVERT_ERR_DISABLED;
    }

    g_covert.tx_channel = channel;
    g_covert.tx_active = 0;

    return COVERT_OK;
}

int covert_tx_send(const void *data, uint8_t len) {
    if (len == 0 || len > COVERT_MAX_PAYLOAD) {
        return COVERT_ERR_OVERFLOW;
    }

    /* Build frame */
    struct covert_frame *frame = &g_covert.tx_frame;
    frame->sync = COVERT_SYNC_PATTERN;
    frame->channel_type = g_covert.tx_channel;
    frame->payload_len = len;
    memcpy(frame->payload, data, len);
    frame->crc8 = covert_crc8(frame, 3 + len);

    g_covert.tx_active = 1;

    /* Transmit preamble (8 sync bytes) */
    for (int i = 0; i < 8; i++) {
        tx_byte(COVERT_SYNC_PATTERN);
    }

    /* Transmit header */
    tx_byte(frame->sync);
    tx_byte(frame->channel_type);
    tx_byte(frame->payload_len);

    /* Transmit payload */
    for (uint8_t i = 0; i < len; i++) {
        tx_byte(frame->payload[i]);
    }

    /* Transmit CRC */
    tx_byte(frame->crc8);

    /* Turn off LED/buzzer */
    if (g_covert.tx_channel == COVERT_CHANNEL_OPTICAL) {
        hal_gpio_write(g_covert.optical.led_pin, false);
    } else {
        hal_pwm_duty(g_covert.acoustic.pwm_pin, 0);
    }

    g_covert.tx_active = 0;
    g_covert.tx_frames++;
    g_covert.tx_bytes += len;

    serial_puts("[COVERT] TX ");
    serial_put_dec(len);
    serial_puts(" bytes\n");

    return len;
}

bool covert_tx_complete(void) {
    return g_covert.tx_active == 0;
}

/* ==========================================================================
 * Frame RX
 * ========================================================================== */

int covert_rx_init(uint8_t channel) {
    if (channel == COVERT_CHANNEL_OPTICAL && !g_covert.optical.enabled) {
        return COVERT_ERR_DISABLED;
    }
    if (channel == COVERT_CHANNEL_ACOUSTIC && !g_covert.acoustic.enabled) {
        return COVERT_ERR_DISABLED;
    }

    g_covert.rx_channel = channel;
    g_covert.rx_active = 1;
    g_covert.rx_synced = 0;
    g_covert.rx_bit_index = 0;
    memset(&g_covert.rx_frame, 0, sizeof(g_covert.rx_frame));

    return COVERT_OK;
}

/**
 * Sample one bit from the channel
 */
static uint8_t rx_sample_bit(void) {
    uint16_t sample;

    if (g_covert.rx_channel == COVERT_CHANNEL_OPTICAL) {
        sample = covert_optical_sample();
        return (sample > g_covert.optical.threshold) ? 1 : 0;
    } else {
        /* For acoustic, we need more sophisticated detection */
        /* For now, simple threshold */
        sample = covert_acoustic_sample();
        return (sample > 512) ? 1 : 0;  /* TODO: proper FSK detection */
    }
}

/**
 * Receive a byte (blocking)
 */
static uint8_t rx_byte(uint16_t bit_time_ms) {
    uint8_t byte = 0;

    for (int bit = 7; bit >= 0; bit--) {
        hal_delay_ms(bit_time_ms);
        uint8_t b = rx_sample_bit();
        byte |= (b << bit);
    }

    return byte;
}

int covert_rx_receive(void *buffer, uint8_t max_len, uint32_t timeout_ms) {
    uint32_t start_tick = ticks;
    uint16_t bit_time_ms = (g_covert.rx_channel == COVERT_CHANNEL_OPTICAL)
        ? g_covert.optical.bit_time_ms
        : g_covert.acoustic.bit_time_ms;

    /* Wait for sync pattern */
    uint8_t sync_count = 0;
    while (sync_count < 4) {
        if ((ticks - start_tick) * 10 > timeout_ms) {
            return COVERT_ERR_TIMEOUT;
        }

        uint8_t byte = rx_byte(bit_time_ms);
        if (byte == COVERT_SYNC_PATTERN) {
            sync_count++;
        } else {
            sync_count = 0;
        }
    }

    /* Read header */
    g_covert.rx_frame.sync = rx_byte(bit_time_ms);
    g_covert.rx_frame.channel_type = rx_byte(bit_time_ms);
    g_covert.rx_frame.payload_len = rx_byte(bit_time_ms);

    if (g_covert.rx_frame.sync != COVERT_SYNC_PATTERN) {
        g_covert.rx_sync_lost++;
        return COVERT_ERR_NOSYNC;
    }

    if (g_covert.rx_frame.payload_len > COVERT_MAX_PAYLOAD) {
        return COVERT_ERR_OVERFLOW;
    }

    /* Read payload */
    for (uint8_t i = 0; i < g_covert.rx_frame.payload_len; i++) {
        g_covert.rx_frame.payload[i] = rx_byte(bit_time_ms);
    }

    /* Read and verify CRC */
    uint8_t received_crc = rx_byte(bit_time_ms);
    uint8_t expected_crc = covert_crc8(&g_covert.rx_frame, 3 + g_covert.rx_frame.payload_len);

    if (received_crc != expected_crc) {
        g_covert.rx_crc_errors++;
        return COVERT_ERR_CRC;
    }

    /* Copy to output */
    uint8_t copy_len = (g_covert.rx_frame.payload_len < max_len)
        ? g_covert.rx_frame.payload_len : max_len;
    memcpy(buffer, g_covert.rx_frame.payload, copy_len);

    g_covert.rx_frames++;
    g_covert.rx_bytes += copy_len;

    serial_puts("[COVERT] RX ");
    serial_put_dec(copy_len);
    serial_puts(" bytes\n");

    return copy_len;
}

bool covert_rx_available(void) {
    /* Would need async sampling to implement properly */
    return false;
}

int covert_rx_read(void *buffer, uint8_t max_len) {
    if (!covert_rx_available()) {
        return -1;
    }

    uint8_t copy_len = (g_covert.rx_frame.payload_len < max_len)
        ? g_covert.rx_frame.payload_len : max_len;
    memcpy(buffer, g_covert.rx_frame.payload, copy_len);

    return copy_len;
}

/* ==========================================================================
 * Debug
 * ========================================================================== */

void covert_print_status(void) {
    serial_puts("\n=== COVERT CHANNEL STATUS ===\n");

    serial_puts("Optical: ");
    serial_puts(g_covert.optical.enabled ? "ENABLED" : "disabled");
    serial_puts(" LED=GPIO");
    serial_put_dec(g_covert.optical.led_pin);
    serial_puts(" ADC=");
    serial_put_dec(g_covert.optical.adc_channel);
    serial_puts(" rate=");
    serial_put_dec(1000 / g_covert.optical.bit_time_ms);
    serial_puts("bps\n");

    serial_puts("Acoustic: ");
    serial_puts(g_covert.acoustic.enabled ? "ENABLED" : "disabled");
    serial_puts(" PWM=GPIO");
    serial_put_dec(g_covert.acoustic.pwm_pin);
    serial_puts(" freq0=");
    serial_put_dec(g_covert.acoustic.freq_0);
    serial_puts("Hz freq1=");
    serial_put_dec(g_covert.acoustic.freq_1);
    serial_puts("Hz\n");

    serial_puts("Stats: TX frames=");
    serial_put_dec(g_covert.tx_frames);
    serial_puts(" bytes=");
    serial_put_dec(g_covert.tx_bytes);
    serial_puts(" RX frames=");
    serial_put_dec(g_covert.rx_frames);
    serial_puts(" bytes=");
    serial_put_dec(g_covert.rx_bytes);
    serial_puts("\n");

    serial_puts("Errors: CRC=");
    serial_put_dec(g_covert.rx_crc_errors);
    serial_puts(" sync_lost=");
    serial_put_dec(g_covert.rx_sync_lost);
    serial_puts("\n");

    serial_puts("=============================\n\n");
}

struct covert_state* covert_get_state(void) {
    return &g_covert;
}
