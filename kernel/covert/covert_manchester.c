/*
 * Manchester Encoding for Covert Channels - "El Reloj Oculto" (v0.7)
 *
 * Implements Manchester/bi-phase encoding for self-clocking data:
 * - 0 is encoded as LOW→HIGH transition
 * - 1 is encoded as HIGH→LOW transition
 *
 * Benefits:
 * - Self-clocking (clock embedded in signal)
 * - DC balanced (equal highs and lows)
 * - Easy to detect sync errors
 *
 * "Every transition carries both time and truth."
 */
#include <nanos.h>
#include <nanos/covert.h>

/* ==========================================================================
 * Manchester Encoding
 *
 * Each data bit is encoded as two symbol bits:
 * Data 0 → Symbol 01 (LOW then HIGH)
 * Data 1 → Symbol 10 (HIGH then LOW)
 * ========================================================================== */

uint16_t covert_manchester_encode(const uint8_t *input, uint16_t in_len,
                                   uint8_t *output) {
    uint16_t out_idx = 0;
    uint8_t out_byte = 0;
    uint8_t out_bit = 0;

    for (uint16_t i = 0; i < in_len; i++) {
        uint8_t byte = input[i];

        /* Encode each bit MSB first */
        for (int bit = 7; bit >= 0; bit--) {
            uint8_t data_bit = (byte >> bit) & 0x01;

            /* Encode as two symbol bits */
            uint8_t symbol_high = data_bit ? 1 : 0;
            uint8_t symbol_low = data_bit ? 0 : 1;

            /* First symbol bit */
            out_byte |= (symbol_high << (7 - out_bit));
            out_bit++;
            if (out_bit == 8) {
                output[out_idx++] = out_byte;
                out_byte = 0;
                out_bit = 0;
            }

            /* Second symbol bit */
            out_byte |= (symbol_low << (7 - out_bit));
            out_bit++;
            if (out_bit == 8) {
                output[out_idx++] = out_byte;
                out_byte = 0;
                out_bit = 0;
            }
        }
    }

    /* Flush remaining bits */
    if (out_bit > 0) {
        output[out_idx++] = out_byte;
    }

    return out_idx;
}

/* ==========================================================================
 * Manchester Decoding
 *
 * Each pair of symbol bits decodes to one data bit:
 * Symbol 01 → Data 0
 * Symbol 10 → Data 1
 * Symbol 00 or 11 → Error (no transition)
 * ========================================================================== */

int16_t covert_manchester_decode(const uint8_t *input, uint16_t in_len,
                                  uint8_t *output) {
    uint16_t out_idx = 0;
    uint8_t out_byte = 0;
    uint8_t out_bit = 0;
    uint16_t in_bit_idx = 0;

    while (in_bit_idx + 1 < in_len * 8) {
        /* Get two symbol bits */
        uint8_t byte1 = input[in_bit_idx / 8];
        uint8_t bit1_pos = 7 - (in_bit_idx % 8);
        uint8_t symbol_high = (byte1 >> bit1_pos) & 0x01;

        in_bit_idx++;

        uint8_t byte2 = input[in_bit_idx / 8];
        uint8_t bit2_pos = 7 - (in_bit_idx % 8);
        uint8_t symbol_low = (byte2 >> bit2_pos) & 0x01;

        in_bit_idx++;

        /* Decode symbol pair */
        uint8_t data_bit;
        if (symbol_high == 1 && symbol_low == 0) {
            data_bit = 1;  /* 10 → 1 */
        } else if (symbol_high == 0 && symbol_low == 1) {
            data_bit = 0;  /* 01 → 0 */
        } else {
            /* Invalid Manchester encoding */
            return COVERT_ERR_CRC;  /* Use CRC error to indicate bad encoding */
        }

        /* Build output byte */
        out_byte |= (data_bit << (7 - out_bit));
        out_bit++;

        if (out_bit == 8) {
            output[out_idx++] = out_byte;
            out_byte = 0;
            out_bit = 0;
        }
    }

    return (int16_t)out_idx;
}

/* ==========================================================================
 * Preamble Generation
 *
 * Generate sync preamble (alternating 1010...)
 * This helps receiver synchronize to bit boundaries
 * ========================================================================== */

void covert_generate_preamble(uint8_t *output, uint8_t num_bits) {
    uint8_t byte = 0;
    uint8_t bit_pos = 0;
    uint8_t idx = 0;

    for (uint8_t i = 0; i < num_bits; i++) {
        /* Alternating pattern */
        uint8_t bit = (i % 2) ? 0 : 1;

        byte |= (bit << (7 - bit_pos));
        bit_pos++;

        if (bit_pos == 8) {
            output[idx++] = byte;
            byte = 0;
            bit_pos = 0;
        }
    }

    /* Flush */
    if (bit_pos > 0) {
        output[idx] = byte;
    }
}

/* ==========================================================================
 * Sync Detection
 *
 * Detect preamble pattern in received data
 * Returns bit offset where sync was found, or -1
 * ========================================================================== */

int16_t covert_detect_sync(const uint8_t *data, uint16_t len,
                            uint8_t sync_byte, uint8_t *confidence) {
    *confidence = 0;

    for (uint16_t byte_idx = 0; byte_idx < len; byte_idx++) {
        if (data[byte_idx] == sync_byte) {
            /* Found potential sync */
            /* Check for consecutive sync bytes */
            uint8_t consecutive = 1;
            for (uint16_t j = byte_idx + 1; j < len && consecutive < 4; j++) {
                if (data[j] == sync_byte) {
                    consecutive++;
                } else {
                    break;
                }
            }

            *confidence = consecutive * 64;  /* 1-4 → 64-255 */
            return (int16_t)(byte_idx * 8);
        }
    }

    return -1;  /* No sync found */
}

/* ==========================================================================
 * Bit Timing Recovery
 *
 * Adjust sampling phase based on received transitions
 * Used for adaptive clock recovery
 * ========================================================================== */

struct bit_timing_state {
    uint32_t expected_tick;     /* When we expect next transition */
    uint16_t bit_period;        /* Current bit period in ticks */
    int16_t  phase_error;       /* Accumulated phase error */
    uint8_t  locked;            /* 1 if timing is locked */
};

void covert_timing_init(struct bit_timing_state *state, uint16_t bit_period_ticks) {
    state->expected_tick = 0;
    state->bit_period = bit_period_ticks;
    state->phase_error = 0;
    state->locked = 0;
}

/**
 * Update timing based on observed transition
 * @param state       Timing state
 * @param actual_tick When transition actually occurred
 */
void covert_timing_update(struct bit_timing_state *state, uint32_t actual_tick) {
    if (state->expected_tick == 0) {
        /* First transition - initialize */
        state->expected_tick = actual_tick + state->bit_period;
        state->locked = 1;
        return;
    }

    /* Calculate phase error */
    int32_t error = (int32_t)actual_tick - (int32_t)state->expected_tick;

    /* Clamp error to half a bit period */
    int32_t max_error = state->bit_period / 2;
    if (error > max_error) error = max_error;
    if (error < -max_error) error = -max_error;

    /* Low-pass filter the error */
    state->phase_error = (state->phase_error * 3 + (int16_t)error) / 4;

    /* Adjust next expected tick */
    state->expected_tick = actual_tick + state->bit_period;

    /* Mark as locked if error is small */
    state->locked = (error > -max_error/4 && error < max_error/4) ? 1 : 0;
}

/**
 * Get optimal sample point for current bit
 */
uint32_t covert_timing_sample_point(struct bit_timing_state *state) {
    /* Sample in middle of bit period, adjusted for phase error */
    return state->expected_tick - state->bit_period / 2 + state->phase_error / 2;
}
