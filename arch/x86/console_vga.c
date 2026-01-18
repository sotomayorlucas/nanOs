/*
 * NanOS VGA Console - x86 Text Mode Display
 *
 * Simple VGA text-mode console for x86 architecture.
 * Uses memory-mapped I/O at 0xB8000.
 */
#include <nanos.h>

/* ==========================================================================
 * VGA Constants
 * ========================================================================== */
#define VGA_ADDR    0xB8000
#define VGA_WIDTH   80
#define VGA_HEIGHT  25

/* ==========================================================================
 * State
 * ========================================================================== */
static uint16_t* const vga_buffer = (uint16_t*)VGA_ADDR;
static int vga_row = 0;
static int vga_col = 0;
static uint8_t vga_color = 0x0A;  /* Default: bright green */

/* ==========================================================================
 * Public API
 * ========================================================================== */

void vga_set_color(uint8_t color) {
    vga_color = color;
}

void vga_clear(void) {
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = (vga_color << 8) | ' ';
    }
    vga_row = 0;
    vga_col = 0;
}

void vga_putchar(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
    } else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = (vga_color << 8) | c;
        vga_col++;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row++;
        }
    }

    if (vga_row >= VGA_HEIGHT) {
        /* Scroll up */
        for (int i = 0; i < VGA_WIDTH * (VGA_HEIGHT - 1); i++) {
            vga_buffer[i] = vga_buffer[i + VGA_WIDTH];
        }
        for (int i = 0; i < VGA_WIDTH; i++) {
            vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + i] = (vga_color << 8) | ' ';
        }
        vga_row = VGA_HEIGHT - 1;
    }
}

void vga_puts(const char* str) {
    while (*str) vga_putchar(*str++);
}

void vga_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    vga_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        vga_putchar(hex[(value >> i) & 0xF]);
    }
}

void vga_put_dec(uint32_t value) {
    char buf[12];
    int i = 0;
    if (value == 0) {
        vga_putchar('0');
        return;
    }
    while (value > 0) {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i > 0) vga_putchar(buf[--i]);
}
