/*
 * NanOS Serial Port (COM1) - x86 Serial Logging
 *
 * Simple serial output for debugging and dashboard communication.
 */
#include <nanos.h>
#include "../../include/io.h"

/* ==========================================================================
 * COM1 Constants
 * ========================================================================== */
#define COM1_PORT       0x3F8

/* ==========================================================================
 * Public API
 * ========================================================================== */

void serial_init(void) {
    outb(COM1_PORT + 1, 0x00);  /* Disable interrupts */
    outb(COM1_PORT + 3, 0x80);  /* Enable DLAB */
    outb(COM1_PORT + 0, 0x03);  /* 38400 baud (low byte) */
    outb(COM1_PORT + 1, 0x00);  /* (high byte) */
    outb(COM1_PORT + 3, 0x03);  /* 8 bits, no parity, 1 stop */
    outb(COM1_PORT + 2, 0xC7);  /* Enable FIFO */
    outb(COM1_PORT + 4, 0x0B);  /* IRQs enabled, RTS/DSR set */
}

void serial_putchar(char c) {
    while ((inb(COM1_PORT + 5) & 0x20) == 0);
    outb(COM1_PORT, c);
}

void serial_puts(const char* str) {
    while (*str) serial_putchar(*str++);
}

void serial_put_hex(uint32_t value) {
    const char* hex = "0123456789ABCDEF";
    serial_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        serial_putchar(hex[(value >> i) & 0xF]);
    }
}

void serial_put_dec(uint32_t value) {
    char buf[12];
    int i = 0;
    if (value == 0) { serial_putchar('0'); return; }
    while (value > 0) {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }
    while (i > 0) serial_putchar(buf[--i]);
}
