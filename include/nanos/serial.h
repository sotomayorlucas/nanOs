/*
 * NanOS Serial Port Interface
 * x86 COM1 serial output for logging and dashboard communication
 */
#ifndef NANOS_SERIAL_H
#define NANOS_SERIAL_H

#include <nanos.h>

/* Initialize serial port (COM1 at 38400 baud) */
void serial_init(void);

/* Output a single character */
void serial_putchar(char c);

/* Output a null-terminated string */
void serial_puts(const char* str);

/* Output a 32-bit hex value with 0x prefix */
void serial_put_hex(uint32_t value);

/* Output a 32-bit decimal value */
void serial_put_dec(uint32_t value);

#endif /* NANOS_SERIAL_H */
