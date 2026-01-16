/*
 * NanOS - Port I/O Functions
 * Direct hardware communication - no syscalls, no abstraction
 */

#ifndef IO_H
#define IO_H

#include <stdint.h>

/* ==========================================================================
 * Port I/O - Inline assembly for speed
 * These are the nerve endings of our cell
 * ========================================================================== */

/* Write a byte to a port */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

/* Read a byte from a port */
static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* Write a word (16-bit) to a port */
static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

/* Read a word from a port */
static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* Write a dword (32-bit) to a port */
static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

/* Read a dword from a port */
static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* I/O wait - Sometimes hardware needs a moment */
static inline void io_wait(void) {
    outb(0x80, 0);  /* Write to unused port - creates small delay */
}

/* ==========================================================================
 * Memory-Mapped I/O - For devices like e1000
 * ========================================================================== */

/* Write to memory-mapped register */
static inline void mmio_write32(uint32_t addr, uint32_t value) {
    *((volatile uint32_t*)addr) = value;
}

/* Read from memory-mapped register */
static inline uint32_t mmio_read32(uint32_t addr) {
    return *((volatile uint32_t*)addr);
}

#endif /* IO_H */
