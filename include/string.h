/**
 * NanOS - Minimal string.h for freestanding environment
 *
 * Provides memset, memcpy, memcmp, strlen for kernel use.
 */

#ifndef NANOS_STRING_H
#define NANOS_STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fill memory with a constant byte
 */
static inline void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

/**
 * Copy memory area
 */
static inline void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

/**
 * Compare memory areas
 */
static inline int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

/**
 * Calculate the length of a string
 */
static inline size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) {
        len++;
    }
    return len;
}

/**
 * Copy string
 */
static inline char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

/**
 * Compare strings
 */
static inline int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

#ifdef __cplusplus
}
#endif

#endif /* NANOS_STRING_H */
