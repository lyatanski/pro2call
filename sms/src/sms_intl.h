#ifndef SMS_INTL_H
#define SMS_INTL_H

/* Private helpers shared by the sms sources. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define SMS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SMS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define SMS_LIKELY(x)   (x)
#define SMS_UNLIKELY(x) (x)
#endif

/* ---- semi-octet (swapped-nibble BCD) ----
 *
 * A pair of digits "AB" is stored as one octet (B << 4) | A: the wire
 * carries the *second* digit in the high nibble. 0xF is the filler an
 * odd-length field ends with, and 0xA..0xE are the four extra symbols
 * the address table defines (TS 23.040 §9.1.2.3). */

static const char sms_bcd_chars[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '*', '#', 'a', 'b', 'c', '\0'
};

/* Nibble -> character; '\0' for the 0xF filler. */
static inline char sms_bcd_char(uint8_t nib)
{
    return sms_bcd_chars[nib & 0x0F];
}

/* Character -> nibble, or 0xFF when it is not an address symbol. */
static inline uint8_t sms_bcd_nibble(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    switch (c) {
    case '*': return 0x0A;
    case '#': return 0x0B;
    case 'a':
    case 'A': return 0x0C;
    case 'b':
    case 'B': return 0x0D;
    case 'c':
    case 'C': return 0x0E;
    default:  return 0xFF;
    }
}

/* Two-digit BCD as an integer, for the timestamp fields. Returns -1
 * when either nibble is not a decimal digit. */
static inline int sms_bcd2(uint8_t o)
{
    uint8_t tens = o & 0x0F, units = (uint8_t)(o >> 4);
    if (tens > 9 || units > 9) return -1;
    return tens * 10 + units;
}

static inline uint8_t sms_bcd2_enc(unsigned v)
{
    return (uint8_t)(((v % 10) << 4) | ((v / 10) % 10));
}

/* ---- UTF-8 ---- */

/* Decode one code point from s[*i .. n). Advances *i. Returns the code
 * point, or -1 on a malformed or truncated sequence (the caller stops;
 * nothing here tries to resynchronise). Overlong forms, surrogates and
 * anything past U+10FFFF are rejected — a codec that silently accepted
 * them would encode them onward. */
static inline int32_t sms_utf8_next(const char* s, size_t n, size_t* i)
{
    const uint8_t* p = (const uint8_t*)s;
    size_t         k = *i;
    if (k >= n) return -1;
    uint32_t c = p[k++];
    uint32_t v;
    unsigned extra;
    if (c < 0x80) {
        *i = k;
        return (int32_t)c;
    } else if ((c & 0xE0) == 0xC0) {
        v     = c & 0x1F;
        extra = 1;
    } else if ((c & 0xF0) == 0xE0) {
        v     = c & 0x0F;
        extra = 2;
    } else if ((c & 0xF8) == 0xF0) {
        v     = c & 0x07;
        extra = 3;
    } else {
        return -1;
    }
    if (k + extra > n) return -1;
    for (unsigned j = 0; j < extra; j++) {
        if ((p[k] & 0xC0) != 0x80) return -1;
        v = (v << 6) | (uint32_t)(p[k++] & 0x3F);
    }
    if ((extra == 1 && v < 0x80) || (extra == 2 && v < 0x800) ||
        (extra == 3 && v < 0x10000))
        return -1; /* overlong */
    if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return -1;
    *i = k;
    return (int32_t)v;
}

/* Encode one code point. Returns the byte count, or 0 when it does not
 * fit in cap. */
static inline size_t sms_utf8_put(char* out, size_t cap, uint32_t c)
{
    uint8_t* p = (uint8_t*)out;
    if (c < 0x80) {
        if (cap < 1) return 0;
        p[0] = (uint8_t)c;
        return 1;
    }
    if (c < 0x800) {
        if (cap < 2) return 0;
        p[0] = (uint8_t)(0xC0 | (c >> 6));
        p[1] = (uint8_t)(0x80 | (c & 0x3F));
        return 2;
    }
    if (c < 0x10000) {
        if (cap < 3) return 0;
        p[0] = (uint8_t)(0xE0 | (c >> 12));
        p[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
        p[2] = (uint8_t)(0x80 | (c & 0x3F));
        return 3;
    }
    if (cap < 4) return 0;
    p[0] = (uint8_t)(0xF0 | (c >> 18));
    p[1] = (uint8_t)(0x80 | ((c >> 12) & 0x3F));
    p[2] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
    p[3] = (uint8_t)(0x80 | (c & 0x3F));
    return 4;
}

#endif /* SMS_INTL_H */
