#ifndef SIP_INTL_H
#define SIP_INTL_H

/* Private helpers shared by the sip sources. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define SIP_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SIP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define SIP_LIKELY(x)   (x)
#define SIP_UNLIKELY(x) (x)
#endif

/* ASCII lowercase for the characters legal in tokens and header names;
 * '|0x20' maps A-Z onto a-z and leaves digits and '-' alone. */
static inline char sip_lc(char c)
{
    return (char)(c | 0x20);
}

/* Case-insensitive equality against a lowercase reference string. */
static inline bool sip_ieq(const char* p, const char* lc_ref, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (sip_lc(p[i]) != lc_ref[i]) return false;
    return true;
}

/* Case-insensitive equality, neither side pre-lowered. */
static inline bool sip_ieq2(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (sip_lc(a[i]) != sip_lc(b[i])) return false;
    return true;
}

static inline bool sip_is_ws(char c)
{
    return c == ' ' || c == '\t';
}

static inline bool sip_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Parse an unsigned decimal run of exactly [p, p+n). Returns false on
 * empty input, a non-digit, or overflow past UINT32_MAX. */
static inline bool sip_parse_u32(const char* p, size_t n, uint32_t* out)
{
    if (n == 0 || n > 10) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (!sip_is_digit(p[i])) return false;
        v = v * 10 + (uint64_t)(p[i] - '0');
    }
    if (v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

#endif /* SIP_INTL_H */
