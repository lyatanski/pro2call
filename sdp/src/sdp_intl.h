#ifndef SDP_INTL_H
#define SDP_INTL_H

/* Private helpers shared by the sdp sources. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define SDP_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SDP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define SDP_LIKELY(x)   (x)
#define SDP_UNLIKELY(x) (x)
#endif

/* ASCII lowercase for the characters legal in attribute names;
 * '|0x20' maps A-Z onto a-z and leaves digits and '-' alone. */
static inline char sdp_lc(char c)
{
    return (char)(c | 0x20);
}

/* Case-insensitive equality against a lowercase reference string. */
static inline bool sdp_ieq(const char* p, const char* lc_ref, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (sdp_lc(p[i]) != lc_ref[i]) return false;
    return true;
}

/* Case-insensitive equality, neither side pre-lowered. */
static inline bool sdp_ieq2(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (sdp_lc(a[i]) != sdp_lc(b[i])) return false;
    return true;
}

static inline bool sdp_is_ws(char c)
{
    return c == ' ' || c == '\t';
}

static inline bool sdp_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Parse an unsigned decimal run of exactly [p, p+n). Returns false on
 * empty input, a non-digit, or overflow past UINT64_MAX. */
static inline bool sdp_parse_u64(const char* p, size_t n, uint64_t* out)
{
    if (n == 0 || n > 20) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (!sdp_is_digit(p[i])) return false;
        if (v > (UINT64_MAX - (uint64_t)(p[i] - '0')) / 10) return false;
        v = v * 10 + (uint64_t)(p[i] - '0');
    }
    *out = v;
    return true;
}

static inline bool sdp_parse_u32(const char* p, size_t n, uint32_t* out)
{
    uint64_t v;
    if (!sdp_parse_u64(p, n, &v) || v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

static inline bool sdp_parse_u16(const char* p, size_t n, uint16_t* out)
{
    uint64_t v;
    if (!sdp_parse_u64(p, n, &v) || v > UINT16_MAX) return false;
    *out = (uint16_t)v;
    return true;
}

#endif /* SDP_INTL_H */
