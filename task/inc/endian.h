#ifndef ENDIAN_H
#define ENDIAN_H

/* Big-endian byte helpers and compiler hints shared across the protocol
 * codecs (diam, gtp1, gtp2, ...). Byte-wise loads/stores compile down to
 * bswap/movbe on modern toolchains and avoid unaligned-access UB on
 * strict-alignment platforms. */

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define TASK_LIKELY(x)     __builtin_expect(!!(x), 1)
#define TASK_UNLIKELY(x)   __builtin_expect(!!(x), 0)
#define TASK_ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define TASK_LIKELY(x)     (x)
#define TASK_UNLIKELY(x)   (x)
#define TASK_ALWAYS_INLINE inline
#endif

static TASK_ALWAYS_INLINE uint16_t be16_load(const uint8_t* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static TASK_ALWAYS_INLINE uint32_t be24_load(const uint8_t* p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static TASK_ALWAYS_INLINE uint32_t be32_load(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static TASK_ALWAYS_INLINE uint64_t be40_load(const uint8_t* p)
{
    return ((uint64_t)p[0] << 32) | ((uint64_t)p[1] << 24) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 8) | (uint64_t)p[4];
}

static TASK_ALWAYS_INLINE uint64_t be64_load(const uint8_t* p)
{
    return ((uint64_t)be32_load(p) << 32) | (uint64_t)be32_load(p + 4);
}

static TASK_ALWAYS_INLINE void be16_store(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static TASK_ALWAYS_INLINE void be24_store(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

static TASK_ALWAYS_INLINE void be32_store(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static TASK_ALWAYS_INLINE void be40_store(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 32);
    p[1] = (uint8_t)(v >> 24);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 8);
    p[4] = (uint8_t)v;
}

static TASK_ALWAYS_INLINE void be64_store(uint8_t* p, uint64_t v)
{
    be32_store(p, (uint32_t)(v >> 32));
    be32_store(p + 4, (uint32_t)v);
}

#endif /* ENDIAN_H */
