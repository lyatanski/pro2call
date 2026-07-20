#ifndef TLV_H
#define TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic zero-copy TLV codec.
 *
 * One iterator/writer pair covers any type-length-value stream whose
 * fixed header can be described by a tlv_prof_t: field offsets and
 * sizes, whether the length field counts the header, byte order, and
 * inter-entry alignment. Profiles are provided for GTPv2-C IEs
 * (3GPP TS 29.274), Diameter AVPs (RFC 6733) and netlink attributes
 * (RFC 3549).
 *
 * Decode is zero-copy: the iterator yields (type, meta, length, value)
 * views over the caller's buffer, which must remain valid while views
 * are in use. Nested (grouped) entries are walked by pointing a second
 * iterator at the parent's value range.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Overflow on the write buffer is sticky: once any write exceeds
 * capacity every subsequent call fails, so return codes can be chained
 * and checked once at the end. Nested entries use begin/end pairs that
 * backfill the parent's length field.
 *
 * Everything is static inline: bound to a compile-time-constant
 * profile, the descriptor folds away and the code matches a
 * hand-written parser for that wire format.
 */

typedef enum {
    TLV_OK         = 0,
    TLV_E_OVERFLOW = -1, /* write buffer too small, or length field range */
    TLV_E_INVAL    = -2  /* invalid argument */
} tlv_err_t;

enum { TLV_NO_META = 0xFF };

/* Wire-format descriptor. Offsets are into the fixed header. Fields in
 * host byte order (big_endian == false) must be 1, 2 or 4 bytes wide;
 * big-endian fields may be 1..4 bytes. */
typedef struct {
    uint8_t hdr_len;      /* fixed header size in bytes */
    uint8_t type_off;     /* type field offset */
    uint8_t type_size;    /* type field width */
    uint8_t len_off;      /* length field offset */
    uint8_t len_size;     /* length field width */
    uint8_t meta_off;     /* aux octet (instance/flags), TLV_NO_META if none */
    uint8_t align;        /* entry alignment: 1 = packed, 4 = dword */
    bool    len_incl_hdr; /* length field counts the header too */
    bool    big_endian;   /* false = host byte order (netlink) */
} tlv_prof_t;

/* GTPv2-C IE (TS 29.274 §8.2): type(1) | length(2) | spare/instance(1),
 * big-endian, length excludes the 4-byte header, packed. meta is the
 * spare/instance octet; mask the low nibble for the instance. */
#define TLV_PROF_GTP2C       \
    { .hdr_len      = 4,     \
      .type_off     = 0,     \
      .type_size    = 1,     \
      .len_off      = 1,     \
      .len_size     = 2,     \
      .meta_off     = 3,     \
      .align        = 1,     \
      .len_incl_hdr = false, \
      .big_endian   = true }

/* Diameter AVP (RFC 6733 §4.1): code(4) | flags(1) | length(3),
 * big-endian, length includes the 8-byte header, entries padded to 4.
 * meta is the flags octet; when the V bit (0x80) is set the first 4
 * value bytes are the Vendor-ID. */
#define TLV_PROF_DIAMETER   \
    { .hdr_len      = 8,    \
      .type_off     = 0,    \
      .type_size    = 4,    \
      .len_off      = 5,    \
      .len_size     = 3,    \
      .meta_off     = 4,    \
      .align        = 4,    \
      .len_incl_hdr = true, \
      .big_endian   = true }

/* Netlink attribute (RFC 3549 §2.3.2): nla_len(2) | nla_type(2), host
 * byte order, length includes the 4-byte header, entries padded to
 * NLA_ALIGNTO (4). No meta octet; the nested/byte-order flags live in
 * the type field's high bits. */
#define TLV_PROF_NETLINK           \
    { .hdr_len      = 4,           \
      .type_off     = 2,           \
      .type_size    = 2,           \
      .len_off      = 0,           \
      .len_size     = 2,           \
      .meta_off     = TLV_NO_META, \
      .align        = 4,           \
      .len_incl_hdr = true,        \
      .big_endian   = false }

/* Entry view — points into the caller's input buffer. No ownership. */
typedef struct {
    uint32_t       type;
    uint32_t       len;  /* value length in bytes */
    uint8_t        meta; /* aux octet; 0 when the profile has none */
    const uint8_t* value;
} tlv_view_t;

typedef struct {
    const uint8_t*    cur;
    const uint8_t*    end;
    const tlv_prof_t* prof;
} tlv_iter_t;

typedef struct {
    uint8_t* buf;
    size_t   cap;
    size_t   off;
    bool     overflow; /* sticky: once set, all subsequent ops fail */
} tlv_wbuf_t;

#if defined(__GNUC__) || defined(__clang__)
#define TLV_UNLIKELY(x)   __builtin_expect(!!(x), 0)
#define TLV_ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define TLV_UNLIKELY(x)   (x)
#define TLV_ALWAYS_INLINE inline
#endif

/* Load/store a header field of 1..4 bytes. Big-endian fields are read
 * byte-wise (no unaligned-access UB); host-order fields go through
 * memcpy and must be 1, 2 or 4 bytes wide. */
static TLV_ALWAYS_INLINE uint32_t tlv_load(const uint8_t* p, uint8_t size,
                                           bool big_endian)
{
    if (big_endian) {
        uint32_t v = 0;
        for (uint8_t i = 0; i < size; i++)
            v = (v << 8) | p[i];
        return v;
    }
    if (size == 2) {
        uint16_t v;
        memcpy(&v, p, 2);
        return v;
    }
    if (size == 4) {
        uint32_t v;
        memcpy(&v, p, 4);
        return v;
    }
    return p[0];
}

static TLV_ALWAYS_INLINE void tlv_store(uint8_t* p, uint8_t size,
                                        bool big_endian, uint32_t v)
{
    if (big_endian) {
        for (uint8_t i = size; i--;) {
            p[i] = (uint8_t)v;
            v >>= 8;
        }
        return;
    }
    if (size == 2) {
        const uint16_t h = (uint16_t)v;
        memcpy(p, &h, 2);
        return;
    }
    if (size == 4) {
        memcpy(p, &v, 4);
        return;
    }
    p[0] = (uint8_t)v;
}

/* Largest value the profile's length field can carry. */
static TLV_ALWAYS_INLINE uint32_t tlv_len_max(uint8_t len_size)
{
    return len_size >= 4 ? UINT32_MAX : ((uint32_t)1 << (8u * len_size)) - 1u;
}

/* ---- Zero-copy decode ---- */

static inline void tlv_iter_init(tlv_iter_t* it, const tlv_prof_t* prof,
                                 const uint8_t* payload, size_t len)
{
    it
        ->cur = payload;
    it
        ->end = payload + len;
    it
        ->prof = prof;
}

/* Initialize an iterator over a nested (grouped) entry's children. */
static inline void tlv_iter_grouped(tlv_iter_t* it, const tlv_prof_t* prof,
                                    const tlv_view_t* grouped)
{
    it
        ->cur = grouped->value;
    it
        ->end = grouped->value + grouped->len;
    it
        ->prof = prof;
}

/* Returns true with *out filled; false at end-of-stream or on a
 * malformed/truncated entry. Trailing padding of the final entry may
 * be absent from the stream. */
static inline bool tlv_iter_next(tlv_iter_t* it, tlv_view_t* out)
{
    const tlv_prof_t* p     = it->prof;
    const size_t      avail = (size_t)(it->end - it->cur);
    if (TLV_UNLIKELY(avail < p->hdr_len)) return false;

    const uint32_t lfield =
        tlv_load(it->cur + p->len_off, p->len_size, p->big_endian);
    if (TLV_UNLIKELY(p->len_incl_hdr && lfield < p->hdr_len)) return false;
    const uint32_t vlen = p->len_incl_hdr ? lfield - p->hdr_len : lfield;
    if (TLV_UNLIKELY(vlen > avail - p->hdr_len)) return false;

    out->type  = tlv_load(it->cur + p->type_off, p->type_size, p->big_endian);
    out->len   = vlen;
    out->meta  = p->meta_off == TLV_NO_META ? 0 : it->cur[p->meta_off];
    out->value = it->cur + p->hdr_len;

    size_t adv = (size_t)p->hdr_len + vlen;
    if (p->align > 1) {
        const size_t rem = adv % p->align;
        if (rem) adv += p->align - rem;
    }
    it
        ->cur += adv < avail ? adv : avail;
    return true;
}

/* ---- Encode into caller's buffer ---- */

static inline void tlv_wbuf_init(tlv_wbuf_t* w, uint8_t* buf, size_t cap)
{
    w->buf      = buf;
    w->cap      = cap;
    w->off      = 0;
    w->overflow = false;
}

static TLV_ALWAYS_INLINE int tlv_wbuf_reserve(tlv_wbuf_t* w, size_t n)
{
    if (TLV_UNLIKELY(w->overflow)) return TLV_E_OVERFLOW;
    if (TLV_UNLIKELY(n > w->cap - w->off)) {
        w->overflow = true;
        return TLV_E_OVERFLOW;
    }
    return TLV_OK;
}

/* Append one complete entry (header, value, alignment padding). */
static inline int tlv_put(tlv_wbuf_t* w, const tlv_prof_t* p, uint32_t type,
                          uint8_t meta, const void* val, uint32_t vlen)
{
    const uint32_t lfield = p->len_incl_hdr ? p->hdr_len + vlen : vlen;
    if (TLV_UNLIKELY(lfield < vlen || lfield > tlv_len_max(p->len_size)))
        return TLV_E_INVAL;

    size_t total = (size_t)p->hdr_len + vlen;
    if (p->align > 1) {
        const size_t rem = total % p->align;
        if (rem) total += p->align - rem;
    }

    const int rc = tlv_wbuf_reserve(w, total);
    if (rc) return rc;

    uint8_t* q = w->buf + w->off;
    memset(q, 0, p->hdr_len);
    tlv_store(q + p->type_off, p->type_size, p->big_endian, type);
    tlv_store(q + p->len_off, p->len_size, p->big_endian, lfield);
    if (p->meta_off != TLV_NO_META) q[p->meta_off] = meta;
    if (vlen) memcpy(q + p->hdr_len, val, vlen);
    memset(q + p->hdr_len + vlen, 0, total - p->hdr_len - vlen);
    w->off += total;
    return TLV_OK;
}

/* Integer shortcuts; the value follows the profile's byte order. */
static inline int tlv_put_u8(tlv_wbuf_t* w, const tlv_prof_t* p, uint32_t type,
                             uint8_t meta, uint8_t v)
{
    return tlv_put(w, p, type, meta, &v, 1);
}

static inline int tlv_put_u16(tlv_wbuf_t* w, const tlv_prof_t* p, uint32_t type,
                              uint8_t meta, uint16_t v)
{
    uint8_t b[2];
    tlv_store(b, 2, p->big_endian, v);
    return tlv_put(w, p, type, meta, b, sizeof b);
}

static inline int tlv_put_u32(tlv_wbuf_t* w, const tlv_prof_t* p, uint32_t type,
                              uint8_t meta, uint32_t v)
{
    uint8_t b[4];
    tlv_store(b, 4, p->big_endian, v);
    return tlv_put(w, p, type, meta, b, sizeof b);
}

/* Nested entry: write begin, then any child entries, then end. The end
 * call backfills the parent's length and pads the stream to the
 * profile's alignment. Begin returns a handle (offset) or a negative
 * error; pass it back to end. */
static inline int tlv_begin(tlv_wbuf_t* w, const tlv_prof_t* p, uint32_t type,
                            uint8_t meta)
{
    const int rc = tlv_wbuf_reserve(w, p->hdr_len);
    if (rc) return rc;

    const size_t off = w->off;
    uint8_t*     q   = w->buf + off;
    memset(q, 0, p->hdr_len); /* length backfilled by tlv_end */
    tlv_store(q + p->type_off, p->type_size, p->big_endian, type);
    if (p->meta_off != TLV_NO_META) q[p->meta_off] = meta;
    w->off += p->hdr_len;
    return (int)off;
}

static inline int tlv_end(tlv_wbuf_t* w, const tlv_prof_t* p, int handle)
{
    if (TLV_UNLIKELY(w->overflow)) return TLV_E_OVERFLOW;
    if (TLV_UNLIKELY(handle < 0)) return TLV_E_INVAL;

    const size_t off = (size_t)handle;
    if (TLV_UNLIKELY(off + p->hdr_len > w->off)) return TLV_E_INVAL;

    const size_t content = w->off - off; /* header + children */
    const size_t lfield  = p->len_incl_hdr ? content : content - p->hdr_len;
    if (TLV_UNLIKELY(lfield > tlv_len_max(p->len_size))) return TLV_E_OVERFLOW;

    tlv_store(w->buf + off + p->len_off, p->len_size, p->big_endian,
              (uint32_t)lfield);

    if (p->align > 1) {
        const size_t rem = content % p->align;
        if (rem) {
            const size_t pad = p->align - rem;
            const int    rc  = tlv_wbuf_reserve(w, pad);
            if (rc) return rc;
            memset(w->buf + w->off, 0, pad);
            w->off += pad;
        }
    }
    return TLV_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* TLV_H */
