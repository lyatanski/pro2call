#ifndef GTP1_H
#define GTP1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GTPv1-C codec — 3GPP TS 29.060.
 *
 * The message header and IE walk are local: GTPv1 mixes two IE
 * encodings, so the generic TLV codec (task/inc/tlv.h) cannot describe
 * it with a profile. IEs with type < 128 are TV — a type octet followed
 * by a fixed-length value the receiver must already know — and IEs with
 * type >= 128 are TLV with a 2-byte big-endian length. The iterator
 * takes the TV length table as a parameter; the generated message layer
 * (gtp1_msg.h) provides the full table of the pinned spec release.
 *
 * Decode is zero-copy: the iterator yields (type, length, value) views
 * over the caller's buffer. An unknown TV type ends the walk — its
 * length is unknowable, so nothing after it can be framed.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * The write buffer is the shared tlv_wbuf_t, so overflow is sticky:
 * once any write exceeds capacity every subsequent call fails, and the
 * error is reported once by gtp1_hdr_finalize.
 *
 * Wire layout reference (§6):
 *   header (8 or 12 B): flags | type | length(2) | TEID(4) |
 *                       [seq(2) | N-PDU(1) | next-ext(1) when E/S/PN]
 *   ext hdr chain     : len(1, 4-octet units) | content | next type(1)
 *   TV IE  (1+N B)    : type<128 | value(fixed N)
 *   TLV IE (3+N B)    : type>=128 | length(2) | value(length)
 */

enum {
    GTP1_VERSION     = 1,
    GTP1_HDR_MIN     = 8,  /* E/S/PN all clear */
    GTP1_HDR_CTRL    = 12, /* with the optional seq/N-PDU/next octets */
    GTP1_TLV_HDR_LEN = 3
};

typedef enum {
    GTP1_OK         = 0,
    GTP1_E_SHORT    = -1, /* input buffer truncated */
    GTP1_E_VERSION  = -2, /* not GTPv1, or GTP' (PT = 0) */
    GTP1_E_LENGTH   = -3, /* header length field inconsistent with buffer */
    GTP1_E_OVERFLOW = -4, /* write buffer too small */
    GTP1_E_INVAL    = -5, /* invalid argument */
    GTP1_E_MISSING  = -6  /* mandatory IE absent */
} gtp1_err_t;

/* Decoded header in host byte order. The optional octets are valid only
 * when their flag is set. */
typedef struct {
    uint8_t  version; /* must be 1 */
    bool     pt;      /* protocol type: true = GTP, false = GTP' */
    bool     e;       /* extension header chain present */
    bool     s;       /* sequence number present */
    bool     pn;      /* N-PDU number present */
    uint8_t  message_type;
    uint16_t length; /* bytes following octet 8 */
    uint32_t teid;
    uint16_t sequence; /* 0 when !s */
    uint8_t  npdu;     /* 0 when !pn */
    uint8_t  next_ext; /* first extension header type, 0 when !e */
} gtp1_hdr_t;

/* IE view — points into the caller's input buffer. No ownership. */
typedef struct {
    uint8_t        type;
    uint16_t       len; /* value length */
    const uint8_t* value;
} gtp1_ie_view_t;

/* Borrowed byte range; data == NULL means the field is absent. */
typedef struct {
    const uint8_t* data;
    uint16_t       len;
} gtp1_view_t;

typedef struct {
    const uint8_t*  cur;
    const uint8_t*  end;
    const uint16_t* tvlen; /* 128-entry TV value-length table */
} gtp1_ie_iter_t;

typedef tlv_wbuf_t gtp1_wbuf_t;

/* ---- Header ---- */

/* Decode the header and skip any extension-header chain. Returns the
 * offset where IEs begin (8, 12, or beyond), or a negative gtp1_err_t.
 * The message's total wire size is 8 + out->length. */
API_EXPORT int gtp1_hdr_decode(const uint8_t* buf, size_t len, gtp1_hdr_t* out);

/* Encode a control-plane header: S is forced set (signalling messages
 * carry a sequence number), E/PN clear, so the header is 12 bytes. The
 * Length field is taken from hdr->length; use gtp1_hdr_finalize() to
 * backfill it after writing IEs. Returns the header byte count. */
API_EXPORT int gtp1_hdr_encode(uint8_t* buf, size_t cap, const gtp1_hdr_t* hdr);

/* Backfill the Length field of a header written at hdr_off. Call once
 * all IEs are written. */
API_EXPORT int gtp1_hdr_finalize(gtp1_wbuf_t* w, size_t hdr_off);

/* ---- IE walk (zero-copy decode) ---- */

/* tvlen maps TV type -> fixed value length; 0 marks an unknown type,
 * which ends the walk. The generated gtp1_tv_len table (gtp1_msg.h)
 * covers the full registry of the pinned spec release. */
API_EXPORT void gtp1_ie_iter_init(gtp1_ie_iter_t* it, const uint8_t* payload,
                                  size_t len, const uint16_t tvlen[128]);

/* Returns true with *out filled; false at end-of-stream, on truncation,
 * or at an unknown TV type. */
API_EXPORT bool gtp1_ie_iter_next(gtp1_ie_iter_t* it, gtp1_ie_view_t* out);

/* ---- IE write (encode into caller's buffer) ---- */

API_EXPORT void gtp1_wbuf_init(gtp1_wbuf_t* w, uint8_t* buf, size_t cap);

/* Returns 0 on success, negative gtp1_err_t on error. The caller is
 * responsible for vlen matching the type's fixed length on TV puts. */
API_EXPORT int gtp1_ie_put_tv(gtp1_wbuf_t* w, uint8_t type, const void* val,
                              uint16_t vlen);
API_EXPORT int gtp1_ie_put_tlv(gtp1_wbuf_t* w, uint8_t type, const void* val,
                               uint16_t vlen);

/* Integer shortcuts (host -> network byte order). */
API_EXPORT int gtp1_ie_put_tv_u8(gtp1_wbuf_t* w, uint8_t type, uint8_t v);
API_EXPORT int gtp1_ie_put_tv_u16(gtp1_wbuf_t* w, uint8_t type, uint16_t v);
API_EXPORT int gtp1_ie_put_tv_u32(gtp1_wbuf_t* w, uint8_t type, uint32_t v);
API_EXPORT int gtp1_ie_put_tlv_u8(gtp1_wbuf_t* w, uint8_t type, uint8_t v);
API_EXPORT int gtp1_ie_put_tlv_u16(gtp1_wbuf_t* w, uint8_t type, uint16_t v);
API_EXPORT int gtp1_ie_put_tlv_u32(gtp1_wbuf_t* w, uint8_t type, uint32_t v);

#ifdef __cplusplus
}
#endif

#endif /* GTP1_H */
