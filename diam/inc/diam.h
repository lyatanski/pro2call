#ifndef DIAM_H
#define DIAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Diameter base codec — RFC 6733.
 *
 * The AVP layer binds the generic zero-copy TLV codec (task/inc/tlv.h)
 * to the Diameter AVP wire profile; the message header codec is local.
 *
 * Decode is zero-copy: the iterator yields (code, flags, vendor-id,
 * length, value) views over the caller's buffer. When the V bit is set
 * the iterator consumes the Vendor-ID from the value itself, so views
 * always point at the bare data. Grouped AVPs are walked by nesting a
 * second iterator over the parent AVP's value range.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Grouped AVPs use begin/end pairs that backfill the length field and
 * pad the stream to the 4-byte AVP alignment.
 *
 * Wire layout reference:
 *   header (20 B): version | length(3) | flags | code(3) | app-id(4)
 *                  | hop-by-hop(4) | end-to-end(4)
 *   AVP (8/12+N B): code(4) | flags | length(3) | [vendor-id(4)]
 *                  | data(length - header), padded to 4
 */

enum {
    DIAM_VERSION            = 1,
    DIAM_HDR_LEN            = 20,
    DIAM_AVP_HDR_LEN        = 8, /* without Vendor-ID */
    DIAM_AVP_VENDOR_HDR_LEN = 12
};

/* Command flags — RFC 6733 §3. */
enum {
    DIAM_HDR_F_REQUEST    = 0x80,
    DIAM_HDR_F_PROXIABLE  = 0x40,
    DIAM_HDR_F_ERROR      = 0x20,
    DIAM_HDR_F_RETRANSMIT = 0x10
};

/* AVP flags — RFC 6733 §4.1. */
enum {
    DIAM_AVP_F_VENDOR    = 0x80,
    DIAM_AVP_F_MANDATORY = 0x40,
    DIAM_AVP_F_PROTECTED = 0x20
};

typedef enum {
    DIAM_OK         = 0,
    DIAM_E_SHORT    = -1, /* input buffer truncated */
    DIAM_E_VERSION  = -2, /* not Diameter version 1 */
    DIAM_E_LENGTH   = -3, /* header length field inconsistent with buffer */
    DIAM_E_OVERFLOW = -4, /* write buffer too small */
    DIAM_E_INVAL    = -5, /* invalid argument */
    DIAM_E_TYPE     = -6  /* AVP data length does not fit the type */
} diam_err_t;

/* Decoded header in host byte order. */
typedef struct {
    uint8_t  version; /* must be 1 */
    uint32_t length;  /* total message bytes, header included */
    bool     request;
    bool     proxiable;
    bool     error;
    bool     retransmit;
    uint32_t cmd_code; /* 24-bit */
    uint32_t app_id;
    uint32_t hbh; /* Hop-by-Hop identifier */
    uint32_t e2e; /* End-to-End identifier */
} diam_hdr_t;

/* AVP view — points into the caller's input buffer. No ownership, no
 * copy. vendor_id is 0 and the V bit absent from flags for standard
 * AVPs; value/len never include the Vendor-ID octets. */
typedef struct {
    uint32_t       code;
    uint8_t        flags;
    uint32_t       vendor_id;
    uint32_t       len; /* data length */
    const uint8_t* value;
} diam_avp_view_t;

/* Iterator and write buffer are the generic TLV codec's types, bound to
 * the Diameter AVP wire profile by the functions below. Write-buffer
 * overflow is sticky: once set, all subsequent ops fail. */
typedef tlv_iter_t diam_avp_iter_t;
typedef tlv_wbuf_t diam_wbuf_t;

/* ---- Header ---- */

/* Decode header. Returns DIAM_HDR_LEN on success, or a negative
 * diam_err_t. Requires the whole message (hdr->length bytes) to be in
 * buf. The caller's buffer must remain valid while diam_avp_view_t
 * values referencing it are in use. */
API_EXPORT int diam_hdr_decode(const uint8_t* buf, size_t len, diam_hdr_t* out);

/* Encode header. Returns DIAM_HDR_LEN on success, negative on error.
 * The Message Length field is taken from hdr->length; use
 * diam_hdr_finalize() if you would rather backfill it after writing
 * AVPs. */
API_EXPORT int diam_hdr_encode(uint8_t* buf, size_t cap, const diam_hdr_t* hdr);

/* ---- AVP walk (zero-copy decode) ---- */

API_EXPORT void diam_avp_iter_init(diam_avp_iter_t* it, const uint8_t* payload,
                                   size_t len);

/* Returns true with *out filled; false at end-of-stream or on a
 * malformed/truncated AVP (a V bit with fewer than 4 data bytes is
 * malformed). */
API_EXPORT bool diam_avp_iter_next(diam_avp_iter_t* it, diam_avp_view_t* out);

/* Convenience: initialize an iterator over a grouped AVP's children. */
API_EXPORT void diam_avp_iter_grouped(diam_avp_iter_t* it,
                                      const diam_avp_view_t* grouped);

/* Find the first AVP with the given code/vendor in a payload range.
 * Returns true with *out filled. vendor_id 0 matches standard AVPs. */
API_EXPORT bool diam_avp_find(const uint8_t* payload, size_t len, uint32_t code,
                              uint32_t vendor_id, diam_avp_view_t* out);

/* ---- Typed data readers (length-checked) ---- */

API_EXPORT int diam_avp_u32(const diam_avp_view_t* avp, uint32_t* out);
API_EXPORT int diam_avp_u64(const diam_avp_view_t* avp, uint64_t* out);
API_EXPORT int diam_avp_i32(const diam_avp_view_t* avp, int32_t* out);
API_EXPORT int diam_avp_i64(const diam_avp_view_t* avp, int64_t* out);

/* Address AVP data (RFC 6733 §4.3.1): AddressType(2) | address.
 * Yields the address family and the bare address bytes. */
API_EXPORT int diam_avp_addr(const diam_avp_view_t* avp, uint16_t* family,
                             const uint8_t** addr, uint32_t* addr_len);

/* ---- AVP write (encode into caller's buffer) ---- */

API_EXPORT void diam_wbuf_init(diam_wbuf_t* w, uint8_t* buf, size_t cap);

/* Append one complete AVP. When vendor_id != 0 the V bit is set and the
 * Vendor-ID octets are written; flags may add M/P. A V bit in flags
 * with vendor_id == 0 is DIAM_E_INVAL. Returns 0 or a negative
 * diam_err_t. */
API_EXPORT int diam_avp_put(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                            uint32_t vendor_id, const void* val, uint32_t vlen);

/* Integer/string shortcuts (host -> network byte order). */
API_EXPORT int diam_avp_put_u32(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                uint32_t vendor_id, uint32_t v);
API_EXPORT int diam_avp_put_u64(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                uint32_t vendor_id, uint64_t v);
API_EXPORT int diam_avp_put_i32(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                uint32_t vendor_id, int32_t v);
API_EXPORT int diam_avp_put_i64(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                uint32_t vendor_id, int64_t v);
API_EXPORT int diam_avp_put_str(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                uint32_t vendor_id, const char* s);
API_EXPORT int diam_avp_put_addr(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                                 uint32_t vendor_id, uint16_t family,
                                 const uint8_t* addr, uint32_t addr_len);

/* Grouped AVP: write begin, then any child AVPs, then end. The end call
 * backfills the parent's length and pads to the 4-byte alignment.
 * Begin returns a handle (offset) or a negative error; pass it back to
 * end. */
API_EXPORT int diam_avp_begin(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                              uint32_t vendor_id);
API_EXPORT int diam_avp_end(diam_wbuf_t* w, int handle);

/* Backfill the Message Length field of a header written at hdr_off.
 * Call once all AVPs are written. */
API_EXPORT int diam_hdr_finalize(diam_wbuf_t* w, size_t hdr_off);

#ifdef __cplusplus
}
#endif

#endif /* DIAM_H */
