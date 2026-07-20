# gtp2

GTPv2-C codec — 3GPP TS 29.274.

Decode is zero-copy: an iterator yields views into the caller's buffer.
Encode writes directly into a caller-supplied buffer; no allocation.
Grouped IEs are supported on both paths.

The IE layer is the generic TLV codec from `task/inc/tlv.h` bound to
the GTPv2-C wire profile (`TLV_PROF_GTP2C`); the same codec carries
Diameter AVP and netlink attribute profiles for reuse elsewhere.

## Build

Add as a CMake subdirectory and link the target:

```cmake
add_subdirectory(gtp/v2)
target_link_libraries(your_target PRIVATE gtp2)
```

The codec (header + IE encode/decode) lives in `gtp2.h`; typed message
structs are layered on top of it in `gtp2_msg.h`:

```c
#include "gtp2.h"      /* header + IE codec */
#include "gtp2_msg.h"  /* typed Create Session Request/Response */
```

## Encode

Initialize a `gtp2_wbuf_t` over a caller-supplied buffer, emit the header,
append IEs, then backfill the header's Length field with `gtp2_hdr_finalize`.
Errors on the write buffer are sticky (see [Errors](#errors)), so individual
return codes can be ignored and checked once at the end.

### Example 1 — Echo Request

Echo Request (§7.1.1) uses the no-TEID header and carries a single Recovery IE.

```c
uint8_t out[64];
gtp2_wbuf_t w;
gtp2_wbuf_init(&w, out, sizeof out);

gtp2_hdr_t hdr = {
    .has_teid     = false,
    .message_type = GTP2_MT_ECHO_REQUEST,
    .sequence     = 0x000001,
};
size_t hdr_off = w.off;
gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &hdr);
w.off += GTP2_HDR_FIXED_LEN;

gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, 7 /* restart counter */);

if (gtp2_hdr_finalize(&w, hdr_off) != GTP2_OK) {
    /* overflow — buffer was too small */
}
/* Wire bytes: out[0 .. w.off) */
```

Integer shortcuts (`gtp2_ie_put_u8/u16/u32`) write the value in network byte
order. For arbitrary payloads, use `gtp2_ie_put(w, type, instance, val, vlen)`.

### Example 2 — Create Session Request

Create Session Request (§7.2.1) uses the with-TEID header and combines flat IEs
with a grouped Bearer Context. `gtp2_ie_begin` returns a handle; pass it to
`gtp2_ie_end` after the children are written and the parent's length is
backfilled. Grouped IEs may be nested.

```c
/* IMSI 234150999999999, BCD-encoded little-nibble-first. */
static const uint8_t imsi[]  = { 0x32, 0x43, 0x51, 0x90, 0x99, 0x99, 0x99, 0xF9 };
/* MCC 234 / MNC 15 in Serving Network format. */
static const uint8_t plmn[]  = { 0x32, 0xF4, 0x51 };
/* F-TEID: V4=1, IF_TYPE=10 (S11 MME GTP-C), TEID, IPv4. */
static const uint8_t ftc[]   = {
    0x8A,                            /* V4=1, V6=0, IF_TYPE=10 */
    0xDE, 0xAD, 0xBE, 0xEF,          /* TEID */
    0x0A, 0x00, 0x00, 0x01           /* 10.0.0.1 */
};

uint8_t out[512];
gtp2_wbuf_t w;
gtp2_wbuf_init(&w, out, sizeof out);

gtp2_hdr_t hdr = {
    .has_teid     = true,
    .message_type = GTP2_MT_CREATE_SESSION_REQUEST,
    .teid         = 0,               /* unknown on initial attach */
    .sequence     = 0x000042,
};
size_t hdr_off = w.off;
gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &hdr);
w.off += GTP2_HDR_WITH_TEID;

gtp2_ie_put   (&w, GTP2_IE_IMSI,            0, imsi, sizeof imsi);
gtp2_ie_put   (&w, GTP2_IE_SERVING_NETWORK, 0, plmn, sizeof plmn);
gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE,        0, 6 /* EUTRAN */);
gtp2_ie_put   (&w, GTP2_IE_FTEID,           0, ftc,  sizeof ftc);

int bc = gtp2_ie_begin(&w, GTP2_IE_BEARER_CONTEXT, 0);
gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0, 5);
gtp2_ie_end(&w, bc);

if (gtp2_hdr_finalize(&w, hdr_off) != GTP2_OK) {
    /* overflow */
}
/* Wire bytes: out[0 .. w.off) */
```

## Decode

Decode the header first, then walk IEs over the payload that follows it.
`gtp2_ie_view_t::value` is a pointer into the original input buffer; the
buffer must remain valid for as long as any view referencing it is in use.

### Example 1 — Echo Response

Echo Response (§7.1.2) uses the no-TEID header and carries a Recovery IE.

```c
gtp2_hdr_t hdr;
int hlen = gtp2_hdr_decode(buf, len, &hdr);
if (hlen < 0) return hlen;   /* gtp2_err_t */
if (hdr.message_type != GTP2_MT_ECHO_RESPONSE) return -1;

const uint8_t* payload     = buf + hlen;
size_t         payload_len = (size_t)hdr.length + 4 - hlen;

gtp2_ie_iter_t it;
gtp2_ie_iter_init(&it, payload, payload_len);

uint8_t peer_restart_counter = 0;
gtp2_ie_view_t ie;
while (gtp2_ie_iter_next(&it, &ie)) {
    if (ie.type == GTP2_IE_RECOVERY && ie.len == 1) {
        peer_restart_counter = ie.value[0];
    }
}
```

### Example 2 — Create Session Response

Create Session Response (§7.2.2) uses the with-TEID header and combines flat IEs
with a grouped Bearer Context. Nest a second iterator over the grouped IE's
value range to walk its children.

```c
gtp2_hdr_t hdr;
int hlen = gtp2_hdr_decode(buf, len, &hdr);
if (hlen < 0) return hlen;
if (hdr.message_type != GTP2_MT_CREATE_SESSION_RESPONSE) return -1;

gtp2_ie_iter_t it;
gtp2_ie_iter_init(&it, buf + hlen, (size_t)hdr.length + 4 - hlen);

uint8_t  cause     = 0;
uint32_t cp_teid   = 0;       /* PGW S5/S8 control-plane TEID */
uint8_t  ebi       = 0;
uint32_t u_teid    = 0;       /* SGW S1-U user-plane TEID */

gtp2_ie_view_t ie;
while (gtp2_ie_iter_next(&it, &ie)) {
    switch (ie.type) {
    case GTP2_IE_CAUSE:
        if (ie.len >= 1) cause = ie.value[0];
        break;

    case GTP2_IE_FTEID:
        /* F-TEID layout: flags(1) | TEID(4) | IPv4(4) [| IPv6(16)] */
        if (ie.len >= 5)
            cp_teid = ((uint32_t)ie.value[1] << 24) |
                      ((uint32_t)ie.value[2] << 16) |
                      ((uint32_t)ie.value[3] <<  8) |
                       (uint32_t)ie.value[4];
        break;

    case GTP2_IE_BEARER_CONTEXT: {
        gtp2_ie_iter_t inner;
        gtp2_ie_iter_grouped(&inner, &ie);
        gtp2_ie_view_t child;
        while (gtp2_ie_iter_next(&inner, &child)) {
            if (child.type == GTP2_IE_EBI && child.len == 1) {
                ebi = child.value[0];
            } else if (child.type == GTP2_IE_FTEID && child.len >= 5) {
                u_teid = ((uint32_t)child.value[1] << 24) |
                         ((uint32_t)child.value[2] << 16) |
                         ((uint32_t)child.value[3] <<  8) |
                          (uint32_t)child.value[4];
            }
        }
        break;
    }
    }
}
```

## Typed messages

`gtp2_msg.h` provides struct-level encode/decode for Create Session
Request/Response (TS 29.274 §7.2.1/§7.2.2), Create Bearer
Request/Response (§7.2.3/§7.2.4), Modify Bearer Request/Response
(§7.2.7/§7.2.8), Delete Session Request/Response (§7.2.9/§7.2.10), and
Update Bearer Request/Response (§7.2.15/§7.2.16), including the Bearer
Context grouped IE and codecs for its composite members (F-TEID, Bearer
QoS, PAA, APN-AMBR).
Variable-length fields stay zero-copy `gtp2_view_t` ranges; `data == NULL`
(or an unset `has_*` flag) marks a field absent.

```c
gtp2_cs_req_t req;
memset(&req, 0, sizeof req);
req.sequence     = 0x000042;
req.imsi         = (gtp2_view_t){ imsi, sizeof imsi };
req.apn          = (gtp2_view_t){ apn, sizeof apn };   /* label-encoded */
req.rat_type     = GTP2_RAT_EUTRAN;
req.sender_fteid = (gtp2_fteid_t){
    .v4 = true, .if_type = GTP2_IF_S11_MME,
    .teid = 0x11111111, .addr4 = { 10, 0, 0, 1 },
};
req.n_bearers    = 1;
req.bearer[0].ebi = 5;

uint8_t out[512];
int n = gtp2_cs_req_encode(out, sizeof out, &req);
if (n < 0) { /* gtp2_err_t */ }

gtp2_cs_rsp_t rsp;
int consumed = gtp2_cs_rsp_decode(in, in_len, &rsp);
if (consumed < 0) { /* gtp2_err_t */ }
/* rsp.cause, rsp.sender_fteid, rsp.bearer[0].fteid[0], ... */
```

Encode validates mandatory fields (`GTP2_E_MISSING`); decode skips unknown
IEs and returns the message's total byte count, so a piggybacked message
can be decoded from `buf + consumed`.

## Errors

All entry points return `0` on success or a negative `gtp2_err_t`. Decode
entry points additionally return positive byte counts on success.

| Code               | Meaning                                       |
| ------------------ | --------------------------------------------- |
| `GTP2_E_SHORT`     | input buffer truncated                        |
| `GTP2_E_VERSION`   | not GTPv2                                     |
| `GTP2_E_LENGTH`    | header length field inconsistent with buffer  |
| `GTP2_E_OVERFLOW`  | write buffer too small                        |
| `GTP2_E_INVAL`     | invalid argument                              |

`gtp2_wbuf_t` overflow is sticky: once any write exceeds capacity, every
subsequent call returns `GTP2_E_OVERFLOW`, so it is safe to chain calls
and check only at the end.

## Thread safety

No global state. Distinct `gtp2_ie_iter_t` / `gtp2_wbuf_t` instances may be
used concurrently from different threads.
