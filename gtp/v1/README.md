# gtp1

GTPv1-C codec — 3GPP TS 29.060.

Decode is zero-copy: an iterator yields views into the caller's buffer.
Encode writes directly into a caller-supplied buffer; no allocation.

GTPv1 mixes two IE encodings, which is why this module keeps its own
iterator instead of a `tlv.h` profile (the write buffer is still the
shared `tlv_wbuf_t`):

- **TV** (type < 128): a type octet followed by a fixed-length value
  the receiver must already know. The iterator takes a 128-entry
  value-length table; an unknown TV type ends the walk, since nothing
  after it can be framed.
- **TLV** (type >= 128): type, 2-byte big-endian length, value.
  Unknown TLV IEs are skippable.

The full TV length table of the pinned spec release is generated as
`gtp1_tv_len` (`gtp1_msg.h`).

## Build

```cmake
add_subdirectory(gtp/v1)
target_link_libraries(your_target PRIVATE gtp1)
```

```c
#include "gtp1.h"      /* header + IE codec */
#include "gtp1_msg.h"  /* typed messages + gtp1_tv_len (generated) */
```

## Encode

Initialize a `gtp1_wbuf_t` over a caller-supplied buffer, emit the
header, append IEs, then backfill the header's Length field with
`gtp1_hdr_finalize`. Write-buffer errors are sticky, so return codes
can be checked once at the end. `gtp1_hdr_encode` always writes the
12-byte control-plane header (S set, E/PN clear).

TS 29.060 §7.1 requires IEs in ascending type order within a message —
the typed message layer does this for you; keep it in mind when using
the IE layer directly.

```c
uint8_t out[64];
gtp1_wbuf_t w;
gtp1_wbuf_init(&w, out, sizeof out);

gtp1_hdr_t hdr = {
    .message_type = GTP1_MT_ECHO_REQUEST,
    .teid         = 0,          /* echo: always 0 */
    .sequence     = 0x0001,
};
size_t hdr_off = w.off;
gtp1_hdr_encode(w.buf + w.off, w.cap - w.off, &hdr);
w.off += GTP1_HDR_CTRL;

/* Recovery (type 14 < 128) is a TV IE with a 1-byte value */
gtp1_ie_put_tv_u8(&w, GTP1_IE_RECOVERY, 7 /* restart counter */);

if (gtp1_hdr_finalize(&w, hdr_off) != GTP1_OK) {
    /* overflow — buffer was too small */
}
/* Wire bytes: out[0 .. w.off) */
```

The put helpers do not know the TV length table: the caller is
responsible for `vlen` matching the type's fixed length on
`gtp1_ie_put_tv` (e.g. IMSI 8 bytes, RAI 6). The typed layer validates
this and returns `GTP1_E_INVAL` on mismatch.

## Decode

Decode the header first — it returns the offset where IEs begin (8,
12, or beyond, since it also skips any extension-header chain) — then
walk IEs with the TV table:

```c
gtp1_hdr_t hdr;
int off = gtp1_hdr_decode(buf, len, &hdr);
if (off < 0) return off;                 /* gtp1_err_t */
/* total wire size is 8 + hdr.length */

gtp1_ie_iter_t it;
gtp1_ie_iter_init(&it, buf + off, 8 + (size_t)hdr.length - off, gtp1_tv_len);

gtp1_ie_view_t ie;
while (gtp1_ie_iter_next(&it, &ie)) {
    if (ie.type == GTP1_IE_RECOVERY && ie.len == 1) {
        uint8_t peer_restart_counter = ie.value[0];
    }
}
```

`gtp1_ie_view_t::value` points into the input buffer; keep the buffer
valid while views are in use.

## Typed messages

`gtp1_msg.h` (generated at build time by `gtp/gen` from the curated
grammar in `gtp/gen/gtp1.go`) provides struct-level encode/decode for
Echo Request/Response (§7.2.1/§7.2.2) and Create / Update / Delete PDP
Context Request/Response (§7.3.1–§7.3.6):

```c
gtp1_cpc_req_t req;
memset(&req, 0, sizeof req);
req.sequence   = 0x0042;
req.teid       = 0;                 /* initial request */
req.imsi       = (gtp1_view_t){ imsi, sizeof imsi };   /* 8 bytes BCD */
req.teid_data  = 0x000000AA;
req.has_teid_ctrl = true;
req.teid_ctrl  = 0x000000BB;
req.nsapi      = 5;
req.apn        = (gtp1_view_t){ apn, sizeof apn };     /* label-encoded */
req.qos_profile = (gtp1_view_t){ qos, sizeof qos };
req.sgsn_addr_ctrl = (gtp1_view_t){ sgsn_c, 4 };
req.sgsn_addr_user = (gtp1_view_t){ sgsn_u, 4 };
req.end_user_address = (gtp1_view_t){ eua, sizeof eua };

uint8_t out[512];
int n = gtp1_cpc_req_encode(out, sizeof out, &req);
if (n < 0) { /* gtp1_err_t */ }
```

Field conventions match gtp2: zero-copy `gtp1_view_t` fields with
`data == NULL` (or an unset `has_*` flag) marking absence. IEs a
message can carry twice with positional meaning get one field per
occurrence (`teid_data`/`teid_ctrl`, `sgsn_addr_ctrl`/`sgsn_addr_user`,
`nsapi`/`linked_nsapi`).

## Errors

All entry points return `0`/byte counts on success or a negative
`gtp1_err_t`; the codes mirror gtp2's (`GTP1_E_SHORT`,
`GTP1_E_VERSION` — also raised for GTP' —, `GTP1_E_LENGTH`,
`GTP1_E_OVERFLOW`, `GTP1_E_INVAL`, `GTP1_E_MISSING`). Write-buffer
overflow is sticky and reported once by `gtp1_hdr_finalize`.

## Thread safety

No global state. Distinct iterators/write buffers may be used
concurrently from different threads.
