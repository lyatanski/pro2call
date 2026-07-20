#include "diam.h"
#include "endian.h"

#include <string.h>

/* Diameter AVP wire profile for the generic TLV codec (task/inc/tlv.h). */
static const tlv_prof_t diam_avp_prof = TLV_PROF_DIAMETER;

static int diam_tlv_err(int rc)
{
    switch (rc) {
    case TLV_OK:         return DIAM_OK;
    case TLV_E_OVERFLOW: return DIAM_E_OVERFLOW;
    default:             return DIAM_E_INVAL;
    }
}

/* Raw append between tlv_begin/tlv_end; follows sticky-overflow rules. */
static int wbuf_append(diam_wbuf_t* w, const void* p, size_t n)
{
    const int rc = tlv_wbuf_reserve(w, n);
    if (rc) return rc;
    if (n) memcpy(w->buf + w->off, p, n);
    w->off += n;
    return TLV_OK;
}

int diam_hdr_decode(const uint8_t* buf, size_t len, diam_hdr_t* out)
{
    if (TASK_UNLIKELY(!buf || !out)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(len < DIAM_HDR_LEN)) return DIAM_E_SHORT;

    out->version = buf[0];
    out->length  = be24_load(buf + 1);

    const uint8_t flags = buf[4];
    out->request        = (flags & DIAM_HDR_F_REQUEST) != 0;
    out->proxiable      = (flags & DIAM_HDR_F_PROXIABLE) != 0;
    out->error          = (flags & DIAM_HDR_F_ERROR) != 0;
    out->retransmit     = (flags & DIAM_HDR_F_RETRANSMIT) != 0;

    out->cmd_code = be24_load(buf + 5);
    out->app_id   = be32_load(buf + 8);
    out->hbh      = be32_load(buf + 12);
    out->e2e      = be32_load(buf + 16);

    if (TASK_UNLIKELY(out->version != DIAM_VERSION)) return DIAM_E_VERSION;

    /* Message Length covers the whole message, header included, and is
     * a multiple of 4 (RFC 6733 §3). It must fit in the buffer. */
    if (TASK_UNLIKELY(out->length < DIAM_HDR_LEN)) return DIAM_E_LENGTH;
    if (TASK_UNLIKELY(out->length > len)) return DIAM_E_LENGTH;
    if (TASK_UNLIKELY(out->length & 3u)) return DIAM_E_LENGTH;

    return DIAM_HDR_LEN;
}

int diam_hdr_encode(uint8_t* buf, size_t cap, const diam_hdr_t* hdr)
{
    if (TASK_UNLIKELY(!buf || !hdr)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(cap < DIAM_HDR_LEN)) return DIAM_E_OVERFLOW;
    if (TASK_UNLIKELY(hdr->length > 0x00FFFFFFu)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(hdr->cmd_code > 0x00FFFFFFu)) return DIAM_E_INVAL;

    uint8_t flags = 0;
    if (hdr->request) flags |= DIAM_HDR_F_REQUEST;
    if (hdr->proxiable) flags |= DIAM_HDR_F_PROXIABLE;
    if (hdr->error) flags |= DIAM_HDR_F_ERROR;
    if (hdr->retransmit) flags |= DIAM_HDR_F_RETRANSMIT;

    buf[0] = DIAM_VERSION;
    be24_store(buf + 1, hdr->length);
    buf[4] = flags;
    be24_store(buf + 5, hdr->cmd_code);
    be32_store(buf + 8, hdr->app_id);
    be32_store(buf + 12, hdr->hbh);
    be32_store(buf + 16, hdr->e2e);

    return DIAM_HDR_LEN;
}

void diam_avp_iter_init(diam_avp_iter_t* it, const uint8_t* payload, size_t len)
{
    tlv_iter_init(it, &diam_avp_prof, payload, len);
}

bool diam_avp_iter_next(diam_avp_iter_t* it, diam_avp_view_t* out)
{
    tlv_view_t v;
    if (!tlv_iter_next(it, &v)) return false;

    out->code  = v.type;
    out->flags = v.meta;
    if (v.meta & DIAM_AVP_F_VENDOR) {
        if (TASK_UNLIKELY(v.len < 4)) return false; /* malformed */
        out->vendor_id = be32_load(v.value);
        out->value     = v.value + 4;
        out->len       = v.len - 4;
    } else {
        out->vendor_id = 0;
        out->value     = v.value;
        out->len       = v.len;
    }
    return true;
}

void diam_avp_iter_grouped(diam_avp_iter_t* it, const diam_avp_view_t* grouped)
{
    tlv_iter_init(it, &diam_avp_prof, grouped->value, grouped->len);
}

bool diam_avp_find(const uint8_t* payload, size_t len, uint32_t code,
                   uint32_t vendor_id, diam_avp_view_t* out)
{
    diam_avp_iter_t it;
    diam_avp_iter_init(&it, payload, len);
    while (diam_avp_iter_next(&it, out)) {
        if (out->code == code && out->vendor_id == vendor_id) return true;
    }
    return false;
}

/* ---- Typed data readers ---- */

int diam_avp_u32(const diam_avp_view_t* avp, uint32_t* out)
{
    if (TASK_UNLIKELY(!avp || !out)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(avp->len != 4)) return DIAM_E_TYPE;
    *out = be32_load(avp->value);
    return DIAM_OK;
}

int diam_avp_u64(const diam_avp_view_t* avp, uint64_t* out)
{
    if (TASK_UNLIKELY(!avp || !out)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(avp->len != 8)) return DIAM_E_TYPE;
    *out = be64_load(avp->value);
    return DIAM_OK;
}

int diam_avp_i32(const diam_avp_view_t* avp, int32_t* out)
{
    uint32_t  u;
    const int rc = diam_avp_u32(avp, &u);
    if (rc) return rc;
    *out = (int32_t)u;
    return DIAM_OK;
}

int diam_avp_i64(const diam_avp_view_t* avp, int64_t* out)
{
    uint64_t  u;
    const int rc = diam_avp_u64(avp, &u);
    if (rc) return rc;
    *out = (int64_t)u;
    return DIAM_OK;
}

int diam_avp_addr(const diam_avp_view_t* avp, uint16_t* family,
                  const uint8_t** addr, uint32_t* addr_len)
{
    if (TASK_UNLIKELY(!avp || !family || !addr || !addr_len))
        return DIAM_E_INVAL;
    if (TASK_UNLIKELY(avp->len < 2)) return DIAM_E_TYPE;
    *family   = be16_load(avp->value);
    *addr     = avp->value + 2;
    *addr_len = avp->len - 2;
    return DIAM_OK;
}

/* ---- AVP write ---- */

void diam_wbuf_init(diam_wbuf_t* w, uint8_t* buf, size_t cap)
{
    tlv_wbuf_init(w, buf, cap);
}

/* Normalize flags/vendor: a non-zero vendor id implies the V bit; a V
 * bit without a vendor id is an error. */
static int diam_flags(uint8_t* flags, uint32_t vendor_id)
{
    if (vendor_id != 0) {
        *flags |= DIAM_AVP_F_VENDOR;
    } else if (*flags & DIAM_AVP_F_VENDOR) {
        return DIAM_E_INVAL;
    }
    return DIAM_OK;
}

int diam_avp_put(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                 uint32_t vendor_id, const void* val, uint32_t vlen)
{
    if (TASK_UNLIKELY(!w || (!val && vlen))) return DIAM_E_INVAL;
    const int rc = diam_flags(&flags, vendor_id);
    if (rc) return rc;

    if (vendor_id == 0)
        return diam_tlv_err(tlv_put(w, &diam_avp_prof, code, flags, val, vlen));

    const int h = tlv_begin(w, &diam_avp_prof, code, flags);
    if (h < 0) return diam_tlv_err(h);

    uint8_t vid[4];
    be32_store(vid, vendor_id);
    int arc = wbuf_append(w, vid, sizeof vid);
    if (!arc) arc = wbuf_append(w, val, vlen);
    if (arc) return diam_tlv_err(arc);

    return diam_tlv_err(tlv_end(w, &diam_avp_prof, h));
}

int diam_avp_put_u32(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                     uint32_t vendor_id, uint32_t v)
{
    uint8_t b[4];
    be32_store(b, v);
    return diam_avp_put(w, code, flags, vendor_id, b, sizeof b);
}

int diam_avp_put_u64(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                     uint32_t vendor_id, uint64_t v)
{
    uint8_t b[8];
    be64_store(b, v);
    return diam_avp_put(w, code, flags, vendor_id, b, sizeof b);
}

int diam_avp_put_i32(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                     uint32_t vendor_id, int32_t v)
{
    return diam_avp_put_u32(w, code, flags, vendor_id, (uint32_t)v);
}

int diam_avp_put_i64(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                     uint32_t vendor_id, int64_t v)
{
    return diam_avp_put_u64(w, code, flags, vendor_id, (uint64_t)v);
}

int diam_avp_put_str(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                     uint32_t vendor_id, const char* s)
{
    if (TASK_UNLIKELY(!s)) return DIAM_E_INVAL;
    const size_t n = strlen(s);
    if (TASK_UNLIKELY(n > UINT32_MAX)) return DIAM_E_INVAL;
    return diam_avp_put(w, code, flags, vendor_id, s, (uint32_t)n);
}

int diam_avp_put_addr(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                      uint32_t vendor_id, uint16_t family, const uint8_t* addr,
                      uint32_t addr_len)
{
    if (TASK_UNLIKELY(!addr && addr_len)) return DIAM_E_INVAL;

    const int h = diam_avp_begin(w, code, flags, vendor_id);
    if (h < 0) return h;

    uint8_t fam[2];
    be16_store(fam, family);
    int rc = wbuf_append(w, fam, sizeof fam);
    if (!rc) rc = wbuf_append(w, addr, addr_len);
    if (rc) return diam_tlv_err(rc);

    return diam_avp_end(w, h);
}

int diam_avp_begin(diam_wbuf_t* w, uint32_t code, uint8_t flags,
                   uint32_t vendor_id)
{
    if (TASK_UNLIKELY(!w)) return DIAM_E_INVAL;
    const int rc = diam_flags(&flags, vendor_id);
    if (rc) return rc;

    const int h = tlv_begin(w, &diam_avp_prof, code, flags);
    if (h < 0) return diam_tlv_err(h);

    if (vendor_id != 0) {
        uint8_t vid[4];
        be32_store(vid, vendor_id);
        const int arc = wbuf_append(w, vid, sizeof vid);
        if (arc) return diam_tlv_err(arc);
    }
    return h;
}

int diam_avp_end(diam_wbuf_t* w, int handle)
{
    return diam_tlv_err(tlv_end(w, &diam_avp_prof, handle));
}

int diam_hdr_finalize(diam_wbuf_t* w, size_t hdr_off)
{
    if (TASK_UNLIKELY(!w)) return DIAM_E_INVAL;
    if (TASK_UNLIKELY(w->overflow)) return DIAM_E_OVERFLOW;
    if (TASK_UNLIKELY(hdr_off + DIAM_HDR_LEN > w->off)) return DIAM_E_INVAL;

    const size_t total = w->off - hdr_off;
    if (TASK_UNLIKELY(total > 0x00FFFFFFu)) return DIAM_E_OVERFLOW;

    be24_store(w->buf + hdr_off + 1, (uint32_t)total);
    return DIAM_OK;
}
