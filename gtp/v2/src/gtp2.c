#include "gtp2.h"
#include "endian.h"

#include <string.h>

/* GTPv2-C IE wire profile for the generic TLV codec (task/inc/tlv.h). */
static const tlv_prof_t gtp2_ie_prof = TLV_PROF_GTP2C;

static int gtp2_tlv_err(int rc)
{
    switch (rc) {
    case TLV_OK:         return GTP2_OK;
    case TLV_E_OVERFLOW: return GTP2_E_OVERFLOW;
    default:             return GTP2_E_INVAL;
    }
}

int gtp2_hdr_decode(const uint8_t* buf, size_t len, gtp2_hdr_t* out)
{
    if (TASK_UNLIKELY(!buf || !out)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(len < GTP2_HDR_FIXED_LEN)) return GTP2_E_SHORT;

    const uint8_t flags = buf[0];
    out->version        = (uint8_t)((flags >> 5) & 0x07);
    out->piggyback      = (flags & 0x10) != 0;
    out->has_teid       = (flags & 0x08) != 0;
    out->has_mp         = (flags & 0x04) != 0;
    out->message_type   = buf[1];
    out->length         = be16_load(buf + 2);

    if (TASK_UNLIKELY(out->version != GTP2_VERSION)) return GTP2_E_VERSION;

    const size_t hdr_len =
        out->has_teid ? GTP2_HDR_WITH_TEID : GTP2_HDR_FIXED_LEN;
    if (TASK_UNLIKELY(len < hdr_len)) return GTP2_E_SHORT;

    /* Length covers everything from octet 5 onward. The total message
     * is therefore length + 4 bytes; it must fit in buf and cover at
     * least the rest of the header. */
    const size_t total = (size_t)out->length + 4;
    if (TASK_UNLIKELY(total > len)) return GTP2_E_LENGTH;
    if (TASK_UNLIKELY(total < hdr_len)) return GTP2_E_LENGTH;

    const uint8_t* p = buf + 4;
    if (out->has_teid) {
        out->teid = be32_load(p);
        p += 4;
    } else {
        out->teid = 0;
    }
    out->sequence = be24_load(p);
    p += 3;
    out->priority = out->has_mp ? (uint8_t)((p[0] >> 4) & 0x0F) : 0;

    return (int)hdr_len;
}

int gtp2_hdr_encode(uint8_t* buf, size_t cap, const gtp2_hdr_t* hdr)
{
    if (TASK_UNLIKELY(!buf || !hdr)) return GTP2_E_INVAL;
    const size_t hdr_len =
        hdr->has_teid ? GTP2_HDR_WITH_TEID : GTP2_HDR_FIXED_LEN;
    if (TASK_UNLIKELY(cap < hdr_len)) return GTP2_E_OVERFLOW;

    uint8_t flags = (uint8_t)(GTP2_VERSION << 5);
    if (hdr->piggyback) flags |= 0x10;
    if (hdr->has_teid) flags |= 0x08;
    if (hdr->has_mp) flags |= 0x04;

    buf[0] = flags;
    buf[1] = hdr->message_type;
    be16_store(buf + 2, hdr->length);

    uint8_t* p = buf + 4;
    if (hdr->has_teid) {
        be32_store(p, hdr->teid);
        p += 4;
    }
    be24_store(p, hdr->sequence & 0x00FFFFFFu);
    p += 3;
    p[0] = hdr->has_mp ? (uint8_t)((hdr->priority & 0x0F) << 4) : 0;

    return (int)hdr_len;
}

void gtp2_ie_iter_init(gtp2_ie_iter_t* it, const uint8_t* payload, size_t len)
{
    tlv_iter_init(it, &gtp2_ie_prof, payload, len);
}

bool gtp2_ie_iter_next(gtp2_ie_iter_t* it, gtp2_ie_view_t* out)
{
    tlv_view_t v;
    if (!tlv_iter_next(it, &v)) return false;

    out->type     = (uint8_t)v.type;
    out->len      = (uint16_t)v.len;
    out->instance = (uint8_t)(v.meta & 0x0F);
    out->value    = v.value;
    return true;
}

void gtp2_ie_iter_grouped(gtp2_ie_iter_t* it, const gtp2_ie_view_t* grouped)
{
    tlv_iter_init(it, &gtp2_ie_prof, grouped->value, grouped->len);
}

void gtp2_wbuf_init(gtp2_wbuf_t* w, uint8_t* buf, size_t cap)
{
    tlv_wbuf_init(w, buf, cap);
}

int gtp2_ie_put(gtp2_wbuf_t* w, uint8_t type, uint8_t instance, const void* val,
                uint16_t vlen)
{
    return gtp2_tlv_err(
        tlv_put(w, &gtp2_ie_prof, type, (uint8_t)(instance & 0x0F), val, vlen));
}

int gtp2_ie_put_u8(gtp2_wbuf_t* w, uint8_t type, uint8_t instance, uint8_t v)
{
    return gtp2_ie_put(w, type, instance, &v, 1);
}

int gtp2_ie_put_u16(gtp2_wbuf_t* w, uint8_t type, uint8_t instance, uint16_t v)
{
    uint8_t b[2];
    be16_store(b, v);
    return gtp2_ie_put(w, type, instance, b, sizeof b);
}

int gtp2_ie_put_u32(gtp2_wbuf_t* w, uint8_t type, uint8_t instance, uint32_t v)
{
    uint8_t b[4];
    be32_store(b, v);
    return gtp2_ie_put(w, type, instance, b, sizeof b);
}

int gtp2_ie_begin(gtp2_wbuf_t* w, uint8_t type, uint8_t instance)
{
    const int h = tlv_begin(w, &gtp2_ie_prof, type, (uint8_t)(instance & 0x0F));
    return h < 0 ? gtp2_tlv_err(h) : h;
}

int gtp2_ie_end(gtp2_wbuf_t* w, int handle)
{
    return gtp2_tlv_err(tlv_end(w, &gtp2_ie_prof, handle));
}

int gtp2_hdr_finalize(gtp2_wbuf_t* w, size_t hdr_off)
{
    if (TASK_UNLIKELY(w->overflow)) return GTP2_E_OVERFLOW;
    if (TASK_UNLIKELY(hdr_off + GTP2_HDR_FIXED_LEN > w->off))
        return GTP2_E_INVAL;

    const size_t total = w->off - hdr_off;
    if (TASK_UNLIKELY(total < 4)) return GTP2_E_INVAL;

    const size_t length_field = total - 4;
    if (TASK_UNLIKELY(length_field > 0xFFFFu)) return GTP2_E_OVERFLOW;

    be16_store(w->buf + hdr_off + 2, (uint16_t)length_field);
    return GTP2_OK;
}
