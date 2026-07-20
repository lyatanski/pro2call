#include "gtp1.h"
#include "endian.h"

#include <string.h>

/* Octet 1: version(3) | PT(1) | spare(1) | E(1) | S(1) | PN(1) */
enum { FLAG_PN = 0x01, FLAG_S = 0x02, FLAG_E = 0x04, FLAG_PT = 0x10 };

int gtp1_hdr_decode(const uint8_t* buf, size_t len, gtp1_hdr_t* out)
{
    if (TASK_UNLIKELY(!buf || !out)) return GTP1_E_INVAL;
    if (TASK_UNLIKELY(len < GTP1_HDR_MIN)) return GTP1_E_SHORT;

    const uint8_t flags = buf[0];
    out->version        = (uint8_t)(flags >> 5);
    if (TASK_UNLIKELY(out->version != GTP1_VERSION)) return GTP1_E_VERSION;
    out->pt = (flags & FLAG_PT) != 0;
    if (TASK_UNLIKELY(!out->pt)) return GTP1_E_VERSION; /* GTP', not GTP */

    out->e            = (flags & FLAG_E) != 0;
    out->s            = (flags & FLAG_S) != 0;
    out->pn           = (flags & FLAG_PN) != 0;
    out->message_type = buf[1];
    out->length       = be16_load(buf + 2);
    out->teid         = be32_load(buf + 4);
    out->sequence     = 0;
    out->npdu         = 0;
    out->next_ext     = 0;

    const size_t total = (size_t)GTP1_HDR_MIN + out->length;
    if (TASK_UNLIKELY(total > len)) return GTP1_E_LENGTH;

    size_t off = GTP1_HDR_MIN;
    if (out->e || out->s || out->pn) {
        /* all four optional octets are present if any flag is set */
        if (TASK_UNLIKELY(total < GTP1_HDR_CTRL)) return GTP1_E_LENGTH;
        if (out->s) out->sequence = be16_load(buf + 8);
        if (out->pn) out->npdu = buf[10];
        off = GTP1_HDR_CTRL;

        uint8_t next  = out->e ? buf[11] : 0;
        out->next_ext = next;
        while (next != 0) {
            /* ext header: len(1, 4-octet units) | content | next(1) */
            if (TASK_UNLIKELY(off >= total)) return GTP1_E_LENGTH;
            const size_t n = (size_t)buf[off] * 4;
            if (TASK_UNLIKELY(n == 0 || off + n > total)) return GTP1_E_LENGTH;
            next = buf[off + n - 1];
            off += n;
        }
    }
    return (int)off;
}

int gtp1_hdr_encode(uint8_t* buf, size_t cap, const gtp1_hdr_t* hdr)
{
    if (TASK_UNLIKELY(!buf || !hdr)) return GTP1_E_INVAL;
    if (TASK_UNLIKELY(cap < GTP1_HDR_CTRL)) return GTP1_E_OVERFLOW;

    buf[0] = (uint8_t)((GTP1_VERSION << 5) | FLAG_PT | FLAG_S);
    buf[1] = hdr->message_type;
    be16_store(buf + 2, hdr->length);
    be32_store(buf + 4, hdr->teid);
    be16_store(buf + 8, hdr->sequence);
    buf[10] = 0; /* N-PDU number, meaningless without PN */
    buf[11] = 0; /* no extension headers */
    return GTP1_HDR_CTRL;
}

int gtp1_hdr_finalize(gtp1_wbuf_t* w, size_t hdr_off)
{
    if (TASK_UNLIKELY(!w)) return GTP1_E_INVAL;
    if (TASK_UNLIKELY(w->overflow)) return GTP1_E_OVERFLOW;
    if (TASK_UNLIKELY(w->off < hdr_off + GTP1_HDR_MIN)) return GTP1_E_INVAL;

    const size_t payload = w->off - hdr_off - GTP1_HDR_MIN;
    if (TASK_UNLIKELY(payload > UINT16_MAX)) return GTP1_E_OVERFLOW;
    be16_store(w->buf + hdr_off + 2, (uint16_t)payload);
    return GTP1_OK;
}

void gtp1_ie_iter_init(gtp1_ie_iter_t* it, const uint8_t* payload, size_t len,
                       const uint16_t tvlen[128])
{
    it
        ->cur = payload;
    it
        ->end = payload + len;
    it
        ->tvlen = tvlen;
}

bool gtp1_ie_iter_next(gtp1_ie_iter_t* it, gtp1_ie_view_t* out)
{
    const size_t avail = (size_t)(it->end - it->cur);
    if (avail < 1) return false;

    const uint8_t type = it->cur[0];
    if (type < 0x80) {
        /* TV: fixed length from the table; unknown type ends the walk */
        const uint16_t vlen = it->tvlen ? it->tvlen[type] : 0;
        if (TASK_UNLIKELY(vlen == 0 || avail < 1u + (size_t)vlen)) return false;
        out->type  = type;
        out->len   = vlen;
        out->value = it->cur + 1;
        it
            ->cur += 1u + vlen;
        return true;
    }

    if (TASK_UNLIKELY(avail < GTP1_TLV_HDR_LEN)) return false;
    const uint16_t vlen = be16_load(it->cur + 1);
    if (TASK_UNLIKELY(vlen > avail - GTP1_TLV_HDR_LEN)) return false;
    out->type  = type;
    out->len   = vlen;
    out->value = it->cur + GTP1_TLV_HDR_LEN;
    it
        ->cur += (size_t)GTP1_TLV_HDR_LEN + vlen;
    return true;
}

void gtp1_wbuf_init(gtp1_wbuf_t* w, uint8_t* buf, size_t cap)
{
    tlv_wbuf_init(w, buf, cap);
}

int gtp1_ie_put_tv(gtp1_wbuf_t* w, uint8_t type, const void* val, uint16_t vlen)
{
    if (TASK_UNLIKELY(!w || (!val && vlen))) return GTP1_E_INVAL;
    if (tlv_wbuf_reserve(w, 1u + (size_t)vlen)) return GTP1_E_OVERFLOW;

    uint8_t* q = w->buf + w->off;
    q[0]       = type;
    memcpy(q + 1, val, vlen);
    w->off += 1u + (size_t)vlen;
    return GTP1_OK;
}

int gtp1_ie_put_tlv(gtp1_wbuf_t* w, uint8_t type, const void* val,
                    uint16_t vlen)
{
    if (TASK_UNLIKELY(!w || (!val && vlen))) return GTP1_E_INVAL;
    if (tlv_wbuf_reserve(w, (size_t)GTP1_TLV_HDR_LEN + vlen))
        return GTP1_E_OVERFLOW;

    uint8_t* q = w->buf + w->off;
    q[0]       = type;
    be16_store(q + 1, vlen);
    memcpy(q + GTP1_TLV_HDR_LEN, val, vlen);
    w->off += (size_t)GTP1_TLV_HDR_LEN + vlen;
    return GTP1_OK;
}

int gtp1_ie_put_tv_u8(gtp1_wbuf_t* w, uint8_t type, uint8_t v)
{
    return gtp1_ie_put_tv(w, type, &v, 1);
}

int gtp1_ie_put_tv_u16(gtp1_wbuf_t* w, uint8_t type, uint16_t v)
{
    uint8_t b[2];
    be16_store(b, v);
    return gtp1_ie_put_tv(w, type, b, sizeof b);
}

int gtp1_ie_put_tv_u32(gtp1_wbuf_t* w, uint8_t type, uint32_t v)
{
    uint8_t b[4];
    be32_store(b, v);
    return gtp1_ie_put_tv(w, type, b, sizeof b);
}

int gtp1_ie_put_tlv_u8(gtp1_wbuf_t* w, uint8_t type, uint8_t v)
{
    return gtp1_ie_put_tlv(w, type, &v, 1);
}

int gtp1_ie_put_tlv_u16(gtp1_wbuf_t* w, uint8_t type, uint16_t v)
{
    uint8_t b[2];
    be16_store(b, v);
    return gtp1_ie_put_tlv(w, type, b, sizeof b);
}

int gtp1_ie_put_tlv_u32(gtp1_wbuf_t* w, uint8_t type, uint32_t v)
{
    uint8_t b[4];
    be32_store(b, v);
    return gtp1_ie_put_tlv(w, type, b, sizeof b);
}
