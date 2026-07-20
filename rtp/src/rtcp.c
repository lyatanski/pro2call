#include <string.h>

#include "rtp.h"
#include "rtp_intl.h"

/* RTCP compound codec — RFC 3550 §6. Every packet starts with the
 * common 4-byte header (V P C | PT | length in words - 1); the
 * iterator validates it once, the per-type parsers work from the
 * yielded view. */

#define RTCP_HDR_LEN 4

/* ---- compound iteration ---- */

void rtcp_iter_init(rtcp_iter_t* it, const void* buf, size_t len)
{
    it
        ->p = buf;
    it
        ->len = len;
}

int rtcp_iter_next(rtcp_iter_t* it, rtcp_view_t* v)
{
    if (it->len == 0) return 0;
    if (!it->p || it->len < RTCP_HDR_LEN) return RTP_E_SHORT;

    const uint8_t* b = it->p;
    if (b[0] >> 6 != RTP_VERSION) return RTP_E_VERSION;

    size_t plen = ((size_t)rtp_rd16(b + 2) + 1) * 4;
    if (plen > it->len) return RTP_E_SHORT;

    v->type     = b[1];
    v->count    = b[0] & 0x1F;
    v->body     = b + RTCP_HDR_LEN;
    v->body_len = (uint32_t)(plen - RTCP_HDR_LEN);

    if ((b[0] >> 5) & 1) { /* strip padding */
        if (v->body_len == 0) return RTP_E_FORMAT;
        uint8_t npad = b[plen - 1];
        if (npad == 0 || npad > v->body_len) return RTP_E_FORMAT;
        v->body_len -= npad;
    }

    it
        ->p += plen;
    it
        ->len -= plen;
    return 1;
}

/* ---- SR / RR ---- */

#define REPORT_LEN 24

static void report_parse(const uint8_t* b, rtcp_report_t* r)
{
    r->ssrc     = rtp_rd32(b);
    r->fraction = b[4];
    /* 24-bit signed cumulative loss */
    int32_t lost = (int32_t)((uint32_t)b[5] << 16 | (uint32_t)b[6] << 8 | b[7]);
    if (lost & 0x800000) lost -= 0x1000000;
    r->lost     = lost;
    r->last_seq = rtp_rd32(b + 8);
    r->jitter   = rtp_rd32(b + 12);
    r->lsr      = rtp_rd32(b + 16);
    r->dlsr     = rtp_rd32(b + 20);
}

static int rep_parse(const rtcp_view_t* v, rtcp_rep_t* out, bool sr)
{
    uint32_t fixed = sr ? 24 : 4; /* SSRC (+ sender info for an SR) */
    if (v->body_len < fixed + (uint32_t)v->count * REPORT_LEN)
        return RTP_E_SHORT;

    memset(out, 0, sizeof *out);
    out->ssrc = rtp_rd32(v->body);
    if (sr) {
        out->ntp_sec     = rtp_rd32(v->body + 4);
        out->ntp_frac    = rtp_rd32(v->body + 8);
        out->rtp_ts      = rtp_rd32(v->body + 12);
        out->pkt_count   = rtp_rd32(v->body + 16);
        out->octet_count = rtp_rd32(v->body + 20);
    }
    out->count = v->count;
    for (unsigned i = 0; i < v->count; i++)
        report_parse(v->body + fixed + i * REPORT_LEN, &out->reports[i]);
    return RTP_OK;
}

int rtcp_sr_parse(const rtcp_view_t* v, rtcp_rep_t* out)
{
    if (!v || !out) return RTP_E_INVAL;
    if (v->type != RTCP_SR) return RTP_E_FORMAT;
    return rep_parse(v, out, true);
}

int rtcp_rr_parse(const rtcp_view_t* v, rtcp_rep_t* out)
{
    if (!v || !out) return RTP_E_INVAL;
    if (v->type != RTCP_RR) return RTP_E_FORMAT;
    return rep_parse(v, out, false);
}

/* ---- BYE ---- */

int rtcp_bye_parse(const rtcp_view_t* v, rtcp_bye_t* out)
{
    if (!v || !out) return RTP_E_INVAL;
    if (v->type != RTCP_BYE) return RTP_E_FORMAT;
    if (v->body_len < (uint32_t)v->count * 4) return RTP_E_SHORT;

    memset(out, 0, sizeof *out);
    out->count = v->count;
    for (unsigned i = 0; i < v->count; i++)
        out->ssrc[i] = rtp_rd32(v->body + i * 4);

    uint32_t off = (uint32_t)v->count * 4;
    if (v->body_len > off) { /* optional reason */
        uint8_t rlen = v->body[off];
        if (off + 1 + rlen > v->body_len) return RTP_E_FORMAT;
        out->reason.p   = (const char*)v->body + off + 1;
        out->reason.len = rlen;
    }
    return RTP_OK;
}

/* ---- SDES ---- */

int rtcp_sdes_init(const rtcp_view_t* v, rtcp_sdes_iter_t* it)
{
    if (!v || !it) return RTP_E_INVAL;
    if (v->type != RTCP_SDES) return RTP_E_FORMAT;
    it
        ->p = v->body;
    it
        ->len = v->body_len;
    it
        ->ssrc = 0;
    it
        ->chunks_left = v->count;
    it
        ->in_chunk = false;
    return RTP_OK;
}

int rtcp_sdes_next(rtcp_sdes_iter_t* it, uint32_t* ssrc, uint8_t* item,
                   rtp_str_t* value)
{
    for (;;) {
        if (!it->in_chunk) {
            if (it->chunks_left == 0) return 0;
            if (it->len < 4) return RTP_E_SHORT;
            it
                ->ssrc = rtp_rd32(it->p);
            it
                ->p += 4;
            it
                ->len -= 4;
            it
                ->chunks_left--;
            it
                ->in_chunk = true;
        }
        if (it->len < 1) return RTP_E_SHORT;
        uint8_t ty = it->p[0];
        if (ty == RTCP_SDES_END) {
            /* Chunk ends: consume the END octet plus null pad up to
             * the next 32-bit boundary. The item list starts word-
             * aligned, so the remaining length gives the phase. */
            uint32_t skip = ((it->len - 1) & 3) + 1;
            if (skip > it->len) skip = it->len;
            it
                ->p += skip;
            it
                ->len -= skip;
            it
                ->in_chunk = false;
            continue;
        }
        if (it->len < 2 || (uint32_t)2 + it->p[1] > it->len) return RTP_E_SHORT;
        *ssrc      = it->ssrc;
        *item      = ty;
        value->p   = (const char*)it->p + 2;
        value->len = it->p[1];
        it
            ->p += 2 + value->len;
        it
            ->len -= 2 + value->len;
        return 1;
    }
}

/* ---- write ---- */

void rtcp_wbuf_init(rtcp_wbuf_t* w, void* buf, size_t cap)
{
    w->buf      = buf;
    w->cap      = cap;
    w->off      = 0;
    w->overflow = false;
}

/* Reserve n bytes; NULL (and sticky overflow) when they do not fit. */
static uint8_t* put(rtcp_wbuf_t* w, size_t n)
{
    if (w->overflow || w->off + n > w->cap) {
        w->overflow = true;
        return NULL;
    }
    uint8_t* p = w->buf + w->off;
    w->off += n;
    return p;
}

static void hdr(uint8_t* b, uint8_t count, uint8_t type, size_t pkt_len)
{
    b[0] = (uint8_t)(RTP_VERSION << 6 | (count & 0x1F));
    b[1] = type;
    rtp_wr16(b + 2, (uint16_t)(pkt_len / 4 - 1));
}

static void report_write(uint8_t* b, const rtcp_report_t* r)
{
    rtp_wr32(b, r->ssrc);
    b[4]          = r->fraction;
    uint32_t lost = (uint32_t)r->lost & 0xFFFFFF;
    b[5]          = (uint8_t)(lost >> 16);
    b[6]          = (uint8_t)(lost >> 8);
    b[7]          = (uint8_t)lost;
    rtp_wr32(b + 8, r->last_seq);
    rtp_wr32(b + 12, r->jitter);
    rtp_wr32(b + 16, r->lsr);
    rtp_wr32(b + 20, r->dlsr);
}

int rtcp_put_sr(rtcp_wbuf_t* w, uint32_t ssrc, uint32_t ntp_sec,
                uint32_t ntp_frac, uint32_t rtp_ts, uint32_t pkt_count,
                uint32_t octet_count, const rtcp_report_t* reports, unsigned n)
{
    if (n > RTCP_MAX_REPORTS || (n && !reports)) return RTP_E_INVAL;
    size_t   len = RTCP_HDR_LEN + 24 + (size_t)n * REPORT_LEN;
    uint8_t* b   = put(w, len);
    if (!b) return RTP_E_OVERFLOW;
    hdr(b, (uint8_t)n, RTCP_SR, len);
    rtp_wr32(b + 4, ssrc);
    rtp_wr32(b + 8, ntp_sec);
    rtp_wr32(b + 12, ntp_frac);
    rtp_wr32(b + 16, rtp_ts);
    rtp_wr32(b + 20, pkt_count);
    rtp_wr32(b + 24, octet_count);
    for (unsigned i = 0; i < n; i++)
        report_write(b + 28 + i * REPORT_LEN, &reports[i]);
    return RTP_OK;
}

int rtcp_put_rr(rtcp_wbuf_t* w, uint32_t ssrc, const rtcp_report_t* reports,
                unsigned n)
{
    if (n > RTCP_MAX_REPORTS || (n && !reports)) return RTP_E_INVAL;
    size_t   len = RTCP_HDR_LEN + 4 + (size_t)n * REPORT_LEN;
    uint8_t* b   = put(w, len);
    if (!b) return RTP_E_OVERFLOW;
    hdr(b, (uint8_t)n, RTCP_RR, len);
    rtp_wr32(b + 4, ssrc);
    for (unsigned i = 0; i < n; i++)
        report_write(b + 8 + i * REPORT_LEN, &reports[i]);
    return RTP_OK;
}

int rtcp_put_sdes_cname(rtcp_wbuf_t* w, uint32_t ssrc, const char* cname,
                        size_t len)
{
    if (len > 255 || (len && !cname)) return RTP_E_INVAL;
    /* chunk: SSRC + item(2 + len) + END, padded to a word boundary */
    size_t   items = 2 + len + 1;
    size_t   plen  = RTCP_HDR_LEN + 4 + ((items + 3) & ~(size_t)3);
    uint8_t* b     = put(w, plen);
    if (!b) return RTP_E_OVERFLOW;
    memset(b, 0, plen); /* END item + pad */
    hdr(b, 1, RTCP_SDES, plen);
    rtp_wr32(b + 4, ssrc);
    b[8] = RTCP_SDES_CNAME;
    b[9] = (uint8_t)len;
    memcpy(b + 10, cname, len);
    return RTP_OK;
}

int rtcp_put_bye(rtcp_wbuf_t* w, const uint32_t* ssrc, unsigned n,
                 const char* reason, size_t len)
{
    if (n == 0 || n > RTCP_MAX_REPORTS || !ssrc || len > 255 ||
        (len && !reason))
        return RTP_E_INVAL;
    size_t body = (size_t)n * 4;
    if (len) body += (1 + len + 3) & ~(size_t)3;
    size_t   plen = RTCP_HDR_LEN + body;
    uint8_t* b    = put(w, plen);
    if (!b) return RTP_E_OVERFLOW;
    memset(b, 0, plen);
    hdr(b, (uint8_t)n, RTCP_BYE, plen);
    for (unsigned i = 0; i < n; i++)
        rtp_wr32(b + 4 + i * 4, ssrc[i]);
    if (len) {
        b[4 + n * 4] = (uint8_t)len;
        memcpy(b + 4 + n * 4 + 1, reason, len);
    }
    return RTP_OK;
}

int rtcp_end(rtcp_wbuf_t* w)
{
    return w->overflow ? RTP_E_OVERFLOW : (int)w->off;
}
