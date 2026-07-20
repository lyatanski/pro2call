#define _POSIX_C_SOURCE 199309L /* clock_gettime */

#include <string.h>
#include <time.h>

#include "rtp.h"

/* ---- byte order helpers (shared with rtcp.c) ---- */

#include "rtp_intl.h"

uint16_t rtp_rd16(const uint8_t* p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}
uint32_t rtp_rd32(const uint8_t* p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}
void rtp_wr16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
void rtp_wr32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---- RTP packet codec (RFC 3550 §5.1) ---- */

#define RTP_HDR_LEN 12

int rtp_pkt_parse(rtp_pkt_t* p, const void* buf, size_t len)
{
    const uint8_t* b = buf;
    if (!p || !b) return RTP_E_INVAL;
    if (len < RTP_HDR_LEN) return RTP_E_SHORT;

    uint8_t v = b[0] >> 6;
    if (v != RTP_VERSION) return RTP_E_VERSION;

    memset(p, 0, sizeof *p);
    bool pad   = (b[0] >> 5) & 1;
    p->has_ext = (b[0] >> 4) & 1;
    p->cc      = b[0] & 0x0F;
    p->marker  = (b[1] >> 7) & 1;
    p->pt      = b[1] & 0x7F;
    p->seq     = rtp_rd16(b + 2);
    p->ts      = rtp_rd32(b + 4);
    p->ssrc    = rtp_rd32(b + 8);

    size_t off = RTP_HDR_LEN + (size_t)p->cc * 4;
    if (len < off) return RTP_E_SHORT;
    for (unsigned i = 0; i < p->cc; i++)
        p->csrc[i] = rtp_rd32(b + RTP_HDR_LEN + i * 4);

    if (p->has_ext) {
        if (len < off + 4) return RTP_E_SHORT;
        p->ext_profile = rtp_rd16(b + off);
        p->ext_len     = (uint32_t)rtp_rd16(b + off + 2) * 4;
        off += 4;
        if (len < off + p->ext_len) return RTP_E_SHORT;
        p->ext = b + off;
        off += p->ext_len;
    }

    size_t plen = len - off;
    if (pad) {
        if (plen == 0) return RTP_E_FORMAT;
        uint8_t npad = b[len - 1];
        if (npad == 0 || npad > plen) return RTP_E_FORMAT;
        plen -= npad;
    }
    p->payload     = b + off;
    p->payload_len = (uint32_t)plen;
    return RTP_OK;
}

int rtp_pkt_encode(const rtp_pkt_t* p, void* buf, size_t cap)
{
    uint8_t* b = buf;
    if (!p || !b) return RTP_E_INVAL;
    if (p->cc > RTP_MAX_CSRC || p->pt > 127) return RTP_E_INVAL;
    if (p->has_ext && (p->ext_len % 4 != 0 || (p->ext_len && !p->ext)))
        return RTP_E_INVAL;
    if (p->payload_len && !p->payload) return RTP_E_INVAL;

    size_t need = RTP_HDR_LEN + (size_t)p->cc * 4 +
                  (p->has_ext ? 4 + p->ext_len : 0) + p->payload_len;
    if (cap < need) return RTP_E_OVERFLOW;

    b[0] = (uint8_t)(RTP_VERSION << 6 | (p->has_ext ? 0x10 : 0) | p->cc);
    b[1] = (uint8_t)((p->marker ? 0x80 : 0) | p->pt);
    rtp_wr16(b + 2, p->seq);
    rtp_wr32(b + 4, p->ts);
    rtp_wr32(b + 8, p->ssrc);

    size_t off = RTP_HDR_LEN;
    for (unsigned i = 0; i < p->cc; i++, off += 4)
        rtp_wr32(b + off, p->csrc[i]);

    if (p->has_ext) {
        rtp_wr16(b + off, p->ext_profile);
        rtp_wr16(b + off + 2, (uint16_t)(p->ext_len / 4));
        off += 4;
        memcpy(b + off, p->ext, p->ext_len);
        off += p->ext_len;
    }

    if (p->payload_len) memcpy(b + off, p->payload, p->payload_len);
    return (int)need;
}

/* ---- Receiver-side source statistics (RFC 3550 appendix A) ---- */

#define RTP_SEQ_MOD      (1 << 16)
#define RTP_MAX_DROPOUT  3000
#define RTP_MAX_MISORDER 100

static void source_reset(rtp_source_t* s, uint16_t seq)
{
    s->base_seq       = seq;
    s->max_seq        = seq;
    s->bad_seq        = RTP_SEQ_MOD + 1; /* so seq == bad_seq is false */
    s->cycles         = 0;
    s->received       = 0;
    s->received_prior = 0;
    s->expected_prior = 0;
}

void rtp_source_init(rtp_source_t* s, uint32_t ssrc, uint16_t seq)
{
    memset(s, 0, sizeof *s);
    s->ssrc = ssrc;
    source_reset(s, seq);
    s->max_seq   = (uint16_t)(seq - 1);
    s->probation = RTP_MIN_SEQUENTIAL;
}

int rtp_source_update(rtp_source_t* s, uint16_t seq)
{
    uint16_t udelta = (uint16_t)(seq - s->max_seq);

    /* Source is not valid until RTP_MIN_SEQUENTIAL packets with
     * sequential numbers have been received (A.1). */
    if (s->probation) {
        if (seq == (uint16_t)(s->max_seq + 1)) {
            s->probation--;
            s->max_seq = seq;
            if (s->probation == 0) {
                source_reset(s, seq);
                s->received++;
                return 1;
            }
        } else {
            s->probation = RTP_MIN_SEQUENTIAL - 1;
            s->max_seq   = seq;
        }
        return 0;
    } else if (udelta < RTP_MAX_DROPOUT) {
        /* in order, with permissible gap */
        if (seq < s->max_seq) s->cycles += RTP_SEQ_MOD; /* wrapped */
        s->max_seq = seq;
    } else if (udelta <= RTP_SEQ_MOD - RTP_MAX_MISORDER) {
        /* the sequence number made a very large jump */
        if (seq == s->bad_seq) {
            /* Two sequential packets: the other side restarted without
             * telling us — resync. */
            source_reset(s, seq);
        } else {
            s->bad_seq = (uint16_t)(seq + 1);
            return 0;
        }
    } else {
        /* duplicate or reordered packet */
    }
    s->received++;
    return 1;
}

void rtp_source_jitter(rtp_source_t* s, uint32_t rtp_ts, uint32_t arrival)
{
    uint32_t transit = arrival - rtp_ts;
    if (!s->has_transit) {
        s->has_transit = true;
        s->transit     = transit;
        return;
    }
    uint32_t d = transit - s->transit;
    s->transit = transit;
    if ((int32_t)d < 0) d = (uint32_t)-(int32_t)d;
    /* J += (1/16) * (|D| - J), in fixed point scaled by 16 (A.8). */
    s->jitter += d - ((s->jitter + 8) >> 4);
}

void rtp_source_report(rtp_source_t* s, rtcp_report_t* out)
{
    uint32_t ext_max  = s->cycles + s->max_seq;
    uint32_t expected = ext_max - s->base_seq + 1;
    int32_t  lost     = (int32_t)(expected - s->received);

    /* clamp to the 24-bit signed field (A.3) */
    if (lost > 0x7FFFFF) lost = 0x7FFFFF;
    if (lost < -0x800000) lost = -0x800000;

    uint32_t expected_interval = expected - s->expected_prior;
    uint32_t received_interval = s->received - s->received_prior;
    s->expected_prior          = expected;
    s->received_prior          = s->received;
    int32_t lost_interval = (int32_t)(expected_interval - received_interval);

    memset(out, 0, sizeof *out);
    out->ssrc     = s->ssrc;
    out->lost     = lost;
    out->last_seq = ext_max;
    out->jitter   = s->jitter >> 4;
    if (expected_interval != 0 && lost_interval > 0)
        out->fraction = (uint8_t)((lost_interval << 8) / expected_interval);
}

/* ---- NTP wallclock ---- */

#define NTP_UNIX_OFFSET 2208988800u /* 1900-01-01 .. 1970-01-01 */

void rtp_ntp_now(uint32_t* sec, uint32_t* frac)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    *sec = (uint32_t)ts.tv_sec + NTP_UNIX_OFFSET;
    /* 2^32 * nsec / 1e9, without 64-bit overflow: 2^32/1e9 = 4.294967296 */
    *frac = (uint32_t)(((uint64_t)ts.tv_nsec << 32) / 1000000000u);
}
