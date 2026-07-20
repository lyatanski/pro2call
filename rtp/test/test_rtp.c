#include <string.h>

#include "rtp.h"
#include "test.h"

/* Slice vs C-string equality (exact). */
static int seq_str(rtp_str_t s, const char* z)
{
    size_t n = strlen(z);
    return s.len == n && (n == 0 || memcmp(s.p, z, n) == 0);
}

spec ("rtp") {
    context ("rtp packet codec") {
        it ("round-trips a plain packet") {
            static const uint8_t pay[] = { 0xDE, 0xAD, 0xBE, 0xEF };
            rtp_pkt_t            p     = { 0 };
            p.marker                   = true;
            p.pt                       = RTP_PT_PCMU;
            p.seq                      = 0xBEEF;
            p.ts                       = 0x12345678;
            p.ssrc                     = 0xCAFEBABE;
            p.payload                  = pay;
            p.payload_len              = sizeof pay;

            uint8_t buf[64];
            int     n = rtp_pkt_encode(&p, buf, sizeof buf);
            check(n == 12 + (int)sizeof pay);
            check(buf[0] == 0x80); /* V=2, no P/X/CC */
            check(buf[1] == (0x80 | RTP_PT_PCMU));

            rtp_pkt_t q;
            check(rtp_pkt_parse(&q, buf, (size_t)n) == RTP_OK);
            check(q.marker && q.pt == RTP_PT_PCMU);
            check(q.seq == 0xBEEF && q.ts == 0x12345678);
            check(q.ssrc == 0xCAFEBABE);
            check(q.cc == 0 && !q.has_ext);
            check(q.payload_len == sizeof pay);
            check(memcmp(q.payload, pay, sizeof pay) == 0);
        }

        it ("round-trips CSRCs and a header extension") {
            static const uint8_t ext[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            rtp_pkt_t            p     = { 0 };
            p.pt                       = RTP_PT_DYNAMIC;
            p.cc                       = 2;
            p.csrc[0]                  = 0x11111111;
            p.csrc[1]                  = 0x22222222;
            p.has_ext                  = true;
            p.ext_profile              = 0xBEDE;
            p.ext                      = ext;
            p.ext_len                  = sizeof ext;
            p.payload                  = ext;
            p.payload_len              = 3;

            uint8_t buf[64];
            int     n = rtp_pkt_encode(&p, buf, sizeof buf);
            check(n == 12 + 8 + 4 + 8 + 3);

            rtp_pkt_t q;
            check(rtp_pkt_parse(&q, buf, (size_t)n) == RTP_OK);
            check(q.cc == 2);
            check(q.csrc[0] == 0x11111111 && q.csrc[1] == 0x22222222);
            check(q.has_ext && q.ext_profile == 0xBEDE);
            check(q.ext_len == sizeof ext);
            check(memcmp(q.ext, ext, sizeof ext) == 0);
            check(q.payload_len == 3);
        }

        it ("strips padding") {
            /* V=2 P=1, PT 0, seq 1, ts 0, ssrc 0, 3 payload + pad(5) */
            uint8_t buf[12 + 8] = { 0xA0, 0, 0, 1 };
            buf[12]             = 0xAA;
            buf[13]             = 0xBB;
            buf[14]             = 0xCC;
            buf[19]             = 5; /* pad count */
            rtp_pkt_t q;
            check(rtp_pkt_parse(&q, buf, sizeof buf) == RTP_OK);
            check(q.payload_len == 3);
            check(q.payload[2] == 0xCC);
        }

        it ("rejects bad version, short input and bad padding") {
            uint8_t   buf[16] = { 0x40 }; /* V=1 */
            rtp_pkt_t q;
            check(rtp_pkt_parse(&q, buf, sizeof buf) == RTP_E_VERSION);
            buf[0] = 0x80;
            check(rtp_pkt_parse(&q, buf, 4) == RTP_E_SHORT);
            buf[0] = 0x83; /* CC=3 but no CSRCs */
            check(rtp_pkt_parse(&q, buf, 12) == RTP_E_SHORT);
            buf[0]  = 0xA0; /* P=1, pad > payload */
            buf[15] = 200;
            check(rtp_pkt_parse(&q, buf, sizeof buf) == RTP_E_FORMAT);
        }

        it ("rejects invalid encode arguments") {
            rtp_pkt_t p = { 0 };
            uint8_t   buf[64];
            p.pt = 200; /* > 127 */
            check(rtp_pkt_encode(&p, buf, sizeof buf) == RTP_E_INVAL);
            p.pt                      = 0;
            p.has_ext                 = true;
            p.ext_len                 = 3; /* not a word multiple */
            static const uint8_t e[4] = { 0 };
            p.ext                     = e;
            check(rtp_pkt_encode(&p, buf, sizeof buf) == RTP_E_INVAL);
            p.has_ext = false;
            check(rtp_pkt_encode(&p, buf, 4) == RTP_E_OVERFLOW);
        }
    }

    context ("rtcp codec") {
        it ("round-trips an SR + SDES + BYE compound") {
            rtcp_report_t rep = { 0 };
            rep.ssrc          = 0x1111;
            rep.fraction      = 42;
            rep.lost          = -3;
            rep.last_seq      = 0x00010042;
            rep.jitter        = 7;
            rep.lsr           = 0xAABBCCDD;
            rep.dlsr          = 65536;

            uint8_t     buf[256];
            rtcp_wbuf_t w;
            rtcp_wbuf_init(&w, buf, sizeof buf);
            check(rtcp_put_sr(&w, 0x2222, 100, 200, 300, 10, 1600, &rep, 1) ==
                  RTP_OK);
            check(rtcp_put_sdes_cname(&w, 0x2222, "a@b", 3) == RTP_OK);
            uint32_t me = 0x2222;
            check(rtcp_put_bye(&w, &me, 1, "bye now", 7) == RTP_OK);
            int n = rtcp_end(&w);
            check(n > 0 && n % 4 == 0);

            rtcp_iter_t it;
            rtcp_view_t v;
            rtcp_iter_init(&it, buf, (size_t)n);

            check(rtcp_iter_next(&it, &v) == 1);
            check(v.type == RTCP_SR && v.count == 1);
            rtcp_rep_t sr;
            check(rtcp_sr_parse(&v, &sr) == RTP_OK);
            check(sr.ssrc == 0x2222);
            check(sr.ntp_sec == 100 && sr.ntp_frac == 200 && sr.rtp_ts == 300);
            check(sr.pkt_count == 10 && sr.octet_count == 1600);
            check(sr.count == 1);
            check(sr.reports[0].ssrc == 0x1111);
            check(sr.reports[0].fraction == 42);
            check(sr.reports[0].lost == -3);
            check(sr.reports[0].last_seq == 0x00010042);
            check(sr.reports[0].jitter == 7);
            check(sr.reports[0].lsr == 0xAABBCCDD);
            check(sr.reports[0].dlsr == 65536);

            check(rtcp_iter_next(&it, &v) == 1);
            check(v.type == RTCP_SDES);
            rtcp_sdes_iter_t si;
            check(rtcp_sdes_init(&v, &si) == RTP_OK);
            uint32_t  ssrc;
            uint8_t   item;
            rtp_str_t val;
            check(rtcp_sdes_next(&si, &ssrc, &item, &val) == 1);
            check(ssrc == 0x2222 && item == RTCP_SDES_CNAME);
            check(seq_str(val, "a@b"));
            check(rtcp_sdes_next(&si, &ssrc, &item, &val) == 0);

            check(rtcp_iter_next(&it, &v) == 1);
            check(v.type == RTCP_BYE);
            rtcp_bye_t bye;
            check(rtcp_bye_parse(&v, &bye) == RTP_OK);
            check(bye.count == 1 && bye.ssrc[0] == 0x2222);
            check(seq_str(bye.reason, "bye now"));

            check(rtcp_iter_next(&it, &v) == 0);
        }

        it ("round-trips an RR") {
            rtcp_report_t rep = { 0 };
            rep.ssrc          = 0x3333;
            uint8_t     buf[64];
            rtcp_wbuf_t w;
            rtcp_wbuf_init(&w, buf, sizeof buf);
            check(rtcp_put_rr(&w, 0x4444, &rep, 1) == RTP_OK);
            int n = rtcp_end(&w);
            check(n == 4 + 4 + 24);

            rtcp_iter_t it;
            rtcp_view_t v;
            rtcp_iter_init(&it, buf, (size_t)n);
            check(rtcp_iter_next(&it, &v) == 1);
            check(v.type == RTCP_RR);
            rtcp_rep_t rr;
            check(rtcp_rr_parse(&v, &rr) == RTP_OK);
            check(rr.ssrc == 0x4444 && rr.count == 1);
            check(rr.reports[0].ssrc == 0x3333);
            check(rr.ntp_sec == 0 && rr.pkt_count == 0);
        }

        it ("SDES chunks pad to word boundaries") {
            /* CNAME lengths 0..7 hit every padding phase */
            for (unsigned len = 0; len < 8; len++) {
                uint8_t     buf[64];
                rtcp_wbuf_t w;
                rtcp_wbuf_init(&w, buf, sizeof buf);
                check(rtcp_put_sdes_cname(&w, 9, "abcdefg", len) == RTP_OK);
                int n = rtcp_end(&w);
                check(n > 0 && n % 4 == 0);

                rtcp_iter_t it;
                rtcp_view_t v;
                rtcp_iter_init(&it, buf, (size_t)n);
                check(rtcp_iter_next(&it, &v) == 1);
                rtcp_sdes_iter_t si;
                check(rtcp_sdes_init(&v, &si) == RTP_OK);
                uint32_t  ssrc;
                uint8_t   item;
                rtp_str_t val;
                check(rtcp_sdes_next(&si, &ssrc, &item, &val) == 1);
                check(ssrc == 9 && item == RTCP_SDES_CNAME && val.len == len);
                check(rtcp_sdes_next(&si, &ssrc, &item, &val) == 0);
            }
        }

        it ("is sticky on overflow") {
            uint8_t     buf[4]; /* an empty RR needs 8 */
            rtcp_wbuf_t w;
            rtcp_wbuf_init(&w, buf, sizeof buf);
            check(rtcp_put_rr(&w, 1, NULL, 0) == RTP_E_OVERFLOW);
            check(rtcp_put_rr(&w, 1, NULL, 0) == RTP_E_OVERFLOW);
            check(rtcp_end(&w) == RTP_E_OVERFLOW);
        }

        it ("rejects a truncated compound") {
            uint8_t     buf[64];
            rtcp_wbuf_t w;
            rtcp_wbuf_init(&w, buf, sizeof buf);
            check(rtcp_put_rr(&w, 1, NULL, 0) == RTP_OK);
            int n = rtcp_end(&w);
            rtcp_iter_t it;
            rtcp_view_t v;
            rtcp_iter_init(&it, buf, (size_t)n - 1);
            check(rtcp_iter_next(&it, &v) == RTP_E_SHORT);
        }
    }

    context ("source statistics") {
        it ("passes probation after sequential packets") {
            rtp_source_t s;
            rtp_source_init(&s, 7, 100);
            check(rtp_source_update(&s, 100) == 0); /* probation */
            check(rtp_source_update(&s, 101) == 1); /* valid now  */
            check(rtp_source_update(&s, 102) == 1);
            check(s.received == 2);
        }

        it ("counts loss across a gap") {
            rtp_source_t s;
            rtp_source_init(&s, 7, 1);
            rtp_source_update(&s, 1);
            rtp_source_update(&s, 2);
            rtp_source_update(&s, 3);
            rtp_source_update(&s, 10); /* 4..9 lost */
            rtcp_report_t r;
            rtp_source_report(&s, &r);
            check(r.ssrc == 7);
            check(r.lost == 6);
            check(r.last_seq == 10);
            check(r.fraction > 0);
            /* next interval: nothing new lost */
            rtp_source_update(&s, 11);
            rtp_source_report(&s, &r);
            check(r.lost == 6);
            check(r.fraction == 0);
        }

        it ("tracks sequence wrap in the extended count") {
            rtp_source_t s;
            rtp_source_init(&s, 7, 65534);
            rtp_source_update(&s, 65534);
            rtp_source_update(&s, 65535);
            check(rtp_source_update(&s, 0) == 1); /* wraps */
            rtcp_report_t r;
            rtp_source_report(&s, &r);
            check(r.last_seq == 65536);
            check(r.lost == 0);
        }

        it ("estimates jitter from interarrival variation") {
            rtp_source_t s;
            rtp_source_init(&s, 7, 0);
            rtp_source_update(&s, 0);
            /* constant spacing: jitter stays 0 */
            for (unsigned i = 1; i < 10; i++) {
                rtp_source_update(&s, (uint16_t)i);
                rtp_source_jitter(&s, i * 160, 1000 + i * 160);
            }
            check(s.jitter == 0);
            /* one late packet moves the estimator */
            rtp_source_update(&s, 10);
            rtp_source_jitter(&s, 10 * 160, 1000 + 10 * 160 + 80);
            check(s.jitter > 0);
        }
    }
}
