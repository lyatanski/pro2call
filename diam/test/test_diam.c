#include "diam.h"
#include "test.h"

#include <string.h>

/* AVP codes used by the tests (RFC 6733 / 3GPP registries). */
enum {
    AVP_AUTH_APPLICATION_ID = 258,
    AVP_VS_APPLICATION_ID   = 260,
    AVP_ORIGIN_HOST         = 264,
    AVP_VENDOR_ID           = 266,
    AVP_RESULT_CODE         = 268,
    AVP_HOST_IP_ADDRESS     = 257,
    AVP_PUBLIC_IDENTITY     = 601 /* TS 29.229, vendor 10415 */
};

enum { VENDOR_3GPP = 10415 };

spec ("diam: Diameter base codec (RFC 6733)") {
    context ("header codec") {
        it ("round-trips a request header") {
            diam_hdr_t h = { 0 }, d = { 0 };
            h.length    = DIAM_HDR_LEN;
            h.request   = true;
            h.proxiable = true;
            h.cmd_code  = 257; /* Capabilities-Exchange */
            h.app_id    = 0;
            h.hbh       = 0x11223344;
            h.e2e       = 0x55667788;

            uint8_t buf[64];
            check(diam_hdr_encode(buf, sizeof buf, &h) == DIAM_HDR_LEN);
            check(buf[0] == 1);    /* version */
            check(buf[4] == 0xC0); /* R + P */
            check(diam_hdr_decode(buf, sizeof buf, &d) == DIAM_HDR_LEN);
            check(d.version == 1);
            check(d.request && d.proxiable && !d.error && !d.retransmit);
            check(d.cmd_code == 257);
            check(d.app_id == 0);
            check(d.hbh == 0x11223344 && d.e2e == 0x55667788);
        }

        it ("rejects truncated, wrong-version and bad-length input") {
            uint8_t    buf[64] = { 0 };
            diam_hdr_t h       = { 0 }, d;
            h.length           = DIAM_HDR_LEN;
            check(diam_hdr_encode(buf, sizeof buf, &h) == DIAM_HDR_LEN);

            check(diam_hdr_decode(buf, 19, &d) == DIAM_E_SHORT);

            buf[0] = 2;
            check(diam_hdr_decode(buf, sizeof buf, &d) == DIAM_E_VERSION);
            buf[0] = 1;

            uint8_t save = buf[3];
            buf[3]       = 19; /* length < header */
            check(diam_hdr_decode(buf, sizeof buf, &d) == DIAM_E_LENGTH);
            buf[3] = 22; /* not 4-aligned */
            check(diam_hdr_decode(buf, sizeof buf, &d) == DIAM_E_LENGTH);
            buf[3] = save;

            check(diam_hdr_decode(buf, 20, &d) == DIAM_HDR_LEN);
            buf[3] = 24; /* length > buffer */
            check(diam_hdr_decode(buf, 20, &d) == DIAM_E_LENGTH);
        }

        it ("rejects an over-range command code on encode") {
            uint8_t    buf[64];
            diam_hdr_t h = { 0 };
            h.cmd_code   = 0x01000000;
            check(diam_hdr_encode(buf, sizeof buf, &h) == DIAM_E_INVAL);
        }
    }

    context ("AVP encode") {
        it ("writes the exact RFC 6733 wire form of a standard AVP") {
            /* Result-Code (268), M set, Unsigned32 2001. */
            static const uint8_t want[] = {
                0x00, 0x00, 0x01, 0x0C, /* code   */
                0x40, 0x00, 0x00, 0x0C, /* M, len 12 */
                0x00, 0x00, 0x07, 0xD1  /* 2001   */
            };
            uint8_t     buf[32];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_u32(&w, AVP_RESULT_CODE, DIAM_AVP_F_MANDATORY, 0,
                                   2001) == DIAM_OK);
            check(w.off == sizeof want);
            check(memcmp(buf, want, sizeof want) == 0);
        }

        it ("writes the exact wire form of a vendor AVP") {
            /* Public-Identity (601), V+M, vendor 10415 (0x28AF). */
            static const uint8_t want[] = {
                0x00, 0x00, 0x02, 0x59,
                0xC0, 0x00, 0x00, 0x10, /* V+M, len 16 */
                0x00, 0x00, 0x28, 0xAF, /* Vendor-ID */
                'a',  'b',  'c',  'd'
            };
            uint8_t     buf[32];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put(&w, AVP_PUBLIC_IDENTITY, DIAM_AVP_F_MANDATORY,
                               VENDOR_3GPP, "abcd", 4) == DIAM_OK);
            check(w.off == sizeof want);
            check(memcmp(buf, want, sizeof want) == 0);
        }

        it ("pads AVPs to the 4-byte boundary with zeros") {
            uint8_t     buf[32];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_str(&w, AVP_ORIGIN_HOST, 0, 0, "abcde") ==
                  DIAM_OK);
            check(w.off == 16); /* 8 + 5 padded to 16 */
            check(buf[13] == 0 && buf[14] == 0 && buf[15] == 0);
        }

        it ("refuses a V flag without a vendor id") {
            uint8_t     buf[32];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put(&w, 1, DIAM_AVP_F_VENDOR, 0, "x", 1) ==
                  DIAM_E_INVAL);
        }

        it ("keeps overflow sticky across chained puts") {
            uint8_t     buf[10];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            int rc = 0;
            rc |= diam_avp_put_u32(&w, AVP_RESULT_CODE, 0, 0, 2001);
            rc |= diam_avp_put_u32(&w, AVP_RESULT_CODE, 0, 0, 2001);
            check(rc != 0);
            check(diam_avp_put_u32(&w, AVP_RESULT_CODE, 0, 0, 1) ==
                  DIAM_E_OVERFLOW);
        }
    }

    context ("AVP decode") {
        it ("walks a stream and strips the Vendor-ID from vendor AVPs") {
            uint8_t     buf[128];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_str(&w, AVP_ORIGIN_HOST, DIAM_AVP_F_MANDATORY, 0,
                                   "hss.example.net") == DIAM_OK);
            check(diam_avp_put(&w, AVP_PUBLIC_IDENTITY, DIAM_AVP_F_MANDATORY,
                               VENDOR_3GPP, "sip:alice@x", 11) == DIAM_OK);

            diam_avp_iter_t it;
            diam_avp_view_t v;
            diam_avp_iter_init(&it, buf, w.off);

            check(diam_avp_iter_next(&it, &v));
            check(v.code == AVP_ORIGIN_HOST);
            check(v.vendor_id == 0);
            check(v.len == 15);
            check(memcmp(v.value, "hss.example.net", 15) == 0);

            check(diam_avp_iter_next(&it, &v));
            check(v.code == AVP_PUBLIC_IDENTITY);
            check(v.flags & DIAM_AVP_F_VENDOR);
            check(v.vendor_id == VENDOR_3GPP);
            check(v.len == 11);
            check(memcmp(v.value, "sip:alice@x", 11) == 0);

            check(!diam_avp_iter_next(&it, &v));
        }

        it ("stops on a truncated AVP") {
            uint8_t     buf[64];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_u32(&w, AVP_RESULT_CODE, 0, 0, 2001) == DIAM_OK);

            diam_avp_iter_t it;
            diam_avp_view_t v;
            diam_avp_iter_init(&it, buf, w.off - 1);
            check(!diam_avp_iter_next(&it, &v));
        }

        it ("stops on a V bit with fewer than 4 data bytes") {
            /* Hand-built: V flag set, AVP length 10 -> 2 data bytes. */
            static const uint8_t bad[] = { 0x00, 0x00, 0x01, 0x00, 0x80, 0x00,
                                           0x00, 0x0A, 0x28, 0xAF, 0x00, 0x00 };
            diam_avp_iter_t it;
            diam_avp_view_t v;
            diam_avp_iter_init(&it, bad, sizeof bad);
            check(!diam_avp_iter_next(&it, &v));
        }

        it ("finds AVPs by code and vendor") {
            uint8_t     buf[128];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_u32(&w, AVP_VENDOR_ID, 0, 0, 10415) == DIAM_OK);
            check(diam_avp_put(&w, AVP_PUBLIC_IDENTITY, 0, VENDOR_3GPP, "id",
                               2) == DIAM_OK);

            diam_avp_view_t v;
            check(diam_avp_find(buf, w.off, AVP_PUBLIC_IDENTITY, VENDOR_3GPP,
                                &v));
            check(v.len == 2);
            check(!diam_avp_find(buf, w.off, AVP_PUBLIC_IDENTITY, 0, &v));
            check(!diam_avp_find(buf, w.off, AVP_RESULT_CODE, 0, &v));
        }
    }

    context ("grouped AVPs") {
        it ("nests, backfills the parent length and iterates children") {
            /* Vendor-Specific-Application-Id { Vendor-Id, Auth-Application-Id }
             */
            uint8_t     buf[128];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);

            const int g = diam_avp_begin(&w, AVP_VS_APPLICATION_ID,
                                         DIAM_AVP_F_MANDATORY, 0);
            check(g >= 0);
            check(diam_avp_put_u32(&w, AVP_VENDOR_ID, DIAM_AVP_F_MANDATORY, 0,
                                   10415) == DIAM_OK);
            check(diam_avp_put_u32(&w, AVP_AUTH_APPLICATION_ID,
                                   DIAM_AVP_F_MANDATORY, 0,
                                   16777216) == DIAM_OK);
            check(diam_avp_end(&w, g) == DIAM_OK);
            check(w.off == 8 + 12 + 12);

            diam_avp_iter_t it, sub;
            diam_avp_view_t v, c;
            diam_avp_iter_init(&it, buf, w.off);
            check(diam_avp_iter_next(&it, &v));
            check(v.code == AVP_VS_APPLICATION_ID);
            check(v.len == 24);

            diam_avp_iter_grouped(&sub, &v);
            uint32_t u = 0;
            check(diam_avp_iter_next(&sub, &c));
            check(c.code == AVP_VENDOR_ID);
            check(diam_avp_u32(&c, &u) == DIAM_OK && u == 10415);
            check(diam_avp_iter_next(&sub, &c));
            check(c.code == AVP_AUTH_APPLICATION_ID);
            check(diam_avp_u32(&c, &u) == DIAM_OK && u == 16777216);
            check(!diam_avp_iter_next(&sub, &c));
        }

        it ("supports vendor-flagged grouped AVPs") {
            uint8_t     buf[128];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);

            const int g = diam_avp_begin(&w, 700 /* User-Identity, TS 29.329 */,
                                         DIAM_AVP_F_MANDATORY, VENDOR_3GPP);
            check(g >= 0);
            check(diam_avp_put(&w, AVP_PUBLIC_IDENTITY, DIAM_AVP_F_MANDATORY,
                               VENDOR_3GPP, "sip:a@b", 7) == DIAM_OK);
            check(diam_avp_end(&w, g) == DIAM_OK);

            diam_avp_iter_t it, sub;
            diam_avp_view_t v, c;
            diam_avp_iter_init(&it, buf, w.off);
            check(diam_avp_iter_next(&it, &v));
            check(v.code == 700 && v.vendor_id == VENDOR_3GPP);

            diam_avp_iter_grouped(&sub, &v);
            check(diam_avp_iter_next(&sub, &c));
            check(c.code == AVP_PUBLIC_IDENTITY && c.vendor_id == VENDOR_3GPP);
            check(c.len == 7 && memcmp(c.value, "sip:a@b", 7) == 0);
        }
    }

    context ("typed data") {
        it ("checks data lengths against the type") {
            uint8_t     buf[64];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_u64(&w, 421 /* CC-Total-Octets */, 0, 0,
                                   0x0102030405060708ull) == DIAM_OK);

            diam_avp_view_t v;
            check(diam_avp_find(buf, w.off, 421, 0, &v));

            uint64_t u64 = 0;
            uint32_t u32 = 0;
            check(diam_avp_u64(&v, &u64) == DIAM_OK);
            check(u64 == 0x0102030405060708ull);
            check(diam_avp_u32(&v, &u32) == DIAM_E_TYPE);

            int64_t i64 = 0;
            check(diam_avp_i64(&v, &i64) == DIAM_OK);
            check(i64 == 0x0102030405060708ll);
        }

        it ("round-trips the Address type") {
            static const uint8_t ip4[] = { 192, 0, 2, 1 };
            uint8_t              buf[64];
            diam_wbuf_t          w;
            diam_wbuf_init(&w, buf, sizeof buf);
            check(diam_avp_put_addr(&w, AVP_HOST_IP_ADDRESS, 0, 0,
                                    1 /* IANA IPv4 */, ip4,
                                    sizeof ip4) == DIAM_OK);

            diam_avp_view_t v;
            check(diam_avp_find(buf, w.off, AVP_HOST_IP_ADDRESS, 0, &v));
            check(v.len == 6);

            uint16_t       family = 0;
            const uint8_t* addr   = NULL;
            uint32_t       alen   = 0;
            check(diam_avp_addr(&v, &family, &addr, &alen) == DIAM_OK);
            check(family == 1);
            check(alen == 4 && memcmp(addr, ip4, 4) == 0);
        }
    }

    context ("whole messages") {
        it ("encodes header + AVPs with a backfilled length and decodes them") {
            uint8_t     buf[256];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);

            diam_hdr_t h = { 0 };
            h.request    = true;
            h.cmd_code   = 272; /* Credit-Control */
            h.app_id     = 4;
            h.hbh        = 1;
            h.e2e        = 2;
            check(diam_hdr_encode(w.buf, w.cap, &h) == DIAM_HDR_LEN);
            w.off = DIAM_HDR_LEN;

            check(diam_avp_put_str(&w, 263 /* Session-Id */,
                                   DIAM_AVP_F_MANDATORY, 0,
                                   "client;1;1") == DIAM_OK);
            check(diam_avp_put_u32(&w, 416 /* CC-Request-Type */,
                                   DIAM_AVP_F_MANDATORY, 0, 1) == DIAM_OK);
            check(diam_hdr_finalize(&w, 0) == DIAM_OK);

            diam_hdr_t d;
            check(diam_hdr_decode(buf, w.off, &d) == DIAM_HDR_LEN);
            check(d.length == w.off);
            check(d.request && d.cmd_code == 272 && d.app_id == 4);

            diam_avp_view_t v;
            check(diam_avp_find(buf + DIAM_HDR_LEN, d.length - DIAM_HDR_LEN,
                                416, 0, &v));
            uint32_t u = 0;
            check(diam_avp_u32(&v, &u) == DIAM_OK && u == 1);
        }
    }
}
