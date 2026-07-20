#include "gtp2.h"
#include "test.h"
#include <string.h>

spec ("gtp2") {
    context ("header decode") {
        it ("decodes a header without TEID") {
            const uint8_t buf[] = { 0x40, 0x01, 0x00, 0x04,
                                    0x00, 0x00, 0x42, 0x00 };
            gtp2_hdr_t    h;
            int           rc = gtp2_hdr_decode(buf, sizeof buf, &h);
            check(rc == GTP2_HDR_FIXED_LEN);
            check(h.version == 2);
            check(!h.has_teid);
            check(!h.has_mp);
            check(!h.piggyback);
            check(h.message_type == 1);
            check(h.length == 4);
            check(h.teid == 0);
            check(h.sequence == 0x000042u);
            check(h.priority == 0);
        }

        it ("decodes a header with TEID") {
            const uint8_t buf[] = { 0x48, 0x20, 0x00, 0x08, 0x12, 0x34,
                                    0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x00 };
            gtp2_hdr_t    h;
            int           rc = gtp2_hdr_decode(buf, sizeof buf, &h);
            check(rc == GTP2_HDR_WITH_TEID);
            check(h.has_teid);
            check(h.teid == 0x12345678u);
            check(h.sequence == 0xABCDEFu);
            check(h.message_type == 32);
            check(h.length == 8);
        }

        it ("decodes piggyback and message priority flags") {
            const uint8_t buf[] = {
                0x40 | 0x10 | 0x04, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0xA0
            };
            gtp2_hdr_t h;
            int        rc = gtp2_hdr_decode(buf, sizeof buf, &h);
            check(rc == GTP2_HDR_FIXED_LEN);
            check(h.piggyback);
            check(h.has_mp);
            check(h.priority == 0x0A);
        }

        it ("rejects wrong version") {
            const uint8_t buf[] = { 0x20, 0x01, 0x00, 0x04,
                                    0x00, 0x00, 0x00, 0x00 };
            gtp2_hdr_t    h;
            check(gtp2_hdr_decode(buf, sizeof buf, &h) == GTP2_E_VERSION);
        }

        it ("rejects a short buffer") {
            const uint8_t buf[] = { 0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 };
            gtp2_hdr_t    h;
            check(gtp2_hdr_decode(buf, sizeof buf, &h) == GTP2_E_SHORT);
        }

        it ("rejects a short buffer when TEID flag is set") {
            const uint8_t buf[] = { 0x48, 0x20, 0x00, 0x08,
                                    0x12, 0x34, 0x56, 0x78 };
            gtp2_hdr_t    h;
            check(gtp2_hdr_decode(buf, sizeof buf, &h) == GTP2_E_SHORT);
        }

        it ("rejects a length field that overflows the buffer") {
            const uint8_t buf[] = { 0x40, 0x01, 0x00, 0x40,
                                    0x00, 0x00, 0x00, 0x00 };
            gtp2_hdr_t    h;
            check(gtp2_hdr_decode(buf, sizeof buf, &h) == GTP2_E_LENGTH);
        }

        it ("rejects NULL arguments") {
            gtp2_hdr_t    h;
            const uint8_t b[8] = { 0 };
            check(gtp2_hdr_decode(NULL, sizeof b, &h) == GTP2_E_INVAL);
            check(gtp2_hdr_decode(b, sizeof b, NULL) == GTP2_E_INVAL);
        }
    }

    context ("header encode") {
        it ("encodes a header without TEID") {
            uint8_t    out[GTP2_HDR_FIXED_LEN] = { 0 };
            gtp2_hdr_t h                       = {
                .has_teid     = false,
                .message_type = GTP2_MT_ECHO_REQUEST,
                .length       = 4,
                .sequence     = 0x000042u,
            };
            int rc = gtp2_hdr_encode(out, sizeof out, &h);
            check(rc == GTP2_HDR_FIXED_LEN);

            const uint8_t expect[] = { 0x40, 0x01, 0x00, 0x04,
                                       0x00, 0x00, 0x42, 0x00 };
            check(memcmp(out, expect, sizeof expect) == 0);
        }

        it ("encodes a header with TEID") {
            uint8_t    out[GTP2_HDR_WITH_TEID] = { 0 };
            gtp2_hdr_t h                       = {
                .has_teid     = true,
                .message_type = GTP2_MT_CREATE_SESSION_REQUEST,
                .length       = 8,
                .teid         = 0x12345678u,
                .sequence     = 0xABCDEFu,
            };
            int rc = gtp2_hdr_encode(out, sizeof out, &h);
            check(rc == GTP2_HDR_WITH_TEID);

            const uint8_t expect[] = { 0x48, 0x20, 0x00, 0x08, 0x12, 0x34,
                                       0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x00 };
            check(memcmp(out, expect, sizeof expect) == 0);
        }

        it ("encodes the message priority bit and value") {
            uint8_t    out[GTP2_HDR_FIXED_LEN] = { 0 };
            gtp2_hdr_t h                       = {
                .has_mp       = true,
                .message_type = 1,
                .priority     = 0x0A,
                .sequence     = 1,
            };
            int rc = gtp2_hdr_encode(out, sizeof out, &h);
            check(rc == GTP2_HDR_FIXED_LEN);
            check((out[0] & 0x04) == 0x04);
            check(out[7] == 0xA0);
        }

        it ("rejects buffer overflow") {
            uint8_t    out[4] = { 0 };
            gtp2_hdr_t h      = { .has_teid = false, .message_type = 1 };
            check(gtp2_hdr_encode(out, sizeof out, &h) == GTP2_E_OVERFLOW);
        }

        it ("rejects NULL arguments") {
            uint8_t    out[8];
            gtp2_hdr_t h = { 0 };
            check(gtp2_hdr_encode(NULL, sizeof out, &h) == GTP2_E_INVAL);
            check(gtp2_hdr_encode(out, sizeof out, NULL) == GTP2_E_INVAL);
        }
    }

    context ("IE iterator") {
        it ("yields nothing for an empty buffer") {
            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, NULL, 0);
            gtp2_ie_view_t v;
            check(!gtp2_ie_iter_next(&it, &v));
        }

        it ("decodes a single IE") {
            const uint8_t buf[] = { 82, 0x00, 0x01, 0x00, 0x06 };
            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, sizeof buf);
            gtp2_ie_view_t v;
            check(gtp2_ie_iter_next(&it, &v));
            check(v.type == 82);
            check(v.instance == 0);
            check(v.len == 1);
            check(v.value[0] == 6);
            check(v.value == buf + GTP2_IE_HDR_LEN);
            check(!gtp2_ie_iter_next(&it, &v));
        }

        it ("decodes multiple IEs with instance numbers") {
            const uint8_t buf[] = { 82,   0x00, 0x01, 0x03, 0x06, 73,
                                    0x00, 0x01, 0x00, 0x05, 94,   0x00,
                                    0x04, 0x0F, 0xDE, 0xAD, 0xBE, 0xEF };
            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, sizeof buf);
            gtp2_ie_view_t v;

            check(gtp2_ie_iter_next(&it, &v));
            check(v.type == 82);
            check(v.instance == 3);

            check(gtp2_ie_iter_next(&it, &v));
            check(v.type == 73);
            check(v.instance == 0);
            check(v.value[0] == 5);

            check(gtp2_ie_iter_next(&it, &v));
            check(v.type == 94);
            check(v.instance == 15);
            check(v.len == 4);

            check(!gtp2_ie_iter_next(&it, &v));
        }

        it ("rejects an IE whose length overruns the buffer") {
            const uint8_t buf[] = { 82, 0x00, 0x04, 0x00, 0x01, 0x02 };
            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, sizeof buf);
            gtp2_ie_view_t v;
            check(!gtp2_ie_iter_next(&it, &v));
        }

        it ("rejects a partial IE header") {
            const uint8_t buf[] = { 82, 0x00, 0x01 };
            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, sizeof buf);
            gtp2_ie_view_t v;
            check(!gtp2_ie_iter_next(&it, &v));
        }
    }

    context ("IE write") {
        it ("writes a u8 IE") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, 6) == GTP2_OK);
            check(w.off == 5u);
            const uint8_t expect[] = { 82, 0x00, 0x01, 0x00, 0x06 };
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("writes a u16 IE") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u16(&w, GTP2_IE_PORT_NUMBER, 0, 0x1F90) ==
                  GTP2_OK);
            const uint8_t expect[] = { 126, 0x00, 0x02, 0x00, 0x1F, 0x90 };
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("writes a u32 IE") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0, 0xCAFEBABEu) ==
                  GTP2_OK);
            const uint8_t expect[] = { 94,   0x00, 0x04, 0x00,
                                       0xCA, 0xFE, 0xBA, 0xBE };
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("masks instance bits into the low nibble") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0xF7, 5) == GTP2_OK);
            check(buf[3] == 0x07);
        }

        it ("writes a zero-length IE") {
            uint8_t     buf[8];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put(&w, GTP2_IE_PRIVATE_EXTENSION, 0, NULL, 0) ==
                  GTP2_OK);
            check(w.off == 4u);
            check(buf[1] == 0x00);
            check(buf[2] == 0x00);
        }

        it ("returns overflow when the buffer is too small") {
            uint8_t     buf[6];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0, 0) ==
                  GTP2_E_OVERFLOW);
            check(w.overflow);
        }

        it ("makes wbuf overflow sticky") {
            uint8_t     buf[6];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0, 0) ==
                  GTP2_E_OVERFLOW);
            check(gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, 6) ==
                  GTP2_E_OVERFLOW);
        }
    }

    context ("grouped IE") {
        it ("encodes and decodes a grouped IE", 3000000) {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            int h = gtp2_ie_begin(&w, GTP2_IE_BEARER_CONTEXT, 0);
            check(h >= 0);
            check(gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0, 5) == GTP2_OK);
            check(gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0, 0xCAFEBABEu) ==
                  GTP2_OK);
            check(gtp2_ie_end(&w, h) == GTP2_OK);

            check(buf[0] == GTP2_IE_BEARER_CONTEXT);
            check(buf[1] == 0x00);
            check(buf[2] == 13);

            gtp2_ie_iter_t outer;
            gtp2_ie_iter_init(&outer, buf, w.off);
            gtp2_ie_view_t v;
            check(gtp2_ie_iter_next(&outer, &v));
            check(v.type == GTP2_IE_BEARER_CONTEXT);
            check(v.len == 13);

            gtp2_ie_iter_t inner;
            gtp2_ie_iter_grouped(&inner, &v);

            gtp2_ie_view_t child;
            check(gtp2_ie_iter_next(&inner, &child));
            check(child.type == GTP2_IE_EBI);
            check(child.value[0] == 5);

            check(gtp2_ie_iter_next(&inner, &child));
            check(child.type == GTP2_IE_CHARGING_ID);
            check(child.len == 4);

            check(!gtp2_ie_iter_next(&inner, &child));
            check(!gtp2_ie_iter_next(&outer, &v));
        }

        it ("encodes nested grouped IEs") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            int outer_h =
                gtp2_ie_begin(&w, GTP2_IE_OVERLOAD_CONTROL_INFORMATION, 0);
            check(outer_h >= 0);
            int inner_h =
                gtp2_ie_begin(&w, GTP2_IE_LOAD_CONTROL_INFORMATION, 1);
            check(inner_h >= 0);
            check(gtp2_ie_put_u8(&w, GTP2_IE_METRIC, 0, 42) == GTP2_OK);
            check(gtp2_ie_end(&w, inner_h) == GTP2_OK);
            check(gtp2_ie_end(&w, outer_h) == GTP2_OK);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t outer;
            check(gtp2_ie_iter_next(&it, &outer));
            check(outer.type == GTP2_IE_OVERLOAD_CONTROL_INFORMATION);
            check(outer.len == 9);

            gtp2_ie_iter_t mid;
            gtp2_ie_iter_grouped(&mid, &outer);
            gtp2_ie_view_t lci;
            check(gtp2_ie_iter_next(&mid, &lci));
            check(lci.type == GTP2_IE_LOAD_CONTROL_INFORMATION);
            check(lci.instance == 1);
            check(lci.len == 5);

            gtp2_ie_iter_t inner;
            gtp2_ie_iter_grouped(&inner, &lci);
            gtp2_ie_view_t metric;
            check(gtp2_ie_iter_next(&inner, &metric));
            check(metric.type == GTP2_IE_METRIC);
            check(metric.value[0] == 42);
        }

        it ("rejects ie_end with a bad handle") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_ie_end(&w, -1) == GTP2_E_INVAL);
            check(gtp2_ie_end(&w, 100) == GTP2_E_INVAL);
        }
    }

    context ("header finalize") {
        it ("backfills the length field") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            gtp2_hdr_t h = {
                .has_teid     = true,
                .message_type = GTP2_MT_CREATE_SESSION_REQUEST,
                .length       = 0,
                .teid         = 0x11,
                .sequence     = 1,
            };
            size_t hdr_off = w.off;
            int    rc      = gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &h);
            check(rc == GTP2_HDR_WITH_TEID);
            w.off += (size_t)rc;

            check(gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, 6) == GTP2_OK);
            check(gtp2_hdr_finalize(&w, hdr_off) == GTP2_OK);

            const uint16_t want = (uint16_t)(w.off - 4);
            const uint16_t got  = (uint16_t)((buf[2] << 8) | buf[3]);
            check(got == want);
        }

        it ("rejects an invalid header offset") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            check(gtp2_hdr_finalize(&w, 8) == GTP2_E_INVAL);
        }
    }

    it ("round-trips a Create Session Request") {
        uint8_t     buf[128];
        gtp2_wbuf_t w;
        gtp2_wbuf_init(&w, buf, sizeof buf);

        gtp2_hdr_t h = {
            .has_teid     = true,
            .message_type = GTP2_MT_CREATE_SESSION_REQUEST,
            .teid         = 0xDEADBEEFu,
            .sequence     = 0x010203u,
        };
        size_t hdr_off = w.off;
        int    hrc     = gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &h);
        check(hrc == GTP2_HDR_WITH_TEID);
        w.off += (size_t)hrc;

        check(gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, 6) == GTP2_OK);
        check(gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0, 0x12345678u) ==
              GTP2_OK);

        int bh = gtp2_ie_begin(&w, GTP2_IE_BEARER_CONTEXT, 0);
        check(bh >= 0);
        check(gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0, 5) == GTP2_OK);
        check(gtp2_ie_end(&w, bh) == GTP2_OK);

        check(gtp2_hdr_finalize(&w, hdr_off) == GTP2_OK);

        gtp2_hdr_t dh;
        int        dlen = gtp2_hdr_decode(buf, w.off, &dh);
        check(dlen == GTP2_HDR_WITH_TEID);
        check(dh.message_type == GTP2_MT_CREATE_SESSION_REQUEST);
        check(dh.teid == 0xDEADBEEFu);
        check(dh.sequence == 0x010203u);

        check((size_t)dh.length + 4 == w.off);

        gtp2_ie_iter_t it;
        gtp2_ie_iter_init(&it, buf + dlen, w.off - (size_t)dlen);

        gtp2_ie_view_t v;
        check(gtp2_ie_iter_next(&it, &v));
        check(v.type == GTP2_IE_RAT_TYPE);
        check(v.value[0] == 6);

        check(gtp2_ie_iter_next(&it, &v));
        check(v.type == GTP2_IE_CHARGING_ID);
        check(v.len == 4);
        check(v.value[0] == 0x12);
        check(v.value[3] == 0x78);

        check(gtp2_ie_iter_next(&it, &v));
        check(v.type == GTP2_IE_BEARER_CONTEXT);
        gtp2_ie_iter_t inner;
        gtp2_ie_iter_grouped(&inner, &v);
        gtp2_ie_view_t child;
        check(gtp2_ie_iter_next(&inner, &child));
        check(child.type == GTP2_IE_EBI);
        check(child.value[0] == 5);
        check(!gtp2_ie_iter_next(&inner, &child));

        check(!gtp2_ie_iter_next(&it, &v));
    }
}
