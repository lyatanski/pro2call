#include "gtp1.h"
#include "test.h"
#include <string.h>

/* Minimal TV length table for runtime tests: Recovery (14) = 1,
 * TEID Data I (16) = 4, IMSI (2) = 8. The full spec table lives in the
 * generated layer and is tested there. */
static uint16_t tvlen[128];

static void tvlen_init(void)
{
    memset(tvlen, 0, sizeof tvlen);
    tvlen[2]  = 8;
    tvlen[14] = 1;
    tvlen[16] = 4;
}

spec ("gtp1") {
    tvlen_init();

    context ("header codec") {
        it ("encodes a control header with known bytes") {
            uint8_t          buf[16];
            const gtp1_hdr_t h = {
                .message_type = 16,
                .length       = 0,
                .teid         = 0xDEADBEEFu,
                .sequence     = 0x1234,
            };
            check(gtp1_hdr_encode(buf, sizeof buf, &h) == GTP1_HDR_CTRL);
            check(buf[0] == 0x32); /* version 1, PT, S */
            check(buf[1] == 16);
            check(buf[4] == 0xDE && buf[7] == 0xEF);
            check(buf[8] == 0x12 && buf[9] == 0x34);
            check(buf[10] == 0 && buf[11] == 0);
        }

        it ("round-trips a header and reports the IE offset") {
            uint8_t     buf[32];
            gtp1_wbuf_t w;
            gtp1_wbuf_init(&w, buf, sizeof buf);

            const gtp1_hdr_t h = {
                .message_type = 17,
                .teid         = 0x01020304u,
                .sequence     = 7,
            };
            const int hlen = gtp1_hdr_encode(w.buf, w.cap, &h);
            check(hlen == GTP1_HDR_CTRL);
            w.off = (size_t)hlen;

            check(gtp1_ie_put_tv_u8(&w, 14, 42) == GTP1_OK);
            check(gtp1_hdr_finalize(&w, 0) == GTP1_OK);

            gtp1_hdr_t d;
            const int  off = gtp1_hdr_decode(buf, w.off, &d);
            check(off == GTP1_HDR_CTRL);
            check(d.version == 1 && d.pt && d.s && !d.e && !d.pn);
            check(d.message_type == 17);
            check(d.teid == 0x01020304u);
            check(d.sequence == 7);
            check(d.length == 6); /* seq tail (4) + TV IE (2) */
        }

        it ("rejects GTPv2 and GTP' buffers") {
            uint8_t    v2[12] = { 0x48, 32, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0 };
            gtp1_hdr_t d;
            check(gtp1_hdr_decode(v2, sizeof v2, &d) == GTP1_E_VERSION);

            uint8_t gp[12] = { 0x22, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0 };
            check(gtp1_hdr_decode(gp, sizeof gp, &d) == GTP1_E_VERSION);
        }

        it ("rejects a length field beyond the buffer") {
            uint8_t    buf[12] = { 0x32, 1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            gtp1_hdr_t d;
            check(gtp1_hdr_decode(buf, sizeof buf, &d) == GTP1_E_LENGTH);
        }

        it ("skips an extension header chain") {
            /* E+S set; one 4-byte extension header, then a TV IE */
            const uint8_t buf[] = {
                0x36, 16,   0x00, 0x0A, /* length = 10 */
                0x00, 0x00, 0x00, 0x01, /* TEID */
                0x00, 0x05, 0x00, 0xC0, /* seq, N-PDU, next ext */
                0x01, 0xAA, 0xBB, 0x00, /* ext: len 1, content, next 0 */
                14,   42                /* Recovery TV */
            };
            gtp1_hdr_t d;
            const int  off = gtp1_hdr_decode(buf, sizeof buf, &d);
            check(off == 16);
            check(d.e && d.s && d.sequence == 5);
            check(d.next_ext == 0xC0);

            gtp1_ie_iter_t it;
            gtp1_ie_iter_init(&it, buf + off, sizeof buf - (size_t)off, tvlen);
            gtp1_ie_view_t ie;
            check(gtp1_ie_iter_next(&it, &ie));
            check(ie.type == 14 && ie.len == 1 && ie.value[0] == 42);
        }

        it ("rejects a malformed extension chain") {
            const uint8_t buf[] = {
                0x36, 16,   0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x05, 0x00, 0xC0, 0x00, 0xAA, 0xBB, 0x00 /* ext length 0:
                                                            invalid */
            };
            gtp1_hdr_t d;
            check(gtp1_hdr_decode(buf, sizeof buf, &d) == GTP1_E_LENGTH);
        }
    }

    context ("IE iterator") {
        it ("walks mixed TV and TLV entries") {
            uint8_t     buf[64];
            gtp1_wbuf_t w;
            gtp1_wbuf_init(&w, buf, sizeof buf);

            const uint8_t imsi[8] = { 0x21, 0x43, 0x65, 0x87,
                                      0x09, 0x21, 0x43, 0xF5 };
            check(gtp1_ie_put_tv(&w, 2, imsi, sizeof imsi) == GTP1_OK);
            check(gtp1_ie_put_tv_u32(&w, 16, 0xCAFEBABEu) == GTP1_OK);
            check(gtp1_ie_put_tlv(&w, 131, "apn", 3) == GTP1_OK);

            gtp1_ie_iter_t it;
            gtp1_ie_iter_init(&it, buf, w.off, tvlen);

            gtp1_ie_view_t ie;
            check(gtp1_ie_iter_next(&it, &ie));
            check(ie.type == 2 && ie.len == 8);
            check(memcmp(ie.value, imsi, 8) == 0);

            check(gtp1_ie_iter_next(&it, &ie));
            check(ie.type == 16 && ie.len == 4);
            check(ie.value[0] == 0xCA && ie.value[3] == 0xBE);

            check(gtp1_ie_iter_next(&it, &ie));
            check(ie.type == 131 && ie.len == 3);
            check(memcmp(ie.value, "apn", 3) == 0);

            check(!gtp1_ie_iter_next(&it, &ie));
        }

        it ("stops at an unknown TV type") {
            const uint8_t buf[] = { 99, 0xAA, 14, 42 }; /* 99 not in table */
            gtp1_ie_iter_t it;
            gtp1_ie_iter_init(&it, buf, sizeof buf, tvlen);
            gtp1_ie_view_t ie;
            check(!gtp1_ie_iter_next(&it, &ie));
        }

        it ("stops at a truncated TLV") {
            const uint8_t buf[] = { 131, 0x00, 0x05, 'a', 'b' };
            gtp1_ie_iter_t it;
            gtp1_ie_iter_init(&it, buf, sizeof buf, tvlen);
            gtp1_ie_view_t ie;
            check(!gtp1_ie_iter_next(&it, &ie));
        }
    }

    context ("write buffer") {
        it ("overflow is sticky and reported by finalize") {
            uint8_t     buf[14];
            gtp1_wbuf_t w;
            gtp1_wbuf_init(&w, buf, sizeof buf);

            const gtp1_hdr_t h = { .message_type = 1 };
            w.off              = (size_t)gtp1_hdr_encode(w.buf, w.cap, &h);

            check(gtp1_ie_put_tv_u8(&w, 14, 1) == GTP1_OK); /* fits */
            check(gtp1_ie_put_tv_u32(&w, 16, 9) == GTP1_E_OVERFLOW);
            check(gtp1_ie_put_tv_u8(&w, 14, 1) == GTP1_E_OVERFLOW); /* sticky */
            check(gtp1_hdr_finalize(&w, 0) == GTP1_E_OVERFLOW);
        }
    }
}
