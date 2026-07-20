#include "tlv.h"
#include "test.h"
#include <string.h>

static const tlv_prof_t gtp2c    = TLV_PROF_GTP2C;
static const tlv_prof_t diameter = TLV_PROF_DIAMETER;
static const tlv_prof_t netlink  = TLV_PROF_NETLINK;

/* Build a netlink attribute in host byte order at buf, return its
 * padded size. */
static size_t nla_write(uint8_t* buf, uint16_t type, const void* val,
                        uint16_t vlen)
{
    const uint16_t nla_len = (uint16_t)(4 + vlen);
    size_t         total   = 4u + vlen;
    if (total % 4) total += 4 - total % 4;

    memset(buf, 0, total);
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    memcpy(buf + 4, val, vlen);
    return total;
}

spec ("tlv") {
    context ("GTPv2-C profile (packed, length excludes header)") {
        it ("iterates entries and yields the meta octet") {
            const uint8_t buf[] = { 82,   0x00, 0x01, 0x03, 0x06, 94,  0x00,
                                    0x04, 0x0F, 0xDE, 0xAD, 0xBE, 0xEF };
            tlv_iter_t it;
            tlv_iter_init(&it, &gtp2c, buf, sizeof buf);

            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 82);
            check(v.meta == 0x03);
            check(v.len == 1);
            check(v.value == buf + 4);
            check(v.value[0] == 6);

            check(tlv_iter_next(&it, &v));
            check(v.type == 94);
            check(v.meta == 0x0F);
            check(v.len == 4);

            check(!tlv_iter_next(&it, &v));
        }

        it ("stops on a value overrunning the buffer") {
            const uint8_t buf[] = { 82, 0x00, 0x04, 0x00, 0x01, 0x02 };
            tlv_iter_t it;
            tlv_iter_init(&it, &gtp2c, buf, sizeof buf);
            tlv_view_t v;
            check(!tlv_iter_next(&it, &v));
        }

        it ("writes an entry with a big-endian u16 value") {
            uint8_t    buf[16];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_put_u16(&w, &gtp2c, 126, 0, 0x1F90) == TLV_OK);
            const uint8_t expect[] = { 126, 0x00, 0x02, 0x00, 0x1F, 0x90 };
            check(w.off == sizeof expect);
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("backfills the length of a nested entry") {
            uint8_t    buf[32];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);

            const int h = tlv_begin(&w, &gtp2c, 93, 0);
            check(h >= 0);
            check(tlv_put_u8(&w, &gtp2c, 73, 0, 5) == TLV_OK);
            check(tlv_end(&w, &gtp2c, h) == TLV_OK);
            check(buf[1] == 0x00 && buf[2] == 5);

            tlv_iter_t it;
            tlv_iter_init(&it, &gtp2c, buf, w.off);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 93 && v.len == 5);

            tlv_iter_t inner;
            tlv_iter_grouped(&inner, &gtp2c, &v);
            tlv_view_t child;
            check(tlv_iter_next(&inner, &child));
            check(child.type == 73 && child.value[0] == 5);
            check(!tlv_iter_next(&inner, &child));
        }

        it ("rejects a value the 16-bit length field cannot carry") {
            uint8_t    buf[8];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_put(&w, &gtp2c, 82, 0, buf, 0x10000u) == TLV_E_INVAL);
        }
    }

    context ("Diameter profile (4-byte aligned, length includes header)") {
        it ("iterates AVPs across padding") {
            const uint8_t buf[] = {
                /* code 263, flags 0x40, length 8+5=13, 3 pad bytes */
                0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x0D, 's', 'e', 's',
                '-', '1', 0x00, 0x00, 0x00,
                /* code 268, flags 0x40, length 12, u32 2001 */
                0x00, 0x00, 0x01, 0x0C, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00,
                0x07, 0xD1
            };
            tlv_iter_t it;
            tlv_iter_init(&it, &diameter, buf, sizeof buf);

            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 263);
            check(v.meta == 0x40);
            check(v.len == 5);
            check(memcmp(v.value, "ses-1", 5) == 0);

            check(tlv_iter_next(&it, &v));
            check(v.type == 268);
            check(v.len == 4);
            check(tlv_load(v.value, 4, true) == 2001);

            check(!tlv_iter_next(&it, &v));
        }

        it ("parses a final AVP whose trailing pad is absent") {
            const uint8_t buf[] = { 0x00, 0x00, 0x01, 0x07, 0x40,
                                    0x00, 0x00, 0x0A, 'h',  'i' };
            tlv_iter_t it;
            tlv_iter_init(&it, &diameter, buf, sizeof buf);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.len == 2);
            check(!tlv_iter_next(&it, &v));
        }

        it ("stops on a length smaller than the header") {
            const uint8_t buf[] = { 0x00, 0x00, 0x01, 0x07,
                                    0x40, 0x00, 0x00, 0x04 };
            tlv_iter_t it;
            tlv_iter_init(&it, &diameter, buf, sizeof buf);
            tlv_view_t v;
            check(!tlv_iter_next(&it, &v));
        }

        it ("exposes the V flag so the caller can strip the Vendor-ID") {
            const uint8_t buf[] = {
                0x00, 0x00, 0x00, 0x09, 0x80, 0x00,
                0x00, 0x10, 0x00, 0x00, 0x28, 0xAF, /* Vendor-ID 10415 */
                0xCA, 0xFE, 0xBA, 0xBE
            };
            tlv_iter_t it;
            tlv_iter_init(&it, &diameter, buf, sizeof buf);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.meta & 0x80);
            check(v.len == 8);
            check(tlv_load(v.value, 4, true) == 10415);
        }

        it ("writes header, length-with-header and zeroed padding") {
            uint8_t buf[32];
            memset(buf, 0xAA, sizeof buf);
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_put(&w, &diameter, 263, 0x40, "hi", 2) == TLV_OK);
            check(w.off == 12u); /* 8 + 2, padded to 4 */
            const uint8_t expect[] = { 0x00, 0x00, 0x01, 0x07, 0x40, 0x00,
                                       0x00, 0x0A, 'h',  'i',  0x00, 0x00 };
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("round-trips a grouped AVP") {
            uint8_t    buf[64];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);

            const int h = tlv_begin(&w, &diameter, 297, 0x40);
            check(h >= 0);
            check(tlv_put_u32(&w, &diameter, 268, 0x40, 2001) == TLV_OK);
            check(tlv_end(&w, &diameter, h) == TLV_OK);
            check(w.off == 20u); /* 8-byte parent header + 12-byte child */

            tlv_iter_t it;
            tlv_iter_init(&it, &diameter, buf, w.off);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 297);
            check(v.len == 12);

            tlv_iter_t inner;
            tlv_iter_grouped(&inner, &diameter, &v);
            tlv_view_t child;
            check(tlv_iter_next(&inner, &child));
            check(child.type == 268);
            check(tlv_load(child.value, 4, true) == 2001);
        }
    }

    context ("netlink profile (host order, length includes header)") {
        it ("iterates attributes across padding") {
            uint8_t        buf[32];
            const uint32_t v32 = 0xDEADBEEFu;
            const uint16_t v16 = 0x1234;
            size_t         off = nla_write(buf, 1, &v32, sizeof v32);
            off += nla_write(buf + off, 2, &v16, sizeof v16);

            tlv_iter_t it;
            tlv_iter_init(&it, &netlink, buf, off);

            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 1);
            check(v.meta == 0);
            check(v.len == 4);
            check(tlv_load(v.value, 4, false) == 0xDEADBEEFu);

            check(tlv_iter_next(&it, &v));
            check(v.type == 2);
            check(v.len == 2);
            check(tlv_load(v.value, 2, false) == 0x1234);

            check(!tlv_iter_next(&it, &v));
        }

        it ("keeps the NLA_F_NESTED bit and walks the nested attributes") {
            uint8_t        inner[8];
            const uint32_t ival = 7;
            const size_t   ilen = nla_write(inner, 3, &ival, sizeof ival);

            uint8_t      buf[16];
            const size_t off =
                nla_write(buf, 0x8000u | 1u, inner, (uint16_t)ilen);

            tlv_iter_t it;
            tlv_iter_init(&it, &netlink, buf, off);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == (0x8000u | 1u));

            tlv_iter_t nested;
            tlv_iter_grouped(&nested, &netlink, &v);
            tlv_view_t child;
            check(tlv_iter_next(&nested, &child));
            check(child.type == 3);
            check(tlv_load(child.value, 4, false) == 7);
        }

        it ("writes host-order attributes the iterator reads back") {
            uint8_t    buf[32];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_put_u32(&w, &netlink, 1, 0, 0xCAFEBABEu) == TLV_OK);
            check(tlv_put_u16(&w, &netlink, 2, 0, 0xBEEF) == TLV_OK);
            check(w.off == 16u); /* both entries padded to 4 */

            uint16_t nla_len;
            memcpy(&nla_len, buf, 2);
            check(nla_len == 8);

            tlv_iter_t it;
            tlv_iter_init(&it, &netlink, buf, w.off);
            tlv_view_t v;
            check(tlv_iter_next(&it, &v));
            check(v.type == 1);
            check(tlv_load(v.value, 4, false) == 0xCAFEBABEu);
            check(tlv_iter_next(&it, &v));
            check(v.type == 2);
            check(tlv_load(v.value, 2, false) == 0xBEEF);
            check(!tlv_iter_next(&it, &v));
        }
    }

    context ("write buffer") {
        it ("makes overflow sticky") {
            uint8_t    buf[6];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_put_u32(&w, &gtp2c, 94, 0, 0) == TLV_E_OVERFLOW);
            check(w.overflow);
            check(tlv_put_u8(&w, &gtp2c, 82, 0, 6) == TLV_E_OVERFLOW);
        }

        it ("rejects tlv_end with a bad handle") {
            uint8_t    buf[16];
            tlv_wbuf_t w;
            tlv_wbuf_init(&w, buf, sizeof buf);
            check(tlv_end(&w, &gtp2c, -1) == TLV_E_INVAL);
            check(tlv_end(&w, &gtp2c, 100) == TLV_E_INVAL);
        }
    }
}
