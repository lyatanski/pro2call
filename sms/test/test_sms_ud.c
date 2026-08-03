#include <string.h>

#include "sms.h"
#include "test.h"

/* TS 23.038 alphabets and TS 23.040 §9.2.3.24 user data: the DCS table,
 * the 7-bit alphabet, septet packing, the UDH and concatenation.
 *
 * The vectors here are real PDU bodies whose expected text was unpacked
 * by hand septet by septet, so a table typo cannot pass by agreeing
 * with itself. */

/* The TP-UD of a published SMS-DELIVER carrying "How are you?" —
 * 12 septets in 11 octets. */
static const uint8_t ud_how[] = { 0xC8, 0xF7, 0x1D, 0x14, 0x96, 0x97,
                                  0x41, 0xF9, 0x77, 0xFD, 0x07 };

/* Hex helper, for readable expectations. */
static int hexeq(const uint8_t* b, size_t n, const char* hex)
{
    if (strlen(hex) != n * 2) return 0;
    static const char* d = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        if (hex[i * 2] != d[b[i] >> 4]) return 0;
        if (hex[i * 2 + 1] != d[b[i] & 0x0F]) return 0;
    }
    return 1;
}

spec ("sms user data") {
    context ("data coding scheme") {
        it ("reads the general data coding group") {
            sms_dcs_t d;
            sms_dcs_decode(0x00, &d);
            check(d.alphabet == SMS_ALPHA_GSM7);
            check(!d.compressed && !d.has_class && !d.auto_delete && !d.mwi);

            sms_dcs_decode(0x04, &d);
            check(d.alphabet == SMS_ALPHA_8BIT);
            sms_dcs_decode(0x08, &d);
            check(d.alphabet == SMS_ALPHA_UCS2);

            /* class bit set: 0xF1 in the "data coding/message class"
             * group, 0x11 in the general one */
            sms_dcs_decode(0x11, &d);
            check(d.alphabet == SMS_ALPHA_GSM7 && d.has_class && d.cls == 1);
            sms_dcs_decode(0xF1, &d);
            check(d.alphabet == SMS_ALPHA_GSM7 && d.has_class && d.cls == 1);
            sms_dcs_decode(0xF5, &d);
            check(d.alphabet == SMS_ALPHA_8BIT && d.has_class && d.cls == 1);
        }

        it ("refuses to call a compressed body text") {
            sms_dcs_t d;
            sms_dcs_decode(0x20, &d); /* compressed, alphabet bits say GSM7 */
            check(d.compressed);
            check(d.alphabet == SMS_ALPHA_RESERVED);
        }

        it ("reads the automatic-deletion and reserved groups") {
            sms_dcs_t d;
            sms_dcs_decode(0x48, &d); /* 0100: auto delete, UCS2 */
            check(d.auto_delete && d.alphabet == SMS_ALPHA_UCS2);
            sms_dcs_decode(0x80, &d); /* 1000: reserved */
            check(d.alphabet == SMS_ALPHA_RESERVED);
        }

        it ("reads the message-waiting groups") {
            sms_dcs_t d;
            sms_dcs_decode(0xC0, &d); /* discard, voicemail, inactive */
            check(d.mwi && d.mwi_discard && !d.mwi_active);
            check(d.mwi_type == 0 && d.alphabet == SMS_ALPHA_GSM7);
            sms_dcs_decode(0xD9, &d); /* store, active, fax */
            check(d.mwi && !d.mwi_discard && d.mwi_active && d.mwi_type == 1);
            check(d.alphabet == SMS_ALPHA_GSM7);
            sms_dcs_decode(0xE8, &d); /* store as UCS2, active, voicemail */
            check(d.mwi && d.mwi_active && d.alphabet == SMS_ALPHA_UCS2);
        }

        it ("builds the DCS it promises") {
            check(sms_dcs_make(SMS_ALPHA_GSM7, -1) == 0x00);
            check(sms_dcs_make(SMS_ALPHA_8BIT, -1) == 0x04);
            check(sms_dcs_make(SMS_ALPHA_UCS2, -1) == 0x08);
            check(sms_dcs_make(SMS_ALPHA_GSM7, 0) == 0x10);
            check(sms_dcs_alphabet(sms_dcs_make(SMS_ALPHA_UCS2, 2)) ==
                  SMS_ALPHA_UCS2);
        }
    }

    context ("GSM 7-bit default alphabet") {
        it ("round-trips every septet but the escape") {
            for (unsigned i = 0; i < 128; i++) {
                if (i == 0x1B) continue;
                int32_t ucs = sms_gsm7_to_ucs((uint8_t)i);
                check(ucs > 0);
                check(sms_gsm7_from_ucs((uint32_t)ucs) == (int32_t)i);
            }
        }

        it ("keeps the escape out of the character table") {
            check(sms_gsm7_to_ucs(0x1B) == -1);
            check(sms_gsm7_to_ucs(0x80) == -1);
        }

        it ("puts the spec's characters where the spec puts them") {
            /* Table 6.2.1.1 spot checks — the positions ASCII does not
             * agree with are the whole point of having a table. */
            check(sms_gsm7_to_ucs(0x00) == 0x40);   /* @             */
            check(sms_gsm7_to_ucs(0x01) == 0x00A3); /* pound         */
            check(sms_gsm7_to_ucs(0x02) == 0x24);   /* $             */
            check(sms_gsm7_to_ucs(0x09) == 0x00C7); /* C-cedilla     */
            check(sms_gsm7_to_ucs(0x10) == 0x0394); /* Delta         */
            check(sms_gsm7_to_ucs(0x11) == 0x5F);   /* _             */
            check(sms_gsm7_to_ucs(0x1F) == 0x00C9); /* E-acute       */
            check(sms_gsm7_to_ucs(0x24) == 0x00A4); /* currency sign */
            check(sms_gsm7_to_ucs(0x40) == 0x00A1); /* inverted !    */
            check(sms_gsm7_to_ucs(0x5F) == 0x00A7); /* section sign  */
            check(sms_gsm7_to_ucs(0x60) == 0x00BF); /* inverted ?    */
            check(sms_gsm7_to_ucs(0x7F) == 0x00E0); /* a-grave       */
        }

        it ("reaches the extension table through the escape") {
            /* '{' is 0x1B 0x28, the euro sign 0x1B 0x65 (§6.2.1.1). */
            check(sms_gsm7_from_ucs('{') == (0x1B00 | 0x28));
            check(sms_gsm7_from_ucs('}') == (0x1B00 | 0x29));
            check(sms_gsm7_from_ucs('[') == (0x1B00 | 0x3C));
            check(sms_gsm7_from_ucs(']') == (0x1B00 | 0x3E));
            check(sms_gsm7_from_ucs('\\') == (0x1B00 | 0x2F));
            check(sms_gsm7_from_ucs('~') == (0x1B00 | 0x3D));
            check(sms_gsm7_from_ucs('^') == (0x1B00 | 0x14));
            check(sms_gsm7_from_ucs('|') == (0x1B00 | 0x40));
            check(sms_gsm7_from_ucs(0x20AC) == (0x1B00 | 0x65));
        }

        it ("has no mapping for what the alphabet cannot hold") {
            check(sms_gsm7_from_ucs(0x0416) == -1);  /* Cyrillic Zhe  */
            check(sms_gsm7_from_ucs(0x1F600) == -1); /* emoji         */
        }

        it ("counts septets with extension pairs as two") {
            check(sms_gsm7_septets("abc", 3) == 3);
            check(sms_gsm7_septets("a{b}", 4) == 6);
            check(sms_gsm7_septets("\xE2\x82\xAC", 3) == 2); /* euro */
            check(sms_gsm7_septets("\xD0\x96", 2) == SMS_E_ALPHABET);
        }

        it ("round-trips UTF-8 through septets") {
            const char* s = "Hi {a} 5\xC2\xA4 \xC3\xA9\xE2\x82\xAC";
            uint8_t     sep[64];
            char        back[64];
            int         n = sms_gsm7_from_utf8(s, strlen(s), sep, sizeof sep);
            check(n > 0);
            check(sms_gsm7_to_utf8(sep, (size_t)n, back, sizeof back) > 0);
            check(strcmp(back, s) == 0);
        }

        it ("renders a dangling escape as a space, per 6.2.1.1") {
            uint8_t sep[3] = { 'A', 0x1B, 0 };
            char    out[8];
            /* 0x1B 0x00 is not a defined extension position. */
            check(sms_gsm7_to_utf8(sep, 3, out, sizeof out) == 2);
            check(strcmp(out, "A ") == 0);
            /* ... and so is an escape with nothing after it at all. */
            check(sms_gsm7_to_utf8(sep, 2, out, sizeof out) == 2);
            check(strcmp(out, "A ") == 0);
        }

        it ("rejects malformed UTF-8 rather than encoding it onward") {
            uint8_t sep[8];
            check(sms_gsm7_from_utf8("\xC3", 1, sep, sizeof sep) ==
                  SMS_E_INVAL);
            check(sms_gsm7_from_utf8("\xC0\xAF", 2, sep, sizeof sep) ==
                  SMS_E_INVAL); /* overlong '/' */
            check(sms_gsm7_from_utf8("\xED\xA0\x80", 3, sep, sizeof sep) ==
                  SMS_E_INVAL); /* surrogate */
        }
    }

    context ("septet packing") {
        it ("unpacks a real PDU body") {
            uint8_t sep[16];
            char    text[32];
            int     n =
                sms_gsm7_unpack(ud_how, sizeof ud_how, 0, 12, sep, sizeof sep);
            check(n == 12);
            check(sms_gsm7_to_utf8(sep, 12, text, sizeof text) == 12);
            check(strcmp(text, "How are you?") == 0);
        }

        it ("packs it back to the same octets") {
            uint8_t sep[16], out[16];
            int     n = sms_gsm7_from_utf8("How are you?", 12, sep, sizeof sep);
            check(n == 12);
            memset(out, 0, sizeof out);
            check(sms_gsm7_pack(sep, 12, 0, out, sizeof out) ==
                  (int)sizeof ud_how);
            check(memcmp(out, ud_how, sizeof ud_how) == 0);
        }

        it ("takes the septet count from TP-UDL, not from the octets") {
            /* Seven septets occupy seven octets, and seven octets hold
             * eight septet positions — so the octet count alone cannot
             * say whether the eighth is a character or padding. Ask for
             * eight and you get the padding as a '@' (0x00); that is the
             * phantom trailing character, and the defence is that only
             * TP-UDL decides, which is what sms_ud_to_utf8() uses. */
            uint8_t sep[8] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G' };
            uint8_t out[8];
            uint8_t back[8];
            memset(out, 0, sizeof out);
            check(sms_gsm7_pack(sep, 7, 0, out, sizeof out) == 7);
            check(sms_gsm7_unpack(out, 7, 0, 7, back, sizeof back) == 7);
            check(memcmp(back, sep, 7) == 0);
            check(sms_gsm7_unpack(out, 7, 0, 8, back, sizeof back) == 8);
            check(back[7] == 0x00); /* the padding, read as '@' */

            char text[16];
            check(sms_ud_to_utf8(0x00, false, out, 7, 7, text, sizeof text) ==
                  7);
            check(strcmp(text, "ABCDEFG") == 0);

            /* Nine will not fit in seven octets at all. */
            check(sms_gsm7_unpack(out, 7, 0, 9, back, sizeof back) ==
                  SMS_E_OVERFLOW);
            uint8_t wide[16];
            check(sms_gsm7_unpack(out, 7, 0, 9, wide, sizeof wide) ==
                  SMS_E_LENGTH);
        }

        it ("aligns text to the septet boundary after a header") {
            /* A 6-octet concatenation header is 48 bits; the next
             * septet boundary is septet 7 (bit 49), so bit 48 is a
             * single fill bit and the first text septet lands shifted
             * left by one. TS 23.040 §9.2.3.24. */
            check(sms_gsm7_septet_off(6) == 7);
            check(sms_gsm7_septet_off(7) == 8);
            check(sms_gsm7_septet_off(0) == 0);

            uint8_t ud[8];
            memset(ud, 0, sizeof ud);
            ud[0]          = 5; /* UDHL */
            ud[1]          = SMS_UDH_CONCAT8;
            ud[2]          = 3;
            ud[3]          = 0x2A;     /* ref   */
            ud[4]          = 3;        /* total */
            ud[5]          = 1;        /* seq   */
            uint8_t sep[1] = { 0x41 }; /* 'A' */
            int     total  = sms_gsm7_pack(sep, 1, 7, ud, sizeof ud);
            check(total == 7);
            /* 0x41 << 1 == 0x82, and the fill bit below it stays 0 */
            check(hexeq(ud, 7, "0500032A030182"));

            /* and back out again */
            uint8_t back[4];
            check(sms_gsm7_unpack(ud, 7, 7, 1, back, sizeof back) == 1);
            check(back[0] == 0x41);
        }

        it ("keeps the header's bits when packing over them") {
            /* A 1-octet header (UDHL 0) puts the boundary at septet 2,
             * bit 14, which is octet 1 bit 6 — so the pack has to
             * preserve bits 0..5 of octet 1 as fill. */
            uint8_t ud[4]  = { 0x00, 0x00, 0x00, 0x00 };
            uint8_t sep[1] = { 0x7F };
            check(sms_gsm7_septet_off(1) == 2);
            check(sms_gsm7_pack(sep, 1, 2, ud, sizeof ud) == 3);
            check(ud[0] == 0x00);
            check(ud[1] == 0xC0); /* 0x7F << 6, truncated */
            check(ud[2] == 0x1F); /* the spill */
        }

        it ("refuses to pack past the buffer") {
            uint8_t sep[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            uint8_t out[4];
            memset(out, 0, sizeof out);
            check(sms_gsm7_pack(sep, 8, 0, out, sizeof out) == SMS_E_OVERFLOW);
            check(sms_gsm7_unpack(out, 4, 0, 8, sep, 4) == SMS_E_OVERFLOW);
        }
    }

    context ("TP-UD to and from UTF-8") {
        it ("decodes 7-bit user data with the TPDU's UDL") {
            char out[64];
            int  n = sms_ud_to_utf8(0x00, false, ud_how, sizeof ud_how, 12, out,
                                    sizeof out);
            check(n == 12);
            check(strcmp(out, "How are you?") == 0);
        }

        it ("builds 7-bit user data and reports septets, not octets") {
            uint8_t ud[SMS_UD_MAX];
            uint8_t udl = 0, dcs = 0xFF;
            int n = sms_ud_from_utf8("How are you?", 12, SMS_ALPHA_GSM7, NULL,
                                     0, ud, sizeof ud, &udl, &dcs);
            check(n == 11);   /* octets */
            check(udl == 12); /* septets */
            check(dcs == 0x00);
            check(memcmp(ud, ud_how, 11) == 0);
        }

        it ("picks UCS2 only when GSM 7-bit cannot hold the text") {
            uint8_t ud[SMS_UD_MAX];
            uint8_t udl = 0, dcs = 0xFF;
            check(sms_ud_from_utf8("plain", 5, SMS_ALPHA_AUTO, NULL, 0, ud,
                                   sizeof ud, &udl, &dcs) > 0);
            check(dcs == 0x00);
            /* Cyrillic has no GSM 7-bit mapping */
            check(sms_ud_from_utf8("\xD0\x9F\xD1\x80", 4, SMS_ALPHA_AUTO, NULL,
                                   0, ud, sizeof ud, &udl, &dcs) > 0);
            check(dcs == 0x08);
        }

        it ("round-trips UCS2, surrogate pairs included") {
            /* "Привет 🙂" — Cyrillic in the BMP plus an emoji that needs
             * a surrogate pair on the wire. */
            const char* s = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82"
                            " \xF0\x9F\x99\x82";
            uint8_t     ud[SMS_UD_MAX];
            uint8_t     udl = 0, dcs = 0;
            char        back[SMS_UD_MAX];
            int n = sms_ud_from_utf8(s, strlen(s), SMS_ALPHA_UCS2, NULL, 0, ud,
                                     sizeof ud, &udl, &dcs);
            check(n > 0);
            check(dcs == 0x08);
            check(udl == (uint8_t)n); /* UCS2 counts octets */
            /* 6 BMP chars + space = 7 units, emoji = 2 units */
            check(n == 18);
            check(sms_ud_to_utf8(dcs, false, ud, (size_t)n, udl, back,
                                 sizeof back) == (int)strlen(s));
            check(strcmp(back, s) == 0);
        }

        it ("hands 8-bit data back verbatim") {
            const uint8_t blob[] = { 0x00, 0x01, 0xFF, 0x7F };
            uint8_t       ud[SMS_UD_MAX];
            uint8_t       udl = 0, dcs = 0;
            check(sms_ud_from_utf8((const char*)blob, sizeof blob,
                                   SMS_ALPHA_8BIT, NULL, 0, ud, sizeof ud, &udl,
                                   &dcs) == 4);
            check(dcs == 0x04 && udl == 4);
            check(memcmp(ud, blob, 4) == 0);
        }

        it ("round-trips 7-bit text behind a header") {
            uint8_t     udh[6] = { 5, SMS_UDH_CONCAT8, 3, 0x11, 2, 1 };
            uint8_t     ud[SMS_UD_MAX];
            uint8_t     udl = 0, dcs = 0;
            char        back[SMS_UD_MAX];
            const char* s = "Second half";
            int n = sms_ud_from_utf8(s, strlen(s), SMS_ALPHA_GSM7, udh,
                                     sizeof udh, ud, sizeof ud, &udl, &dcs);
            check(n > 0);
            check(memcmp(ud, udh, sizeof udh) == 0);
            /* UDL counts the header's septet-equivalent (7) too */
            check(udl == 7 + 11);
            check(sms_ud_to_utf8(dcs, true, ud, (size_t)n, udl, back,
                                 sizeof back) == 11);
            check(strcmp(back, s) == 0);
        }

        it ("refuses text that will not fit one message") {
            char    big[200];
            uint8_t ud[SMS_UD_MAX];
            uint8_t udl = 0, dcs = 0;
            memset(big, 'x', sizeof big);
            check(sms_ud_from_utf8(big, 161, SMS_ALPHA_GSM7, NULL, 0, ud,
                                   sizeof ud, &udl, &dcs) == SMS_E_LENGTH);
            /* 160 septets is exactly 140 octets — the boundary case */
            check(sms_ud_from_utf8(big, 160, SMS_ALPHA_GSM7, NULL, 0, ud,
                                   sizeof ud, &udl, &dcs) == 140);
            check(udl == 160);
        }

        it ("rejects a header whose UDHL disagrees with the run") {
            uint8_t udh[3] = { 9, 0, 3 }; /* claims 9, three octets given */
            uint8_t ud[SMS_UD_MAX];
            uint8_t udl = 0, dcs = 0;
            check(sms_ud_from_utf8("x", 1, SMS_ALPHA_GSM7, udh, sizeof udh, ud,
                                   sizeof ud, &udl, &dcs) == SMS_E_INVAL);
        }
    }

    context ("user data header") {
        it ("walks the information elements") {
            const uint8_t ud[] = {
                0x0B,                               /* UDHL              */
                0x00, 0x03, 0x2A, 0x03, 0x02,       /* concat 8-bit      */
                0x05, 0x04, 0x23, 0xF0, 0x00, 0x00, /* port 16-bit  */
                0x41 /* one packed septet of text */
            };
            sms_udh_iter_t it;
            sms_udh_ie_t ie;
            check(sms_udh_len(ud, sizeof ud) == 12);
            check(sms_udh_begin(&it, ud, sizeof ud));
            check(sms_udh_next(&it, &ie));
            check(ie.iei == SMS_UDH_CONCAT8 && ie.len == 3);
            check(ie.data[0] == 0x2A && ie.data[1] == 3 && ie.data[2] == 2);
            check(sms_udh_next(&it, &ie));
            check(ie.iei == SMS_UDH_PORT16 && ie.len == 4);
            check(!sms_udh_next(&it, &ie));
        }

        it ("stops at a header that overruns the field") {
            const uint8_t bad[] = { 0x0A, 0x00, 0x03, 0x01 };
            sms_udh_iter_t it;
            check(sms_udh_len(bad, sizeof bad) == 0);
            check(!sms_udh_begin(&it, bad, sizeof bad));
        }

        it ("stops at an element that overruns the header") {
            /* UDHL says 3, but the element claims 5 octets of data. */
            const uint8_t bad[] = { 0x03, 0x00, 0x05, 0x01, 0x02 };
            sms_udh_iter_t it;
            sms_udh_ie_t ie;
            check(sms_udh_begin(&it, bad, sizeof bad));
            check(!sms_udh_next(&it, &ie));
        }

        it ("reads either width of concatenation reference") {
            const uint8_t ud8[]  = { 5, 0x00, 3, 0x2A, 3, 2 };
            const uint8_t ud16[] = { 6, 0x08, 4, 0x12, 0x34, 4, 1 };
            sms_concat_t  c;
            check(sms_concat_get(ud8, sizeof ud8, &c));
            check(c.ref == 0x2A && c.total == 3 && c.seq == 2 && !c.ref16);
            check(sms_concat_get(ud16, sizeof ud16, &c));
            check(c.ref == 0x1234 && c.total == 4 && c.seq == 1 && c.ref16);
        }

        it ("builds the header it reads") {
            uint8_t      out[8];
            sms_concat_t c = { 0x1234, 3, 2, true };
            sms_concat_t back;
            check(sms_concat_udh(out, sizeof out, &c) == 7);
            check(hexeq(out, 7, "06080412340302"));
            check(sms_concat_get(out, 7, &back));
            check(back.ref == 0x1234 && back.total == 3 && back.seq == 2);
            check(back.ref16);

            c.ref16 = false;
            c.ref   = 0x2A;
            check(sms_concat_udh(out, sizeof out, &c) == 6);
            check(hexeq(out, 6, "0500032A0302"));
        }

        it ("rejects a nonsense sequence") {
            uint8_t      out[8];
            sms_concat_t c = { 1, 0, 1, false }; /* total 0 */
            check(sms_concat_udh(out, sizeof out, &c) == SMS_E_INVAL);
            c.total = 2;
            c.seq   = 3; /* part 3 of 2 */
            check(sms_concat_udh(out, sizeof out, &c) == SMS_E_INVAL);
        }
    }

    context ("concatenation") {
        it ("leaves a short message alone") {
            sms_part_t parts[4];
            int n = sms_concat_split("short", 5, SMS_ALPHA_GSM7, 7, false,
                                     parts, 4);
            check(n == 1);
            check(parts[0].total == 1 && parts[0].seq == 1);
            /* no header: the first octet is packed text, not a UDHL */
            check(parts[0].udl == 5);
            check(parts[0].ud_len == 5);
            check(sms_udh_len(parts[0].ud, parts[0].ud_len) == 0);
        }

        it ("splits and reassembles GSM 7-bit text byte for byte") {
            char text[400];
            for (size_t i = 0; i < sizeof text; i++)
                text[i] = (char)('a' + (i % 26));

            sms_part_t parts[8];
            int n = sms_concat_split(text, sizeof text, SMS_ALPHA_GSM7, 0x2A,
                                     false, parts, 8);
            /* 153 septets per part after the 6-octet header */
            check(n == 3);

            char   joined[512];
            size_t at = 0;
            for (int i = 0; i < n; i++) {
                sms_concat_t c;
                check(sms_concat_get(parts[i].ud, parts[i].ud_len, &c));
                check(c.ref == 0x2A && c.total == 3 && c.seq == i + 1);
                char piece[SMS_UD_MAX * 4];
                int  len = sms_ud_to_utf8(parts[i].dcs, true, parts[i].ud,
                                          parts[i].ud_len, parts[i].udl, piece,
                                          sizeof piece);
                check(len > 0);
                check(at + (size_t)len <= sizeof joined);
                memcpy(joined + at, piece, (size_t)len);
                at += (size_t)len;
            }
            check(at == sizeof text);
            check(memcmp(joined, text, sizeof text) == 0);
        }

        it ("never splits an escape pair across parts") {
            /* 152 plain characters then a run of '{', each of which
             * costs two septets. The 153-septet budget cannot hold a
             * half escape, so part 1 must stop at 152 and the '{' moves
             * to part 2 rather than losing its escape. */
            char text[400];
            memset(text, 'a', 152);
            for (size_t i = 152; i < sizeof text; i++)
                text[i] = '{';

            sms_part_t parts[8];
            int n = sms_concat_split(text, sizeof text, SMS_ALPHA_GSM7, 1,
                                     false, parts, 8);
            check(n > 1);
            char piece[SMS_UD_MAX * 4];
            int  len =
                sms_ud_to_utf8(parts[0].dcs, true, parts[0].ud, parts[0].ud_len,
                               parts[0].udl, piece, sizeof piece);
            check(len == 152);
            check(memcmp(piece, text, 152) == 0);
        }

        it ("splits UCS2 without breaking a surrogate pair") {
            /* 134 octets of payload per part = 67 UCS2 units; an emoji
             * is two units, so a part must not end between them. */
            char   text[600];
            size_t at = 0;
            for (int i = 0; i < 66; i++) { /* 66 BMP chars */
                text[at++] = (char)0xD0;
                text[at++] = (char)0x9F;
            }
            for (int i = 0; i < 20; i++) { /* emoji, 4 UTF-8 bytes each */
                memcpy(text + at, "\xF0\x9F\x99\x82", 4);
                at += 4;
            }

            sms_part_t parts[8];
            int        n =
                sms_concat_split(text, at, SMS_ALPHA_UCS2, 9, true, parts, 8);
            check(n > 1);
            char   joined[1024];
            size_t k = 0;
            for (int i = 0; i < n; i++) {
                char piece[SMS_UD_MAX * 4];
                int  len = sms_ud_to_utf8(parts[i].dcs, true, parts[i].ud,
                                          parts[i].ud_len, parts[i].udl, piece,
                                          sizeof piece);
                check(len > 0);
                memcpy(joined + k, piece, (size_t)len);
                k += (size_t)len;
            }
            check(k == at);
            check(memcmp(joined, text, at) == 0);
        }

        it ("says so rather than truncating when max is too small") {
            char text[400];
            memset(text, 'x', sizeof text);
            sms_part_t parts[2];
            check(sms_concat_split(text, sizeof text, SMS_ALPHA_GSM7, 1, false,
                                   parts, 2) == SMS_E_LENGTH);
        }
    }

    context ("malformed input") {
        it ("never reads past a truncated user data field") {
            char out[64];
            /* UDL claims 12 septets but only two octets are there */
            check(sms_ud_to_utf8(0x00, false, ud_how, 2, 12, out, sizeof out) ==
                  SMS_E_LENGTH);
            /* UDHI set, but the field is empty */
            check(sms_ud_to_utf8(0x00, true, ud_how, 0, 0, out, sizeof out) ==
                  SMS_E_LENGTH);
            /* UDL smaller than the header alignment needs */
            uint8_t ud[8] = { 5, 0, 3, 1, 2, 1, 0x82, 0 };
            check(sms_ud_to_utf8(0x00, true, ud, 7, 3, out, sizeof out) ==
                  SMS_E_LENGTH);
        }

        it ("rejects a compressed or reserved DCS as unreadable") {
            char out[64];
            check(sms_ud_to_utf8(0x20, false, ud_how, sizeof ud_how, 12, out,
                                 sizeof out) == SMS_E_ALPHABET);
            check(sms_ud_to_utf8(0x80, false, ud_how, sizeof ud_how, 12, out,
                                 sizeof out) == SMS_E_ALPHABET);
        }

        it ("reports overflow instead of writing past the caller's buffer") {
            char tiny[4];
            check(sms_ud_to_utf8(0x00, false, ud_how, sizeof ud_how, 12, tiny,
                                 sizeof tiny) == SMS_E_OVERFLOW);
        }
    }
}
