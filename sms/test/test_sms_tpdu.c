#include <limits.h>
#include <string.h>

#include "sms.h"
#include "test.h"

/* TS 23.040 §9.2.2.x TPDUs, §9.1.2.5 addresses, §9.2.3.11 timestamps.
 *
 * The two long hex vectors are real PDUs (the transfer-layer part, with
 * the AT-command SMSC prefix stripped) whose every field was decoded by
 * hand before being written down here, so the test does not merely
 * agree with the codec. */

/* SMS-DELIVER from +31641600986, "How are you?", 2002-08-26 19:37:41. */
static const uint8_t deliver_pdu[] = {
    0x04,                                           /* MTI=DELIVER, MMS   */
    0x0B, 0x91, 0x13, 0x46, 0x61, 0x00, 0x89, 0xF6, /* TP-OA              */
    0x00,                                           /* TP-PID             */
    0x00,                                           /* TP-DCS: GSM 7-bit  */
    0x20, 0x80, 0x62, 0x91, 0x73, 0x14, 0x08,       /* TP-SCTS            */
    0x0C,                                           /* TP-UDL: 12 septets */
    0xC8, 0xF7, 0x1D, 0x14, 0x96, 0x97, 0x41, 0xF9, 0x77, 0xFD, 0x07
};

/* SMS-SUBMIT to +31628870634, "hellohello", relative validity 63 weeks. */
static const uint8_t submit_pdu[] = { 0x11, /* MTI=SUBMIT, VPF=rel */
                                      0x00, /* TP-MR               */
                                      0x0B, 0x91, 0x13, 0x26, 0x88,
                                      0x07, 0x36, 0xF4, /* TP-DA */
                                      0x00, /* TP-PID              */
                                      0x00, /* TP-DCS              */
                                      0xFF, /* TP-VP: 63 weeks     */
                                      0x0A, /* TP-UDL: 10 septets  */
                                      0xE8, 0x32, 0x9B, 0xFD, 0x46,
                                      0x97, 0xD9, 0xEC, 0x37 };

static int streq(const char* a, const char* b)
{
    return strcmp(a, b) == 0;
}

spec ("sms tpdu") {
    context ("addresses") {
        it ("decodes an even-length international number") {
            /* eight semi-octets: 12345678 */
            const uint8_t b[] = { 0x08, 0x91, 0x21, 0x43, 0x65, 0x87 };
            sms_addr_t    a;
            check(sms_addr_decode(b, sizeof b, &a) == 6);
            check(a.ton == SMS_TON_INTERNATIONAL);
            check(a.npi == SMS_NPI_ISDN);
            check(streq(a.digits, "12345678"));
        }

        it ("stops at the filler of an odd-length number") {
            sms_addr_t a;
            check(sms_addr_decode(deliver_pdu + 1, sizeof deliver_pdu - 1,
                                  &a) == 8);
            check(a.ton == SMS_TON_INTERNATIONAL);
            check(streq(a.digits, "31641600986")); /* 11 digits, not 12 */
        }

        it ("decodes the four extra BCD symbols") {
            /* 0xA..0xE are '*', '#', 'a', 'b', 'c' (§9.1.2.3) */
            const uint8_t b[] = { 0x05, 0x81, 0xBA, 0xDC, 0xFE };
            sms_addr_t    a;
            check(sms_addr_decode(b, sizeof b, &a) == 5);
            check(streq(a.digits, "*#abc"));
        }

        it ("round-trips through the encoder") {
            sms_addr_t a, back;
            uint8_t    b[SMS_ADDR_MAX_OCTETS];
            check(sms_addr_set(&a, "+31641600986", SMS_TON_UNKNOWN) == SMS_OK);
            check(a.ton == SMS_TON_INTERNATIONAL); /* the '+' selected it */
            check(streq(a.digits, "31641600986"));
            int n = sms_addr_encode(b, sizeof b, &a);
            check(n == 8);
            check(memcmp(b, deliver_pdu + 1, 8) == 0);
            check(sms_addr_decode(b, (size_t)n, &back) == n);
            check(back.ton == a.ton && streq(back.digits, a.digits));
        }

        it ("keeps no '+' on the wire and adds one only on request") {
            sms_addr_t a;
            char       out[32];
            check(sms_addr_set(&a, "+4412345", SMS_TON_UNKNOWN) == SMS_OK);
            check(streq(a.digits, "4412345"));
            check(sms_addr_e164(&a, out, sizeof out) == 8);
            check(streq(out, "+4412345"));
            /* a national number gets no '+' */
            check(sms_addr_set(&a, "012345", SMS_TON_NATIONAL) == SMS_OK);
            check(sms_addr_e164(&a, out, sizeof out) == 6);
            check(streq(out, "012345"));
        }

        it ("decodes an alphanumeric address as packed text") {
            /* TOA 0xD0 is alphanumeric: the "digits" are GSM 7-bit
             * septets, not BCD (§9.1.2.5). */
            sms_addr_t a, back;
            uint8_t    b[SMS_ADDR_MAX_OCTETS];
            check(sms_addr_set_text(&a, "Info") == SMS_OK);
            check(a.ton == SMS_TON_ALPHANUM);
            int n = sms_addr_encode(b, sizeof b, &a);
            check(n > 2);
            check(b[1] == 0xD0);
            check(sms_addr_decode(b, (size_t)n, &back) == n);
            check(back.ton == SMS_TON_ALPHANUM);
            /* The field carries no character count, only a semi-octet
             * one, so padding septets can add trailing characters — a
             * prefix match is all the encoding guarantees. */
            check(strncmp(back.digits, "Info", 4) == 0);
        }

        it ("refuses what it cannot represent") {
            sms_addr_t a;
            uint8_t    b[SMS_ADDR_MAX_OCTETS];
            check(sms_addr_set(&a, "123456789012345678901", 1) ==
                  SMS_E_LENGTH); /* 21 digits */
            check(sms_addr_set(&a, "12x45", 1) == SMS_E_INVAL);
            /* an address-length past the 20-digit maximum */
            const uint8_t bad[] = { 0x15, 0x91, 0x21 };
            check(sms_addr_decode(bad, sizeof bad, &a) == SMS_E_LENGTH);
            /* truncated value */
            const uint8_t shrt[] = { 0x08, 0x91, 0x21 };
            check(sms_addr_decode(shrt, sizeof shrt, &a) == SMS_E_SHORT);
            check(sms_addr_decode(shrt, 1, &a) == SMS_E_SHORT);
            /* no room to write */
            check(sms_addr_set(&a, "+441234567890", 0) == SMS_OK);
            check(sms_addr_encode(b, 3, &a) == SMS_E_OVERFLOW);
        }

        it ("rejects a filler in the middle of a number") {
            /* the length says four digits, but the second value octet's
             * low nibble is the 0xF filler */
            const uint8_t bad[] = { 0x04, 0x91, 0x21, 0x3F };
            sms_addr_t    a;
            check(sms_addr_decode(bad, sizeof bad, &a) == SMS_E_LENGTH);
        }
    }

    context ("timestamps") {
        it ("decodes the SCTS of the sample PDU") {
            sms_ts_t t;
            check(sms_ts_decode(deliver_pdu + 11, 7, &t) == 7);
            check(t.year == 2002 && t.mon == 8 && t.day == 26);
            check(t.hour == 19 && t.min == 37 && t.sec == 41);
        }

        it ("reads the sign out of bit 3, not out of the tens digit") {
            /* 0x08: sign bit set, digits 00 -> GMT. A naive BCD decode
             * would read the low nibble as 8 and produce 80 quarters. */
            uint8_t  b[7] = { 0x20, 0x80, 0x62, 0x91, 0x73, 0x14, 0x08 };
            sms_ts_t t;
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.tz_qh == 0);

            /* +2 h is 8 quarters: tens 0, units 8, nibble-swapped 0x80 */
            b[6] = 0x80;
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.tz_qh == 8);

            /* -5 h 30 min is -22 quarters: tens 2 with the sign bit
             * above it (0xA = 1010), units 2 */
            b[6] = 0x2A;
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.tz_qh == -22);

            /* +12 h is the maximum, 48 quarters: tens 4, units 8 */
            b[6] = 0x84;
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.tz_qh == 48);
        }

        it ("round-trips every timezone the field can hold") {
            for (int qh = -48; qh <= 48; qh++) {
                sms_ts_t t = { 2026, 8, 3, 7, 14, 5, (int8_t)qh };
                uint8_t  b[7];
                sms_ts_t back;
                check(sms_ts_encode(b, sizeof b, &t) == 7);
                check(sms_ts_decode(b, 7, &back) == 7);
                check(back.tz_qh == qh);
                check(back.year == 2026 && back.mon == 8 && back.day == 3);
                check(back.hour == 7 && back.min == 14 && back.sec == 5);
            }
        }

        it ("splits the two-digit year at the documented pivot") {
            uint8_t  b[7] = { 0x99, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00 };
            sms_ts_t t;
            check(sms_ts_decode(b, 7, &t) == 7); /* 99 -> 1999 */
            check(t.year == 1999);
            b[0] = 0x07; /* 70, the pivot itself -> 1970 */
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.year == 1970);
            b[0] = 0x96; /* 69 -> 2069 */
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.year == 2069);
            b[0] = 0x00; /* 00 -> 2000 */
            check(sms_ts_decode(b, 7, &t) == 7);
            check(t.year == 2000);
        }

        it ("converts to and from Unix time with the offset applied") {
            /* 2026-08-03T07:14:05+02:00 is 05:14:05 UTC. */
            sms_ts_t t = { 2026, 8, 3, 7, 14, 5, 8 };
            int64_t  u = sms_ts_unix(&t);
            check(u > 0);
            sms_ts_t back;
            sms_ts_from_unix(&back, u, 8);
            check(back.year == 2026 && back.mon == 8 && back.day == 3);
            check(back.hour == 7 && back.min == 14 && back.sec == 5);
            check(back.tz_qh == 8);
            /* the same instant read at GMT is two hours earlier */
            sms_ts_from_unix(&back, u, 0);
            check(back.hour == 5 && back.tz_qh == 0);
            /* the epoch itself */
            sms_ts_from_unix(&back, 0, 0);
            check(back.year == 1970 && back.mon == 1 && back.day == 1);
            check(back.hour == 0 && back.min == 0 && back.sec == 0);
        }

        it ("renders ISO-8601") {
            sms_ts_t t = { 2026, 8, 3, 7, 14, 5, -22 };
            char     out[32];
            check(sms_ts_iso8601(&t, out, sizeof out) == 25);
            check(streq(out, "2026-08-03T07:14:05-05:30"));
            check(sms_ts_iso8601(&t, out, 10) == SMS_E_OVERFLOW);
        }

        it ("rejects nonsense rather than encoding it") {
            sms_ts_t bad = { 2026, 13, 3, 7, 14, 5, 0 };
            uint8_t  b[7];
            check(sms_ts_encode(b, sizeof b, &bad) == SMS_E_INVAL);
            bad.mon   = 8;
            bad.tz_qh = 60;
            check(sms_ts_encode(b, sizeof b, &bad) == SMS_E_INVAL);
            bad.tz_qh = 0;
            bad.year  = 2100;
            check(sms_ts_encode(b, sizeof b, &bad) == SMS_E_INVAL);
            bad.year = 2026;
            check(sms_ts_encode(b, 6, &bad) == SMS_E_OVERFLOW);
            /* a timezone past ±12 h on the wire */
            const uint8_t wire[7] = {
                0x20, 0x80, 0x62, 0x91, 0x73, 0x14, 0x95
            };
            sms_ts_t t;
            check(sms_ts_decode(wire, 7, &t) == SMS_E_LENGTH);
            /* a non-decimal nibble */
            const uint8_t nd[7] = { 0xA0, 0x80, 0x62, 0x91, 0x73, 0x14, 0x00 };
            check(sms_ts_decode(nd, 7, &t) == SMS_E_LENGTH);
            check(sms_ts_decode(nd, 6, &t) == SMS_E_SHORT);
        }
    }

    context ("validity period") {
        it ("decodes the four ranges of the relative format") {
            check(sms_vp_secs(0) == 5 * 60);      /* 5 minutes  */
            check(sms_vp_secs(143) == 12 * 3600); /* 12 hours   */
            check(sms_vp_secs(144) == 12 * 3600 + 1800);
            check(sms_vp_secs(167) == 24 * 3600); /* 24 hours   */
            check(sms_vp_secs(168) == 2 * 86400); /* 2 days     */
            check(sms_vp_secs(196) == 30u * 86400u);
            check(sms_vp_secs(197) == 5u * 7u * 86400u);
            check(sms_vp_secs(255) == 63u * 7u * 86400u); /* 63 weeks */
        }

        it ("picks a code that covers the requested time") {
            for (uint32_t s = 60; s < 40u * 86400u; s += 3607) {
                uint8_t code = sms_vp_rel_from_secs(s);
                check(sms_vp_secs(code) >= s);
            }
            check(sms_vp_rel_from_secs(0) == 0);
            check(sms_vp_rel_from_secs(5 * 60) == 0);
            check(sms_vp_rel_from_secs(10 * 60) == 1);
            check(sms_vp_rel_from_secs(1000u * 86400u) == 255); /* clamped */
        }
    }

    context ("SMS-DELIVER") {
        it ("decodes the sample PDU field by field") {
            sms_tpdu_t t;
            int        n = sms_tpdu_decode(deliver_pdu, sizeof deliver_pdu,
                                           SMS_DIR_SC_TO_MS, &t);
            check(n == (int)sizeof deliver_pdu);
            check(t.type == SMS_T_DELIVER);
            check(t.mti == 0);
            const sms_deliver_t* d = &t.u.deliver;
            check(d->mms); /* 0x04 set: no more messages waiting */
            check(!d->sri && !d->rp && !d->udhi && !d->lp);
            check(streq(d->oa.digits, "31641600986"));
            check(d->oa.ton == SMS_TON_INTERNATIONAL);
            check(d->pid == 0 && d->dcs == 0);
            check(d->scts.year == 2002 && d->scts.mon == 8);
            check(d->ud.udl == 12);
            check(d->ud.len == 11); /* 12 septets pack into 11 octets */
            /* zero-copy: the view points into the caller's buffer, just
             * past the TP-UDL octet at index 18 */
            check(d->ud.p == deliver_pdu + 19);

            char text[64];
            check(sms_ud_to_utf8(d->dcs, d->udhi, d->ud.p, d->ud.len, d->ud.udl,
                                 text, sizeof text) == 12);
            check(streq(text, "How are you?"));
        }

        it ("re-encodes it to the same bytes bar one spec quirk") {
            sms_tpdu_t t;
            uint8_t    out[SMS_TPDU_MAX];
            check(sms_tpdu_decode(deliver_pdu, sizeof deliver_pdu,
                                  SMS_DIR_SC_TO_MS, &t) > 0);
            int n = sms_tpdu_encode(out, sizeof out, &t);
            check(n == (int)sizeof deliver_pdu);

            /* Everything is byte-exact except the TP-SCTS timezone
             * octet. This SMSC wrote 0x08 — the sign bit set on a zero
             * magnitude, i.e. "minus zero quarters of an hour". Minus
             * zero and plus zero are the same offset from GMT, so no
             * struct holding a signed count can keep them apart, and
             * the encoder emits the canonical 0x00. The alternative
             * would be a bool whose only job is to reproduce a bit that
             * means nothing. */
            check(deliver_pdu[17] == 0x08);
            check(out[17] == 0x00);
            check(t.u.deliver.scts.tz_qh == 0);
            check(memcmp(out, deliver_pdu, 17) == 0);
            check(memcmp(out + 18, deliver_pdu + 18, sizeof deliver_pdu - 18) ==
                  0);
        }

        it ("is a DELIVER-REPORT in the other direction") {
            /* Same TP-MTI, different message: §9.2.3.1. */
            sms_tpdu_t t;
            check(sms_tpdu_decode(deliver_pdu, sizeof deliver_pdu,
                                  SMS_DIR_MS_TO_SC, &t) > 0);
            check(t.type == SMS_T_DELIVER_REPORT);
        }
    }

    context ("SMS-SUBMIT") {
        it ("decodes the sample PDU field by field") {
            sms_tpdu_t t;
            int        n = sms_tpdu_decode(submit_pdu, sizeof submit_pdu,
                                           SMS_DIR_MS_TO_SC, &t);
            check(n == (int)sizeof submit_pdu);
            check(t.type == SMS_T_SUBMIT);
            const sms_submit_t* s = &t.u.submit;
            check(!s->rd && !s->srr && !s->udhi && !s->rp);
            check(s->mr == 0);
            check(streq(s->da.digits, "31628870634"));
            check(s->vp.fmt == SMS_VPF_RELATIVE);
            check(s->vp.rel == 0xFF);
            check(sms_vp_secs(s->vp.rel) == 63u * 7u * 86400u);
            check(s->ud.udl == 10 && s->ud.len == 9);

            char text[64];
            check(sms_ud_to_utf8(s->dcs, s->udhi, s->ud.p, s->ud.len, s->ud.udl,
                                 text, sizeof text) == 10);
            check(streq(text, "hellohello"));
        }

        it ("re-encodes it to the same bytes") {
            sms_tpdu_t t;
            uint8_t    out[SMS_TPDU_MAX];
            check(sms_tpdu_decode(submit_pdu, sizeof submit_pdu,
                                  SMS_DIR_MS_TO_SC, &t) > 0);
            check(sms_tpdu_encode(out, sizeof out, &t) ==
                  (int)sizeof submit_pdu);
            check(memcmp(out, submit_pdu, sizeof submit_pdu) == 0);
        }

        it ("builds one from scratch the way a UE would") {
            sms_tpdu_t t;
            uint8_t    ud[SMS_UD_MAX], out[SMS_TPDU_MAX];
            sms_tpdu_init(&t, SMS_T_SUBMIT);
            check(t.mti == 1 && t.dir == SMS_DIR_MS_TO_SC);
            sms_submit_t* s = &t.u.submit;
            s->srr          = true;
            s->mr           = 42;
            check(sms_addr_set(&s->da, "+447700900123", 0) == SMS_OK);
            s->vp.fmt = SMS_VPF_RELATIVE;
            s->vp.rel = sms_vp_rel_from_secs(24 * 3600);
            /* the euro sign is three UTF-8 bytes and two septets */
            const char* body = "Test \xE2\x82\xAC 1";
            int udn = sms_ud_from_utf8(body, strlen(body), SMS_ALPHA_AUTO, NULL,
                                       0, ud, sizeof ud, &s->ud.udl, &s->dcs);
            check(udn > 0);
            check(s->ud.udl == 9); /* 7 characters, one of them escaped */
            s->ud.p   = ud;
            s->ud.len = (uint8_t)udn;
            check(s->dcs == 0x00); /* the euro sign is in the extension */

            int n = sms_tpdu_encode(out, sizeof out, &t);
            check(n > 0);

            sms_tpdu_t back;
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_MS_TO_SC, &back) ==
                  n);
            check(back.type == SMS_T_SUBMIT);
            check(back.u.submit.srr && back.u.submit.mr == 42);
            check(streq(back.u.submit.da.digits, "447700900123"));
            check(back.u.submit.vp.fmt == SMS_VPF_RELATIVE);
            char text[32];
            check(sms_ud_to_utf8(back.u.submit.dcs, back.u.submit.udhi,
                                 back.u.submit.ud.p, back.u.submit.ud.len,
                                 back.u.submit.ud.udl, text,
                                 sizeof text) == (int)strlen(body));
            check(streq(text, body));
        }

        it ("sizes TP-VP by TP-VPF") {
            sms_tpdu_t t;
            uint8_t    out[SMS_TPDU_MAX];
            uint8_t    ud[4] = { 0x41 };

            for (int fmt = SMS_VPF_NONE; fmt <= SMS_VPF_ABSOLUTE; fmt++) {
                sms_tpdu_init(&t, SMS_T_SUBMIT);
                sms_submit_t* s = &t.u.submit;
                check(sms_addr_set(&s->da, "+1", 0) == SMS_OK);
                s->vp.fmt = (uint8_t)fmt;
                s->vp.rel = 100;
                sms_ts_from_unix(&s->vp.abs, 1780000000, 4);
                memset(s->vp.enh, 0xAB, sizeof s->vp.enh);
                s->vp.enh[0] = 0x01;
                s->ud.udl    = 1;
                s->ud.len    = 1;
                s->ud.p      = ud;

                int n = sms_tpdu_encode(out, sizeof out, &t);
                check(n > 0);
                /* octet0 + MR + 3 address octets + PID + DCS + UDL +
                 * one UD octet is 9, plus whatever TP-VPF costs. The
                 * enum order is NONE, ENHANCED, RELATIVE, ABSOLUTE. */
                static const int vp_octets[4] = { 0, 7, 1, 7 };
                check(n == 9 + vp_octets[fmt]);

                sms_tpdu_t back;
                check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_MS_TO_SC,
                                      &back) == n);
                check(back.u.submit.vp.fmt == fmt);
                if (fmt == SMS_VPF_RELATIVE) check(back.u.submit.vp.rel == 100);
                if (fmt == SMS_VPF_ABSOLUTE)
                    check(back.u.submit.vp.abs.year == s->vp.abs.year);
                if (fmt == SMS_VPF_ENHANCED)
                    check(memcmp(back.u.submit.vp.enh, s->vp.enh, 7) == 0);
            }
        }
    }

    context ("SMS-STATUS-REPORT") {
        it ("round-trips with and without the optional tail") {
            sms_tpdu_t t, back;
            uint8_t    out[SMS_TPDU_MAX];
            sms_tpdu_init(&t, SMS_T_STATUS_REPORT);
            check(t.mti == 2 && t.dir == SMS_DIR_SC_TO_MS);
            sms_status_report_t* r = &t.u.status_report;
            r->mr                  = 42;
            r->st                  = 0x00; /* delivered to the SME */
            check(sms_addr_set(&r->ra, "+447700900123", 0) == SMS_OK);
            sms_ts_from_unix(&r->scts, 1780000000, 8);
            sms_ts_from_unix(&r->dt, 1780000060, 8);

            int n = sms_tpdu_encode(out, sizeof out, &t);
            /* octet0 + MR + 8 address + 7 SCTS + 7 DT + ST */
            check(n == 25);

            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_SC_TO_MS, &back) ==
                  n);
            check(back.type == SMS_T_STATUS_REPORT);
            check(back.u.status_report.mr == 42);
            check(back.u.status_report.st == 0);
            check(!back.u.status_report.has_pi);
            check(streq(back.u.status_report.ra.digits, "447700900123"));
            check(back.u.status_report.dt.sec == r->dt.sec);
            check(sms_st_completed(back.u.status_report.st));
            check(!sms_st_permanent(back.u.status_report.st));

            /* now with TP-PI gating a PID and a body */
            uint8_t ud[2] = { 0x41, 0x00 };
            r->has_pid    = true;
            r->pid        = 0x40;
            r->has_ud     = true;
            r->ud.udl     = 1;
            r->ud.len     = 1;
            r->ud.p       = ud;
            n             = sms_tpdu_encode(out, sizeof out, &t);
            check(n == 25 + 1 + 1 + 1 + 1); /* PI + PID + UDL + UD */
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_SC_TO_MS, &back) ==
                  n);
            check(back.u.status_report.has_pi);
            check(back.u.status_report.pi == 0x05); /* the PID and UD bits */
            check(back.u.status_report.has_pid);
            check(back.u.status_report.pid == 0x40);
            check(back.u.status_report.has_ud);
            check(!back.u.status_report.has_dcs);
            check(back.u.status_report.ud.len == 1);
        }

        it ("bands the status value the way the SC means it") {
            check(sms_st_completed(0x00) && sms_st_completed(0x02));
            check(sms_st_temporary(0x20) && !sms_st_completed(0x20));
            check(sms_st_permanent(0x46)); /* validity period expired  */
            check(sms_st_permanent(0x60)); /* congestion, SC gave up   */
            check(!sms_st_temporary(0x60));
            check(!sms_st_completed(0x80) && !sms_st_permanent(0x80));
        }
    }

    context ("SMS-COMMAND") {
        it ("round-trips") {
            sms_tpdu_t t, back;
            uint8_t    out[SMS_TPDU_MAX];
            uint8_t    cd[3] = { 1, 2, 3 };
            sms_tpdu_init(&t, SMS_T_COMMAND);
            sms_command_t* c = &t.u.command;
            c->srr           = true;
            c->mr            = 7;
            c->ct            = 0x02; /* delete previously submitted SM */
            c->mn            = 42;
            c->cdl           = 3;
            c->cd            = cd;
            check(sms_addr_set(&c->da, "+123", 0) == SMS_OK);

            int n = sms_tpdu_encode(out, sizeof out, &t);
            check(n > 0);
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_MS_TO_SC, &back) ==
                  n);
            check(back.type == SMS_T_COMMAND);
            check(back.u.command.srr && back.u.command.mr == 7);
            check(back.u.command.ct == 2 && back.u.command.mn == 42);
            check(back.u.command.cdl == 3);
            check(memcmp(back.u.command.cd, cd, 3) == 0);
        }
    }

    context ("report TPDUs") {
        it ("carries TP-FCS only in the RP-ERROR variant") {
            sms_tpdu_t t, back;
            uint8_t    out[SMS_TPDU_MAX];

            /* the positive form is octet0 + TP-PI and nothing else */
            sms_tpdu_init(&t, SMS_T_DELIVER_REPORT);
            check(sms_tpdu_encode(out, sizeof out, &t) == 2);

            /* the negative form adds TP-FCS between them */
            t.u.report.has_fcs = true;
            t.u.report.fcs     = 0xD0; /* (U)SIM SMS storage full */
            int n              = sms_tpdu_encode(out, sizeof out, &t);
            check(n == 3);
            check(out[1] == 0xD0);

            /* Decoded as the positive form, TP-FCS is read as TP-PI —
             * which is exactly why the direction argument carries the
             * SMS_DIR_NEGATIVE modifier instead of being guessed. */
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_MS_TO_SC, &back) ==
                  2);
            check(!back.u.report.has_fcs);
            check(back.u.report.pi == 0xD0); /* misread, as promised */

            check(sms_tpdu_decode(out, (size_t)n,
                                  SMS_DIR_MS_TO_SC | SMS_DIR_NEGATIVE,
                                  &back) == n);
            check(back.u.report.has_fcs && back.u.report.fcs == 0xD0);
            check(back.u.report.pi == 0x00);
        }

        it ("timestamps a SUBMIT-REPORT but not a DELIVER-REPORT") {
            sms_tpdu_t t, back;
            uint8_t    out[SMS_TPDU_MAX];
            sms_tpdu_init(&t, SMS_T_SUBMIT_REPORT);
            sms_ts_from_unix(&t.u.report.scts, 1780000000, 0);
            int n = sms_tpdu_encode(out, sizeof out, &t);
            check(n == 9); /* octet0 + PI + 7 SCTS */
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_SC_TO_MS, &back) ==
                  n);
            check(back.type == SMS_T_SUBMIT_REPORT);
            check(back.u.report.has_scts);
            check(back.u.report.scts.year == t.u.report.scts.year);

            sms_tpdu_init(&t, SMS_T_DELIVER_REPORT);
            check(sms_tpdu_encode(out, sizeof out, &t) == 2);
            check(sms_tpdu_decode(out, 2, SMS_DIR_MS_TO_SC, &back) == 2);
            check(!back.u.report.has_scts);
        }

        it ("does not announce a field it was not given") {
            sms_tpdu_t t, back;
            uint8_t    out[SMS_TPDU_MAX];
            sms_tpdu_init(&t, SMS_T_DELIVER_REPORT);
            t.u.report.pi = 0xFF; /* claims everything */
            int n         = sms_tpdu_encode(out, sizeof out, &t);
            check(n == 2);
            /* only the extension bit of the caller's PI survives */
            check(out[1] == 0x80);
            check(sms_tpdu_decode(out, (size_t)n, SMS_DIR_MS_TO_SC, &back) ==
                  n);
            check(!back.u.report.has_pid && !back.u.report.has_dcs);
            check(!back.u.report.has_ud);
        }
    }

    context ("malformed input") {
        it ("rejects the reserved message type in both directions") {
            const uint8_t b[] = { 0x03, 0x00, 0x00 };
            sms_tpdu_t    t;
            check(sms_tpdu_decode(b, sizeof b, SMS_DIR_MS_TO_SC, &t) ==
                  SMS_E_MTI);
            check(sms_tpdu_decode(b, sizeof b, SMS_DIR_SC_TO_MS, &t) ==
                  SMS_E_MTI);
        }

        it ("refuses every truncation of a valid PDU") {
            /* Every prefix must be rejected without reading past its
             * end — run under valgrind (the bld-vg image) and this is
             * also the out-of-bounds test. */
            sms_tpdu_t t;
            for (size_t k = 0; k < sizeof deliver_pdu; k++)
                check(sms_tpdu_decode(deliver_pdu, k, SMS_DIR_SC_TO_MS, &t) <
                      0);
            for (size_t k = 0; k < sizeof submit_pdu; k++)
                check(sms_tpdu_decode(submit_pdu, k, SMS_DIR_MS_TO_SC, &t) < 0);
        }

        it ("rejects a TP-UDL that overruns the buffer") {
            uint8_t    b[sizeof deliver_pdu];
            sms_tpdu_t t;
            memcpy(b, deliver_pdu, sizeof b);
            b[18] = 0xA0; /* 160 septets is 140 octets; 11 are present */
            check(sms_tpdu_decode(b, sizeof b, SMS_DIR_SC_TO_MS, &t) ==
                  SMS_E_SHORT);
            b[18] = 0xFF; /* 255 septets is 224 octets, past TP-UD's max */
            check(sms_tpdu_decode(b, sizeof b, SMS_DIR_SC_TO_MS, &t) ==
                  SMS_E_LENGTH);
        }

        it ("validates its arguments") {
            sms_tpdu_t t;
            uint8_t    out[4];
            check(sms_tpdu_decode(NULL, 4, SMS_DIR_SC_TO_MS, &t) ==
                  SMS_E_INVAL);
            check(sms_tpdu_decode(deliver_pdu, 4, 9, &t) == SMS_E_INVAL);
            check(sms_tpdu_decode(deliver_pdu, 0, SMS_DIR_SC_TO_MS, &t) ==
                  SMS_E_SHORT);
            check(sms_tpdu_encode(out, sizeof out, NULL) == SMS_E_INVAL);
            sms_tpdu_init(&t, SMS_T_DELIVER);
            check(sms_tpdu_encode(out, 0, &t) == SMS_E_OVERFLOW);
            check(sms_tpdu_encode(out, sizeof out, &t) == SMS_E_OVERFLOW);
        }

        it ("refuses a user data view that is not there") {
            sms_tpdu_t t;
            uint8_t    out[SMS_TPDU_MAX];
            sms_tpdu_init(&t, SMS_T_DELIVER);
            check(sms_addr_set(&t.u.deliver.oa, "+1", 0) == SMS_OK);
            t.u.deliver.ud.len = 4;
            t.u.deliver.ud.p   = NULL;
            check(sms_tpdu_encode(out, sizeof out, &t) == SMS_E_INVAL);
        }
    }

    context ("names") {
        it ("names the types and errors") {
            check(streq(sms_type_name(SMS_T_DELIVER), "SMS-DELIVER"));
            check(streq(sms_type_name(SMS_T_SUBMIT), "SMS-SUBMIT"));
            check(streq(sms_type_name(SMS_T_MAX), ""));
            check(streq(sms_ton_name(SMS_TON_INTERNATIONAL), "international"));
            check(streq(sms_npi_name(SMS_NPI_ISDN), "ISDN/E.164"));
            check(streq(sms_err_name(SMS_E_SHORT), "truncated"));
        }

        /* Both ends of the range, not just the top: these names are
         * reachable from a script, which can pass anything. */
        it ("refuses an out-of-range value from either end") {
            check(streq(sms_type_name((sms_type_t)-1), ""));
            check(streq(sms_type_name((sms_type_t)INT_MIN), ""));
            check(streq(sms_ton_name((sms_ton_t)-1), ""));
            check(streq(sms_ton_name((sms_ton_t)8), ""));
            check(streq(sms_npi_name((sms_npi_t)-1), ""));
        }

        it ("names the registries a gateway logs") {
            check(streq(sms_st_name(0x00), "delivered to SME"));
            check(streq(sms_st_name(0x46), "validity period expired"));
            check(streq(sms_fcs_name(0xD0), "(U)SIM SMS storage full"));
            check(streq(sms_fcs_name(0xFF), "unspecified error cause"));
            check(streq(sms_pid_name(0x40), "short message type 0"));
            check(streq(sms_ct_name(0x01), "cancel status report request"));
            /* the range cases, so a stray value still logs readably */
            check(sms_st_name(0x35)[0] != '\0');
            check(sms_fcs_name(0x10)[0] != '\0');
            check(sms_pid_name(0xC5)[0] != '\0');
            check(sms_ct_name(0x50)[0] != '\0');
        }
    }
}
