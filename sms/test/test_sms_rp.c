#include <limits.h>
#include <string.h>

#include "sms_rp.h"
#include "test.h"

/* TS 24.011 §7.3 RPDU formats and §8.2 contents.
 *
 * The shapes worth pinning down are the ones that differ between
 * messages: RP-User-Data is a mandatory LV in RP-DATA and an optional
 * TLV (IEI 0x41) in RP-ACK and RP-ERROR, and an RP address has no digit
 * count — the 0xF filler is the only thing marking an odd length. */

/* A minimal SMS-SUBMIT to stand in as RP-User-Data: MTI=01, TP-MR, a
 * one-digit TP-DA, TP-PID, TP-DCS, TP-UDL 0. */
static const uint8_t tpdu[] = {
    0x01, 0x2A, 0x01, 0x91, 0x21, 0x00, 0x00, 0x00
};

static int streq(const char* a, const char* b)
{
    return strcmp(a, b) == 0;
}

spec ("sms rp") {
    context ("addresses") {
        it ("decodes an even and an odd number") {
            /* the length octet counts the type octet too */
            const uint8_t even[] = { 0x05, 0x91, 0x21, 0x43, 0x65, 0x87 };
            const uint8_t odd[]  = { 0x04, 0x91, 0x21, 0x43, 0xF5 };
            sms_rp_addr_t a;
            check(sms_rp_addr_decode(even, sizeof even, &a) == 6);
            check(a.present && a.ton == SMS_TON_INTERNATIONAL);
            check(a.npi == SMS_NPI_ISDN);
            check(streq(a.digits, "12345678"));
            check(sms_rp_addr_decode(odd, sizeof odd, &a) == 5);
            check(streq(a.digits, "12345")); /* the 0xF ends it */
        }

        it ("tells an absent address from an empty one") {
            const uint8_t none[] = { 0x00 };
            sms_rp_addr_t a;
            check(sms_rp_addr_decode(none, sizeof none, &a) == 1);
            check(!a.present);
            check(streq(a.digits, ""));

            /* length 1: a type octet and no digits at all */
            const uint8_t empty[] = { 0x01, 0x91 };
            check(sms_rp_addr_decode(empty, sizeof empty, &a) == 2);
            check(a.present);
            check(streq(a.digits, ""));
        }

        it ("round-trips through the encoder") {
            sms_rp_addr_t a, back;
            uint8_t       b[SMS_RP_ADDR_MAX];
            check(sms_rp_addr_set(&a, "+447700900123", 0) == SMS_OK);
            check(a.present && a.ton == SMS_TON_INTERNATIONAL);
            int n = sms_rp_addr_encode(b, sizeof b, &a);
            check(n == 8); /* len + type + 6 value octets (12 digits) */
            check(b[0] == 7);
            check(b[1] == 0x91);
            check(sms_rp_addr_decode(b, (size_t)n, &back) == n);
            check(streq(back.digits, "447700900123"));

            /* an absent address is one zero octet */
            check(sms_rp_addr_set(&a, NULL, 0) == SMS_OK);
            check(!a.present);
            check(sms_rp_addr_encode(b, sizeof b, &a) == 1);
            check(b[0] == 0);
        }

        it ("refuses what it cannot hold") {
            sms_rp_addr_t a;
            uint8_t       b[SMS_RP_ADDR_MAX];
            check(sms_rp_addr_set(&a, "123456789012345678901", 1) ==
                  SMS_E_LENGTH);
            check(sms_rp_addr_set(&a, "12/45", 1) == SMS_E_INVAL);
            check(sms_rp_addr_set(&a, "+441234", 0) == SMS_OK);
            check(sms_rp_addr_encode(b, 3, &a) == SMS_E_OVERFLOW);
            const uint8_t shrt[] = { 0x05, 0x91 };
            check(sms_rp_addr_decode(shrt, sizeof shrt, &a) == SMS_E_SHORT);
            check(sms_rp_addr_decode(shrt, 0, &a) == SMS_E_SHORT);
            /* a declared length no address can have, checked before the
             * buffer bound so it reads as malformed, not truncated */
            const uint8_t big[] = { 0x20, 0x91, 0x21 };
            check(sms_rp_addr_decode(big, sizeof big, &a) == SMS_E_LENGTH);
        }
    }

    context ("RP-DATA") {
        it ("builds the MS-to-network form") {
            uint8_t b[SMS_RP_MAX];
            int n = sms_rp_data(b, sizeof b, SMS_DIR_MS_TO_SC, 0x2A, "+123456",
                                tpdu, sizeof tpdu);
            check(n > 0);
            check(b[0] == SMS_RP_DATA_MS_TO_N);
            check(b[1] == 0x2A);
            check(b[2] == 0x00); /* originator absent towards the network */

            sms_rp_pdu_t p;
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
            check(p.type == SMS_RP_T_DATA && p.from_ms);
            check(p.mr == 0x2A);
            check(!p.oa.present);
            check(p.da.present && streq(p.da.digits, "123456"));
            check(p.has_ud && p.ud_len == sizeof tpdu);
            check(memcmp(p.ud, tpdu, sizeof tpdu) == 0);
            /* zero-copy: the view points into the caller's buffer */
            check(p.ud >= b && p.ud < b + n);
        }

        it ("builds the network-to-MS form with the roles swapped") {
            uint8_t b[SMS_RP_MAX];
            int     n = sms_rp_data(b, sizeof b, SMS_DIR_SC_TO_MS, 7, "+123456",
                                    tpdu, sizeof tpdu);
            check(n > 0);
            check(b[0] == SMS_RP_DATA_N_TO_MS);

            sms_rp_pdu_t p;
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_SC_TO_MS, &p) == n);
            check(p.type == SMS_RP_T_DATA && !p.from_ms);
            check(p.mr == 7);
            check(p.oa.present && streq(p.oa.digits, "123456"));
            check(!p.da.present);
        }

        it ("keeps the user data element even when it is empty") {
            /* §7.3.1 makes RP-User-Data mandatory in RP-DATA, so the
             * length octet is there whether or not a TPDU is. */
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            int          n =
                sms_rp_data(b, sizeof b, SMS_DIR_MS_TO_SC, 1, "+1", NULL, 0);
            check(n > 0);
            check(b[n - 1] == 0x00); /* the length octet, value zero */
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
            check(p.has_ud && p.ud_len == 0);
            check(p.ud == NULL);
        }
    }

    context ("RP-ACK") {
        it ("carries no user data by default") {
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            int n = sms_rp_ack(b, sizeof b, SMS_DIR_MS_TO_SC, 0x2A, NULL, 0);
            check(n == 2); /* header only */
            check(b[0] == SMS_RP_ACK_MS_TO_N && b[1] == 0x2A);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
            check(p.type == SMS_RP_T_ACK && p.mr == 0x2A);
            check(!p.has_ud);
        }

        it ("wraps a report TPDU in the IEI when there is one") {
            uint8_t       b[SMS_RP_MAX];
            sms_rp_pdu_t  p;
            const uint8_t report[2] = { 0x00, 0x00 }; /* DELIVER-REPORT */
            int n = sms_rp_ack(b, sizeof b, SMS_DIR_SC_TO_MS, 9, report,
                               sizeof report);
            check(n == 2 + 2 + 2);
            check(b[0] == SMS_RP_ACK_N_TO_MS);
            check(b[2] == SMS_RP_IEI_USER_DATA);
            check(b[3] == 2);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_SC_TO_MS, &p) == n);
            check(p.has_ud && p.ud_len == 2);
            check(memcmp(p.ud, report, 2) == 0);
        }
    }

    context ("RP-ERROR") {
        it ("carries the cause as an LV") {
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            int          n = sms_rp_error(b, sizeof b, SMS_DIR_SC_TO_MS, 5,
                                          SMS_RP_CAUSE_UNKNOWN_SUB, NULL, 0);
            check(n == 4); /* MTI, MR, cause length, cause */
            check(b[0] == SMS_RP_ERROR_N_TO_MS);
            check(b[2] == 1);
            check(b[3] == SMS_RP_CAUSE_UNKNOWN_SUB);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_SC_TO_MS, &p) == n);
            check(p.type == SMS_RP_T_ERROR);
            check(p.cause == SMS_RP_CAUSE_UNKNOWN_SUB);
            check(!p.has_cause_diag && !p.has_ud);
        }

        it ("reads the optional diagnostic octet") {
            const uint8_t wire[] = { SMS_RP_ERROR_MS_TO_N, 0x11, 0x02,
                                     SMS_RP_CAUSE_TEMPORARY_FAILURE, 0x42 };
            sms_rp_pdu_t  p;
            check(sms_rp_decode(wire, sizeof wire, SMS_DIR_MS_TO_SC, &p) ==
                  (int)sizeof wire);
            check(p.cause == SMS_RP_CAUSE_TEMPORARY_FAILURE);
            check(p.has_cause_diag && p.cause_diag == 0x42);
        }

        it ("masks the extension bit off the cause") {
            /* Bit 8 of the cause octet is the extension bit, not part
             * of the value (§8.2.5.4). */
            const uint8_t wire[] = { SMS_RP_ERROR_N_TO_MS, 0x01, 0x01,
                                     0x80 | SMS_RP_CAUSE_CONGESTION };
            sms_rp_pdu_t  p;
            check(sms_rp_decode(wire, sizeof wire, SMS_DIR_SC_TO_MS, &p) ==
                  (int)sizeof wire);
            check(p.cause == SMS_RP_CAUSE_CONGESTION);
        }

        it ("round-trips a cause with a TPDU behind it") {
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            int          n =
                sms_rp_error(b, sizeof b, SMS_DIR_MS_TO_SC, 3,
                             SMS_RP_CAUSE_TRANSFER_REJECTED, tpdu, sizeof tpdu);
            check(n == 2 + 2 + 2 + (int)sizeof tpdu);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
            check(p.cause == SMS_RP_CAUSE_TRANSFER_REJECTED);
            check(p.has_ud && p.ud_len == sizeof tpdu);
        }

        it ("folds unassigned causes onto temporary failure") {
            /* §8.2.5.4: "All other cause values shall be treated as
             * cause number 41". 22 is a common mistake — it is a
             * Q.931/CC cause, not an RP one. */
            check(sms_rp_cause_fold(SMS_RP_CAUSE_CONGESTION) ==
                  SMS_RP_CAUSE_CONGESTION);
            check(sms_rp_cause_fold(0) == SMS_RP_CAUSE_TEMPORARY_FAILURE);
            check(sms_rp_cause_fold(22) == SMS_RP_CAUSE_TEMPORARY_FAILURE);
            check(sms_rp_cause_fold(126) == SMS_RP_CAUSE_TEMPORARY_FAILURE);
            check(sms_rp_cause_name(SMS_RP_CAUSE_UNKNOWN_SUB)[0] != '\0');
            check(sms_rp_cause_name(22)[0] != '\0');
        }
    }

    context ("RP-SMMA") {
        it ("is a bare header and exists only towards the network") {
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            int          n = sms_rp_smma(b, sizeof b, 0x77);
            check(n == 2);
            check(b[0] == SMS_RP_SMMA_MS_TO_N && b[1] == 0x77);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
            check(p.type == SMS_RP_T_SMMA && p.mr == 0x77);
            check(!p.has_ud);

            /* there is no network-to-MS SMMA to encode */
            sms_rp_init(&p, SMS_RP_T_SMMA, SMS_DIR_SC_TO_MS);
            check(sms_rp_encode(b, sizeof b, &p) == SMS_E_MTI);
        }
    }

    context ("direction") {
        it ("refuses a PDU that travels the other way") {
            uint8_t b[SMS_RP_MAX];
            int     n = sms_rp_ack(b, sizeof b, SMS_DIR_MS_TO_SC, 1, NULL, 0);
            check(n == 2);
            sms_rp_pdu_t p;
            /* The MTI already encodes the direction, so a caller that
             * got it wrong is told rather than handed a PDU that will be
             * misread one layer up. */
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_SC_TO_MS, &p) ==
                  SMS_E_MTI);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_MS_TO_SC, &p) == n);
        }

        it ("rejects the unassigned message type") {
            const uint8_t wire[] = { 0x07, 0x00 };
            sms_rp_pdu_t  p;
            check(sms_rp_decode(wire, sizeof wire, SMS_DIR_MS_TO_SC, &p) ==
                  SMS_E_MTI);
        }

        it ("ignores the spare bits of the first octet") {
            /* Bits 7-3 are spare (§7.3); a peer that sets them must not
             * change how the message reads. */
            uint8_t b[SMS_RP_MAX];
            check(sms_rp_ack(b, sizeof b, SMS_DIR_MS_TO_SC, 1, NULL, 0) == 2);
            b[0] |= 0xF8;
            sms_rp_pdu_t p;
            check(sms_rp_decode(b, 2, SMS_DIR_MS_TO_SC, &p) == 2);
            check(p.type == SMS_RP_T_ACK);
        }
    }

    context ("malformed input") {
        it ("refuses every truncation of a valid RP-DATA") {
            uint8_t b[SMS_RP_MAX];
            int n = sms_rp_data(b, sizeof b, SMS_DIR_SC_TO_MS, 1, "+447700900",
                                tpdu, sizeof tpdu);
            check(n > 0);
            sms_rp_pdu_t p;
            for (size_t k = 0; k < (size_t)n; k++)
                check(sms_rp_decode(b, k, SMS_DIR_SC_TO_MS, &p) < 0);
            check(sms_rp_decode(b, (size_t)n, SMS_DIR_SC_TO_MS, &p) == n);
        }

        it ("rejects a trailing element that is not the user data IEI") {
            const uint8_t wire[] = { SMS_RP_ACK_N_TO_MS, 0x01, 0x99, 0x01,
                                     0xAA };
            sms_rp_pdu_t  p;
            check(sms_rp_decode(wire, sizeof wire, SMS_DIR_SC_TO_MS, &p) ==
                  SMS_E_LENGTH);
        }

        it ("rejects a zero-length RP-Cause") {
            const uint8_t wire[] = { SMS_RP_ERROR_N_TO_MS, 0x01, 0x00 };
            sms_rp_pdu_t  p;
            check(sms_rp_decode(wire, sizeof wire, SMS_DIR_SC_TO_MS, &p) ==
                  SMS_E_LENGTH);
        }

        it ("reports overflow rather than writing past the buffer") {
            uint8_t small[4];
            check(sms_rp_data(small, sizeof small, SMS_DIR_MS_TO_SC, 1, "+1",
                              tpdu, sizeof tpdu) == SMS_E_OVERFLOW);
            check(sms_rp_ack(small, 1, SMS_DIR_MS_TO_SC, 1, NULL, 0) ==
                  SMS_E_OVERFLOW);
            check(sms_rp_error(small, 3, SMS_DIR_MS_TO_SC, 1, 41, NULL, 0) ==
                  SMS_E_OVERFLOW);
        }

        it ("validates its arguments") {
            uint8_t      b[SMS_RP_MAX];
            sms_rp_pdu_t p;
            check(sms_rp_decode(NULL, 4, SMS_DIR_MS_TO_SC, &p) == SMS_E_INVAL);
            check(sms_rp_decode(b, 1, SMS_DIR_MS_TO_SC, &p) == SMS_E_SHORT);
            check(sms_rp_encode(b, sizeof b, NULL) == SMS_E_INVAL);
            sms_rp_init(&p, SMS_RP_T_ACK, SMS_DIR_MS_TO_SC);
            p.has_ud = true;
            p.ud_len = 4;
            p.ud     = NULL;
            check(sms_rp_encode(b, sizeof b, &p) == SMS_E_INVAL);
        }
    }

    context ("names") {
        it ("names the types and the message types") {
            check(streq(sms_rp_type_name(SMS_RP_T_DATA), "RP-DATA"));
            check(streq(sms_rp_type_name(SMS_RP_T_SMMA), "RP-SMMA"));
            check(streq(sms_rp_type_name(SMS_RP_T_MAX), ""));
            check(
                streq(sms_rp_mti_name(SMS_RP_DATA_N_TO_MS), "RP-DATA (n->ms)"));
            check(streq(sms_rp_mti_name((sms_rp_mti_t)7), ""));
        }

        it ("refuses an out-of-range type from either end") {
            check(streq(sms_rp_type_name((sms_rp_type_t)-1), ""));
            check(streq(sms_rp_type_name((sms_rp_type_t)INT_MIN), ""));
        }
    }
}
