#include "gtp2_msg.h"
#include "test.h"
#include <string.h>

/* The generated message layer (gtp2_msg.h) now exposes every IE as an
 * opaque gtp2_view_t over its wire value; instance selects which field a
 * repeated IE type lands in. The sub-IE codecs (F-TEID, Bearer QoS, PAA,
 * AMBR) are the hand-written base layer (gtp2_ie.h) and are exercised
 * first, unchanged. */

spec ("gtp2_msg") {
    context ("F-TEID codec") {
        it ("writes a v4 F-TEID with known bytes") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            const gtp2_fteid_t f = {
                .v4      = true,
                .if_type = GTP2_IF_S11_MME,
                .teid    = 0xDEADBEEFu,
                .addr4   = { 10, 0, 0, 1 },
            };
            check(gtp2_fteid_put(&w, 0, &f) == GTP2_OK);

            const uint8_t expect[] = {
                87,   0x00, 0x09, 0x00, 0x8A, /* V4=1, IF_TYPE=10 */
                0xDE, 0xAD, 0xBE, 0xEF, 0x0A, 0x00, 0x00, 0x01
            };
            check(w.off == sizeof expect);
            check(memcmp(buf, expect, sizeof expect) == 0);
        }

        it ("round-trips a dual-stack F-TEID") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            gtp2_fteid_t f = {
                .v4      = true,
                .v6      = true,
                .if_type = GTP2_IF_S5S8U_PGW,
                .teid    = 0x00C0FFEEu,
                .addr4   = { 192, 168, 1, 1 },
                .addr6 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0x42 },
            };
            check(gtp2_fteid_put(&w, 2, &f) == GTP2_OK);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t ie;
            check(gtp2_ie_iter_next(&it, &ie));
            check(ie.type == GTP2_IE_FTEID);
            check(ie.instance == 2);
            check(ie.len == 25);

            gtp2_fteid_t d;
            check(gtp2_fteid_decode(&ie, &d) == GTP2_OK);
            check(d.v4 && d.v6);
            check(d.if_type == GTP2_IF_S5S8U_PGW);
            check(d.teid == 0x00C0FFEEu);
            check(memcmp(d.addr4, f.addr4, 4) == 0);
            check(memcmp(d.addr6, f.addr6, 16) == 0);
        }

        it ("rejects an F-TEID with neither address family") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            const gtp2_fteid_t f = { .teid = 1, .if_type = 0 };
            check(gtp2_fteid_put(&w, 0, &f) == GTP2_E_INVAL);
        }

        it ("rejects a truncated F-TEID value") {
            const uint8_t        v4_missing[] = { 0x8A, 0, 0, 0, 1 };
            const gtp2_ie_view_t ie           = { .type     = GTP2_IE_FTEID,
                                                  .instance = 0,
                                                  .len      = sizeof v4_missing,
                                                  .value    = v4_missing };
            gtp2_fteid_t         d;
            check(gtp2_fteid_decode(&ie, &d) == GTP2_E_SHORT);
        }
    }

    context ("Bearer QoS codec") {
        it ("round-trips with known first bytes") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            const gtp2_bearer_qos_t q = {
                .pci    = 1,
                .pl     = 9,
                .pvi    = 0,
                .qci    = 9,
                .mbr_ul = 0x0102030405ull,
                .mbr_dl = 50000,
                .gbr_ul = 0,
                .gbr_dl = 0,
            };
            check(gtp2_bearer_qos_put(&w, 0, &q) == GTP2_OK);
            check(w.off == (size_t)GTP2_IE_HDR_LEN + 22);
            check(buf[0] == GTP2_IE_BEARER_QOS);
            check(buf[4] == 0x64); /* PCI=1, PL=9 */
            check(buf[5] == 9);    /* QCI */
            check(buf[6] == 0x01); /* MBR UL, 40-bit big-endian */
            check(buf[10] == 0x05);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t ie;
            check(gtp2_ie_iter_next(&it, &ie));

            gtp2_bearer_qos_t d;
            check(gtp2_bearer_qos_decode(&ie, &d) == GTP2_OK);
            check(d.pci == 1 && d.pl == 9 && d.pvi == 0 && d.qci == 9);
            check(d.mbr_ul == 0x0102030405ull);
            check(d.mbr_dl == 50000);
            check(d.gbr_ul == 0 && d.gbr_dl == 0);
        }

        it ("rejects a short Bearer QoS value") {
            const uint8_t        v[21] = { 0 };
            const gtp2_ie_view_t ie    = { .type  = GTP2_IE_BEARER_QOS,
                                           .len   = sizeof v,
                                           .value = v };
            gtp2_bearer_qos_t    d;
            check(gtp2_bearer_qos_decode(&ie, &d) == GTP2_E_SHORT);
        }
    }

    context ("PAA codec") {
        it ("round-trips an IPv4 PAA") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            const gtp2_paa_t p = {
                .pdn_type = GTP2_PDN_IPV4,
                .addr4    = { 100, 64, 0, 7 },
            };
            check(gtp2_paa_put(&w, 0, &p) == GTP2_OK);
            check(w.off == (size_t)GTP2_IE_HDR_LEN + 5);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t ie;
            check(gtp2_ie_iter_next(&it, &ie));

            gtp2_paa_t d;
            check(gtp2_paa_decode(&ie, &d) == GTP2_OK);
            check(d.pdn_type == GTP2_PDN_IPV4);
            check(memcmp(d.addr4, p.addr4, 4) == 0);
        }

        it ("round-trips a dual-stack PAA") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            gtp2_paa_t p = {
                .pdn_type   = GTP2_PDN_IPV4V6,
                .prefix_len = 64,
                .addr4      = { 100, 64, 0, 8 },
                .addr6 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 1 },
            };
            check(gtp2_paa_put(&w, 0, &p) == GTP2_OK);
            check(w.off == (size_t)GTP2_IE_HDR_LEN + 22);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t ie;
            check(gtp2_ie_iter_next(&it, &ie));

            gtp2_paa_t d;
            check(gtp2_paa_decode(&ie, &d) == GTP2_OK);
            check(d.pdn_type == GTP2_PDN_IPV4V6);
            check(d.prefix_len == 64);
            check(memcmp(d.addr4, p.addr4, 4) == 0);
            check(memcmp(d.addr6, p.addr6, 16) == 0);
        }

        it ("rejects an unknown PDN type on encode") {
            uint8_t     buf[32];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            const gtp2_paa_t p = { .pdn_type = 7 };
            check(gtp2_paa_put(&w, 0, &p) == GTP2_E_INVAL);
        }

        it ("rejects a PAA value shorter than its PDN type requires") {
            const uint8_t        v[] = { GTP2_PDN_IPV6, 64, 0, 0 };
            const gtp2_ie_view_t ie  = { .type  = GTP2_IE_PAA,
                                         .len   = sizeof v,
                                         .value = v };
            gtp2_paa_t           d;
            check(gtp2_paa_decode(&ie, &d) == GTP2_E_SHORT);
        }
    }

    context ("AMBR codec") {
        it ("round-trips an APN-AMBR") {
            uint8_t     buf[16];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);

            const gtp2_ambr_t a = { .ul_kbps = 50000, .dl_kbps = 150000 };
            check(gtp2_ambr_put(&w, 0, &a) == GTP2_OK);
            check(w.off == (size_t)GTP2_IE_HDR_LEN + 8);

            gtp2_ie_iter_t it;
            gtp2_ie_iter_init(&it, buf, w.off);
            gtp2_ie_view_t ie;
            check(gtp2_ie_iter_next(&it, &ie));

            gtp2_ambr_t d;
            check(gtp2_ambr_decode(&ie, &d) == GTP2_OK);
            check(d.ul_kbps == 50000);
            check(d.dl_kbps == 150000);
        }
    }

    /* ---- Generated message layer: opaque IE views ---- *
     *
     * Each field is a gtp2_view_t over the IE's wire value; content is
     * passed through verbatim, so these tests use representative bytes
     * and check the round-trip, the instance dispatch (a repeated IE
     * type split across fields by instance) and the mandatory-IE checks
     * the generator emits from the spec's "M" presence. */

    context ("Create Session Request") {
        static const uint8_t imsi[] = { 0x32, 0x43, 0x51, 0x90,
                                        0x99, 0x99, 0x99, 0xF9 };
        static const uint8_t apn[]  = {
            8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'
        };
        static const uint8_t rat[] = { 6 }; /* E-UTRAN */
        static const uint8_t ftc[] = {
            0x8A, 0x11, 0x11, 0x11, 0x11, 10, 0, 0, 1
        }; /* sender F-TEID */
        static const uint8_t ftp[] = {
            0x87, 0x22, 0x22, 0x22, 0x22, 10, 0, 0, 2
        }; /* PGW F-TEID */
        static const uint8_t bc0[] = { 0x49, 0x00, 0x01, 0x00,
                                       0x05 }; /* EBI=5 */
        static const uint8_t bc1[] = { 0x49, 0x00, 0x01, 0x00,
                                       0x06 }; /* EBI=6 */

        it ("round-trips views and dispatches F-TEID and bearer instances") {
            gtp2_create_session_request_t m;
            memset(&m, 0, sizeof m);
            m.teid     = 0;
            m.sequence = 0x000042u;
            m.imsi     = (gtp2_view_t){ imsi, sizeof imsi };
            m.rat_type = (gtp2_view_t){ rat, sizeof rat };
            m.sender_fteid_for_control_plane = (gtp2_view_t){ ftc, sizeof ftc };
            m.pgw_s5_s8_address_for_control_plane_or_pmip =
                (gtp2_view_t){ ftp, sizeof ftp };
            m.access_point_name             = (gtp2_view_t){ apn, sizeof apn };
            m.bearer_contexts_to_be_created = (gtp2_view_t){ bc0, sizeof bc0 };
            m.bearer_contexts_to_be_removed = (gtp2_view_t){ bc1, sizeof bc1 };

            uint8_t   buf[512];
            const int n =
                gtp2_create_session_request_encode(buf, sizeof buf, &m);
            check(n > 0);
            check(buf[0] == 0x48); /* v2, TEID flag */
            check(buf[1] == GTP2_MT_CREATE_SESSION_REQUEST);

            gtp2_create_session_request_t d;
            const int                     c =
                gtp2_create_session_request_decode(buf, (size_t)n, &d);
            check(c == n);
            check(d.teid == 0);
            check(d.sequence == 0x000042u);

            /* Views borrow from the wire buffer — zero-copy. */
            check(d.imsi.len == sizeof imsi);
            check(memcmp(d.imsi.data, imsi, sizeof imsi) == 0);
            check(d.imsi.data >= buf && d.imsi.data < buf + n);
            check(d.access_point_name.len == sizeof apn);
            check(memcmp(d.access_point_name.data, apn, sizeof apn) == 0);

            /* Instance 0 -> sender, instance 1 -> PGW. */
            check(d.sender_fteid_for_control_plane.len == sizeof ftc);
            check(memcmp(d.sender_fteid_for_control_plane.data, ftc,
                         sizeof ftc) == 0);
            check(d.pgw_s5_s8_address_for_control_plane_or_pmip.len ==
                  sizeof ftp);
            check(memcmp(d.pgw_s5_s8_address_for_control_plane_or_pmip.data,
                         ftp, sizeof ftp) == 0);

            /* Instance 0 -> to-be-created, instance 1 -> to-be-removed. */
            check(memcmp(d.bearer_contexts_to_be_created.data, bc0,
                         sizeof bc0) == 0);
            check(memcmp(d.bearer_contexts_to_be_removed.data, bc1,
                         sizeof bc1) == 0);

            /* Absent optional IEs stay null. */
            check(!d.msisdn.data && !d.user_location_information.data);
        }

        it ("rejects encoding without mandatory IEs") {
            gtp2_create_session_request_t m;
            memset(&m, 0, sizeof m);
            m.rat_type                       = (gtp2_view_t){ rat, sizeof rat };
            m.sender_fteid_for_control_plane = (gtp2_view_t){ ftc, sizeof ftc };
            m.bearer_contexts_to_be_created  = (gtp2_view_t){ bc0, sizeof bc0 };
            /* APN missing */
            uint8_t buf[256];
            check(gtp2_create_session_request_encode(buf, sizeof buf, &m) ==
                  GTP2_E_MISSING);
        }

        it ("rejects decoding when a mandatory IE is absent") {
            /* A message carrying only APN (no RAT Type, sender F-TEID or
             * bearer context). */
            uint8_t     buf[128];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            gtp2_hdr_t h = {
                .has_teid     = true,
                .message_type = GTP2_MT_CREATE_SESSION_REQUEST,
                .sequence     = 1,
            };
            check(gtp2_hdr_encode(w.buf, w.cap, &h) == GTP2_HDR_WITH_TEID);
            w.off = GTP2_HDR_WITH_TEID;
            check(gtp2_ie_put(&w, GTP2_IE_APN, 0, apn, sizeof apn) == GTP2_OK);
            check(gtp2_hdr_finalize(&w, 0) == GTP2_OK);

            gtp2_create_session_request_t d;
            check(gtp2_create_session_request_decode(buf, w.off, &d) ==
                  GTP2_E_MISSING);
        }

        it ("rejects a wrong message type") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            gtp2_hdr_t h = {
                .has_teid     = true,
                .message_type = GTP2_MT_DELETE_SESSION_REQUEST,
                .sequence     = 1,
            };
            check(gtp2_hdr_encode(w.buf, w.cap, &h) == GTP2_HDR_WITH_TEID);
            w.off = GTP2_HDR_WITH_TEID;
            check(gtp2_hdr_finalize(&w, 0) == GTP2_OK);

            gtp2_create_session_request_t d;
            check(gtp2_create_session_request_decode(buf, w.off, &d) ==
                  GTP2_E_INVAL);
        }

        it ("reports overflow for an undersized buffer") {
            gtp2_create_session_request_t m;
            memset(&m, 0, sizeof m);
            m.rat_type                       = (gtp2_view_t){ rat, sizeof rat };
            m.sender_fteid_for_control_plane = (gtp2_view_t){ ftc, sizeof ftc };
            m.access_point_name              = (gtp2_view_t){ apn, sizeof apn };
            m.bearer_contexts_to_be_created  = (gtp2_view_t){ bc0, sizeof bc0 };

            uint8_t buf[16];
            check(gtp2_create_session_request_encode(buf, sizeof buf, &m) ==
                  GTP2_E_OVERFLOW);
        }
    }

    context ("Create Session Response") {
        static const uint8_t cause[] = { 16, 0 }; /* accepted */
        static const uint8_t bc[]    = { 0x49, 0x00, 0x01, 0x00, 0x05 };
        static const uint8_t ftc[]   = {
            0x8A, 0x33, 0x33, 0x33, 0x33, 10, 0, 0, 3
        };

        it ("round-trips an accepting response") {
            gtp2_create_session_response_t m;
            memset(&m, 0, sizeof m);
            m.teid     = 0x11111111u;
            m.sequence = 0x000042u;
            m.cause    = (gtp2_view_t){ cause, sizeof cause };
            m.sender_fteid_for_control_plane = (gtp2_view_t){ ftc, sizeof ftc };
            m.bearer_contexts_created        = (gtp2_view_t){ bc, sizeof bc };

            uint8_t   buf[256];
            const int n =
                gtp2_create_session_response_encode(buf, sizeof buf, &m);
            check(n > 0);
            check(buf[1] == GTP2_MT_CREATE_SESSION_RESPONSE);

            gtp2_create_session_response_t d;
            check(gtp2_create_session_response_decode(buf, (size_t)n, &d) == n);
            check(d.teid == 0x11111111u);
            check(d.sequence == 0x000042u);
            check(d.cause.len == sizeof cause);
            check(memcmp(d.cause.data, cause, sizeof cause) == 0);
            check(memcmp(d.sender_fteid_for_control_plane.data, ftc,
                         sizeof ftc) == 0);
            check(memcmp(d.bearer_contexts_created.data, bc, sizeof bc) == 0);
        }

        it ("rejects decoding without the mandatory Cause") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            gtp2_hdr_t h = {
                .has_teid     = true,
                .message_type = GTP2_MT_CREATE_SESSION_RESPONSE,
                .sequence     = 1,
            };
            check(gtp2_hdr_encode(w.buf, w.cap, &h) == GTP2_HDR_WITH_TEID);
            w.off = GTP2_HDR_WITH_TEID;
            check(gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, 1) == GTP2_OK);
            check(gtp2_hdr_finalize(&w, 0) == GTP2_OK);

            gtp2_create_session_response_t d;
            check(gtp2_create_session_response_decode(buf, w.off, &d) ==
                  GTP2_E_MISSING);
        }
    }

    context ("Modify Bearer Request") {
        static const uint8_t uli[] = { 0x18, 0x32, 0xF4, 0x51, 0x00, 0x01, 0x32,
                                       0xF4, 0x51, 0x00, 0x00, 0x00, 0x01 };
        static const uint8_t ftc[] = {
            0x8A, 0x11, 0x11, 0x11, 0x11, 10, 0, 0, 1
        };

        it ("round-trips views — every IE is conditional") {
            gtp2_modify_bearer_request_t m;
            memset(&m, 0, sizeof m);
            m.teid                           = 0x33333333u;
            m.sequence                       = 0x000043u;
            m.user_location_information      = (gtp2_view_t){ uli, sizeof uli };
            m.sender_fteid_for_control_plane = (gtp2_view_t){ ftc, sizeof ftc };

            uint8_t   buf[256];
            const int n =
                gtp2_modify_bearer_request_encode(buf, sizeof buf, &m);
            check(n > 0);
            check(buf[1] == GTP2_MT_MODIFY_BEARER_REQUEST);

            gtp2_modify_bearer_request_t d;
            check(gtp2_modify_bearer_request_decode(buf, (size_t)n, &d) == n);
            check(d.teid == 0x33333333u);
            check(d.sequence == 0x000043u);
            check(d.user_location_information.len == sizeof uli);
            check(memcmp(d.user_location_information.data, uli, sizeof uli) ==
                  0);
            check(memcmp(d.sender_fteid_for_control_plane.data, ftc,
                         sizeof ftc) == 0);
            check(!d.serving_network.data);
        }

        it ("round-trips an empty request") {
            gtp2_modify_bearer_request_t m;
            memset(&m, 0, sizeof m);
            m.teid     = 0x33333333u;
            m.sequence = 0x000044u;

            uint8_t   buf[64];
            const int n =
                gtp2_modify_bearer_request_encode(buf, sizeof buf, &m);
            check(n > 0);

            gtp2_modify_bearer_request_t d;
            check(gtp2_modify_bearer_request_decode(buf, (size_t)n, &d) == n);
            check(d.teid == 0x33333333u);
            check(!d.sender_fteid_for_control_plane.data);
        }
    }

    context ("Delete Session Response") {
        static const uint8_t cause[] = { 16, 0 };
        static const uint8_t pco[]   = { 0x80, 0x00, 0x0D, 0x00 };

        it ("round-trips an accepting response") {
            gtp2_delete_session_response_t m;
            memset(&m, 0, sizeof m);
            m.teid     = 0x11111111u;
            m.sequence = 0x000045u;
            m.cause    = (gtp2_view_t){ cause, sizeof cause };
            m.protocol_configuration_options = (gtp2_view_t){ pco, sizeof pco };

            uint8_t   buf[128];
            const int n =
                gtp2_delete_session_response_encode(buf, sizeof buf, &m);
            check(n > 0);
            check(buf[1] == GTP2_MT_DELETE_SESSION_RESPONSE);

            gtp2_delete_session_response_t d;
            check(gtp2_delete_session_response_decode(buf, (size_t)n, &d) == n);
            check(d.cause.len == sizeof cause);
            check(memcmp(d.cause.data, cause, sizeof cause) == 0);
            check(d.protocol_configuration_options.len == sizeof pco);
            check(memcmp(d.protocol_configuration_options.data, pco,
                         sizeof pco) == 0);
        }

        it ("rejects decoding without the mandatory Cause") {
            uint8_t     buf[64];
            gtp2_wbuf_t w;
            gtp2_wbuf_init(&w, buf, sizeof buf);
            gtp2_hdr_t h = {
                .has_teid     = true,
                .message_type = GTP2_MT_DELETE_SESSION_RESPONSE,
                .sequence     = 1,
            };
            check(gtp2_hdr_encode(w.buf, w.cap, &h) == GTP2_HDR_WITH_TEID);
            w.off = GTP2_HDR_WITH_TEID;
            check(gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, 1) == GTP2_OK);
            check(gtp2_hdr_finalize(&w, 0) == GTP2_OK);

            gtp2_delete_session_response_t d;
            check(gtp2_delete_session_response_decode(buf, w.off, &d) ==
                  GTP2_E_MISSING);
        }
    }
}
