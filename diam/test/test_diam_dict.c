#include "diam.h"
#include "diam_dict.h"
#include "test.h"

#include <string.h>

spec ("diam_dict: generated Diameter dictionary") {
    context ("registry lookup") {
        it ("resolves standard AVPs by code") {
            const diam_dict_entry_t* e = diam_dict_get(DIAM_AVP_SESSION_ID, 0);
            check(e != NULL);
            check(e->code == 263);
            check(e->type == DIAM_TYPE_UTF8_STRING);
            check(e->flags & DIAM_AVP_F_MANDATORY);
            check(strcmp(e->name, "Session-Id") == 0);

            e = diam_dict_get(DIAM_AVP_ORIGIN_HOST, 0);
            check(e != NULL);
            check(e->type == DIAM_TYPE_IDENTITY);
        }

        it ("resolves vendor AVPs by (code, vendor)") {
            const diam_dict_entry_t* e =
                diam_dict_get(DIAM_AVP_PUBLIC_IDENTITY, DIAM_VENDOR_3GPP);
            check(e != NULL);
            check(e->vendor_id == 10415);
            check(e->flags & DIAM_AVP_F_VENDOR);
            check(strcmp(e->name, "Public-Identity") == 0);

            /* the same code without the vendor is a different AVP */
            const diam_dict_entry_t* s = diam_dict_get(601, 0);
            check(!s || strcmp(s->name, "Public-Identity") != 0);
        }

        it ("returns NULL for unknown entries") {
            check(diam_dict_get(0xFFFFF, 0) == NULL);
            check(diam_avp_name(0xFFFFF, 0) == NULL);
        }

        it ("iterates the whole registry in sorted order") {
            const size_t n = diam_dict_count();
            check(n > 1000);
            check(diam_dict_at(0) != NULL);
            check(diam_dict_at(n) == NULL);
            for (size_t i = 1; i < n; i++) {
                const diam_dict_entry_t* a = diam_dict_at(i - 1);
                const diam_dict_entry_t* b = diam_dict_at(i);
                check(a->vendor_id < b->vendor_id ||
                      (a->vendor_id == b->vendor_id && a->code < b->code));
            }
        }
    }

    context ("application and command tables") {
        it ("covers Cx, Rx, Ro and Rf application ids") {
            check(DIAM_APP_CX == 16777216);
            check(DIAM_APP_RX == 16777236);
            check(DIAM_APP_CREDIT_CONTROL == 4);  /* Ro */
            check(DIAM_APP_BASE_ACCOUNTING == 3); /* Rf */
            check(strcmp(diam_app_name(DIAM_APP_CX), "Cx") == 0);
            check(diam_app_name(999999) == NULL);
        }

        it ("covers the base, Cx, Rx and charging command codes") {
            check(DIAM_CMD_CAPABILITIES_EXCHANGE == 257);
            check(DIAM_CMD_DEVICE_WATCHDOG == 280);
            check(DIAM_CMD_DISCONNECT_PEER == 282);
            check(DIAM_CMD_USER_AUTHORIZATION == 300); /* Cx UAR/UAA */
            check(DIAM_CMD_SERVER_ASSIGNMENT == 301);  /* Cx SAR/SAA */
            check(DIAM_CMD_LOCATION_INFO == 302);      /* Cx LIR/LIA */
            check(DIAM_CMD_MULTIMEDIA_AUTH == 303);    /* Cx MAR/MAA */
            check(DIAM_CMD_REGISTRATION_TERMINATION == 304);
            check(DIAM_CMD_PUSH_PROFILE == 305);
            check(DIAM_CMD_AA == 265); /* Rx AAR/AAA */
            check(DIAM_CMD_RE_AUTH == 258);
            check(DIAM_CMD_SESSION_TERMINATION == 275);
            check(DIAM_CMD_ABORT_SESSION == 274);
            check(DIAM_CMD_CREDIT_CONTROL == 272); /* Ro CCR/CCA */
            check(DIAM_CMD_ACCOUNTING == 271);     /* Rf ACR/ACA */
            check(strcmp(diam_cmd_name(272), "Credit-Control") == 0);
            check(diam_cmd_name(9999) == NULL);
        }
    }

    context ("per-interface AVPs") {
        it ("knows the Cx AVPs (TS 29.229)") {
            check(DIAM_AVP_PUBLIC_IDENTITY == 601);
            check(DIAM_AVP_SERVER_NAME == 602);
            const diam_dict_entry_t* e =
                diam_dict_get(DIAM_AVP_SERVER_CAPABILITIES, DIAM_VENDOR_3GPP);
            check(e && e->type == DIAM_TYPE_GROUPED);
        }

        it ("knows the Rx AVPs (TS 29.214)") {
            const diam_dict_entry_t* e = diam_dict_get(
                DIAM_AVP_MEDIA_COMPONENT_DESCRIPTION, DIAM_VENDOR_3GPP);
            check(e && e->type == DIAM_TYPE_GROUPED);
            check(diam_dict_get(DIAM_AVP_AF_APPLICATION_IDENTIFIER,
                                DIAM_VENDOR_3GPP) != NULL);
        }

        it ("knows the credit-control AVPs (RFC 4006 / TS 32.299)") {
            const diam_dict_entry_t* e =
                diam_dict_get(DIAM_AVP_CC_REQUEST_TYPE, 0);
            check(e && e->type == DIAM_TYPE_ENUMERATED);
            e = diam_dict_get(DIAM_AVP_MULTIPLE_SERVICES_CREDIT_CONTROL, 0);
            check(e && e->type == DIAM_TYPE_GROUPED);
            e = diam_dict_get(DIAM_AVP_SERVICE_INFORMATION, DIAM_VENDOR_3GPP);
            check(e && e->type == DIAM_TYPE_GROUPED); /* TS 32.299 */
            check(diam_dict_get(DIAM_AVP_CC_TOTAL_OCTETS, 0)->type ==
                  DIAM_TYPE_UNSIGNED64);
        }
    }

    context ("enumerated values") {
        it ("exposes constants and names for curated enums") {
            check(DIAM_CC_REQUEST_TYPE_INITIAL_REQUEST == 1);
            check(DIAM_CC_REQUEST_TYPE_TERMINATION_REQUEST == 3);
            check(strcmp(diam_enum_name(DIAM_AVP_CC_REQUEST_TYPE, 0, 1),
                         "INITIAL_REQUEST") == 0);
            check(strcmp(diam_enum_name(DIAM_AVP_RESULT_CODE, 0, 2001),
                         "DIAMETER_SUCCESS") == 0);
            check(diam_enum_name(DIAM_AVP_CC_REQUEST_TYPE, 0, 99) == NULL);
            check(diam_enum_name(DIAM_AVP_SESSION_ID, 0, 1) == NULL);
        }

        it ("works with the wire codec end to end") {
            uint8_t     buf[64];
            diam_wbuf_t w;
            diam_wbuf_init(&w, buf, sizeof buf);
            const diam_dict_entry_t* e =
                diam_dict_get(DIAM_AVP_CC_REQUEST_TYPE, 0);
            check(e != NULL);
            check(diam_avp_put_u32(&w, e->code, e->flags, e->vendor_id,
                                   DIAM_CC_REQUEST_TYPE_UPDATE_REQUEST) ==
                  DIAM_OK);

            diam_avp_view_t v;
            check(diam_avp_find(buf, w.off, DIAM_AVP_CC_REQUEST_TYPE, 0, &v));
            check(v.flags & DIAM_AVP_F_MANDATORY);
            uint32_t u = 0;
            check(diam_avp_u32(&v, &u) == DIAM_OK);
            check(strcmp(diam_enum_name(v.code, v.vendor_id, (int32_t)u),
                         "UPDATE_REQUEST") == 0);
        }
    }
}
