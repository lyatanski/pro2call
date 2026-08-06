#include <string.h>

#include "json.h"
#include "test.h"

static char        g_buf[1024];
static json_wbuf_t g_w;

static void begin(void)
{
    json_wbuf_init(&g_w, g_buf, sizeof g_buf);
}

/* The document written so far vs a C string. */
static int weq(const char* z)
{
    int n = json_end(&g_w);
    return n > 0 && (size_t)n == strlen(z) && memcmp(g_buf, z, (size_t)n) == 0;
}

/* Round-trip helper: does what was written parse back to one value? */
static int reparses(void)
{
    json_node_t nodes[64];
    json_doc_t  d;
    int         n = json_end(&g_w);
    if (n <= 0) return 0;
    json_doc_init(&d, nodes, 64);
    return json_parse(&d, g_buf, (size_t)n) == JSON_OK;
}

#define K(w, s) json_put_key((w), (s), sizeof(s) - 1)
#define S(w, s) json_put_str((w), (s), sizeof(s) - 1)

spec ("json_write") {
    context ("values") {
        it ("writes each scalar as a whole document") {
            begin();
            check(json_put_null(&g_w) == JSON_OK);
            check(weq("null"));

            begin();
            check(json_put_bool(&g_w, true) == JSON_OK);
            check(weq("true"));

            begin();
            check(json_put_int(&g_w, -42) == JSON_OK);
            check(weq("-42"));

            begin();
            check(S(&g_w, "hi") == JSON_OK);
            check(weq("\"hi\""));
        }

        it ("writes the extremes of an integer") {
            begin();
            check(json_put_int(&g_w, INT64_MIN) == JSON_OK);
            check(weq("-9223372036854775808"));

            begin();
            check(json_put_int(&g_w, INT64_MAX) == JSON_OK);
            check(weq("9223372036854775807"));

            begin();
            check(json_put_int(&g_w, 0) == JSON_OK);
            check(weq("0"));
        }

        it ("writes an integral double as an integer") {
            begin();
            check(json_put_num(&g_w, 1.0) == JSON_OK);
            check(weq("1"));

            begin();
            check(json_put_num(&g_w, -7.0) == JSON_OK);
            check(weq("-7"));

            /* Every number a script hands over is a double; a field a
             * schema calls an integer must not go out as 5.0. */
            begin();
            check(json_put_num(&g_w, 5.0) == JSON_OK);
            check(weq("5"));
        }

        it ("writes a fractional double shortest-round-trip") {
            begin();
            check(json_put_num(&g_w, 0.5) == JSON_OK);
            check(weq("0.5"));

            begin();
            check(json_put_num(&g_w, 0.1) == JSON_OK);
            check(weq("0.1")); /* not 0.10000000000000001 */

            begin();
            check(json_put_num(&g_w, -0.125) == JSON_OK);
            check(weq("-0.125"));

            begin();
            check(json_put_num(&g_w, 1.0 / 3.0) == JSON_OK);
            check(reparses());
        }

        it ("refuses NaN and the infinities") {
            double zero = 0.0;
            double inf  = 1.0 / zero;
            begin();
            check(json_put_num(&g_w, inf) == JSON_E_RANGE);
            begin();
            check(json_put_num(&g_w, -inf) == JSON_E_RANGE);
            begin();
            check(json_put_num(&g_w, zero / zero) == JSON_E_RANGE);
            /* And the error is sticky: nothing half-written escapes. */
            check(json_put_null(&g_w) == JSON_E_RANGE);
            check(json_end(&g_w) == JSON_E_RANGE);
        }
    }

    context ("containers") {
        it ("puts in the commas and the colons") {
            begin();
            json_put_obj_begin(&g_w);
            K(&g_w, "a");
            json_put_int(&g_w, 1);
            K(&g_w, "b");
            S(&g_w, "x");
            K(&g_w, "c");
            json_put_arr_begin(&g_w);
            json_put_int(&g_w, 1);
            json_put_int(&g_w, 2);
            json_put_arr_end(&g_w);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{\"a\":1,\"b\":\"x\",\"c\":[1,2]}"));
        }

        it ("writes empty containers") {
            begin();
            json_put_obj_begin(&g_w);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{}"));

            begin();
            json_put_arr_begin(&g_w);
            json_put_arr_begin(&g_w);
            json_put_arr_end(&g_w);
            json_put_obj_begin(&g_w);
            json_put_obj_end(&g_w);
            check(json_put_arr_end(&g_w) == JSON_OK);
            check(weq("[[],{}]"));
        }

        it ("writes a member name and its value in one call") {
            begin();
            json_put_obj_begin(&g_w);
            json_put_field_str(&g_w, "supi", 4, "imsi-1", 6);
            json_put_field_int(&g_w, "id", 2, 5);
            json_put_field_num(&g_w, "ratio", 5, 0.5);
            json_put_field_bool(&g_w, "eps", 3, false);
            json_put_field_null(&g_w, "gbr", 3);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{\"supi\":\"imsi-1\",\"id\":5,\"ratio\":0.5,"
                      "\"eps\":false,\"gbr\":null}"));
        }

        it ("pretty-prints when asked") {
            begin();
            json_wbuf_indent(&g_w, 2);
            json_put_obj_begin(&g_w);
            K(&g_w, "a");
            json_put_int(&g_w, 1);
            K(&g_w, "b");
            json_put_arr_begin(&g_w);
            json_put_int(&g_w, 1);
            json_put_obj_begin(&g_w);
            json_put_obj_end(&g_w);
            json_put_arr_end(&g_w);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{\n"
                      "  \"a\": 1,\n"
                      "  \"b\": [\n"
                      "    1,\n"
                      "    {}\n"
                      "  ]\n"
                      "}"));
        }

        it ("bounds nesting the same way the parser does") {
            begin();
            int rc = JSON_OK;
            for (int i = 0; i <= JSON_MAX_DEPTH; i++)
                rc = json_put_arr_begin(&g_w);
            check(rc == JSON_E_DEPTH);
        }
    }

    context ("strings") {
        it ("escapes what JSON requires and nothing else") {
            begin();
            check(S(&g_w, "a\"b\\c\nd\te\rf\bg\fh") == JSON_OK);
            check(weq("\"a\\\"b\\\\c\\nd\\te\\rf\\bg\\fh\""));

            /* '/' needs no escape, and adding one would change no
             * parser's reading but every byte comparison. */
            begin();
            check(S(&g_w, "a/b") == JSON_OK);
            check(weq("\"a/b\""));
        }

        it ("escapes the rest of the control range as \\u00xx") {
            begin();
            check(json_put_str(&g_w, "a\x01\x1f", 3) == JSON_OK);
            check(weq("\"a\\u0001\\u001f\""));

            /* An embedded NUL is a byte, not a terminator. */
            begin();
            check(json_put_str(&g_w, "a\0b", 3) == JSON_OK);
            check(weq("\"a\\u0000b\""));
        }

        it ("passes UTF-8 through untouched") {
            begin();
            check(S(&g_w, "é€\xF0\x9F\x98\x80") == JSON_OK);
            check(weq("\"é€\xF0\x9F\x98\x80\""));
        }

        it ("writes an empty string and an empty member name") {
            begin();
            json_put_obj_begin(&g_w);
            json_put_key(&g_w, "", 0);
            json_put_str(&g_w, "", 0);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{\"\":\"\"}"));
        }

        it ("re-emits an already-escaped body without touching it") {
            begin();
            check(json_put_str_esc(&g_w, "a\\/b\\u00e9", 10) == JSON_OK);
            check(weq("\"a\\/b\\u00e9\""));
        }
    }

    context ("fragments") {
        it ("embeds a parsed subtree without re-encoding it") {
            /* The pass-through a proxy does: keep one member's bytes
             * exactly as they arrived, rewrite the rest. */
            const char  body[] = "{\"sNssai\":{\"sst\":1,\"sd\":\"010203\"}}";
            json_node_t nodes[16];
            json_doc_t  d;
            json_doc_init(&d, nodes, 16);
            check(json_parse(&d, body, sizeof body - 1) == JSON_OK);
            const json_node_t* sub = json_get(&d, json_root(&d), "sNssai", 6);
            check(sub != NULL);

            begin();
            json_put_obj_begin(&g_w);
            K(&g_w, "slice");
            json_put_frag(&g_w, sub->raw.p, sub->raw.len);
            check(json_put_obj_end(&g_w) == JSON_OK);
            check(weq("{\"slice\":{\"sst\":1,\"sd\":\"010203\"}}"));
        }
    }

    context ("misuse is reported, not written") {
        it ("refuses a member name outside an object") {
            begin();
            check(K(&g_w, "a") == JSON_E_STATE);

            begin();
            json_put_arr_begin(&g_w);
            check(K(&g_w, "a") == JSON_E_STATE);
        }

        it ("refuses two member names in a row") {
            begin();
            json_put_obj_begin(&g_w);
            K(&g_w, "a");
            check(K(&g_w, "b") == JSON_E_STATE);
        }

        it ("refuses a value where a member name belongs") {
            begin();
            json_put_obj_begin(&g_w);
            check(json_put_int(&g_w, 1) == JSON_E_STATE);
        }

        it ("refuses a mismatched or missing close") {
            begin();
            json_put_obj_begin(&g_w);
            check(json_put_arr_end(&g_w) == JSON_E_STATE);

            begin();
            json_put_arr_begin(&g_w);
            check(json_put_obj_end(&g_w) == JSON_E_STATE);

            begin();
            check(json_put_obj_end(&g_w) == JSON_E_STATE);

            /* Closing an object with a name still owing its value. */
            begin();
            json_put_obj_begin(&g_w);
            K(&g_w, "a");
            check(json_put_obj_end(&g_w) == JSON_E_STATE);
        }

        it ("refuses a second top-level value") {
            begin();
            json_put_int(&g_w, 1);
            check(json_put_int(&g_w, 2) == JSON_E_STATE);

            begin();
            json_put_obj_begin(&g_w);
            json_put_obj_end(&g_w);
            check(json_put_null(&g_w) == JSON_E_STATE);
        }

        it ("refuses an unfinished or empty document at json_end") {
            begin();
            json_put_obj_begin(&g_w);
            K(&g_w, "a");
            json_put_int(&g_w, 1);
            check(json_end(&g_w) == JSON_E_STATE); /* still open */

            begin();
            check(json_end(&g_w) == JSON_E_STATE); /* nothing written */
        }
    }

    context ("overflow") {
        it ("is sticky and reported once") {
            char        small[8];
            json_wbuf_t w;
            json_wbuf_init(&w, small, sizeof small);
            json_put_obj_begin(&w);
            json_put_key(&w, "key", 3);
            json_put_str(&w, "a value too long", 16);
            check(json_put_obj_end(&w) == JSON_E_OVERFLOW);
            check(json_end(&w) == JSON_E_OVERFLOW);
        }

        it ("fills a buffer of exactly the right size") {
            /* {"a":12345} is 11 bytes and no terminator is written, so
             * 11 is enough and 10 is not. */
            for (size_t cap = 10; cap <= 11; cap++) {
                char        exact[11];
                json_wbuf_t w;
                json_wbuf_init(&w, exact, cap);
                json_put_obj_begin(&w);
                json_put_field_int(&w, "a", 1, 12345);
                json_put_obj_end(&w);
                check(json_end(&w) == (cap == 11 ? 11 : JSON_E_OVERFLOW));
            }
        }

        it ("reports a NULL buffer instead of writing to it") {
            json_wbuf_t w;
            json_wbuf_init(&w, NULL, 16);
            check(json_put_null(&w) == JSON_E_INVAL);
            check(json_end(&w) == JSON_E_INVAL);
        }
    }

    context ("round trip") {
        it ("writes what the parser reads back identically") {
            begin();
            json_wbuf_indent(&g_w, 0);
            json_put_obj_begin(&g_w);
            json_put_field_str(&g_w, "supi", 4, "imsi-001010000000001", 20);
            json_put_field_int(&g_w, "pduSessionId", 12, 5);
            K(&g_w, "qosFlows");
            json_put_arr_begin(&g_w);
            json_put_obj_begin(&g_w);
            json_put_field_int(&g_w, "qfi", 3, 5);
            json_put_field_null(&g_w, "gbr", 3);
            json_put_obj_end(&g_w);
            json_put_arr_end(&g_w);
            json_put_field_num(&g_w, "ratio", 5, 0.5);
            json_put_field_str(&g_w, "text", 4, "a\"b\\c\nd", 7);
            check(json_put_obj_end(&g_w) == JSON_OK);

            int n = json_end(&g_w);
            check(n > 0);

            json_node_t nodes[32];
            json_doc_t  d;
            json_doc_init(&d, nodes, 32);
            check(json_parse(&d, g_buf, (size_t)n) == JSON_OK);
            check(json_str_eq(json_ptr(&d, "/supi", 5), "imsi-001010000000001",
                              20));
            int64_t i;
            check(json_i64(json_ptr(&d, "/pduSessionId", 13), &i) == JSON_OK);
            check(i == 5);
            check(json_i64(json_ptr(&d, "/qosFlows/0/qfi", 15), &i) == JSON_OK);
            check(i == 5);
            check(json_ptr(&d, "/qosFlows/0/gbr", 15)->type == JSON_T_NULL);
            double v;
            check(json_num(json_ptr(&d, "/ratio", 6), &v) == JSON_OK);
            check(v == 0.5);
            /* The escapes survived both directions. */
            check(json_str_eq(json_ptr(&d, "/text", 5), "a\"b\\c\nd", 7));
        }
    }
}
