#include <string.h>

#include "json.h"
#include "test.h"

/* One pool, reused by every parse below; big enough for the SBI bodies
 * these tests carry, and deliberately small enough that the exhaustion
 * test can hit it with a pool of its own. */
static json_node_t g_nodes[256];
static json_doc_t  g_doc;

static int parse(const char* s)
{
    json_doc_init(&g_doc, g_nodes, 256);
    return json_parse(&g_doc, s, strlen(s));
}

/* Raw slice vs C-string equality (exact, escapes and all). */
static int req(json_str_t s, const char* z)
{
    size_t n = strlen(z);
    return s.len == n && (n == 0 || memcmp(s.p, z, n) == 0);
}

/* Expanded string value vs C string. */
static int veq(const json_node_t* n, const char* z)
{
    char   buf[256];
    size_t len;
    if (n == NULL || json_str(n, buf, sizeof buf, &len) != JSON_OK) return 0;
    return len == strlen(z) && memcmp(buf, z, len) == 0;
}

static const json_node_t* ptr(const char* p)
{
    return json_ptr(&g_doc, p, strlen(p));
}

static const json_node_t* get(const json_node_t* n, const char* k)
{
    return json_get(&g_doc, n, k, strlen(k));
}

static double num(const json_node_t* n)
{
    double v = -1;
    return json_num(n, &v) == JSON_OK ? v : -1;
}

/* An Nsmf_PDUSession create body, trimmed to the members a test cares
 * about: nesting, a member name with a JSON escape, an array of objects,
 * every scalar type, and a 19-digit counter no double could hold. */
static const char sbi[] =
    "{\n"
    "  \"supi\": \"imsi-001010000000001\",\n"
    "  \"pduSessionId\": 5,\n"
    "  \"dnn\": \"internet\",\n"
    "  \"sNssai\": { \"sst\": 1, \"sd\": \"010203\" },\n"
    "  \"anType\": \"3GPP_ACCESS\",\n"
    "  \"servingNetwork\": { \"mcc\": \"001\", \"mnc\": \"01\" },\n"
    "  \"qosFlows\": [\n"
    "    { \"qfi\": 5, \"5qi\": 5, \"gbr\": null, \"default\": true },\n"
    "    { \"qfi\": 1, \"5qi\": 1, \"gbr\": \"64 Kbps\", \"default\": false }\n"
    "  ],\n"
    "  \"ratio\": 0.5,\n"
    "  \"volume\": 1234567890123456789,\n"
    "  \"a\\/b\": \"escaped name\",\n"
    "  \"epsInterworkingInd\": false\n"
    "}";

spec ("json") {
    context ("value parse") {
        it ("parses each scalar as the top-level value") {
            check(parse("null") == JSON_OK);
            check(json_root(&g_doc)->type == JSON_T_NULL);
            check(g_doc.count == 1);

            check(parse("true") == JSON_OK);
            bool b = false;
            check(json_bool(json_root(&g_doc), &b) == JSON_OK && b);
            check(parse("false") == JSON_OK);
            check(json_bool(json_root(&g_doc), &b) == JSON_OK && !b);

            check(parse("42") == JSON_OK);
            check(json_root(&g_doc)->type == JSON_T_NUM);
            check(num(json_root(&g_doc)) == 42.0);

            check(parse("\"hi\"") == JSON_OK);
            check(json_root(&g_doc)->type == JSON_T_STR);
            check(veq(json_root(&g_doc), "hi"));
        }

        it ("parses empty and nested containers") {
            check(parse("{}") == JSON_OK);
            check(json_root(&g_doc)->type == JSON_T_OBJ);
            check(json_root(&g_doc)->count == 0);
            check(json_first(&g_doc, json_root(&g_doc)) == NULL);

            check(parse("[]") == JSON_OK);
            check(json_root(&g_doc)->type == JSON_T_ARR);
            check(json_root(&g_doc)->count == 0);

            check(parse("[[],{},[{\"a\":[1]}]]") == JSON_OK);
            check(json_root(&g_doc)->count == 3);
            check(ptr("/2/0/a/0") != NULL);
            check(num(ptr("/2/0/a/0")) == 1.0);
        }

        it ("treats space, tab, CR and LF between tokens as whitespace") {
            check(parse(" \t\r\n{ \"a\"\t:\r\n[ 1 , 2 ] }\n ") == JSON_OK);
            check(json_root(&g_doc)->count == 1);
            check(ptr("/a")->count == 2);
        }

        it ("keeps a container's whole span as its raw slice") {
            check(parse("{\"a\":[1,2],\"b\":\"x\"}") == JSON_OK);
            check(req(ptr("/a")->raw, "[1,2]"));
            check(req(json_root(&g_doc)->raw, "{\"a\":[1,2],\"b\":\"x\"}"));
            /* A string's raw slice is the body, quotes off. */
            check(req(ptr("/b")->raw, "x"));
        }

        it ("skips a UTF-8 BOM") {
            check(parse("\xEF\xBB\xBF{\"a\":1}") == JSON_OK);
            check(num(ptr("/a")) == 1.0);
        }
    }

    context ("strictness") {
        it ("refuses what RFC 8259 does not allow") {
            check(parse("") == JSON_E_SYNTAX);
            check(parse("   ") == JSON_E_SYNTAX);
            check(parse("[1,2,]") == JSON_E_SYNTAX); /* trailing comma */
            check(parse("{\"a\":1,}") == JSON_E_SYNTAX);
            check(parse("{a:1}") == JSON_E_SYNTAX);     /* unquoted name  */
            check(parse("{'a':1}") == JSON_E_SYNTAX);   /* single quotes  */
            check(parse("{\"a\" 1}") == JSON_E_SYNTAX); /* no colon       */
            check(parse("[1 2]") == JSON_E_SYNTAX);     /* no comma       */
            check(parse("NaN") == JSON_E_SYNTAX);
            check(parse("Infinity") == JSON_E_SYNTAX);
            check(parse("nul") == JSON_E_SYNTAX);
            check(parse("truex") == JSON_E_TRAILING);
            check(parse("{\"a\":1} {\"b\":2}") == JSON_E_TRAILING);
            check(parse("[1,2") == JSON_E_SYNTAX); /* unterminated   */
            check(parse("{\"a\":1") == JSON_E_SYNTAX);
            check(parse("//comment\n1") == JSON_E_SYNTAX);
        }

        it ("refuses the number forms JSON does not have") {
            check(parse("+1") == JSON_E_SYNTAX);
            check(parse(".5") == JSON_E_SYNTAX);
            check(parse("1.") == JSON_E_SYNTAX);
            check(parse("01") == JSON_E_TRAILING);
            check(parse("-") == JSON_E_SYNTAX);
            check(parse("1e") == JSON_E_SYNTAX);
            check(parse("1e+") == JSON_E_SYNTAX);
            check(parse("0x10") == JSON_E_TRAILING);
            check(parse("-0") == JSON_OK); /* this one is legal */
            check(parse("1E5") == JSON_OK);
        }

        it ("refuses a bad string") {
            check(parse("\"unterminated") == JSON_E_SYNTAX);
            check(parse("\"a\tb\"") == JSON_E_SYNTAX); /* raw control    */
            check(parse("\"a\nb\"") == JSON_E_SYNTAX);
            check(parse("\"\\x\"") == JSON_E_SYNTAX);   /* unknown escape */
            check(parse("\"\\u12\"") == JSON_E_SYNTAX); /* short \u       */
            check(parse("\"\\u12g4\"") == JSON_E_SYNTAX);
            check(parse("\"\\\"") == JSON_E_SYNTAX); /* escaped quote  */
        }

        it ("bounds nesting instead of recursing into it") {
            char deep[2 * JSON_MAX_DEPTH + 3];
            int  n = JSON_MAX_DEPTH + 1;
            for (int i = 0; i < n; i++) {
                deep[i]             = '[';
                deep[2 * n - 1 - i] = ']';
            }
            deep[2 * n] = '\0';
            check(parse(deep) == JSON_E_DEPTH);

            /* Exactly at the bound is still fine. */
            char ok[2 * JSON_MAX_DEPTH + 1];
            for (int i = 0; i < JSON_MAX_DEPTH; i++) {
                ok[i]                          = '[';
                ok[2 * JSON_MAX_DEPTH - 1 - i] = ']';
            }
            ok[2 * JSON_MAX_DEPTH] = '\0';
            check(parse(ok) == JSON_OK);
        }

        it ("reports a pool too small rather than truncating") {
            json_node_t small[3];
            json_doc_t  d;
            json_doc_init(&d, small, 3);
            check(json_parse(&d, "[1,2,3]", 7) == JSON_E_NODES);
            check(json_root(&d) == NULL); /* nothing half-parsed to read */

            json_doc_init(&d, small, 3);
            check(json_parse(&d, "[1,2]", 5) == JSON_OK);
            check(json_nodes_for(7) >= 4);
        }

        it ("says where it gave up") {
            /* "not JSON" about a 4 KiB body is not a diagnosis; the
             * offset is. */
            check(parse("{\"a\":1,\"b\":x}") == JSON_E_SYNTAX);
            check(g_doc.err_off == 11);
            check(parse("{\"a\":1} junk") == JSON_E_TRAILING);
            check(g_doc.err_off == 8);
            check(parse("{\"a\":1}") == JSON_OK);
            check(g_doc.err_off == 0);
        }

        it ("refuses invalid arguments") {
            json_doc_t d;
            json_doc_init(&d, NULL, 4);
            check(json_parse(&d, "1", 1) == JSON_E_INVAL);
            json_doc_init(&d, g_nodes, 4);
            check(json_parse(&d, NULL, 1) == JSON_E_INVAL);
        }
    }

    context ("navigation") {
        it ("walks members and elements in wire order") {
            check(parse("{\"a\":1,\"b\":2,\"c\":3}") == JSON_OK);
            const json_node_t* n = json_first(&g_doc, json_root(&g_doc));
            check(json_key_eq(n, "a", 1));
            n = json_next(&g_doc, n);
            check(json_key_eq(n, "b", 1));
            n = json_next(&g_doc, n);
            check(json_key_eq(n, "c", 1));
            check(json_next(&g_doc, n) == NULL);

            check(parse("[10,20,30]") == JSON_OK);
            check(num(json_at(&g_doc, json_root(&g_doc), 0)) == 10.0);
            check(num(json_at(&g_doc, json_root(&g_doc), 2)) == 30.0);
            check(json_at(&g_doc, json_root(&g_doc), 3) == NULL);
        }

        it ("indexes past a nested value") {
            /* Children are linked, not adjacent: the object's own
             * members sit between the two elements in the pool. */
            check(parse("[{\"a\":1,\"b\":2},7]") == JSON_OK);
            check(num(json_at(&g_doc, json_root(&g_doc), 1)) == 7.0);
        }

        it ("finds a member by name, and says so when there is none") {
            check(parse(sbi) == JSON_OK);
            const json_node_t* root = json_root(&g_doc);
            check(veq(get(root, "dnn"), "internet"));
            check(get(root, "DNN") == NULL); /* names are case-sensitive */
            check(get(root, "absent") == NULL);
            check(get(get(root, "sNssai"), "sst") != NULL);
            /* A miss chains: the lookup below it just misses too. */
            check(get(get(root, "absent"), "sst") == NULL);
            /* A scalar has no members. */
            check(get(get(root, "dnn"), "x") == NULL);
        }

        it ("matches a member name that arrived escaped") {
            check(parse(sbi) == JSON_OK);
            check(veq(get(json_root(&g_doc), "a/b"), "escaped name"));
            check(parse("{\"a\\u0062c\":1}") == JSON_OK);
            check(num(get(json_root(&g_doc), "abc")) == 1.0);
        }

        it ("keeps duplicate names in order, first one found") {
            check(parse("{\"a\":1,\"a\":2}") == JSON_OK);
            check(json_root(&g_doc)->count == 2);
            check(num(get(json_root(&g_doc), "a")) == 1.0);
        }
    }

    context ("json pointer (RFC 6901)") {
        it ("resolves the forms the RFC defines") {
            check(parse(sbi) == JSON_OK);
            check(ptr("") == json_root(&g_doc));
            check(veq(ptr("/supi"), "imsi-001010000000001"));
            check(num(ptr("/sNssai/sst")) == 1.0);
            check(num(ptr("/qosFlows/1/qfi")) == 1.0);
            check(veq(ptr("/qosFlows/1/gbr"), "64 Kbps"));
            check(ptr("/qosFlows/0/gbr")->type == JSON_T_NULL);
            /* "~1" is '/', so this is the member literally named a/b. */
            check(veq(ptr("/a~1b"), "escaped name"));
        }

        it ("finds nothing for a pointer that cannot resolve") {
            check(parse(sbi) == JSON_OK);
            check(ptr("supi") == NULL); /* no leading '/'      */
            check(ptr("/nope") == NULL);
            check(ptr("/qosFlows/9") == NULL);  /* past the end        */
            check(ptr("/qosFlows/-") == NULL);  /* the append slot     */
            check(ptr("/qosFlows/01") == NULL); /* leading zero        */
            check(ptr("/qosFlows/x") == NULL);  /* not an index        */
            check(ptr("/supi/0") == NULL);      /* under a scalar      */
            check(ptr("/a~2b") == NULL);        /* bad escape          */
        }

        it ("addresses the member named by the empty string") {
            check(parse("{\"\":{\"a\":1},\"x\":2}") == JSON_OK);
            check(ptr("/")->type == JSON_T_OBJ);
            check(num(ptr("//a")) == 1.0);
        }
    }

    context ("typed reads") {
        it ("reads numbers as doubles, locale or no locale") {
            check(parse("[0,1,-1,0.5,-0.125,1e3,1E-2,2.5e2,1."
                        "7976931348623157e308]") == JSON_OK);
            const json_node_t* a = json_root(&g_doc);
            check(num(json_at(&g_doc, a, 0)) == 0.0);
            check(num(json_at(&g_doc, a, 1)) == 1.0);
            check(num(json_at(&g_doc, a, 2)) == -1.0);
            check(num(json_at(&g_doc, a, 3)) == 0.5);
            check(num(json_at(&g_doc, a, 4)) == -0.125);
            check(num(json_at(&g_doc, a, 5)) == 1000.0);
            check(num(json_at(&g_doc, a, 6)) == 0.01);
            check(num(json_at(&g_doc, a, 7)) == 250.0);
            check(num(json_at(&g_doc, a, 8)) == 1.7976931348623157e308);
        }

        it ("reports a number no double can hold") {
            check(parse("1e400") == JSON_OK);
            double v;
            check(json_num(json_root(&g_doc), &v) == JSON_E_RANGE);
            /* Underflow is not an error, it is a zero. */
            check(parse("1e-400") == JSON_OK);
            check(json_num(json_root(&g_doc), &v) == JSON_OK && v == 0.0);
        }

        it ("reads an integer literal exactly, whatever its width") {
            check(parse(sbi) == JSON_OK);
            int64_t i = 0;
            check(json_i64(ptr("/volume"), &i) == JSON_OK);
            check(i == 1234567890123456789LL);
            /* Read as a double it would have lost its last digits. */
            check((int64_t)(double)i != i);

            check(parse("[-9223372036854775808,9223372036854775807]") ==
                  JSON_OK);
            check(json_i64(json_at(&g_doc, json_root(&g_doc), 0), &i) ==
                  JSON_OK);
            check(i == INT64_MIN);
            check(json_i64(json_at(&g_doc, json_root(&g_doc), 1), &i) ==
                  JSON_OK);
            check(i == INT64_MAX);

            check(parse("9223372036854775808") == JSON_OK); /* one past */
            check(json_i64(json_root(&g_doc), &i) == JSON_E_RANGE);
        }

        it ("accepts an integer spelled with an exponent, refuses a fraction") {
            int64_t i = 0;
            check(parse("1e3") == JSON_OK);
            check(json_i64(json_root(&g_doc), &i) == JSON_OK && i == 1000);
            check(parse("1.0") == JSON_OK);
            check(json_i64(json_root(&g_doc), &i) == JSON_OK && i == 1);
            check(parse("1.5") == JSON_OK);
            check(json_i64(json_root(&g_doc), &i) == JSON_E_RANGE);
            check(parse("1e30") == JSON_OK);
            check(json_i64(json_root(&g_doc), &i) == JSON_E_RANGE);
        }

        it ("expands string escapes into UTF-8") {
            check(parse("\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\te\"") == JSON_OK);
            check(veq(json_root(&g_doc), "a\"b\\c/d\b\f\n\r\te"));

            check(parse("\"\\u00e9\\u20ac\"") == JSON_OK); /* é € */
            check(veq(json_root(&g_doc), "\xC3\xA9\xE2\x82\xAC"));

            /* A surrogate pair is one character (U+1F600). */
            check(parse("\"\\ud83d\\ude00\"") == JSON_OK);
            check(veq(json_root(&g_doc), "\xF0\x9F\x98\x80"));

            /* A surrogate with no partner is U+FFFD, not a failed read. */
            check(parse("\"\\ud83d\"") == JSON_OK);
            check(veq(json_root(&g_doc), "\xEF\xBF\xBD"));
            check(parse("\"\\ude00x\"") == JSON_OK);
            check(veq(json_root(&g_doc), "\xEF\xBF\xBDx"));
        }

        it ("keeps an escaped NUL as a byte, so values are byte strings") {
            check(parse("\"a\\u0000b\"") == JSON_OK);
            char   buf[8];
            size_t len;
            check(json_str(json_root(&g_doc), buf, sizeof buf, &len) ==
                  JSON_OK);
            check(len == 3 && buf[0] == 'a' && buf[1] == '\0' && buf[2] == 'b');
        }

        it ("sizes an expansion by the raw length") {
            check(parse("\"\\ud83d\\ude00\"") == JSON_OK);
            const json_node_t* n = json_root(&g_doc);
            char               buf[32];
            size_t             len;
            /* raw.len is 12 here and the value is 4 bytes: the raw
             * length is always enough, and a byte short never is. */
            check(json_str(n, buf, n->raw.len, &len) == JSON_OK && len == 4);
            check(json_str(n, buf, 3, &len) == JSON_E_OVERFLOW);
            check(json_str(n, buf, 4, &len) == JSON_OK);
        }

        it ("compares a value without expanding it first") {
            check(parse("{\"a\":\"x\\/y\",\"b\":\"plain\"}") == JSON_OK);
            check(json_str_eq(ptr("/a"), "x/y", 3));
            check(!json_str_eq(ptr("/a"), "x\\/y", 4));
            check(json_str_eq(ptr("/b"), "plain", 5));
            check(!json_str_eq(ptr("/b"), "plainer", 7));
            /* Not a string, and not a crash. */
            check(!json_str_eq(ptr("/nope"), "", 0));
        }

        it ("refuses to read a node as the wrong type") {
            check(parse(sbi) == JSON_OK);
            bool    b;
            double  d;
            int64_t i;
            char    buf[8];
            size_t  len;
            check(json_bool(ptr("/supi"), &b) == JSON_E_TYPE);
            check(json_num(ptr("/supi"), &d) == JSON_E_TYPE);
            check(json_i64(ptr("/supi"), &i) == JSON_E_TYPE);
            check(json_str(ptr("/pduSessionId"), buf, sizeof buf, &len) ==
                  JSON_E_TYPE);
            check(json_num(ptr("/qosFlows"), &d) == JSON_E_TYPE);
            check(json_bool(NULL, &b) == JSON_E_INVAL);
        }

        it ("names types") {
            check(strcmp(json_type_name(JSON_T_NULL), "null") == 0);
            check(strcmp(json_type_name(JSON_T_BOOL), "boolean") == 0);
            check(strcmp(json_type_name(JSON_T_NUM), "number") == 0);
            check(strcmp(json_type_name(JSON_T_STR), "string") == 0);
            check(strcmp(json_type_name(JSON_T_ARR), "array") == 0);
            check(strcmp(json_type_name(JSON_T_OBJ), "object") == 0);
            check(strcmp(json_type_name((json_type_t)99), "") == 0);
        }
    }

    context ("utf-8") {
        it ("validates what it is asked to validate") {
            check(json_utf8_valid("plain ascii", 11));
            check(json_utf8_valid("\xC3\xA9", 2));         /* é         */
            check(json_utf8_valid("\xE2\x82\xAC", 3));     /* €         */
            check(json_utf8_valid("\xF0\x9F\x98\x80", 4)); /* U+1F600   */
            check(json_utf8_valid("", 0));

            check(!json_utf8_valid("\xC3", 1));     /* truncated */
            check(!json_utf8_valid("\x80", 1));     /* stray     */
            check(!json_utf8_valid("\xC0\xAF", 2)); /* overlong  */
            check(!json_utf8_valid("\xE0\x80\xAF", 3));
            check(!json_utf8_valid("\xED\xA0\x80", 3));     /* surrogate */
            check(!json_utf8_valid("\xF5\x80\x80\x80", 4)); /* > U+10FFFF */
        }

        it ("parses a document with invalid UTF-8 rather than refusing it") {
            /* A peer's bad byte is not a reason to drop a readable body;
             * a caller that must not pass it on asks json_utf8_valid. */
            check(parse("{\"a\":\"\xC3\"}") == JSON_OK);
            check(!json_utf8_valid(ptr("/a")->raw.p, ptr("/a")->raw.len));
        }
    }

    context ("a whole SBI body") {
        it ("reads every member the way a service would") {
            check(parse(sbi) == JSON_OK);
            const json_node_t* root = json_root(&g_doc);
            check(root->type == JSON_T_OBJ);
            check(root->count == 11);

            check(veq(get(root, "supi"), "imsi-001010000000001"));
            check(num(get(root, "pduSessionId")) == 5.0);
            check(veq(get(root, "anType"), "3GPP_ACCESS"));
            check(num(get(root, "ratio")) == 0.5);

            bool b = true;
            check(json_bool(get(root, "epsInterworkingInd"), &b) == JSON_OK);
            check(!b);

            /* The qos flows, walked the way a loop over them would. */
            const json_node_t* flows = get(root, "qosFlows");
            check(flows->type == JSON_T_ARR && flows->count == 2);
            int seen = 0;
            for (const json_node_t* f = json_first(&g_doc, flows); f;
                 f                    = json_next(&g_doc, f)) {
                check(f->type == JSON_T_OBJ);
                check(get(f, "qfi") != NULL);
                seen++;
            }
            check(seen == 2);
            check(get(json_at(&g_doc, flows, 0), "gbr")->type == JSON_T_NULL);
        }

        it ("hands a subtree back out as the bytes it arrived as") {
            check(parse(sbi) == JSON_OK);
            /* What json_put_frag() re-embeds without a re-encode. */
            check(
                req(ptr("/sNssai")->raw, "{ \"sst\": 1, \"sd\": \"010203\" }"));
        }
    }
}
