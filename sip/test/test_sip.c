#include <string.h>

#include "sip.h"
#include "test.h"

/* Slice vs C-string equality (exact). */
static int seq(sip_str_t s, const char* z)
{
    size_t n = strlen(z);
    return s.len == n && (n == 0 || memcmp(s.p, z, n) == 0);
}

/* sip_str_t from a string literal. */
#define S(z) (sip_str_t){ z, (uint32_t)sizeof(z) - 1 }

static const char invite[] =
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds\r\n"
    "Via: SIP/2.0/TCP proxy.atlanta.example.com;branch=z9hG4bKnashds8\r\n"
    "Max-Forwards: 70\r\n"
    "To: Bob <sip:bob@biloxi.example.com>\r\n"
    "From: \"Alice Q.\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "i: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@pc33.atlanta.example.com>\r\n"
    "X-Custom: hello\r\n"
    "c: application/sdp\r\n"
    "l: 5\r\n"
    "\r\n"
    "v=0\r\n";

static const char ok200[] =
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

spec ("sip") {
    context ("message parse") {
        it ("parses a request line") {
            sip_msg_t m;
            int       rc = sip_msg_parse(&m, invite, sizeof invite - 1);
            check(rc == (int)(sizeof invite - 1));
            check(m.is_request);
            check(m.method == SIP_M_INVITE);
            check(seq(m.method_name, "INVITE"));
            check(seq(m.ruri, "sip:bob@biloxi.example.com"));
        }

        it ("maps compact and long forms to the same enum") {
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, sizeof invite - 1) > 0);
            const sip_hdr_view_t* h = sip_msg_find(&m, SIP_H_CALL_ID);
            check(h != NULL); /* arrived as "i:" */
            check(seq(h->name, "i"));
            check(seq(h->value, "a84b4c76e66710@pc33.atlanta.example.com"));
            h = sip_msg_find(&m, SIP_H_CONTENT_TYPE);
            check(h != NULL);
            check(seq(h->value, "application/sdp"));
        }

        it ("slices the body by Content-Length") {
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, sizeof invite - 1) > 0);
            check(m.has_clen);
            check(m.clen == 5);
            check(seq(m.body, "v=0\r\n"));
        }

        it ("is zero-copy: every slice points into the input") {
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, sizeof invite - 1) > 0);
            const char* lo = invite;
            const char* hi = invite + sizeof invite - 1;
            check(m.ruri.p >= lo && m.ruri.p + m.ruri.len <= hi);
            check(m.body.p >= lo && m.body.p + m.body.len <= hi);
            for (int k = 0; k < m.hdr_count; k++) {
                check(m.hdrs[k].name.p >= lo);
                check(m.hdrs[k].value.p + m.hdrs[k].value.len <= hi);
            }
        }

        it ("walks repeated headers in order") {
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, sizeof invite - 1) > 0);
            const sip_hdr_view_t* via = sip_msg_find(&m, SIP_H_VIA);
            check(via != NULL);
            const sip_hdr_view_t* via2 = sip_msg_find_next(&m, via);
            check(via2 != NULL);
            check(via2->value.len >= 11);
            check(memcmp(via2->value.p, "SIP/2.0/TCP", 11) == 0);
            check(sip_msg_find_next(&m, via2) == NULL);
        }

        it ("finds extension headers by name, any case") {
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, sizeof invite - 1) > 0);
            const sip_hdr_view_t* h = sip_msg_find_name(&m, "x-custom");
            check(h != NULL);
            check(h->id == SIP_H_OTHER);
            check(seq(h->value, "hello"));
            check(sip_msg_find_name(&m, "Via") != NULL);
            check(sip_msg_find_name(&m, "x-absent") == NULL);
        }

        it ("parses a status line") {
            sip_msg_t m;
            int       rc = sip_msg_parse(&m, ok200, sizeof ok200 - 1);
            check(rc == (int)(sizeof ok200 - 1));
            check(!m.is_request);
            check(m.status == 200);
            check(seq(m.reason, "OK"));
            check(m.has_clen && m.clen == 0);
            check(m.body.len == 0);
        }

        it ("reports SIP_E_SHORT on truncation, any cut point",
            (int)sizeof invite - 2) {
            /* every strict prefix must yield SHORT, never a parse */
            sip_msg_t m;
            check(sip_msg_parse(&m, invite, (size_t)i + 1) == SIP_E_SHORT ||
                  (size_t)i + 1 == sizeof invite - 1);
        }

        it ("takes the body to buffer end without Content-Length") {
            const char msg[] = "MESSAGE sip:x@y SIP/2.0\r\n"
                               "To: <sip:x@y>\r\n"
                               "\r\n"
                               "hi there";
            sip_msg_t  m;
            check(sip_msg_parse(&m, msg, sizeof msg - 1) ==
                  (int)(sizeof msg - 1));
            check(seq(m.body, "hi there"));
        }

        it ("tolerates bare LF, folding and leading keep-alive CRLF") {
            const char msg[] = "\r\n\r\n"
                               "OPTIONS sip:x@y SIP/2.0\n"
                               "Subject: first\r\n second\r\n"
                               "Content-Length: 0\n"
                               "\n";
            sip_msg_t  m;
            check(sip_msg_parse(&m, msg, sizeof msg - 1) ==
                  (int)(sizeof msg - 1));
            check(m.method == SIP_M_OPTIONS);
            const sip_hdr_view_t* h = sip_msg_find(&m, SIP_H_SUBJECT);
            check(h != NULL);
            check(h->value.len == (uint32_t)strlen("first\r\n second"));
        }

        it ("rejects garbage") {
            sip_msg_t  m;
            const char bad1[] = "INVITE sip:x@y SIP/3.0\r\n\r\n";
            check(sip_msg_parse(&m, bad1, sizeof bad1 - 1) == SIP_E_VERSION);
            const char bad2[] = "SIP/2.0 XY OK\r\n\r\n";
            check(sip_msg_parse(&m, bad2, sizeof bad2 - 1) == SIP_E_LINE);
            const char bad3[] = "INVITE sip:x@y SIP/2.0\r\nNoColonHere\r\n\r\n";
            check(sip_msg_parse(&m, bad3, sizeof bad3 - 1) == SIP_E_HEADER);
            const char bad4[] =
                "INVITE sip:x@y SIP/2.0\r\nContent-Length: 12x\r\n\r\n";
            check(sip_msg_parse(&m, bad4, sizeof bad4 - 1) == SIP_E_HEADER);
        }

        it ("keeps an unknown method as a token") {
            const char msg[] = "WIGGLE sip:x@y SIP/2.0\r\n\r\n";
            sip_msg_t  m;
            check(sip_msg_parse(&m, msg, sizeof msg - 1) ==
                  (int)(sizeof msg - 1));
            check(m.method == SIP_M_UNKNOWN);
            check(seq(m.method_name, "WIGGLE"));
        }
    }

    context ("name tables") {
        it ("round-trips every header id through its name", SIP_H_MAX - 1) {
            sip_hdr_t   id   = (sip_hdr_t)(i + 1);
            const char* name = sip_hdr_name(id);
            check(name[0] != '\0');
            check(sip_hdr_from(name, strlen(name)) == id);
        }

        it ("round-trips every method", SIP_M_MAX - 1) {
            sip_method_t mt   = (sip_method_t)(i + 1);
            const char*  name = sip_method_name(mt);
            check(name[0] != '\0');
            check(sip_method_from(name, strlen(name)) == mt);
        }

        it ("treats methods as case-sensitive, headers not") {
            check(sip_method_from("invite", 6) == SIP_M_UNKNOWN);
            check(sip_hdr_from("VIA", 3) == SIP_H_VIA);
            check(sip_hdr_from("cAlL-Id", 7) == SIP_H_CALL_ID);
            check(sip_hdr_from("X-Custom", 8) == SIP_H_OTHER);
        }

        it ("knows the usual phrases") {
            check(strcmp(sip_status_phrase(200), "OK") == 0);
            check(strcmp(sip_status_phrase(486), "Busy Here") == 0);
            check(strcmp(sip_status_phrase(299), "Unknown") == 0);
        }
    }

    context ("uri parse") {
        it ("parses a full sip uri") {
            const char s[] = "sips:alice:pw@atlanta.example.com:5061;transport="
                             "tls;lr?subject=hi";
            sip_uri_t  u;
            check(sip_uri_parse(&u, s, sizeof s - 1) == SIP_OK);
            check(u.scheme == SIP_URI_SIPS);
            check(seq(u.user, "alice:pw"));
            check(seq(u.host, "atlanta.example.com"));
            check(u.port == 5061);
            check(seq(u.params, "transport=tls;lr"));
            check(seq(u.headers, "subject=hi"));
        }

        it ("parses hostless and bracketed forms") {
            const char t[] = "tel:+1-201-555-0123;phone-context=example";
            sip_uri_t  u;
            check(sip_uri_parse(&u, t, sizeof t - 1) == SIP_OK);
            check(u.scheme == SIP_URI_TEL);
            check(seq(u.user, "+1-201-555-0123"));

            const char v6[] = "sip:[2001:db8::1]:5060;transport=tcp";
            check(sip_uri_parse(&u, v6, sizeof v6 - 1) == SIP_OK);
            check(seq(u.host, "2001:db8::1"));
            check(u.port == 5060);
        }

        it ("finds parameters case-insensitively, flags included") {
            sip_str_t params = S("Transport=TLS;lr;maddr=239.255.255.1");
            sip_str_t v;
            check(sip_param(params, "transport", &v));
            check(seq(v, "TLS"));
            check(sip_param(params, "lr", &v));
            check(v.len == 0);
            check(!sip_param(params, "ttl", &v));
        }

        it ("rejects junk") {
            sip_uri_t u;
            check(sip_uri_parse(&u, "nocolon", 7) == SIP_E_URI);
            check(sip_uri_parse(&u, "sip:@:", 6) == SIP_E_URI);
            check(sip_uri_parse(&u, "sip:h:70000", 11) == SIP_E_URI);
        }
    }

    context ("typed headers") {
        it ("parses From/To addresses") {
            sip_str_t v = S(
                "\"Alice Q.\" <sip:alice@atlanta.example.com>;tag=1928301774");
            sip_addr_t a;
            check(sip_addr_parse(v, &a) == SIP_OK);
            check(seq(a.display, "Alice Q."));
            check(seq(a.uri, "sip:alice@atlanta.example.com"));
            check(seq(a.tag, "1928301774"));

            sip_str_t bare = S("sip:bob@biloxi.example.com;tag=abc");
            check(sip_addr_parse(bare, &a) == SIP_OK);
            check(a.display.len == 0);
            check(seq(a.uri, "sip:bob@biloxi.example.com"));
            check(seq(a.tag, "abc"));

            sip_str_t plain = S("Bob <sip:bob@biloxi.example.com>");
            check(sip_addr_parse(plain, &a) == SIP_OK);
            check(seq(a.display, "Bob"));
            check(a.tag.len == 0);
        }

        it ("parses Via") {
            sip_str_t v =
                S("SIP/2.0/UDP "
                  "pc33.atlanta.example.com:5060;branch=z9hG4bK776;rport");
            sip_via_t via;
            check(sip_via_parse(v, &via) == SIP_OK);
            check(seq(via.transport, "UDP"));
            check(seq(via.host, "pc33.atlanta.example.com"));
            check(via.port == 5060);
            check(seq(via.branch, "z9hG4bK776"));
            sip_str_t rport;
            check(sip_param(via.params, "rport", &rport));
        }

        it ("parses CSeq") {
            sip_str_t  v = S("314159 INVITE");
            sip_cseq_t cs;
            check(sip_cseq_parse(v, &cs) == SIP_OK);
            check(cs.seq == 314159);
            check(cs.method == SIP_M_INVITE);
            check(seq(cs.method_name, "INVITE"));
        }
    }

    context ("message write") {
        it ("builds a request that parses back") {
            char       buf[512];
            sip_wbuf_t w;
            sip_wbuf_init(&w, buf, sizeof buf);
            const char uri[] = "sip:bob@biloxi.example.com";
            check(sip_put_request(&w, SIP_M_INVITE, uri, sizeof uri - 1) ==
                  SIP_OK);
            check(sip_put_hdr(&w, SIP_H_VIA, "SIP/2.0/UDP host;branch=z9hG4bK1",
                              32) == SIP_OK);
            check(sip_put_hdr_u32(&w, SIP_H_MAX_FORWARDS, 70) == SIP_OK);
            check(sip_put_hdr_name(&w, "X-Custom", 8, "yo", 2) == SIP_OK);
            int n = sip_put_body(&w, "v=0\r\n", 5);
            check(n > 0);

            sip_msg_t m;
            check(sip_msg_parse(&m, buf, (size_t)n) == n);
            check(m.method == SIP_M_INVITE);
            check(m.clen == 5);
            const sip_hdr_view_t* h = sip_msg_find(&m, SIP_H_MAX_FORWARDS);
            check(h != NULL);
            check(seq(h->value, "70"));
        }

        it ("builds a response with the default phrase") {
            char       buf[256];
            sip_wbuf_t w;
            sip_wbuf_init(&w, buf, sizeof buf);
            check(sip_put_status(&w, 180, NULL, 0) == SIP_OK);
            int n = sip_put_body(&w, NULL, 0);
            check(n > 0);
            sip_msg_t m;
            check(sip_msg_parse(&m, buf, (size_t)n) == n);
            check(m.status == 180);
            check(seq(m.reason, "Ringing"));
        }

        it ("keeps overflow sticky") {
            char       tiny[16];
            sip_wbuf_t w;
            sip_wbuf_init(&w, tiny, sizeof tiny);
            check(sip_put_request(&w, SIP_M_REGISTER, "sip:x@y", 7) ==
                  SIP_E_OVERFLOW);
            check(sip_put_hdr_u32(&w, SIP_H_EXPIRES, 3600) == SIP_E_OVERFLOW);
            check(sip_put_body(&w, NULL, 0) == SIP_E_OVERFLOW);
            check(w.overflow);
        }

        it ("rejects invalid puts without touching the buffer") {
            char       buf[64];
            sip_wbuf_t w;
            sip_wbuf_init(&w, buf, sizeof buf);
            check(sip_put_request(&w, SIP_M_UNKNOWN, "sip:x", 5) ==
                  SIP_E_INVAL);
            check(sip_put_status(&w, 99, NULL, 0) == SIP_E_INVAL);
            check(w.off == 0);
            check(!w.overflow);
        }
    }
}
