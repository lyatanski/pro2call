#include <string.h>

#include "sdp.h"
#include "test.h"

/* Slice vs C-string equality (exact). */
static int seq(sdp_str_t s, const char* z)
{
    size_t n = strlen(z);
    return s.len == n && (n == 0 || memcmp(s.p, z, n) == 0);
}

/* sdp_str_t from a string literal. */
#define S(z) (sdp_str_t){ z, (uint32_t)sizeof(z) - 1 }

/* What this tool actually offers: one audio stream, G.711, 20 ms. */
static const char offer[] = "v=0\r\n"
                            "o=- 42 1 IN IP4 10.45.0.2\r\n"
                            "s=-\r\n"
                            "c=IN IP4 10.45.0.2\r\n"
                            "t=0 0\r\n"
                            "m=audio 40000 RTP/AVP 0 101\r\n"
                            "a=rtpmap:0 PCMU/8000\r\n"
                            "a=rtpmap:101 telephone-event/8000\r\n"
                            "a=fmtp:101 0-15\r\n"
                            "a=ptime:20\r\n"
                            "a=sendrecv\r\n";

/* What comes back through rtpengine: the media address moved to the
 * relay, a media-level c= that overrides the session one, a second
 * stream, bare LF, and attributes the module has no enum for. */
static const char answer[] = "v=0\n"
                             "o=- 42 2 IN IP4 172.20.0.9\n"
                             "s=-\n"
                             "c=IN IP4 1.1.1.1\n"
                             "b=AS:64\n"
                             "t=0 0\n"
                             "a=sendonly\n"
                             "m=audio 30002 RTP/AVP 0\n"
                             "c=IN IP4 172.20.0.9\n"
                             "a=rtpmap:0 PCMU/8000\n"
                             "a=ptime:20\n"
                             "a=rtcp:30003\n"
                             "a=X-Vendor-Thing:1\n"
                             "m=video 0 RTP/AVP 96\n"
                             "a=rtpmap:96 VP8/90000\n"
                             "a=inactive";

spec ("sdp") {
    context ("message parse") {
        it ("parses the offer this tool sends") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            check(m.version == 0);
            check(m.has_origin);
            check(seq(m.origin.username, "-"));
            check(m.origin.sess_id == 42);
            check(m.origin.sess_version == 1);
            check(seq(m.origin.nettype, "IN"));
            check(seq(m.origin.addrtype, "IP4"));
            check(seq(m.origin.addr, "10.45.0.2"));
            check(seq(m.name, "-"));
            check(m.has_conn);
            check(seq(m.conn.addr, "10.45.0.2"));
            check(m.has_time && m.t_start == 0 && m.t_stop == 0);
            check(m.media_count == 1);
        }

        it ("parses the m= line") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            const sdp_media_t* a = &m.media[0];
            check(a->type == SDP_M_AUDIO);
            check(seq(a->type_name, "audio"));
            check(a->port == 40000);
            check(a->nports == 1);
            check(a->proto == SDP_P_RTP_AVP);
            check(seq(a->proto_name, "RTP/AVP"));
            check(a->fmt_count == 2);
            check(seq(m.fmts[a->fmt_off], "0"));
            check(seq(m.fmts[a->fmt_off + 1], "101"));
        }

        it ("accepts bare LF and a final line with no terminator") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            check(m.media_count == 2);
            /* the unterminated last line still lands */
            check(sdp_media_dir(&m, &m.media[1]) == SDP_DIR_INACTIVE);
        }

        it ("keeps session and media attributes in separate runs") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            check(m.attr_count == 1); /* a=sendonly, session level */
            check(m.attrs[0].id == SDP_A_SENDONLY);
            /* the audio section's own four, none of the video one's */
            check(m.media[0].attr_count == 4);
            check(m.media[1].attr_count == 2);
            check(sdp_attr_find(&m, &m.media[0], SDP_A_RTCP) != NULL);
            check(sdp_attr_find(&m, &m.media[1], SDP_A_RTCP) == NULL);
        }

        it ("counts bandwidth lines against the section that owns them") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            check(m.bw_count == 1);
            check(seq(m.bws[0].bwtype, "AS"));
            check(m.bws[0].value == 64);
            check(m.media[0].bw_count == 0);
        }

        it ("reads a hierarchical port count") {
            static const char s[] = "v=0\r\nm=audio 5004/2 RTP/AVP 0\r\n";
            sdp_msg_t         m;
            check(sdp_msg_parse(&m, s, sizeof s - 1) == SDP_OK);
            check(m.media[0].port == 5004);
            check(m.media[0].nports == 2);
        }

        it ("surfaces a rejected stream as port 0, not as an error") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            check(m.media[1].type == SDP_M_VIDEO);
            check(m.media[1].port == 0);
        }

        it ("ignores line types it has no use for") {
            static const char s[] = "v=0\r\n"
                                    "e=alice@example.com\r\n"
                                    "p=+1 617 555 6011\r\n"
                                    "z=2882844526 -1h\r\n"
                                    "k=clear:secret\r\n"
                                    "Q=nonsense\r\n"
                                    "m=audio 1 RTP/AVP 0\r\n";
            sdp_msg_t         m;
            check(sdp_msg_parse(&m, s, sizeof s - 1) == SDP_OK);
            check(m.media_count == 1);
        }

        it ("rejects input that is not a session description") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, "", 0) == SDP_E_VERSION);
            check(sdp_msg_parse(&m, "s=-\r\n", 5) == SDP_E_VERSION);
            check(sdp_msg_parse(&m, "v=1\r\n", 5) == SDP_E_VERSION);
            check(sdp_msg_parse(&m, "hello\r\n", 7) == SDP_E_LINE);
            check(sdp_msg_parse(NULL, "v=0\r\n", 5) == SDP_E_INVAL);
        }

        it ("fails a line that would send media to the wrong place") {
            static const char bad_c[] = "v=0\r\nc=IN IP4\r\n";
            static const char bad_m[] = "v=0\r\nm=audio x RTP/AVP 0\r\n";
            static const char bad_o[] = "v=0\r\no=- 1 1 IN IP4\r\n";
            sdp_msg_t         m;
            check(sdp_msg_parse(&m, bad_c, sizeof bad_c - 1) == SDP_E_LINE);
            check(sdp_msg_parse(&m, bad_m, sizeof bad_m - 1) == SDP_E_LINE);
            check(sdp_msg_parse(&m, bad_o, sizeof bad_o - 1) == SDP_E_LINE);
        }

        it ("reports pool exhaustion by which pool ran out") {
            /* 9 media sections against SDP_MAX_MEDIA = 8. */
            static const char many[] = "v=0\r\n"
                                       "m=audio 1 RTP/AVP 0\r\n"
                                       "m=audio 2 RTP/AVP 0\r\n"
                                       "m=audio 3 RTP/AVP 0\r\n"
                                       "m=audio 4 RTP/AVP 0\r\n"
                                       "m=audio 5 RTP/AVP 0\r\n"
                                       "m=audio 6 RTP/AVP 0\r\n"
                                       "m=audio 7 RTP/AVP 0\r\n"
                                       "m=audio 8 RTP/AVP 0\r\n"
                                       "m=audio 9 RTP/AVP 0\r\n";
            sdp_msg_t         m;
            check(sdp_msg_parse(&m, many, sizeof many - 1) == SDP_E_MEDIA);
        }
    }

    context ("attribute access") {
        it ("resolves known names to enums and keeps the wire name") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            const sdp_attr_t* a = sdp_attr_find(&m, &m.media[0], SDP_A_PTIME);
            check(a != NULL);
            check(seq(a->name, "ptime"));
            check(seq(a->value, "20"));
        }

        it ("hands back extensions as SDP_A_OTHER, matched by name") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            const sdp_attr_t* a =
                sdp_attr_find_name(&m, &m.media[0], "x-vendor-thing");
            check(a != NULL);
            check(a->id == SDP_A_OTHER);
            check(seq(a->name, "X-Vendor-Thing")); /* wire case preserved */
            check(seq(a->value, "1"));
        }

        it ("walks repeated attributes within one section only") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            const sdp_attr_t* a = sdp_attr_find(&m, &m.media[0], SDP_A_RTPMAP);
            check(a != NULL && seq(a->value, "0 PCMU/8000"));
            a = sdp_attr_next(&m, &m.media[0], a);
            check(a != NULL && seq(a->value, "101 telephone-event/8000"));
            check(sdp_attr_next(&m, &m.media[0], a) == NULL);
        }

        it ("treats a flag attribute as present with an empty value") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            const sdp_attr_t* a =
                sdp_attr_find(&m, &m.media[0], SDP_A_SENDRECV);
            check(a != NULL);
            check(a->value.len == 0);
        }

        it ("lets a media-level c= override the session one") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            const sdp_conn_t* c = sdp_media_conn(&m, &m.media[0]);
            check(c != NULL && seq(c->addr, "172.20.0.9"));
            /* the video section has none, so it inherits the session's */
            c = sdp_media_conn(&m, &m.media[1]);
            check(c != NULL && seq(c->addr, "1.1.1.1"));
            c = sdp_media_conn(&m, NULL);
            check(c != NULL && seq(c->addr, "1.1.1.1"));
        }

        it ("inherits the session direction, then defaults to sendrecv") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, answer, sizeof answer - 1) == SDP_OK);
            /* audio carries none, so it takes the session's a=sendonly */
            check(sdp_media_dir(&m, &m.media[0]) == SDP_DIR_SENDONLY);
            check(sdp_media_dir(&m, &m.media[1]) == SDP_DIR_INACTIVE);

            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            check(sdp_media_dir(&m, &m.media[0]) == SDP_DIR_SENDRECV);
            check(sdp_media_dir(&m, NULL) == SDP_DIR_SENDRECV);
        }
    }

    context ("deep parsers") {
        it ("parses a=rtpmap") {
            sdp_rtpmap_t r;
            check(sdp_rtpmap_parse(S("0 PCMU/8000"), &r) == SDP_OK);
            check(r.pt == 0 && seq(r.enc, "PCMU") && r.clock == 8000);
            check(r.params.len == 0);

            check(sdp_rtpmap_parse(S("111 opus/48000/2"), &r) == SDP_OK);
            check(r.pt == 111 && seq(r.enc, "opus") && r.clock == 48000);
            check(seq(r.params, "2"));

            check(sdp_rtpmap_parse(S("0 PCMU"), &r) == SDP_E_LINE);
            check(sdp_rtpmap_parse(S("200 PCMU/8000"), &r) == SDP_E_LINE);
        }

        it ("parses a=fmtp") {
            sdp_fmtp_t f;
            check(sdp_fmtp_parse(S("101 0-15"), &f) == SDP_OK);
            check(seq(f.fmt, "101") && seq(f.params, "0-15"));
            check(sdp_fmtp_parse(S("101"), &f) == SDP_OK);
            check(f.params.len == 0);
        }

        it ("finds the rtpmap and fmtp of one payload type") {
            sdp_msg_t m;
            check(sdp_msg_parse(&m, offer, sizeof offer - 1) == SDP_OK);
            sdp_rtpmap_t r;
            check(sdp_rtpmap_find(&m, &m.media[0], 101, &r) == SDP_OK);
            check(seq(r.enc, "telephone-event"));
            check(sdp_rtpmap_find(&m, &m.media[0], 8, &r) == SDP_E_MISSING);

            sdp_str_t p;
            check(sdp_fmtp_find(&m, &m.media[0], 101, &p) == SDP_OK);
            check(seq(p, "0-15"));
            check(sdp_fmtp_find(&m, &m.media[0], 0, &p) == SDP_E_MISSING);
        }
    }

    context ("name tables") {
        it ("round-trips every attribute name") {
            for (int id = 1; id < SDP_A_MAX; id++) {
                const char* n = sdp_attr_name((sdp_attr_id_t)id);
                check(n[0] != '\0');
                check(sdp_attr_from(n, strlen(n)) == (sdp_attr_id_t)id);
            }
            check(sdp_attr_from("RTPMAP", 6) == SDP_A_RTPMAP); /* ci */
            check(sdp_attr_from("nosuch", 6) == SDP_A_OTHER);
            check(sdp_attr_name(SDP_A_OTHER)[0] == '\0');
            check(sdp_attr_name((sdp_attr_id_t)999)[0] == '\0');
        }

        it ("round-trips media types and transport protocols") {
            for (int t = 1; t < SDP_M_MAX; t++) {
                const char* n = sdp_mtype_name((sdp_mtype_t)t);
                check(sdp_mtype_from(n, strlen(n)) == (sdp_mtype_t)t);
            }
            for (int p = 1; p < SDP_P_MAX; p++) {
                const char* n = sdp_proto_name((sdp_proto_t)p);
                check(sdp_proto_from(n, strlen(n)) == (sdp_proto_t)p);
            }
            /* tokens are case-sensitive on the wire */
            check(sdp_mtype_from("AUDIO", 5) == SDP_M_OTHER);
            check(sdp_proto_from("rtp/avp", 7) == SDP_P_OTHER);
            check(sdp_dir_name(SDP_DIR_INACTIVE)[0] == 'i');
        }
    }

    context ("write") {
        it ("builds the offer byte for byte") {
            char       buf[512];
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, buf, sizeof buf);
            check(sdp_put_version(&w) == SDP_OK);
            check(sdp_put_origin(&w, "", 0, 42, 1, "IP4", 3, "10.45.0.2", 9) ==
                  SDP_OK);
            check(sdp_put_name(&w, "", 0) == SDP_OK);
            check(sdp_put_conn(&w, "IP4", 3, "10.45.0.2", 9) == SDP_OK);
            check(sdp_put_time(&w, 0, 0) == SDP_OK);
            check(sdp_put_media(&w, SDP_M_AUDIO, 40000, 1, SDP_P_RTP_AVP,
                                "0 101", 5) == SDP_OK);
            check(sdp_put_attr(&w, SDP_A_RTPMAP, "0 PCMU/8000", 11) == SDP_OK);
            check(sdp_put_attr(&w, SDP_A_RTPMAP, "101 telephone-event/8000",
                               24) == SDP_OK);
            check(sdp_put_attr(&w, SDP_A_FMTP, "101 0-15", 8) == SDP_OK);
            check(sdp_put_attr(&w, SDP_A_PTIME, "20", 2) == SDP_OK);
            check(sdp_put_attr(&w, SDP_A_SENDRECV, NULL, 0) == SDP_OK);
            int n = sdp_end(&w);
            check(n == (int)(sizeof offer - 1));
            check(memcmp(buf, offer, (size_t)n) == 0);
        }

        it ("round-trips what it wrote") {
            char       buf[512];
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, buf, sizeof buf);
            sdp_put_version(&w);
            sdp_put_origin(&w, "alice", 5, 7, 8, "IP4", 3, "10.0.0.1", 8);
            sdp_put_name(&w, "call", 4);
            sdp_put_conn(&w, "IP4", 3, "10.0.0.1", 8);
            sdp_put_bw(&w, "AS", 2, 64);
            sdp_put_time(&w, 0, 0);
            sdp_put_media(&w, SDP_M_AUDIO, 6000, 2, SDP_P_RTP_AVP, "8", 1);
            sdp_put_attr(&w, SDP_A_RTPMAP, "8 PCMA/8000", 11);
            sdp_put_line(&w, 'k', "clear:x", 7);
            int n = sdp_end(&w);
            check(n > 0);

            sdp_msg_t m;
            check(sdp_msg_parse(&m, buf, (size_t)n) == SDP_OK);
            check(seq(m.origin.username, "alice"));
            check(m.origin.sess_id == 7 && m.origin.sess_version == 8);
            check(seq(m.name, "call"));
            check(m.bw_count == 1 && m.bws[0].value == 64);
            check(m.media_count == 1);
            check(m.media[0].port == 6000 && m.media[0].nports == 2);
            sdp_rtpmap_t r;
            check(sdp_rtpmap_find(&m, &m.media[0], 8, &r) == SDP_OK);
            check(seq(r.enc, "PCMA"));
        }

        it ("writes a rejected stream with no trailing space") {
            char       buf[64];
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, buf, sizeof buf);
            check(sdp_put_media(&w, SDP_M_VIDEO, 0, 1, SDP_P_RTP_AVP, NULL,
                                0) == SDP_OK);
            check(sdp_end(&w) == 19);
            check(memcmp(buf, "m=video 0 RTP/AVP\r\n", 19) == 0);
        }

        it ("keeps overflow sticky") {
            char       tiny[8];
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, tiny, sizeof tiny);
            check(sdp_put_version(&w) == SDP_OK);
            check(sdp_put_conn(&w, "IP4", 3, "10.0.0.1", 8) == SDP_E_OVERFLOW);
            check(sdp_put_time(&w, 0, 0) == SDP_E_OVERFLOW);
            check(sdp_end(&w) == SDP_E_OVERFLOW);
            check(w.overflow);
        }

        it ("rejects invalid puts without touching the buffer") {
            char       buf[128];
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, buf, sizeof buf);
            check(sdp_put_conn(&w, "IP4", 3, NULL, 0) == SDP_E_INVAL);
            check(sdp_put_media(&w, SDP_M_OTHER, 1, 1, SDP_P_RTP_AVP, "0", 1) ==
                  SDP_E_INVAL);
            check(sdp_put_media(&w, SDP_M_AUDIO, 1, 1, SDP_P_OTHER, "0", 1) ==
                  SDP_E_INVAL);
            check(sdp_put_attr(&w, SDP_A_OTHER, "x", 1) == SDP_E_INVAL);
            check(sdp_put_line(&w, 'A', "x", 1) == SDP_E_INVAL);
            check(w.off == 0);
            check(!w.overflow);
        }

        it ("refuses to write into no buffer at all") {
            sdp_wbuf_t w;
            sdp_wbuf_init(&w, NULL, 0);
            check(w.overflow);
            check(sdp_put_version(&w) == SDP_E_OVERFLOW);
        }
    }
}
