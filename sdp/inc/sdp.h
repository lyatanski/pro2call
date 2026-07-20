#ifndef SDP_H
#define SDP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SDP codec — RFC 8866 (Session Description Protocol) plus the usual
 * attribute extensions (RTP/AVP, ICE, DTLS-SRTP, ...).
 *
 * Decode is zero-copy and single-pass: sdp_msg_parse() fills a
 * sdp_msg_t whose every string is a sdp_str_t slice (pointer + length)
 * into the caller's buffer. Nothing is allocated and nothing is
 * copied; the buffer must remain valid while the message (or any slice
 * taken from it) is in use. Attributes and media formats land in pools
 * inside sdp_msg_t — each media section owns a contiguous run, so
 * per-section iteration is a linear scan over a few cache lines.
 *
 * Attribute names are resolved to enums during the parse, so dispatch
 * downstream is integer compares (a=rtpmap:... is SDP_A_RTPMAP).
 * Unrecognized attributes come out as SDP_A_OTHER with the name slice
 * preserved. Lines with an unrecognized type letter are ignored, as
 * RFC 8866 §5 requires; session-level lines the module has no use for
 * (e=, p=, k=, r=, z=) are ignored the same way.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Overflow on the write buffer is sticky: once any write exceeds
 * capacity every subsequent call fails, so return codes can be chained
 * and checked once at sdp_end() (mirrors sip_wbuf_t in sip/inc/sip.h).
 *
 * Wire layout reference (text protocol, lines end in CRLF):
 *   session : v=0, then o=/s=/i=/u=/c=/b=/t=/a= ...
 *   media   : m=<type> <port>[/<n>] <proto> <fmt list>, then
 *             i=/c=/b=/a= ... until the next m= or the end
 */

/* Borrowed view into a buffer owned by someone else. Never
 * NUL-terminated; print with printf("%.*s", SDP_STR_ARG(s)). */
typedef struct {
    const char* p;
    uint32_t    len;
} sdp_str_t;

#define SDP_STR_ARG(s) (int)(s).len, (s).p

/* Pool bounds; override at compile time if a deployment needs more.
 * The defaults keep sdp_msg_t ~6 KiB, so it still lives comfortably
 * on the stack. Attribute and format pools are per-message totals
 * (session + all media sections combined). */
#ifndef SDP_MAX_MEDIA
#define SDP_MAX_MEDIA 8
#endif
#ifndef SDP_MAX_ATTRS
#define SDP_MAX_ATTRS 96
#endif
#ifndef SDP_MAX_FMTS
#define SDP_MAX_FMTS 64
#endif
#ifndef SDP_MAX_BWS
#define SDP_MAX_BWS 8
#endif

typedef enum {
    SDP_OK         = 0,
    SDP_E_LINE     = -1, /* malformed line or field                 */
    SDP_E_VERSION  = -2, /* description does not start with v=0     */
    SDP_E_MEDIA    = -3, /* more than SDP_MAX_MEDIA media sections  */
    SDP_E_ATTRS    = -4, /* more than SDP_MAX_ATTRS attributes      */
    SDP_E_FMTS     = -5, /* more than SDP_MAX_FMTS media formats    */
    SDP_E_BWS      = -6, /* more than SDP_MAX_BWS bandwidth lines   */
    SDP_E_OVERFLOW = -7, /* write buffer too small                  */
    SDP_E_INVAL    = -8, /* invalid argument                        */
    SDP_E_MISSING  = -9  /* expected element absent                 */
} sdp_err_t;

/* Attributes — the hot subset of the IANA registry, alphabetical.
 * Anything unrecognized parses as SDP_A_OTHER with the name slice
 * preserved. Order matters: the name lookup walks per-first-letter
 * ranges. */
typedef enum {
    SDP_A_OTHER       = 0, /* extension attribute; match by name */
    SDP_A_CANDIDATE   = 1, /* RFC 8839 (ICE)                     */
    SDP_A_CRYPTO      = 2, /* RFC 4568 (SDES-SRTP)               */
    SDP_A_EXTMAP      = 3, /* RFC 8285                           */
    SDP_A_FINGERPRINT = 4, /* RFC 8122 (DTLS)                    */
    SDP_A_FMTP        = 5,
    SDP_A_GROUP       = 6,  /* RFC 5888                           */
    SDP_A_ICE_LITE    = 7,  /* RFC 8839                           */
    SDP_A_ICE_OPTIONS = 8,  /* RFC 8839                           */
    SDP_A_ICE_PWD     = 9,  /* RFC 8839                           */
    SDP_A_ICE_UFRAG   = 10, /* RFC 8839                           */
    SDP_A_INACTIVE    = 11,
    SDP_A_MAXPTIME    = 12,
    SDP_A_MID         = 13, /* RFC 5888                           */
    SDP_A_MSID        = 14, /* RFC 8830                           */
    SDP_A_PTIME       = 15,
    SDP_A_RECVONLY    = 16,
    SDP_A_RTCP        = 17, /* RFC 3605                           */
    SDP_A_RTCP_FB     = 18, /* RFC 4585                           */
    SDP_A_RTCP_MUX    = 19, /* RFC 5761                           */
    SDP_A_RTPMAP      = 20,
    SDP_A_SENDONLY    = 21,
    SDP_A_SENDRECV    = 22,
    SDP_A_SETUP       = 23, /* RFC 4145                           */
    SDP_A_SSRC        = 24, /* RFC 5576                           */
    SDP_A_SSRC_GROUP  = 25, /* RFC 5576                           */
    SDP_A_MAX         = 26
} sdp_attr_id_t;

/* Media types — RFC 8866 §5.14. Tokens are case-sensitive. */
typedef enum {
    SDP_M_OTHER       = 0,
    SDP_M_AUDIO       = 1,
    SDP_M_VIDEO       = 2,
    SDP_M_TEXT        = 3,
    SDP_M_APPLICATION = 4,
    SDP_M_MESSAGE     = 5,
    SDP_M_IMAGE       = 6, /* T.38 fax */
    SDP_M_MAX         = 7
} sdp_mtype_t;

/* Transport protocols — the registered tokens seen in VoIP/WebRTC.
 * Tokens are case-sensitive ("udp" and "udptl" really are lowercase). */
typedef enum {
    SDP_P_OTHER             = 0,
    SDP_P_RTP_AVP           = 1,
    SDP_P_RTP_AVPF          = 2, /* RFC 4585  */
    SDP_P_RTP_SAVP          = 3, /* RFC 3711  */
    SDP_P_RTP_SAVPF         = 4, /* RFC 5124  */
    SDP_P_UDP_TLS_RTP_SAVP  = 5, /* RFC 5764  */
    SDP_P_UDP_TLS_RTP_SAVPF = 6, /* RFC 5764  */
    SDP_P_UDP_DTLS_SCTP     = 7, /* RFC 8841  */
    SDP_P_UDPTL             = 8, /* RFC 3362  */
    SDP_P_UDP               = 9,
    SDP_P_TCP               = 10, /* RFC 4145  */
    SDP_P_MAX               = 11
} sdp_proto_t;

/* Stream direction; the value of sdp_media_dir(). */
typedef enum {
    SDP_DIR_SENDRECV = 0,
    SDP_DIR_SENDONLY = 1,
    SDP_DIR_RECVONLY = 2,
    SDP_DIR_INACTIVE = 3
} sdp_dir_t;

/* o= — RFC 8866 §5.2. sess_id/sess_version are numeric per the RFC. */
typedef struct {
    sdp_str_t username; /* "-" when the endpoint has none      */
    uint64_t  sess_id;
    uint64_t  sess_version; /* bumps on every renegotiation        */
    sdp_str_t nettype;      /* "IN"                                */
    sdp_str_t addrtype;     /* "IP4" / "IP6"                       */
    sdp_str_t addr;
} sdp_origin_t;

/* c= — RFC 8866 §5.7. addr keeps any multicast /ttl or /count
 * suffix; unicast VoIP never has one. */
typedef struct {
    sdp_str_t nettype;
    sdp_str_t addrtype;
    sdp_str_t addr;
} sdp_conn_t;

/* b= — RFC 8866 §5.8: <bwtype>:<kilobits>. */
typedef struct {
    sdp_str_t bwtype; /* "AS", "TIAS", ...                   */
    uint64_t  value;
} sdp_bw_t;

/* One a= line — points into the caller's input buffer. No ownership,
 * no copy. A flag attribute (a=sendrecv) has an empty value. */
typedef struct {
    uint8_t   id;    /* sdp_attr_id_t; SDP_A_OTHER for extensions */
    sdp_str_t name;  /* as it appeared on the wire                */
    sdp_str_t value; /* after the ':', leading spaces trimmed     */
} sdp_attr_t;

/* One m= section. Attributes, formats and bandwidth lines live in the
 * message-level pools; [*_off, *_off + *_count) is this section's run. */
typedef struct {
    uint8_t    type;       /* sdp_mtype_t                         */
    sdp_str_t  type_name;  /* raw token, set even for OTHER       */
    uint16_t   port;       /* 0 = stream rejected/disabled        */
    uint16_t   nports;     /* from <port>/<n>; 1 when absent      */
    uint8_t    proto;      /* sdp_proto_t                         */
    sdp_str_t  proto_name; /* raw token, set even for OTHER       */
    sdp_str_t  title;      /* i=, empty if absent                 */
    bool       has_conn;
    sdp_conn_t conn; /* first c= of this section            */
    uint16_t   fmt_off, fmt_count;
    uint16_t   bw_off, bw_count;
    uint16_t   attr_off, attr_count;
} sdp_media_t;

/* Parsed description — slices over one contiguous buffer. Session-
 * level attributes and bandwidth lines occupy the front of the pools
 * (offset 0); media runs follow in wire order. */
typedef struct {
    uint8_t      version; /* always 0                           */
    bool         has_origin;
    sdp_origin_t origin;
    sdp_str_t    name; /* s=                                 */
    sdp_str_t    info; /* i= (session level)                 */
    sdp_str_t    uri;  /* u=                                 */
    bool         has_conn;
    sdp_conn_t   conn; /* session-level c=                   */
    bool         has_time;
    uint64_t     t_start; /* first t=; both 0 = unbounded       */
    uint64_t     t_stop;
    uint16_t     bw_count;   /* session-level b= lines             */
    uint16_t     attr_count; /* session-level a= lines             */
    uint8_t      media_count;
    sdp_media_t  media[SDP_MAX_MEDIA];
    sdp_attr_t   attrs[SDP_MAX_ATTRS];
    sdp_str_t    fmts[SDP_MAX_FMTS];
    sdp_bw_t     bws[SDP_MAX_BWS];
} sdp_msg_t;

/* ---- Parse (zero-copy decode) ---- */

/* Parse one session description (e.g. a SIP application/sdp body).
 * Returns SDP_OK or a negative sdp_err_t. Line terminators may be
 * CRLF or bare LF, and the final line may lack one. The buffer must
 * stay valid while the message is in use. */
API_EXPORT int sdp_msg_parse(sdp_msg_t* m, const char* buf, size_t len);

/* ---- Attribute access ----
 *
 * media selects the section: a pointer into m->media for that
 * section's attributes, NULL for the session-level ones. */

/* First attribute with this id in the section, or NULL. */
API_EXPORT const sdp_attr_t*
sdp_attr_find(const sdp_msg_t* m, const sdp_media_t* media, sdp_attr_id_t id);

/* Next attribute in the same section carrying the same name as *prev
 * (e.g. the second a=candidate), or NULL. */
API_EXPORT const sdp_attr_t* sdp_attr_next(const sdp_msg_t*   m,
                                           const sdp_media_t* media,
                                           const sdp_attr_t*  prev);

/* First attribute whose name matches (case-insensitive), or NULL.
 * Meant for extension attributes — for known ones sdp_attr_find() is
 * the fast path. */
API_EXPORT const sdp_attr_t* sdp_attr_find_name(const sdp_msg_t*   m,
                                                const sdp_media_t* media,
                                                const char*        name);

/* Effective direction of a media section: its own direction
 * attribute, else the session-level one, else sendrecv. */
API_EXPORT sdp_dir_t sdp_media_dir(const sdp_msg_t*   m,
                                   const sdp_media_t* media);

/* Effective connection of a media section: its own c=, else the
 * session-level one, else NULL. */
API_EXPORT const sdp_conn_t* sdp_media_conn(const sdp_msg_t*   m,
                                            const sdp_media_t* media);

/* ---- Deep parsers (slice in, slices out — still zero-copy) ---- */

/* a=rtpmap:<pt> <encoding>/<clock>[/<params>] */
typedef struct {
    uint8_t   pt;  /* payload type, 0..127                  */
    sdp_str_t enc; /* "PCMU", "opus", "telephone-event"     */
    uint32_t  clock;
    sdp_str_t params; /* channels for audio; empty if absent   */
} sdp_rtpmap_t;

API_EXPORT int sdp_rtpmap_parse(sdp_str_t value, sdp_rtpmap_t* out);

/* a=fmtp:<fmt> <params> */
typedef struct {
    sdp_str_t fmt; /* usually a payload type number         */
    sdp_str_t params;
} sdp_fmtp_t;

API_EXPORT int sdp_fmtp_parse(sdp_str_t value, sdp_fmtp_t* out);

/* rtpmap / fmtp of payload type pt within a media section (media as
 * for sdp_attr_find). SDP_E_MISSING when the section has none. */
API_EXPORT int sdp_rtpmap_find(const sdp_msg_t* m, const sdp_media_t* media,
                               unsigned pt, sdp_rtpmap_t* out);
API_EXPORT int sdp_fmtp_find(const sdp_msg_t* m, const sdp_media_t* media,
                             unsigned pt, sdp_str_t* params);

/* ---- Names and tables ---- */

/* Canonical attribute name; "" for SDP_A_OTHER/out of range. */
API_EXPORT const char* sdp_attr_name(sdp_attr_id_t id);

/* Resolve an attribute name (case-insensitive) to its enum;
 * SDP_A_OTHER when unknown. */
API_EXPORT sdp_attr_id_t sdp_attr_from(const char* name, size_t len);

/* Media type / transport protocol tokens; "" for OTHER/out of range.
 * The _from lookups are case-sensitive, as the tokens are on the wire. */
API_EXPORT const char* sdp_mtype_name(sdp_mtype_t t);
API_EXPORT sdp_mtype_t sdp_mtype_from(const char* name, size_t len);
API_EXPORT const char* sdp_proto_name(sdp_proto_t p);
API_EXPORT sdp_proto_t sdp_proto_from(const char* name, size_t len);

/* Direction attribute name ("sendrecv", ...). */
API_EXPORT const char* sdp_dir_name(sdp_dir_t d);

/* ---- Write (encode into caller's buffer) ---- */

/* Write buffer; overflow is sticky. off is the running length. */
typedef struct {
    char*  buf;
    size_t cap;
    size_t off;
    bool   overflow;
} sdp_wbuf_t;

API_EXPORT void sdp_wbuf_init(sdp_wbuf_t* w, char* buf, size_t cap);

/* Every put returns 0 on success or a negative sdp_err_t; after an
 * overflow all further puts return SDP_E_OVERFLOW. Lines are emitted
 * in call order — the caller keeps the RFC's line order. */
API_EXPORT int sdp_put_version(sdp_wbuf_t* w);               /* v=0    */
API_EXPORT int sdp_put_origin(sdp_wbuf_t* w,                 /* o=, IN */
                              const char* user, size_t ulen, /* "" = "-" */
                              uint64_t sess_id, uint64_t sess_version,
                              const char* addrtype, size_t atlen,
                              const char* addr, size_t alen);
API_EXPORT int sdp_put_name(sdp_wbuf_t* w, /* s=, "" = "-" */
                            const char* name, size_t nlen);
API_EXPORT int sdp_put_conn(sdp_wbuf_t* w, /* c=, IN */
                            const char* addrtype, size_t atlen,
                            const char* addr, size_t alen);
API_EXPORT int sdp_put_bw(sdp_wbuf_t* w, const char* bwtype, size_t btlen,
                          uint64_t value);
API_EXPORT int sdp_put_time(sdp_wbuf_t* w, uint64_t start, uint64_t stop);

/* m= line; fmts is the pre-joined format list ("0 8 96"). nports 0
 * and 1 both mean "no /<n> suffix". */
API_EXPORT int sdp_put_media(sdp_wbuf_t* w, sdp_mtype_t type, uint16_t port,
                             uint16_t nports, sdp_proto_t proto,
                             const char* fmts, size_t flen);
API_EXPORT int sdp_put_media_name(sdp_wbuf_t* w, const char* type, size_t tlen,
                                  uint16_t port, uint16_t nports,
                                  const char* proto, size_t plen,
                                  const char* fmts, size_t flen);

/* a= line; vlen 0 writes a flag attribute (a=sendrecv). */
API_EXPORT int sdp_put_attr(sdp_wbuf_t* w, sdp_attr_id_t id, const char* val,
                            size_t vlen);
API_EXPORT int sdp_put_attr_name(sdp_wbuf_t* w, const char* name, size_t nlen,
                                 const char* val, size_t vlen);

/* Escape hatch for any other line type: <type>=<value>. */
API_EXPORT int sdp_put_line(sdp_wbuf_t* w, char type, const char* val,
                            size_t vlen);

/* Finish: returns the total description length, or SDP_E_OVERFLOW. */
API_EXPORT int sdp_end(sdp_wbuf_t* w);

#ifdef __cplusplus
}
#endif

#endif /* SDP_H */
