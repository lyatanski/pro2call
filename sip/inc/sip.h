#ifndef SIP_H
#define SIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SIP codec — RFC 3261 (+ method/header extensions).
 *
 * Decode is zero-copy: sip_msg_parse() fills a sip_msg_t whose every
 * string is a sip_str_t slice (pointer + length) into the caller's
 * buffer. Nothing is allocated and nothing is copied; the buffer must
 * remain valid while the message (or any slice taken from it) is in
 * use. The deeper parsers (URI, address, Via, CSeq) slice further into
 * those slices, again without copying.
 *
 * Methods and header-field names are resolved to enums during the
 * parse, so dispatch is integer compares — a compact form ("v:") and
 * its long form ("Via:") land on the same SIP_H_VIA and are
 * indistinguishable downstream. Extension headers come out as
 * SIP_H_OTHER with the name slice preserved.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Overflow on the write buffer is sticky: once any write exceeds
 * capacity every subsequent call fails, so return codes can be chained
 * and checked once at the end (mirrors tlv_wbuf_t in task/inc/tlv.h).
 *
 * Wire layout reference (text protocol, lines end in CRLF):
 *   start line : METHOD SP Request-URI SP SIP/2.0   (request)
 *                SIP/2.0 SP code SP reason          (response)
 *   headers    : Name ":" value, until an empty line
 *   body       : Content-Length octets after the empty line
 */

/* Borrowed view into a buffer owned by someone else. Never
 * NUL-terminated; print with printf("%.*s", SIP_STR_ARG(s)). */
typedef struct {
    const char* p;
    uint32_t    len;
} sip_str_t;

#define SIP_STR_ARG(s) (int)(s).len, (s).p

/* Upper bound on header fields in one message; override at compile
 * time if a deployment needs more. 48 slots keep sip_msg_t ~2 KiB, so
 * it still lives comfortably on the stack. */
#ifndef SIP_MAX_HDRS
#define SIP_MAX_HDRS 48
#endif

typedef enum {
    SIP_OK         = 0,
    SIP_E_SHORT    = -1, /* message incomplete — feed more bytes */
    SIP_E_LINE     = -2, /* malformed start line */
    SIP_E_VERSION  = -3, /* version is not SIP/2.0 */
    SIP_E_HEADER   = -4, /* malformed header field */
    SIP_E_HEADERS  = -5, /* more than SIP_MAX_HDRS header fields */
    SIP_E_OVERFLOW = -6, /* write buffer too small */
    SIP_E_INVAL    = -7, /* invalid argument */
    SIP_E_URI      = -8, /* malformed URI or address */
    SIP_E_MISSING  = -9  /* expected element absent */
} sip_err_t;

/* Methods — RFC 3261 §7.1 plus the standard extensions. Method names
 * on the wire are case-sensitive; anything unrecognized parses as
 * SIP_M_UNKNOWN with the raw token preserved in method_name. */
typedef enum {
    SIP_M_UNKNOWN   = 0,
    SIP_M_INVITE    = 1,
    SIP_M_ACK       = 2,
    SIP_M_BYE       = 3,
    SIP_M_CANCEL    = 4,
    SIP_M_OPTIONS   = 5,
    SIP_M_REGISTER  = 6,
    SIP_M_PRACK     = 7,  /* RFC 3262 */
    SIP_M_SUBSCRIBE = 8,  /* RFC 6665 */
    SIP_M_NOTIFY    = 9,  /* RFC 6665 */
    SIP_M_PUBLISH   = 10, /* RFC 3903 */
    SIP_M_INFO      = 11, /* RFC 6086 */
    SIP_M_REFER     = 12, /* RFC 3515 */
    SIP_M_MESSAGE   = 13, /* RFC 3428 */
    SIP_M_UPDATE    = 14, /* RFC 3311 */
    SIP_M_MAX       = 15
} sip_method_t;

/* Header fields — RFC 3261 §20 plus common extensions, alphabetical.
 * Compact forms (§7.3.3) are noted and resolve to the same value.
 * Order matters: the name lookup walks per-first-letter ranges. */
typedef enum {
    SIP_H_OTHER                = 0, /* extension header; match by name */
    SIP_H_ACCEPT               = 1,
    SIP_H_ACCEPT_ENCODING      = 2,
    SIP_H_ACCEPT_LANGUAGE      = 3,
    SIP_H_ALERT_INFO           = 4,
    SIP_H_ALLOW                = 5,
    SIP_H_ALLOW_EVENTS         = 6, /* u */
    SIP_H_AUTHENTICATION_INFO  = 7,
    SIP_H_AUTHORIZATION        = 8,
    SIP_H_CALL_ID              = 9, /* i */
    SIP_H_CALL_INFO            = 10,
    SIP_H_CONTACT              = 11, /* m */
    SIP_H_CONTENT_DISPOSITION  = 12,
    SIP_H_CONTENT_ENCODING     = 13, /* e */
    SIP_H_CONTENT_LANGUAGE     = 14,
    SIP_H_CONTENT_LENGTH       = 15, /* l */
    SIP_H_CONTENT_TYPE         = 16, /* c */
    SIP_H_CSEQ                 = 17,
    SIP_H_DATE                 = 18,
    SIP_H_ERROR_INFO           = 19,
    SIP_H_EVENT                = 20, /* o, RFC 6665 */
    SIP_H_EXPIRES              = 21,
    SIP_H_FROM                 = 22, /* f */
    SIP_H_IN_REPLY_TO          = 23,
    SIP_H_MAX_FORWARDS         = 24,
    SIP_H_MIME_VERSION         = 25,
    SIP_H_MIN_EXPIRES          = 26,
    SIP_H_MIN_SE               = 27, /* RFC 4028 */
    SIP_H_ORGANIZATION         = 28,
    SIP_H_P_ASSERTED_IDENTITY  = 29, /* RFC 3325 */
    SIP_H_P_PREFERRED_IDENTITY = 30, /* RFC 3325 */
    SIP_H_PRIORITY             = 31,
    SIP_H_PRIVACY              = 32, /* RFC 3323 */
    SIP_H_PROXY_AUTHENTICATE   = 33,
    SIP_H_PROXY_AUTHORIZATION  = 34,
    SIP_H_PROXY_REQUIRE        = 35,
    SIP_H_RACK                 = 36, /* RFC 3262 */
    SIP_H_RECORD_ROUTE         = 37,
    SIP_H_REFER_TO             = 38, /* r, RFC 3515 */
    SIP_H_REFERRED_BY          = 39, /* b, RFC 3892 */
    SIP_H_REPLY_TO             = 40,
    SIP_H_REQUIRE              = 41,
    SIP_H_RETRY_AFTER          = 42,
    SIP_H_ROUTE                = 43,
    SIP_H_RSEQ                 = 44, /* RFC 3262 */
    SIP_H_SERVER               = 45,
    SIP_H_SESSION_EXPIRES      = 46, /* x, RFC 4028 */
    SIP_H_SUBJECT              = 47, /* s */
    SIP_H_SUBSCRIPTION_STATE   = 48, /* RFC 6665 */
    SIP_H_SUPPORTED            = 49, /* k */
    SIP_H_TIMESTAMP            = 50,
    SIP_H_TO                   = 51, /* t */
    SIP_H_UNSUPPORTED          = 52,
    SIP_H_USER_AGENT           = 53,
    SIP_H_VIA                  = 54, /* v */
    SIP_H_WARNING              = 55,
    SIP_H_WWW_AUTHENTICATE     = 56,
    SIP_H_MAX                  = 57
} sip_hdr_t;

/* Header field view — points into the caller's input buffer. No
 * ownership, no copy. A folded (multi-line, obsolete per RFC) value
 * keeps its raw CRLF + whitespace inside the slice. */
typedef struct {
    uint8_t   id;    /* sip_hdr_t; SIP_H_OTHER for extension headers */
    sip_str_t name;  /* as it appeared on the wire (maybe compact)   */
    sip_str_t value; /* leading/trailing whitespace trimmed          */
} sip_hdr_view_t;

/* Parsed message — slices over one contiguous wire buffer. */
typedef struct {
    bool           is_request;
    uint8_t        method;      /* sip_method_t (requests)            */
    sip_str_t      method_name; /* raw token, set even for UNKNOWN    */
    sip_str_t      ruri;        /* Request-URI (requests)             */
    uint16_t       status;      /* 100..699 (responses)               */
    sip_str_t      reason;      /* reason phrase (responses)          */
    bool           has_clen;    /* Content-Length was present         */
    uint32_t       clen;
    uint16_t       hdr_count;
    sip_hdr_view_t hdrs[SIP_MAX_HDRS];
    sip_str_t      body;
} sip_msg_t;

/* ---- Message parse (zero-copy decode) ---- */

/* Parse one message. Returns the byte count consumed (start line +
 * headers + separator + Content-Length octets of body) on success, or
 * a negative sip_err_t. SIP_E_SHORT means the buffer holds a prefix of
 * a valid message — stream users grow the buffer and call again.
 * Without a Content-Length header the body runs to the end of the
 * buffer (datagram semantics). The buffer must stay valid while the
 * message is in use. */
API_EXPORT int sip_msg_parse(sip_msg_t* m, const char* buf, size_t len);

/* First header with this id, or NULL. */
API_EXPORT const sip_hdr_view_t* sip_msg_find(const sip_msg_t* m, sip_hdr_t id);

/* Next header carrying the same field as *prev (e.g. the second Via),
 * or NULL. For SIP_H_OTHER, "same" is a case-insensitive name match. */
API_EXPORT const sip_hdr_view_t* sip_msg_find_next(const sip_msg_t*      m,
                                                   const sip_hdr_view_t* prev);

/* First header whose name matches (case-insensitive; long or compact
 * form both work), or NULL. Meant for extension headers — for known
 * ones sip_msg_find() is the fast path. */
API_EXPORT const sip_hdr_view_t* sip_msg_find_name(const sip_msg_t* m,
                                                   const char*      name);

/* ---- Names and tables ---- */

/* Canonical (long-form) header name; "" for SIP_H_OTHER/out of range. */
API_EXPORT const char* sip_hdr_name(sip_hdr_t id);

/* Resolve a header name — long or single-letter compact form, case-
 * insensitive — to its enum; SIP_H_OTHER when unknown. */
API_EXPORT sip_hdr_t sip_hdr_from(const char* name, size_t len);

/* Method token; "" for SIP_M_UNKNOWN/out of range. */
API_EXPORT const char* sip_method_name(sip_method_t m);

/* Resolve a method token (case-sensitive, per RFC) to its enum. */
API_EXPORT sip_method_t sip_method_from(const char* name, size_t len);

/* Default reason phrase for a status code ("OK", "Ringing", ...);
 * "Unknown" when the code has no registered phrase. */
API_EXPORT const char* sip_status_phrase(unsigned status);

/* ---- Deep parsers (slice in, slices out — still zero-copy) ---- */

typedef enum {
    SIP_URI_OTHER = 0,
    SIP_URI_SIP   = 1,
    SIP_URI_SIPS  = 2,
    SIP_URI_TEL   = 3
} sip_uri_scheme_t;

typedef struct {
    uint8_t   scheme; /* sip_uri_scheme_t                          */
    sip_str_t scheme_name;
    sip_str_t user;    /* userinfo before '@' (password included);
                          for tel: the whole subscriber number      */
    sip_str_t host;    /* IPv6 literal without the brackets         */
    uint16_t  port;    /* 0 = absent                                */
    sip_str_t params;  /* after the first ';', up to '?' (no ';')   */
    sip_str_t headers; /* after '?'                                 */
} sip_uri_t;

API_EXPORT int sip_uri_parse(sip_uri_t* u, const char* buf, size_t len);

/* From/To/Contact/Route style address: [display] <uri>;params or a
 * bare uri;params (the bare form treats everything after the first ';'
 * as header parameters). tag is the "tag" parameter, empty if absent. */
typedef struct {
    sip_str_t display; /* without surrounding quotes                */
    sip_str_t uri;
    sip_str_t params;
    sip_str_t tag;
} sip_addr_t;

API_EXPORT int sip_addr_parse(sip_str_t value, sip_addr_t* out);

/* One Via value: SIP/2.0/TRANSPORT sent-by[;params]. branch is the
 * "branch" parameter, empty if absent. */
typedef struct {
    sip_str_t transport; /* "UDP", "TCP", "TLS", ...                  */
    sip_str_t host;      /* IPv6 literal without the brackets         */
    uint16_t  port;      /* 0 = absent                                */
    sip_str_t params;
    sip_str_t branch;
} sip_via_t;

API_EXPORT int sip_via_parse(sip_str_t value, sip_via_t* out);

typedef struct {
    uint32_t  seq;
    uint8_t   method; /* sip_method_t                              */
    sip_str_t method_name;
} sip_cseq_t;

API_EXPORT int sip_cseq_parse(sip_str_t value, sip_cseq_t* out);

/* Find ";name=value" (or valueless ";name") in a parameter run, e.g. a
 * URI's or Via's params slice. Name match is case-insensitive. Returns
 * true with *out = value ("" for a valueless flag). */
API_EXPORT bool sip_param(sip_str_t params, const char* name, sip_str_t* out);

/* ---- Message write (encode into caller's buffer) ---- */

/* Write buffer; overflow is sticky. off is the running length. */
typedef struct {
    char*  buf;
    size_t cap;
    size_t off;
    bool   overflow;
} sip_wbuf_t;

API_EXPORT void sip_wbuf_init(sip_wbuf_t* w, char* buf, size_t cap);

/* Start lines. Every put returns 0 on success or a negative
 * sip_err_t; after an overflow all further puts return SIP_E_OVERFLOW. */
API_EXPORT int sip_put_request(sip_wbuf_t* w, sip_method_t m, const char* uri,
                               size_t urilen);
API_EXPORT int sip_put_status(sip_wbuf_t* w, unsigned status,
                              const char* reason,
                              size_t      rlen); /* NULL = default phrase */

/* Header fields; the long-form canonical name is emitted. */
API_EXPORT int sip_put_hdr(sip_wbuf_t* w, sip_hdr_t id, const char* val,
                           size_t vlen);
API_EXPORT int sip_put_hdr_name(sip_wbuf_t* w, const char* name, size_t nlen,
                                const char* val, size_t vlen);
API_EXPORT int sip_put_hdr_u32(sip_wbuf_t* w, sip_hdr_t id, uint32_t v);

/* Terminate the message: writes Content-Length, the empty line and the
 * body (body may be NULL/0). Returns the total message length, or a
 * negative sip_err_t. */
API_EXPORT int sip_put_body(sip_wbuf_t* w, const void* body, size_t blen);

#ifdef __cplusplus
}
#endif

#endif /* SIP_H */
