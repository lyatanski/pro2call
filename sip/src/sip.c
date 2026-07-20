#include <limits.h>
#include <string.h>

#include "sip.h"
#include "sip_intl.h"

/* ---- name tables ---- */

typedef struct {
    const char* name;
    uint8_t     len;
} name_len_t;

static const name_len_t k_hdr[SIP_H_MAX] = {
    [SIP_H_OTHER]                = { "", 0 },
    [SIP_H_ACCEPT]               = { "Accept", 6 },
    [SIP_H_ACCEPT_ENCODING]      = { "Accept-Encoding", 15 },
    [SIP_H_ACCEPT_LANGUAGE]      = { "Accept-Language", 15 },
    [SIP_H_ALERT_INFO]           = { "Alert-Info", 10 },
    [SIP_H_ALLOW]                = { "Allow", 5 },
    [SIP_H_ALLOW_EVENTS]         = { "Allow-Events", 12 },
    [SIP_H_AUTHENTICATION_INFO]  = { "Authentication-Info", 19 },
    [SIP_H_AUTHORIZATION]        = { "Authorization", 13 },
    [SIP_H_CALL_ID]              = { "Call-ID", 7 },
    [SIP_H_CALL_INFO]            = { "Call-Info", 9 },
    [SIP_H_CONTACT]              = { "Contact", 7 },
    [SIP_H_CONTENT_DISPOSITION]  = { "Content-Disposition", 19 },
    [SIP_H_CONTENT_ENCODING]     = { "Content-Encoding", 16 },
    [SIP_H_CONTENT_LANGUAGE]     = { "Content-Language", 16 },
    [SIP_H_CONTENT_LENGTH]       = { "Content-Length", 14 },
    [SIP_H_CONTENT_TYPE]         = { "Content-Type", 12 },
    [SIP_H_CSEQ]                 = { "CSeq", 4 },
    [SIP_H_DATE]                 = { "Date", 4 },
    [SIP_H_ERROR_INFO]           = { "Error-Info", 10 },
    [SIP_H_EVENT]                = { "Event", 5 },
    [SIP_H_EXPIRES]              = { "Expires", 7 },
    [SIP_H_FROM]                 = { "From", 4 },
    [SIP_H_IN_REPLY_TO]          = { "In-Reply-To", 11 },
    [SIP_H_MAX_FORWARDS]         = { "Max-Forwards", 12 },
    [SIP_H_MIME_VERSION]         = { "MIME-Version", 12 },
    [SIP_H_MIN_EXPIRES]          = { "Min-Expires", 11 },
    [SIP_H_MIN_SE]               = { "Min-SE", 6 },
    [SIP_H_ORGANIZATION]         = { "Organization", 12 },
    [SIP_H_P_ASSERTED_IDENTITY]  = { "P-Asserted-Identity", 19 },
    [SIP_H_P_PREFERRED_IDENTITY] = { "P-Preferred-Identity", 20 },
    [SIP_H_PRIORITY]             = { "Priority", 8 },
    [SIP_H_PRIVACY]              = { "Privacy", 7 },
    [SIP_H_PROXY_AUTHENTICATE]   = { "Proxy-Authenticate", 18 },
    [SIP_H_PROXY_AUTHORIZATION]  = { "Proxy-Authorization", 19 },
    [SIP_H_PROXY_REQUIRE]        = { "Proxy-Require", 13 },
    [SIP_H_RACK]                 = { "RAck", 4 },
    [SIP_H_RECORD_ROUTE]         = { "Record-Route", 12 },
    [SIP_H_REFER_TO]             = { "Refer-To", 8 },
    [SIP_H_REFERRED_BY]          = { "Referred-By", 11 },
    [SIP_H_REPLY_TO]             = { "Reply-To", 8 },
    [SIP_H_REQUIRE]              = { "Require", 7 },
    [SIP_H_RETRY_AFTER]          = { "Retry-After", 11 },
    [SIP_H_ROUTE]                = { "Route", 5 },
    [SIP_H_RSEQ]                 = { "RSeq", 4 },
    [SIP_H_SERVER]               = { "Server", 6 },
    [SIP_H_SESSION_EXPIRES]      = { "Session-Expires", 15 },
    [SIP_H_SUBJECT]              = { "Subject", 7 },
    [SIP_H_SUBSCRIPTION_STATE]   = { "Subscription-State", 18 },
    [SIP_H_SUPPORTED]            = { "Supported", 9 },
    [SIP_H_TIMESTAMP]            = { "Timestamp", 9 },
    [SIP_H_TO]                   = { "To", 2 },
    [SIP_H_UNSUPPORTED]          = { "Unsupported", 11 },
    [SIP_H_USER_AGENT]           = { "User-Agent", 10 },
    [SIP_H_VIA]                  = { "Via", 3 },
    [SIP_H_WARNING]              = { "Warning", 7 },
    [SIP_H_WWW_AUTHENTICATE]     = { "WWW-Authenticate", 16 }
};

/* The enum is alphabetical, so each first letter owns a contiguous id
 * range; lookup walks only that bucket. lo == 0 means no such names. */
static const struct {
    uint8_t lo, hi;
} k_hdr_bucket[26] = {
    ['a' - 'a'] = { SIP_H_ACCEPT, SIP_H_AUTHORIZATION },
    ['c' - 'a'] = { SIP_H_CALL_ID, SIP_H_CSEQ },
    ['d' - 'a'] = { SIP_H_DATE, SIP_H_DATE },
    ['e' - 'a'] = { SIP_H_ERROR_INFO, SIP_H_EXPIRES },
    ['f' - 'a'] = { SIP_H_FROM, SIP_H_FROM },
    ['i' - 'a'] = { SIP_H_IN_REPLY_TO, SIP_H_IN_REPLY_TO },
    ['m' - 'a'] = { SIP_H_MAX_FORWARDS, SIP_H_MIN_SE },
    ['o' - 'a'] = { SIP_H_ORGANIZATION, SIP_H_ORGANIZATION },
    ['p' - 'a'] = { SIP_H_P_ASSERTED_IDENTITY, SIP_H_PROXY_REQUIRE },
    ['r' - 'a'] = { SIP_H_RACK, SIP_H_RSEQ },
    ['s' - 'a'] = { SIP_H_SERVER, SIP_H_SUPPORTED },
    ['t' - 'a'] = { SIP_H_TIMESTAMP, SIP_H_TO },
    ['u' - 'a'] = { SIP_H_UNSUPPORTED, SIP_H_USER_AGENT },
    ['v' - 'a'] = { SIP_H_VIA, SIP_H_VIA },
    ['w' - 'a'] = { SIP_H_WARNING, SIP_H_WWW_AUTHENTICATE }
};

/* Compact forms — RFC 3261 §7.3.3 and the extension RFCs. */
static const uint8_t k_hdr_compact[26] = { ['b' - 'a'] = SIP_H_REFERRED_BY,
                                           ['c' - 'a'] = SIP_H_CONTENT_TYPE,
                                           ['e' - 'a'] = SIP_H_CONTENT_ENCODING,
                                           ['f' - 'a'] = SIP_H_FROM,
                                           ['i' - 'a'] = SIP_H_CALL_ID,
                                           ['k' - 'a'] = SIP_H_SUPPORTED,
                                           ['l' - 'a'] = SIP_H_CONTENT_LENGTH,
                                           ['m' - 'a'] = SIP_H_CONTACT,
                                           ['o' - 'a'] = SIP_H_EVENT,
                                           ['r' - 'a'] = SIP_H_REFER_TO,
                                           ['s' - 'a'] = SIP_H_SUBJECT,
                                           ['t' - 'a'] = SIP_H_TO,
                                           ['u' - 'a'] = SIP_H_ALLOW_EVENTS,
                                           ['v' - 'a'] = SIP_H_VIA,
                                           ['x' - 'a'] =
                                               SIP_H_SESSION_EXPIRES };

static const name_len_t k_method[SIP_M_MAX] = {
    [SIP_M_UNKNOWN]   = { "", 0 },
    [SIP_M_INVITE]    = { "INVITE", 6 },
    [SIP_M_ACK]       = { "ACK", 3 },
    [SIP_M_BYE]       = { "BYE", 3 },
    [SIP_M_CANCEL]    = { "CANCEL", 6 },
    [SIP_M_OPTIONS]   = { "OPTIONS", 7 },
    [SIP_M_REGISTER]  = { "REGISTER", 8 },
    [SIP_M_PRACK]     = { "PRACK", 5 },
    [SIP_M_SUBSCRIBE] = { "SUBSCRIBE", 9 },
    [SIP_M_NOTIFY]    = { "NOTIFY", 6 },
    [SIP_M_PUBLISH]   = { "PUBLISH", 7 },
    [SIP_M_INFO]      = { "INFO", 4 },
    [SIP_M_REFER]     = { "REFER", 5 },
    [SIP_M_MESSAGE]   = { "MESSAGE", 7 },
    [SIP_M_UPDATE]    = { "UPDATE", 6 }
};

const char* sip_hdr_name(sip_hdr_t id)
{
    return ((unsigned)id < SIP_H_MAX) ? k_hdr[id].name : "";
}

sip_hdr_t sip_hdr_from(const char* name, size_t len)
{
    if (len == 1) {
        char c = sip_lc(name[0]);
        return (c >= 'a' && c <= 'z') ? (sip_hdr_t)k_hdr_compact[c - 'a']
                                      : SIP_H_OTHER;
    }
    if (len < 2 || len > 20) return SIP_H_OTHER;
    char c = sip_lc(name[0]);
    if (c < 'a' || c > 'z') return SIP_H_OTHER;
    uint8_t hi = k_hdr_bucket[c - 'a'].hi;
    for (uint8_t id = k_hdr_bucket[c - 'a'].lo; id && id <= hi; id++)
        if (k_hdr[id].len == len && sip_ieq2(name, k_hdr[id].name, len))
            return (sip_hdr_t)id;
    return SIP_H_OTHER;
}

const char* sip_method_name(sip_method_t m)
{
    return ((unsigned)m < SIP_M_MAX) ? k_method[m].name : "";
}

sip_method_t sip_method_from(const char* name, size_t len)
{
    /* Methods are case-sensitive tokens; dispatch on length. */
    switch (len) {
    case 3:
        if (memcmp(name, "ACK", 3) == 0) return SIP_M_ACK;
        if (memcmp(name, "BYE", 3) == 0) return SIP_M_BYE;
        break;
    case 4:
        if (memcmp(name, "INFO", 4) == 0) return SIP_M_INFO;
        break;
    case 5:
        if (memcmp(name, "PRACK", 5) == 0) return SIP_M_PRACK;
        if (memcmp(name, "REFER", 5) == 0) return SIP_M_REFER;
        break;
    case 6:
        if (memcmp(name, "INVITE", 6) == 0) return SIP_M_INVITE;
        if (memcmp(name, "CANCEL", 6) == 0) return SIP_M_CANCEL;
        if (memcmp(name, "NOTIFY", 6) == 0) return SIP_M_NOTIFY;
        if (memcmp(name, "UPDATE", 6) == 0) return SIP_M_UPDATE;
        break;
    case 7:
        if (memcmp(name, "OPTIONS", 7) == 0) return SIP_M_OPTIONS;
        if (memcmp(name, "MESSAGE", 7) == 0) return SIP_M_MESSAGE;
        if (memcmp(name, "PUBLISH", 7) == 0) return SIP_M_PUBLISH;
        break;
    case 8:
        if (memcmp(name, "REGISTER", 8) == 0) return SIP_M_REGISTER;
        break;
    case 9:
        if (memcmp(name, "SUBSCRIBE", 9) == 0) return SIP_M_SUBSCRIBE;
        break;
    default: break;
    }
    return SIP_M_UNKNOWN;
}

const char* sip_status_phrase(unsigned status)
{
    switch (status) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 181: return "Call Is Being Forwarded";
    case 182: return "Queued";
    case 183: return "Session Progress";
    case 199: return "Early Dialog Terminated";
    case 200: return "OK";
    case 202: return "Accepted";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 302: return "Moved Temporarily";
    case 305: return "Use Proxy";
    case 380: return "Alternative Service";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Timeout";
    case 410: return "Gone";
    case 413: return "Request Entity Too Large";
    case 414: return "Request-URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Unsupported URI Scheme";
    case 420: return "Bad Extension";
    case 421: return "Extension Required";
    case 422: return "Session Interval Too Small";
    case 423: return "Interval Too Brief";
    case 480: return "Temporarily Unavailable";
    case 481: return "Call/Transaction Does Not Exist";
    case 482: return "Loop Detected";
    case 483: return "Too Many Hops";
    case 484: return "Address Incomplete";
    case 485: return "Ambiguous";
    case 486: return "Busy Here";
    case 487: return "Request Terminated";
    case 488: return "Not Acceptable Here";
    case 489: return "Bad Event";
    case 491: return "Request Pending";
    case 493: return "Undecipherable";
    case 500: return "Server Internal Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Server Time-out";
    case 505: return "Version Not Supported";
    case 513: return "Message Too Large";
    case 600: return "Busy Everywhere";
    case 603: return "Decline";
    case 604: return "Does Not Exist Anywhere";
    case 606: return "Not Acceptable";
    default:  return "Unknown";
    }
}

/* ---- message parse ---- */

/* Locate the terminator of the line starting at p: *eol is set to the
 * first byte of the CRLF (or bare LF), the return value is the start
 * of the following line. NULL when no terminator is in the buffer. */
static const char* line_end(const char* p, const char* end, const char** eol)
{
    const char* nl = memchr(p, '\n', (size_t)(end - p));
    if (SIP_UNLIKELY(nl == NULL)) return NULL;
    *eol = (nl > p && nl[-1] == '\r') ? nl - 1 : nl;
    return nl + 1;
}

static int parse_start_line(sip_msg_t* m, const char* p, const char* eol)
{
    size_t n = (size_t)(eol - p);

    if (n >= 8 && sip_ieq(p, "sip/2.0 ", 8)) {
        /* status line */
        const char* q = p + 8;
        if (SIP_UNLIKELY(eol - q < 3 || !sip_is_digit(q[0]) ||
                         !sip_is_digit(q[1]) || !sip_is_digit(q[2])))
            return SIP_E_LINE;
        unsigned code = (unsigned)(q[0] - '0') * 100 +
                        (unsigned)(q[1] - '0') * 10 + (unsigned)(q[2] - '0');
        if (SIP_UNLIKELY(code < 100)) return SIP_E_LINE;
        q += 3;
        if (q < eol) {
            if (SIP_UNLIKELY(*q != ' ')) return SIP_E_LINE;
            q++;
        }
        m->is_request = false;
        m->status     = (uint16_t)code;
        m->reason.p   = q;
        m->reason.len = (uint32_t)(eol - q);
        return SIP_OK;
    }

    /* request line: METHOD SP Request-URI SP SIP/2.0 */
    const char* sp1 = memchr(p, ' ', n);
    if (SIP_UNLIKELY(sp1 == NULL || sp1 == p)) return SIP_E_LINE;
    const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(eol - sp1 - 1));
    if (SIP_UNLIKELY(sp2 == NULL || sp2 == sp1 + 1)) return SIP_E_LINE;
    if (SIP_UNLIKELY(eol - sp2 - 1 != 7 || !sip_ieq(sp2 + 1, "sip/2.0", 7)))
        return SIP_E_VERSION;

    m->is_request      = true;
    m->method_name.p   = p;
    m->method_name.len = (uint32_t)(sp1 - p);
    m->method          = (uint8_t)sip_method_from(p, (size_t)(sp1 - p));
    m->ruri.p          = sp1 + 1;
    m->ruri.len        = (uint32_t)(sp2 - sp1 - 1);
    return SIP_OK;
}

int sip_msg_parse(sip_msg_t* m, const char* buf, size_t len)
{
    if (SIP_UNLIKELY(m == NULL || buf == NULL || len > (size_t)INT_MAX))
        return SIP_E_INVAL;

    m->is_request  = false;
    m->method      = SIP_M_UNKNOWN;
    m->method_name = (sip_str_t){ NULL, 0 };
    m->ruri        = (sip_str_t){ NULL, 0 };
    m->status      = 0;
    m->reason      = (sip_str_t){ NULL, 0 };
    m->has_clen    = false;
    m->clen        = 0;
    m->hdr_count   = 0;
    m->body        = (sip_str_t){ NULL, 0 };

    const char* p   = buf;
    const char* end = buf + len;

    /* Stream keep-alive CRLFs may precede the start line. */
    while (p < end && (*p == '\r' || *p == '\n'))
        p++;

    const char* eol;
    const char* nl = line_end(p, end, &eol);
    if (SIP_UNLIKELY(nl == NULL)) return SIP_E_SHORT;
    int rc = parse_start_line(m, p, eol);
    if (SIP_UNLIKELY(rc != SIP_OK)) return rc;
    p = nl;

    for (;;) {
        nl = line_end(p, end, &eol);
        if (SIP_UNLIKELY(nl == NULL)) return SIP_E_SHORT;
        if (eol == p) { /* empty line: end of headers */
            p = nl;
            break;
        }

        /* Obsolete folding: continuation lines start with SP/HT and
         * stay inside the value slice, terminators included. */
        while (nl < end && sip_is_ws(*nl)) {
            const char* eol2;
            const char* nl2 = line_end(nl, end, &eol2);
            if (SIP_UNLIKELY(nl2 == NULL)) return SIP_E_SHORT;
            eol = eol2;
            nl  = nl2;
        }

        const char* colon = memchr(p, ':', (size_t)(eol - p));
        if (SIP_UNLIKELY(colon == NULL)) return SIP_E_HEADER;

        const char* ne = colon; /* trim "Name : value" */
        while (ne > p && sip_is_ws(ne[-1]))
            ne--;
        if (SIP_UNLIKELY(ne == p)) return SIP_E_HEADER;

        const char* v = colon + 1;
        while (v < eol && sip_is_ws(*v))
            v++;
        const char* ve = eol;
        while (ve > v && sip_is_ws(ve[-1]))
            ve--;

        if (SIP_UNLIKELY(m->hdr_count >= SIP_MAX_HDRS)) return SIP_E_HEADERS;

        sip_hdr_view_t* h = &m->hdrs[m->hdr_count++];
        h->id             = (uint8_t)sip_hdr_from(p, (size_t)(ne - p));
        h->name.p         = p;
        h->name.len       = (uint32_t)(ne - p);
        h->value.p        = v;
        h->value.len      = (uint32_t)(ve - v);

        if (h->id == SIP_H_CONTENT_LENGTH) {
            if (SIP_UNLIKELY(!sip_parse_u32(v, (size_t)(ve - v), &m->clen)))
                return SIP_E_HEADER;
            m->has_clen = true;
        }

        p = nl;
    }

    size_t hoff = (size_t)(p - buf);
    if (m->has_clen) {
        if (SIP_UNLIKELY((size_t)m->clen > len - hoff)) return SIP_E_SHORT;
        m->body.p   = p;
        m->body.len = m->clen;
        return (int)(hoff + m->clen);
    }
    /* No Content-Length: datagram semantics, body is the rest. */
    m->body.p   = p;
    m->body.len = (uint32_t)(len - hoff);
    return (int)len;
}

const sip_hdr_view_t* sip_msg_find(const sip_msg_t* m, sip_hdr_t id)
{
    for (uint16_t i = 0; i < m->hdr_count; i++)
        if (m->hdrs[i].id == (uint8_t)id) return &m->hdrs[i];
    return NULL;
}

const sip_hdr_view_t* sip_msg_find_next(const sip_msg_t*      m,
                                        const sip_hdr_view_t* prev)
{
    if (SIP_UNLIKELY(prev < m->hdrs || prev >= m->hdrs + m->hdr_count))
        return NULL;
    for (const sip_hdr_view_t* h = prev + 1; h < m->hdrs + m->hdr_count; h++) {
        if (h->id != prev->id) continue;
        if (h->id != SIP_H_OTHER) return h;
        if (h->name.len == prev->name.len &&
            sip_ieq2(h->name.p, prev->name.p, h->name.len))
            return h;
    }
    return NULL;
}

const sip_hdr_view_t* sip_msg_find_name(const sip_msg_t* m, const char* name)
{
    size_t    n  = strlen(name);
    sip_hdr_t id = sip_hdr_from(name, n);
    if (id != SIP_H_OTHER) return sip_msg_find(m, id);
    for (uint16_t i = 0; i < m->hdr_count; i++)
        if (m->hdrs[i].id == SIP_H_OTHER && m->hdrs[i].name.len == n &&
            sip_ieq2(m->hdrs[i].name.p, name, n))
            return &m->hdrs[i];
    return NULL;
}
