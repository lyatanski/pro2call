#include <string.h>

#include "sip.h"
#include "sip_intl.h"

/* All parsers here slice into the input; nothing is copied. */

static const char* find_any(const char* p, const char* end, const char* set)
{
    for (; p < end; p++)
        for (const char* s = set; *s; s++)
            if (*p == *s) return p;
    return end;
}

/* host[:port] where host may be an [IPv6] literal; *rest is advanced
 * past what was consumed. Stops at ';', '?' or whitespace. */
static int parse_hostport(const char** rest, const char* end, sip_str_t* host,
                          uint16_t* port)
{
    const char* p = *rest;
    const char* stop;

    if (p < end && *p == '[') {
        const char* close = memchr(p, ']', (size_t)(end - p));
        if (SIP_UNLIKELY(close == NULL)) return SIP_E_URI;
        host->p   = p + 1;
        host->len = (uint32_t)(close - p - 1);
        p         = close + 1;
    } else {
        stop      = find_any(p, end, ":;? \t");
        host->p   = p;
        host->len = (uint32_t)(stop - p);
        p         = stop;
    }
    if (SIP_UNLIKELY(host->len == 0)) return SIP_E_URI;

    *port = 0;
    if (p < end && *p == ':') {
        p++;
        stop = find_any(p, end, ";? \t");
        uint32_t v;
        if (SIP_UNLIKELY(!sip_parse_u32(p, (size_t)(stop - p), &v) || v == 0 ||
                         v > UINT16_MAX))
            return SIP_E_URI;
        *port = (uint16_t)v;
        p     = stop;
    }
    *rest = p;
    return SIP_OK;
}

/* Splits ";params?headers" (p already past the host part). */
static void parse_tail(const char* p, const char* end, sip_str_t* params,
                       sip_str_t* headers)
{
    *params  = (sip_str_t){ NULL, 0 };
    *headers = (sip_str_t){ NULL, 0 };

    const char* q    = memchr(p, '?', (size_t)(end - p));
    const char* pend = q ? q : end;
    if (p < pend && *p == ';') {
        params->p   = p + 1;
        params->len = (uint32_t)(pend - p - 1);
    }
    if (q) {
        headers->p   = q + 1;
        headers->len = (uint32_t)(end - q - 1);
    }
}

int sip_uri_parse(sip_uri_t* u, const char* buf, size_t len)
{
    if (SIP_UNLIKELY(u == NULL || buf == NULL)) return SIP_E_INVAL;

    const char* p   = buf;
    const char* end = buf + len;

    const char* colon = memchr(p, ':', len);
    if (SIP_UNLIKELY(colon == NULL || colon == p)) return SIP_E_URI;

    u->scheme_name.p   = p;
    u->scheme_name.len = (uint32_t)(colon - p);
    size_t sn          = (size_t)(colon - p);
    if (sn == 3 && sip_ieq(p, "sip", 3)) u->scheme = SIP_URI_SIP;
    else if (sn == 4 && sip_ieq(p, "sips", 4)) u->scheme = SIP_URI_SIPS;
    else if (sn == 3 && sip_ieq(p, "tel", 3)) u->scheme = SIP_URI_TEL;
    else u->scheme = SIP_URI_OTHER;

    p       = colon + 1;
    u->user = (sip_str_t){ NULL, 0 };
    u->host = (sip_str_t){ NULL, 0 };
    u->port = 0;

    if (u->scheme == SIP_URI_TEL) {
        /* tel:number;params — no authority part. */
        const char* stop = find_any(p, end, ";?");
        u->user.p        = p;
        u->user.len      = (uint32_t)(stop - p);
        if (SIP_UNLIKELY(u->user.len == 0)) return SIP_E_URI;
        parse_tail(stop, end, &u->params, &u->headers);
        return SIP_OK;
    }

    /* userinfo ends at the '@' before host — search only up to the
     * first ';' or '?', which always follow the authority. */
    const char* tail = find_any(p, end, ";?");
    const char* at   = NULL;
    for (const char* q = tail; q > p;) /* last '@' wins (RFC 3261) */
        if (*--q == '@') {
            at = q;
            break;
        }
    if (at) {
        u->user.p   = p;
        u->user.len = (uint32_t)(at - p);
        p           = at + 1;
    }

    int rc = parse_hostport(&p, end, &u->host, &u->port);
    if (SIP_UNLIKELY(rc != SIP_OK)) return rc;
    parse_tail(p, end, &u->params, &u->headers);
    return SIP_OK;
}

bool sip_param(sip_str_t params, const char* name, sip_str_t* out)
{
    size_t      n   = strlen(name);
    const char* p   = params.p;
    const char* end = params.p + params.len;

    while (p < end) {
        while (p < end && (*p == ';' || sip_is_ws(*p)))
            p++;
        const char* semi = memchr(p, ';', (size_t)(end - p));
        const char* pe   = semi ? semi : end;

        const char* eq = memchr(p, '=', (size_t)(pe - p));
        const char* ne = eq ? eq : pe;
        while (ne > p && sip_is_ws(ne[-1])) /* trim name */
            ne--;
        if ((size_t)(ne - p) == n && sip_ieq2(p, name, n)) {
            if (out) {
                if (eq) {
                    const char* v = eq + 1;
                    while (v < pe && sip_is_ws(*v))
                        v++;
                    const char* vend = pe;
                    while (vend > v && sip_is_ws(vend[-1]))
                        vend--;
                    out->p   = v;
                    out->len = (uint32_t)(vend - v);
                } else {
                    out->p   = pe;
                    out->len = 0;
                }
            }
            return true;
        }
        p = pe;
    }
    return false;
}

int sip_addr_parse(sip_str_t value, sip_addr_t* out)
{
    if (SIP_UNLIKELY(out == NULL || value.p == NULL)) return SIP_E_INVAL;
    if (SIP_UNLIKELY(value.len == 0)) return SIP_E_URI;

    const char* p   = value.p;
    const char* end = value.p + value.len;

    out->display = (sip_str_t){ NULL, 0 };
    out->uri     = (sip_str_t){ NULL, 0 };
    out->params  = (sip_str_t){ NULL, 0 };
    out->tag     = (sip_str_t){ NULL, 0 };

    while (p < end && sip_is_ws(*p))
        p++;

    const char* lt = NULL;
    if (p < end && *p == '"') {
        /* quoted display name; the '<' follows the closing quote */
        const char* q = p + 1;
        while (q < end && *q != '"') {
            if (*q == '\\' && q + 1 < end) q++;
            q++;
        }
        if (SIP_UNLIKELY(q >= end)) return SIP_E_URI;
        out->display.p   = p + 1;
        out->display.len = (uint32_t)(q - p - 1);
        lt               = memchr(q, '<', (size_t)(end - q));
        if (SIP_UNLIKELY(lt == NULL)) return SIP_E_URI;
    } else {
        lt = memchr(p, '<', (size_t)(end - p));
        if (lt) {
            const char* de = lt;
            while (de > p && sip_is_ws(de[-1]))
                de--;
            out->display.p   = p;
            out->display.len = (uint32_t)(de - p);
        }
    }

    if (lt) {
        const char* gt = memchr(lt, '>', (size_t)(end - lt));
        if (SIP_UNLIKELY(gt == NULL || gt == lt + 1)) return SIP_E_URI;
        out->uri.p    = lt + 1;
        out->uri.len  = (uint32_t)(gt - lt - 1);
        const char* q = gt + 1;
        while (q < end && sip_is_ws(*q))
            q++;
        if (q < end && *q == ';') {
            out->params.p   = q + 1;
            out->params.len = (uint32_t)(end - q - 1);
        }
    } else {
        /* bare URI: everything after the first ';' is header params */
        const char* semi = memchr(p, ';', (size_t)(end - p));
        const char* ue   = semi ? semi : end;
        while (ue > p && sip_is_ws(ue[-1]))
            ue--;
        if (SIP_UNLIKELY(ue == p)) return SIP_E_URI;
        out->uri.p   = p;
        out->uri.len = (uint32_t)(ue - p);
        if (semi) {
            out->params.p   = semi + 1;
            out->params.len = (uint32_t)(end - semi - 1);
        }
    }

    sip_param(out->params, "tag", &out->tag);
    return SIP_OK;
}

int sip_via_parse(sip_str_t value, sip_via_t* out)
{
    if (SIP_UNLIKELY(out == NULL || value.p == NULL)) return SIP_E_INVAL;

    const char* p   = value.p;
    const char* end = value.p + value.len;

    out->transport = (sip_str_t){ NULL, 0 };
    out->host      = (sip_str_t){ NULL, 0 };
    out->port      = 0;
    out->params    = (sip_str_t){ NULL, 0 };
    out->branch    = (sip_str_t){ NULL, 0 };

    if (SIP_UNLIKELY(end - p < 8 || !sip_ieq(p, "sip/2.0/", 8)))
        return SIP_E_HEADER;
    p += 8;

    const char* te = find_any(p, end, " \t");
    if (SIP_UNLIKELY(te == p || te == end)) return SIP_E_HEADER;
    out->transport.p   = p;
    out->transport.len = (uint32_t)(te - p);

    p = te;
    while (p < end && sip_is_ws(*p))
        p++;

    int rc = parse_hostport(&p, end, &out->host, &out->port);
    if (SIP_UNLIKELY(rc != SIP_OK)) return SIP_E_HEADER;

    while (p < end && sip_is_ws(*p))
        p++;
    if (p < end && *p == ';') {
        out->params.p   = p + 1;
        out->params.len = (uint32_t)(end - p - 1);
    }
    sip_param(out->params, "branch", &out->branch);
    return SIP_OK;
}

int sip_cseq_parse(sip_str_t value, sip_cseq_t* out)
{
    if (SIP_UNLIKELY(out == NULL || value.p == NULL)) return SIP_E_INVAL;

    const char* p   = value.p;
    const char* end = value.p + value.len;

    const char* sp = find_any(p, end, " \t");
    if (SIP_UNLIKELY(sp == end)) return SIP_E_HEADER;
    if (SIP_UNLIKELY(!sip_parse_u32(p, (size_t)(sp - p), &out->seq)))
        return SIP_E_HEADER;

    while (sp < end && sip_is_ws(*sp))
        sp++;
    if (SIP_UNLIKELY(sp == end)) return SIP_E_HEADER;

    out->method_name.p   = sp;
    out->method_name.len = (uint32_t)(end - sp);
    out->method          = (uint8_t)sip_method_from(sp, (size_t)(end - sp));
    return SIP_OK;
}
