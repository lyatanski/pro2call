#include <limits.h>
#include <string.h>

#include "sip.h"
#include "sip_intl.h"

/* Everything lands directly in the caller's buffer; overflow is sticky
 * so a whole message can be written and checked once at sip_put_body(). */

static bool put(sip_wbuf_t* w, const void* p, size_t n)
{
    if (SIP_UNLIKELY(w->overflow || n > w->cap - w->off)) {
        w->overflow = true;
        return false;
    }
    memcpy(w->buf + w->off, p, n);
    w->off += n;
    return true;
}

static bool put_u32(sip_wbuf_t* w, uint32_t v)
{
    char  tmp[10];
    char* p = tmp + sizeof tmp;
    do {
        *--p = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    return put(w, p, (size_t)(tmp + sizeof tmp - p));
}

void sip_wbuf_init(sip_wbuf_t* w, char* buf, size_t cap)
{
    w->buf      = buf;
    w->cap      = cap > (size_t)INT_MAX ? (size_t)INT_MAX : cap;
    w->off      = 0;
    w->overflow = (buf == NULL);
}

int sip_put_request(sip_wbuf_t* w, sip_method_t m, const char* uri,
                    size_t urilen)
{
    const char* name = sip_method_name(m);
    if (SIP_UNLIKELY(m == SIP_M_UNKNOWN || name[0] == '\0' || uri == NULL ||
                     urilen == 0))
        return SIP_E_INVAL;
    put(w, name, strlen(name));
    put(w, " ", 1);
    put(w, uri, urilen);
    put(w, " SIP/2.0\r\n", 10);
    return w->overflow ? SIP_E_OVERFLOW : SIP_OK;
}

int sip_put_status(sip_wbuf_t* w, unsigned status, const char* reason,
                   size_t rlen)
{
    if (SIP_UNLIKELY(status < 100 || status > 699)) return SIP_E_INVAL;
    if (reason == NULL) {
        reason = sip_status_phrase(status);
        rlen   = strlen(reason);
    }
    put(w, "SIP/2.0 ", 8);
    char code[3] = { (char)('0' + status / 100), (char)('0' + status / 10 % 10),
                     (char)('0' + status % 10) };
    put(w, code, 3);
    put(w, " ", 1);
    put(w, reason, rlen);
    put(w, "\r\n", 2);
    return w->overflow ? SIP_E_OVERFLOW : SIP_OK;
}

int sip_put_hdr_name(sip_wbuf_t* w, const char* name, size_t nlen,
                     const char* val, size_t vlen)
{
    if (SIP_UNLIKELY(name == NULL || nlen == 0 || (val == NULL && vlen != 0)))
        return SIP_E_INVAL;
    put(w, name, nlen);
    put(w, ": ", 2);
    put(w, val, vlen);
    put(w, "\r\n", 2);
    return w->overflow ? SIP_E_OVERFLOW : SIP_OK;
}

int sip_put_hdr(sip_wbuf_t* w, sip_hdr_t id, const char* val, size_t vlen)
{
    const char* name = sip_hdr_name(id);
    if (SIP_UNLIKELY(name[0] == '\0')) return SIP_E_INVAL;
    return sip_put_hdr_name(w, name, strlen(name), val, vlen);
}

int sip_put_hdr_u32(sip_wbuf_t* w, sip_hdr_t id, uint32_t v)
{
    const char* name = sip_hdr_name(id);
    if (SIP_UNLIKELY(name[0] == '\0')) return SIP_E_INVAL;
    put(w, name, strlen(name));
    put(w, ": ", 2);
    put_u32(w, v);
    put(w, "\r\n", 2);
    return w->overflow ? SIP_E_OVERFLOW : SIP_OK;
}

int sip_put_body(sip_wbuf_t* w, const void* body, size_t blen)
{
    if (SIP_UNLIKELY(body == NULL && blen != 0)) return SIP_E_INVAL;
    if (SIP_UNLIKELY(blen > UINT32_MAX)) return SIP_E_INVAL;
    put(w, "Content-Length: ", 16);
    put_u32(w, (uint32_t)blen);
    put(w, "\r\n\r\n", 4);
    if (blen) put(w, body, blen);
    return w->overflow ? SIP_E_OVERFLOW : (int)w->off;
}
