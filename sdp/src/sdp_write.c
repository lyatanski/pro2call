#include <limits.h>
#include <string.h>

#include "sdp.h"
#include "sdp_intl.h"

/* Everything lands directly in the caller's buffer; overflow is sticky
 * so a whole description can be written and checked once at sdp_end().
 * Line order is the caller's business — RFC 8866 §5 fixes it
 * (v= o= s= i= u= c= b= t= a=, then each m= with its own i= c= b= a=)
 * and a writer that reordered lines behind the caller's back would only
 * hide the mistake. */

static bool put(sdp_wbuf_t* w, const void* p, size_t n)
{
    if (SDP_UNLIKELY(w->overflow || n > w->cap - w->off)) {
        w->overflow = true;
        return false;
    }
    memcpy(w->buf + w->off, p, n);
    w->off += n;
    return true;
}

static bool put_u64(sdp_wbuf_t* w, uint64_t v)
{
    char  tmp[20];
    char* p = tmp + sizeof tmp;
    do {
        *--p = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    return put(w, p, (size_t)(tmp + sizeof tmp - p));
}

void sdp_wbuf_init(sdp_wbuf_t* w, char* buf, size_t cap)
{
    w->buf      = buf;
    w->cap      = cap > (size_t)INT_MAX ? (size_t)INT_MAX : cap;
    w->off      = 0;
    w->overflow = (buf == NULL);
}

/* A value slice must either be absent (NULL, 0) or present and
 * non-empty; a NULL with a length is a caller bug, not an empty line. */
static bool bad_slice(const char* p, size_t n)
{
    return p == NULL && n != 0;
}

static int done(sdp_wbuf_t* w)
{
    return w->overflow ? SDP_E_OVERFLOW : SDP_OK;
}

int sdp_put_version(sdp_wbuf_t* w)
{
    put(w, "v=0\r\n", 5);
    return done(w);
}

int sdp_put_origin(sdp_wbuf_t* w, const char* user, size_t ulen,
                   uint64_t sess_id, uint64_t sess_version,
                   const char* addrtype, size_t atlen, const char* addr,
                   size_t alen)
{
    if (SDP_UNLIKELY(bad_slice(user, ulen) || addrtype == NULL || atlen == 0 ||
                     addr == NULL || alen == 0))
        return SDP_E_INVAL;
    put(w, "o=", 2);
    if (ulen) put(w, user, ulen);
    else put(w, "-", 1);
    put(w, " ", 1);
    put_u64(w, sess_id);
    put(w, " ", 1);
    put_u64(w, sess_version);
    put(w, " IN ", 4);
    put(w, addrtype, atlen);
    put(w, " ", 1);
    put(w, addr, alen);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_name(sdp_wbuf_t* w, const char* name, size_t nlen)
{
    if (SDP_UNLIKELY(bad_slice(name, nlen))) return SDP_E_INVAL;
    put(w, "s=", 2);
    /* s= is mandatory and must not be empty (RFC 8866 §5.3), so an
     * endpoint with no session name sends the placeholder. */
    if (nlen) put(w, name, nlen);
    else put(w, "-", 1);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_conn(sdp_wbuf_t* w, const char* addrtype, size_t atlen,
                 const char* addr, size_t alen)
{
    if (SDP_UNLIKELY(addrtype == NULL || atlen == 0 || addr == NULL ||
                     alen == 0))
        return SDP_E_INVAL;
    put(w, "c=IN ", 5);
    put(w, addrtype, atlen);
    put(w, " ", 1);
    put(w, addr, alen);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_bw(sdp_wbuf_t* w, const char* bwtype, size_t btlen, uint64_t value)
{
    if (SDP_UNLIKELY(bwtype == NULL || btlen == 0)) return SDP_E_INVAL;
    put(w, "b=", 2);
    put(w, bwtype, btlen);
    put(w, ":", 1);
    put_u64(w, value);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_time(sdp_wbuf_t* w, uint64_t start, uint64_t stop)
{
    put(w, "t=", 2);
    put_u64(w, start);
    put(w, " ", 1);
    put_u64(w, stop);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_media_name(sdp_wbuf_t* w, const char* type, size_t tlen,
                       uint16_t port, uint16_t nports, const char* proto,
                       size_t plen, const char* fmts, size_t flen)
{
    if (SDP_UNLIKELY(type == NULL || tlen == 0 || proto == NULL || plen == 0 ||
                     bad_slice(fmts, flen)))
        return SDP_E_INVAL;
    put(w, "m=", 2);
    put(w, type, tlen);
    put(w, " ", 1);
    put_u64(w, port);
    if (nports > 1) {
        put(w, "/", 1);
        put_u64(w, nports);
    }
    put(w, " ", 1);
    put(w, proto, plen);
    /* A rejected stream (port 0) usually carries no format list at all,
     * so an empty one is written without the separator rather than
     * leaving a trailing space on the line. */
    if (flen) {
        put(w, " ", 1);
        put(w, fmts, flen);
    }
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_media(sdp_wbuf_t* w, sdp_mtype_t type, uint16_t port,
                  uint16_t nports, sdp_proto_t proto, const char* fmts,
                  size_t flen)
{
    const char* tname = sdp_mtype_name(type);
    const char* pname = sdp_proto_name(proto);
    if (SDP_UNLIKELY(tname[0] == '\0' || pname[0] == '\0')) return SDP_E_INVAL;
    return sdp_put_media_name(w, tname, strlen(tname), port, nports, pname,
                              strlen(pname), fmts, flen);
}

int sdp_put_attr_name(sdp_wbuf_t* w, const char* name, size_t nlen,
                      const char* val, size_t vlen)
{
    if (SDP_UNLIKELY(name == NULL || nlen == 0 || bad_slice(val, vlen)))
        return SDP_E_INVAL;
    put(w, "a=", 2);
    put(w, name, nlen);
    if (vlen) {
        put(w, ":", 1);
        put(w, val, vlen);
    }
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_put_attr(sdp_wbuf_t* w, sdp_attr_id_t id, const char* val, size_t vlen)
{
    const char* name = sdp_attr_name(id);
    if (SDP_UNLIKELY(name[0] == '\0')) return SDP_E_INVAL;
    return sdp_put_attr_name(w, name, strlen(name), val, vlen);
}

int sdp_put_line(sdp_wbuf_t* w, char type, const char* val, size_t vlen)
{
    /* One lowercase letter, as RFC 8866 §5 defines every line type; the
     * escape hatch is for types this module does not model (e=, k=, r=,
     * z=), not for inventing new syntax. */
    if (SDP_UNLIKELY(type < 'a' || type > 'z' || bad_slice(val, vlen)))
        return SDP_E_INVAL;
    char head[2] = { type, '=' };
    put(w, head, 2);
    if (vlen) put(w, val, vlen);
    put(w, "\r\n", 2);
    return done(w);
}

int sdp_end(sdp_wbuf_t* w)
{
    return w->overflow ? SDP_E_OVERFLOW : (int)w->off;
}
