#include <float.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#include "json.h"
#include "json_intl.h"

/* Everything lands directly in the caller's buffer; the first failure is
 * kept and every later call is a no-op, so a whole document can be
 * written and checked once at json_end().
 *
 * The writer owns the punctuation. A caller says "object, this member
 * name, that value, close" and the commas, the ':' and — when asked for
 * — the newlines and indentation follow; a caller that closes the wrong
 * container or writes a member name where a value belongs is told so
 * (JSON_E_STATE) rather than handed a document its peer will reject. */

#define ST_OBJ  0x01 /* this level is an object, not an array */
#define ST_USED 0x02 /* it already holds a member/element     */

static bool put(json_wbuf_t* w, const void* p, size_t n)
{
    if (JSON_UNLIKELY(w->err != JSON_OK)) return false;
    if (JSON_UNLIKELY(n > w->cap - w->off)) {
        w->err = JSON_E_OVERFLOW;
        return false;
    }
    memcpy(w->buf + w->off, p, n);
    w->off += n;
    return true;
}

static int fail(json_wbuf_t* w, int err)
{
    if (w->err == JSON_OK) w->err = err;
    return w->err;
}

static int done(const json_wbuf_t* w)
{
    return w->err;
}

/* Newline plus one level's worth of indentation; nothing at all when the
 * writer is compact, which is what goes on a wire. */
static void nl(json_wbuf_t* w, unsigned depth)
{
    static const char k_sp[16] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                   ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
    if (w->indent == 0) return;
    put(w, "\n", 1);
    for (unsigned n = depth * w->indent; n > 0;) {
        unsigned k = n > sizeof k_sp ? (unsigned)sizeof k_sp : n;
        put(w, k_sp, k);
        n -= k;
    }
}

/* A member name is due: only inside an object, and only when the
 * previous member's value is in. */
static int pre_key(json_wbuf_t* w)
{
    if (JSON_UNLIKELY(w->err != JSON_OK)) return w->err;
    if (JSON_UNLIKELY(w->depth == 0 || !(w->stack[w->depth - 1] & ST_OBJ) ||
                      w->want_val))
        return fail(w, JSON_E_STATE);
    uint8_t* st = &w->stack[w->depth - 1];
    if (*st & ST_USED) put(w, ",", 1);
    *st |= ST_USED;
    nl(w, w->depth);
    return JSON_OK;
}

/* A value is due: once at the top level, after a member name in an
 * object, anywhere in an array. */
static int pre_val(json_wbuf_t* w)
{
    if (JSON_UNLIKELY(w->err != JSON_OK)) return w->err;
    if (w->depth == 0) {
        if (JSON_UNLIKELY(w->have_root)) return fail(w, JSON_E_STATE);
        w->have_root = true;
        return JSON_OK;
    }
    uint8_t* st = &w->stack[w->depth - 1];
    if (*st & ST_OBJ) {
        /* The name already wrote the separator this member needs. */
        if (JSON_UNLIKELY(!w->want_val)) return fail(w, JSON_E_STATE);
        w->want_val = false;
        return JSON_OK;
    }
    if (*st & ST_USED) put(w, ",", 1);
    *st |= ST_USED;
    nl(w, w->depth);
    return JSON_OK;
}

static void put_esc(json_wbuf_t* w, const char* s, size_t len)
{
    static const char k_hex[] = "0123456789abcdef";

    /* Runs of ordinary bytes are copied whole; only the seven characters
     * JSON names and the rest of the C0 block are rewritten. UTF-8 goes
     * out as it came in (RFC 8259 §7 leaves that to the encoding). */
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        const char*   rep;
        char          u[6];
        size_t        rlen = 2;

        switch (c) {
        case '"':  rep = "\\\""; break;
        case '\\': rep = "\\\\"; break;
        case '\b': rep = "\\b"; break;
        case '\f': rep = "\\f"; break;
        case '\n': rep = "\\n"; break;
        case '\r': rep = "\\r"; break;
        case '\t': rep = "\\t"; break;
        default:
            if (c >= 0x20) continue;
            u[0] = '\\';
            u[1] = 'u';
            u[2] = '0';
            u[3] = '0';
            u[4] = k_hex[c >> 4];
            u[5] = k_hex[c & 0x0F];
            rep  = u;
            rlen = 6;
            break;
        }
        if (i > start) put(w, s + start, i - start);
        put(w, rep, rlen);
        start = i + 1;
    }
    if (len > start) put(w, s + start, len - start);
}

static void put_quoted(json_wbuf_t* w, const char* s, size_t len)
{
    put(w, "\"", 1);
    if (len) put_esc(w, s, len);
    put(w, "\"", 1);
}

static void put_i64(json_wbuf_t* w, int64_t v)
{
    /* Negated in unsigned space, so INT64_MIN needs no special case. */
    uint64_t u = (v < 0) ? ~(uint64_t)v + 1 : (uint64_t)v;
    char     tmp[20];
    char*    p = tmp + sizeof tmp;
    do {
        *--p = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    if (v < 0) put(w, "-", 1);
    put(w, p, (size_t)(tmp + sizeof tmp - p));
}

/* snprintf("%g") writes the decimal separator of the current locale; the
 * one place this codec cannot avoid libc's float formatter is also the
 * one place it has to undo that. Returns the (possibly shortened)
 * length. */
static size_t fix_point(char* s, size_t n)
{
    const char* dp = localeconv()->decimal_point;
    if (dp == NULL || (dp[0] == '.' && dp[1] == '\0')) return n;

    size_t dlen = strlen(dp);
    if (dlen == 0) return n;
    for (size_t i = 0; i + dlen <= n; i++) {
        if (memcmp(s + i, dp, dlen) != 0) continue;
        s[i] = '.';
        if (dlen > 1) {
            memmove(s + i + 1, s + i + dlen, n - i - dlen);
            n -= dlen - 1;
        }
        break;
    }
    return n;
}

static int put_dbl(json_wbuf_t* w, double v)
{
    /* NaN and the infinities have no JSON form. Emitting the token libc
     * prints for them would produce a body the peer cannot parse at all,
     * which is a much worse failure than this one. */
    if (JSON_UNLIKELY(!(v >= -DBL_MAX && v <= DBL_MAX)))
        return fail(w, JSON_E_RANGE);

    /* An integral value goes out as an integer: a field a schema calls
     * an integer must not arrive as 1.0 because it passed through a
     * language whose numbers are all doubles. */
    if (v >= -9223372036854775808.0 && v < 9223372036854775808.0) {
        int64_t i = (int64_t)v;
        if ((double)i == v) {
            put_i64(w, i);
            return done(w);
        }
    }

    /* The shortest of %.15g/%.16g/%.17g that reads back as the same
     * double — 17 significant digits always do, the shorter forms
     * usually do, and the difference is what makes 0.1 print as "0.1". */
    for (int prec = 15; prec <= 17; prec++) {
        char tmp[48];
        int  n = snprintf(tmp, sizeof tmp, "%.*g", prec, v);
        if (JSON_UNLIKELY(n <= 0 || (size_t)n >= sizeof tmp))
            return fail(w, JSON_E_RANGE);
        size_t len = fix_point(tmp, (size_t)n);
        double back;
        if (prec == 17 || (json_dbl_parse(tmp, len, &back) && back == v)) {
            put(w, tmp, len);
            return done(w);
        }
    }
    return fail(w, JSON_E_RANGE); /* not reachable: %.17g round-trips */
}

void json_wbuf_init(json_wbuf_t* w, char* buf, size_t cap)
{
    w->buf       = buf;
    w->cap       = cap > (size_t)INT_MAX ? (size_t)INT_MAX : cap;
    w->off       = 0;
    w->err       = (buf == NULL) ? JSON_E_INVAL : JSON_OK;
    w->indent    = 0;
    w->depth     = 0;
    w->want_val  = false;
    w->have_root = false;
    memset(w->stack, 0, sizeof w->stack);
}

void json_wbuf_indent(json_wbuf_t* w, unsigned spaces)
{
    w->indent = (uint8_t)(spaces > 8 ? 8 : spaces);
}

static int open_container(json_wbuf_t* w, bool obj)
{
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    if (JSON_UNLIKELY(w->depth >= JSON_MAX_DEPTH)) return fail(w, JSON_E_DEPTH);
    put(w, obj ? "{" : "[", 1);
    w->stack[w->depth++] = obj ? ST_OBJ : 0;
    return done(w);
}

static int close_container(json_wbuf_t* w, bool obj)
{
    if (JSON_UNLIKELY(w->err != JSON_OK)) return w->err;
    if (JSON_UNLIKELY(w->depth == 0 || w->want_val))
        return fail(w, JSON_E_STATE);
    uint8_t st = w->stack[w->depth - 1];
    if (JSON_UNLIKELY(((st & ST_OBJ) != 0) != obj))
        return fail(w, JSON_E_STATE);

    w->depth--;
    /* An empty container stays on one line even when pretty-printing;
     * "{}" is what every formatter writes and what reads best. */
    if (st & ST_USED) nl(w, w->depth);
    put(w, obj ? "}" : "]", 1);
    return done(w);
}

int json_put_obj_begin(json_wbuf_t* w)
{
    return open_container(w, true);
}

int json_put_obj_end(json_wbuf_t* w)
{
    return close_container(w, true);
}

int json_put_arr_begin(json_wbuf_t* w)
{
    return open_container(w, false);
}

int json_put_arr_end(json_wbuf_t* w)
{
    return close_container(w, false);
}

int json_put_key(json_wbuf_t* w, const char* k, size_t klen)
{
    if (JSON_UNLIKELY(k == NULL && klen != 0)) return fail(w, JSON_E_INVAL);
    int rc = pre_key(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put_quoted(w, k, klen);
    put(w, ":", 1);
    if (w->indent) put(w, " ", 1);
    w->want_val = true;
    return done(w);
}

int json_put_str(json_wbuf_t* w, const char* s, size_t len)
{
    if (JSON_UNLIKELY(s == NULL && len != 0)) return fail(w, JSON_E_INVAL);
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put_quoted(w, s, len);
    return done(w);
}

int json_put_str_esc(json_wbuf_t* w, const char* s, size_t len)
{
    if (JSON_UNLIKELY(s == NULL && len != 0)) return fail(w, JSON_E_INVAL);
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put(w, "\"", 1);
    if (len) put(w, s, len);
    put(w, "\"", 1);
    return done(w);
}

int json_put_num(json_wbuf_t* w, double v)
{
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    return put_dbl(w, v);
}

int json_put_int(json_wbuf_t* w, int64_t v)
{
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put_i64(w, v);
    return done(w);
}

int json_put_bool(json_wbuf_t* w, bool v)
{
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put(w, v ? "true" : "false", v ? 4 : 5);
    return done(w);
}

int json_put_null(json_wbuf_t* w)
{
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put(w, "null", 4);
    return done(w);
}

int json_put_frag(json_wbuf_t* w, const char* s, size_t len)
{
    if (JSON_UNLIKELY(s == NULL || len == 0)) return fail(w, JSON_E_INVAL);
    int rc = pre_val(w);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    put(w, s, len);
    return done(w);
}

int json_put_field_str(json_wbuf_t* w, const char* k, size_t klen,
                       const char* s, size_t len)
{
    int rc = json_put_key(w, k, klen);
    return (rc != JSON_OK) ? rc : json_put_str(w, s, len);
}

int json_put_field_num(json_wbuf_t* w, const char* k, size_t klen, double v)
{
    int rc = json_put_key(w, k, klen);
    return (rc != JSON_OK) ? rc : json_put_num(w, v);
}

int json_put_field_int(json_wbuf_t* w, const char* k, size_t klen, int64_t v)
{
    int rc = json_put_key(w, k, klen);
    return (rc != JSON_OK) ? rc : json_put_int(w, v);
}

int json_put_field_bool(json_wbuf_t* w, const char* k, size_t klen, bool v)
{
    int rc = json_put_key(w, k, klen);
    return (rc != JSON_OK) ? rc : json_put_bool(w, v);
}

int json_put_field_null(json_wbuf_t* w, const char* k, size_t klen)
{
    int rc = json_put_key(w, k, klen);
    return (rc != JSON_OK) ? rc : json_put_null(w);
}

int json_end(json_wbuf_t* w)
{
    if (JSON_UNLIKELY(w->err != JSON_OK)) return w->err;
    /* An unclosed container or an empty document is not one JSON value,
     * and returning a length for it would hand out a truncated body. */
    if (JSON_UNLIKELY(w->depth != 0 || !w->have_root))
        return fail(w, JSON_E_STATE);
    return (int)w->off;
}
