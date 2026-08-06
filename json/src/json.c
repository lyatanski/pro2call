#include <float.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "json_intl.h"

/* ---- numbers ----
 *
 * Both directions avoid libc's locale: strtod() reads "1.5" as 1 in a
 * locale whose decimal separator is a comma, and a codec that changed
 * its reading of a wire format with the environment would be a very
 * quiet bug. The exponent form fed to strtod() below carries no
 * separator at all, so there is nothing left for a locale to reinterpret.
 *
 * Exact for every literal a double can hold exactly (a mantissa within
 * 2^53 and |exponent| <= 22 needs one correctly-rounded operation);
 * beyond that the first 19 significant digits are handed to strtod(),
 * which rounds them correctly, and digits past the 19th are dropped —
 * they are below the precision of the result. */

static const double k_p10[23] = { 1e0,  1e1,  1e2,  1e3,  1e4,  1e5,
                                  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                                  1e12, 1e13, 1e14, 1e15, 1e16, 1e17,
                                  1e18, 1e19, 1e20, 1e21, 1e22 };

bool json_dbl_parse(const char* s, size_t len, double* out)
{
    const char* p   = s;
    const char* end = s + len;
    if (JSON_UNLIKELY(p == NULL || len == 0)) return false;

    bool neg = false;
    if (*p == '-') {
        neg = true;
        p++;
    }

    /* Every digit of the integer and fraction parts becomes one
     * integer mantissa; exp10 keeps the scale it lost. */
    uint64_t mant  = 0;
    int      exp10 = 0;
    bool     frac = false, any = false;
    for (;;) {
        while (p < end && json_is_digit(*p)) {
            any = true;
            if (JSON_LIKELY(mant < (UINT64_MAX - 9) / 10)) {
                mant = mant * 10 + (uint64_t)(*p - '0');
                if (frac) exp10--;
            } else if (!frac) {
                exp10++; /* mantissa full: the digit only scales it */
            }
            p++;
        }
        if (!frac && p < end && *p == '.') {
            frac = true;
            p++;
            continue;
        }
        break;
    }
    if (JSON_UNLIKELY(!any)) return false;

    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        bool eneg = false;
        if (p < end && (*p == '+' || *p == '-')) {
            eneg = (*p == '-');
            p++;
        }
        if (JSON_UNLIKELY(p >= end || !json_is_digit(*p))) return false;
        int e = 0;
        while (p < end && json_is_digit(*p)) {
            /* Clamped: 1e100000 and 1e999999 are both "out of range",
             * and the clamp keeps the accumulation from overflowing. */
            if (e < 100000) e = e * 10 + (*p - '0');
            p++;
        }
        exp10 += eneg ? -e : e;
    }
    if (JSON_UNLIKELY(p != end)) return false;

    double v;
    if (mant == 0) {
        v = 0.0;
    } else if (exp10 >= -22 && exp10 <= 22 && mant <= (1ULL << 53)) {
        v = (double)mant;
        v = exp10 >= 0 ? v * k_p10[exp10] : v / k_p10[-exp10];
    } else {
        char tmp[48];
        int  n = snprintf(tmp, sizeof tmp, "%llue%d", (unsigned long long)mant,
                          exp10);
        if (JSON_UNLIKELY(n <= 0 || (size_t)n >= sizeof tmp)) return false;
        v = strtod(tmp, NULL);
    }
    *out = neg ? -v : v;
    return true;
}

/* An integer literal as an exact int64. False on a non-digit or on
 * anything outside the range — never a truncated value. */
static bool i64_parse(const char* p, size_t len, int64_t* out)
{
    size_t i   = 0;
    bool   neg = false;
    if (len && *p == '-') {
        neg = true;
        i   = 1;
    }
    if (JSON_UNLIKELY(i >= len || len - i > 19)) return false;

    uint64_t v = 0;
    for (; i < len; i++) {
        if (JSON_UNLIKELY(!json_is_digit(p[i]))) return false;
        v = v * 10 + (uint64_t)(p[i] - '0');
    }
    uint64_t lim = neg ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    if (JSON_UNLIKELY(v > lim)) return false;
    *out = neg ? (v == lim ? INT64_MIN : -(int64_t)v) : (int64_t)v;
    return true;
}

/* ---- parse ----
 *
 * Recursive descent, one node per value, bounded by JSON_MAX_DEPTH so
 * the recursion cannot outrun the stack whatever a peer sends. */

typedef struct {
    json_doc_t* d;
    const char* p;
    const char* end;
} pctx_t;

static void skip_ws(pctx_t* c)
{
    while (c->p < c->end && json_is_ws(*c->p))
        c->p++;
}

static int alloc_node(pctx_t* c, uint32_t* out)
{
    if (JSON_UNLIKELY(c->d->count >= c->d->cap)) return JSON_E_NODES;
    uint32_t     i = c->d->count++;
    json_node_t* n = &c->d->nodes[i];
    n->type        = JSON_T_NULL;
    n->flags       = 0;
    n->count       = 0;
    n->first       = 0;
    n->next        = 0;
    n->key         = (json_str_t){ NULL, 0 };
    n->raw         = (json_str_t){ NULL, 0 };
    *out           = i;
    return JSON_OK;
}

/* On entry *c->p is the opening quote. body is the span between the
 * quotes, escapes intact; *esc says whether it holds any. */
static int scan_str(pctx_t* c, json_str_t* body, bool* esc)
{
    const char* p     = c->p + 1;
    const char* start = p;
    *esc              = false;

    while (p < c->end) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '"') {
            *body = (json_str_t){ start, (uint32_t)(p - start) };
            c->p  = p + 1;
            return JSON_OK;
        }
        if (ch == '\\') {
            *esc = true;
            if (JSON_UNLIKELY(c->end - p < 2)) return JSON_E_SYNTAX;
            switch (p[1]) {
            case '"':
            case '\\':
            case '/':
            case 'b':
            case 'f':
            case 'n':
            case 'r':
            case 't':  p += 2; continue;
            case 'u':
                if (JSON_UNLIKELY(c->end - p < 6)) return JSON_E_SYNTAX;
                for (int i = 2; i < 6; i++)
                    if (JSON_UNLIKELY(json_hex(p[i]) < 0)) return JSON_E_SYNTAX;
                p += 6;
                continue;
            default: return JSON_E_SYNTAX;
            }
        }
        /* RFC 8259 §7: a control character must be escaped. Letting one
         * through would also mean a stored slice could not be echoed
         * back as JSON. */
        if (JSON_UNLIKELY(ch < 0x20)) return JSON_E_SYNTAX;
        p++;
    }
    return JSON_E_SYNTAX; /* unterminated */
}

/* -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)? — RFC 8259 §6 exactly,
 * so "+1", ".5", "1.", "01", "0x10", NaN and Infinity are all refused. */
static int scan_num(pctx_t* c, json_str_t* raw, bool* isint)
{
    const char* p     = c->p;
    const char* start = p;
    if (*p == '-') p++;
    if (JSON_UNLIKELY(p >= c->end || !json_is_digit(*p))) return JSON_E_SYNTAX;
    if (*p == '0') {
        p++;
    } else {
        while (p < c->end && json_is_digit(*p))
            p++;
    }

    *isint = true;
    if (p < c->end && *p == '.') {
        *isint = false;
        p++;
        if (JSON_UNLIKELY(p >= c->end || !json_is_digit(*p)))
            return JSON_E_SYNTAX;
        while (p < c->end && json_is_digit(*p))
            p++;
    }
    if (p < c->end && (*p == 'e' || *p == 'E')) {
        *isint = false;
        p++;
        if (p < c->end && (*p == '+' || *p == '-')) p++;
        if (JSON_UNLIKELY(p >= c->end || !json_is_digit(*p)))
            return JSON_E_SYNTAX;
        while (p < c->end && json_is_digit(*p))
            p++;
    }

    *raw = (json_str_t){ start, (uint32_t)(p - start) };
    c->p = p;
    return JSON_OK;
}

static int scan_lit(pctx_t* c, const char* lit, size_t n, json_str_t* raw)
{
    if (JSON_UNLIKELY((size_t)(c->end - c->p) < n || memcmp(c->p, lit, n) != 0))
        return JSON_E_SYNTAX;
    *raw = (json_str_t){ c->p, (uint32_t)n };
    c->p += n;
    return JSON_OK;
}

static int parse_value(pctx_t* c, unsigned depth, uint32_t* out);

/* An object or an array, from its opening bracket to its closing one.
 * Children are linked in wire order; the container's raw slice ends up
 * spanning the whole bracketed text, which is what makes a subtree
 * re-embeddable with json_put_frag(). */
static int parse_container(pctx_t* c, unsigned depth, uint32_t idx, bool obj)
{
    const char* start = c->p;
    const char  close = obj ? '}' : ']';
    c->p++;

    skip_ws(c);
    if (JSON_UNLIKELY(c->p >= c->end)) return JSON_E_SYNTAX;
    if (*c->p == close) {
        c->p++;
    } else {
        uint32_t prev = 0;
        for (;;) {
            json_str_t key  = { NULL, 0 };
            bool       kesc = false;
            if (obj) {
                skip_ws(c);
                if (JSON_UNLIKELY(c->p >= c->end || *c->p != '"'))
                    return JSON_E_SYNTAX;
                int rc = scan_str(c, &key, &kesc);
                if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
                skip_ws(c);
                if (JSON_UNLIKELY(c->p >= c->end || *c->p != ':'))
                    return JSON_E_SYNTAX;
                c->p++;
            }

            uint32_t child;
            int      rc = parse_value(c, depth + 1, &child);
            if (JSON_UNLIKELY(rc != JSON_OK)) return rc;

            json_node_t* cn = &c->d->nodes[child];
            cn->key         = key;
            if (kesc) cn->flags |= JSON_F_KESC;

            json_node_t* pn = &c->d->nodes[idx];
            if (prev) c->d->nodes[prev].next = child;
            else pn->first = child;
            prev = child;
            pn->count++;

            skip_ws(c);
            if (JSON_UNLIKELY(c->p >= c->end)) return JSON_E_SYNTAX;
            if (*c->p == ',') {
                c->p++;
                continue; /* a trailing comma fails as a missing value */
            }
            if (JSON_UNLIKELY(*c->p != close)) return JSON_E_SYNTAX;
            c->p++;
            break;
        }
    }

    json_node_t* n = &c->d->nodes[idx];
    n->type        = obj ? JSON_T_OBJ : JSON_T_ARR;
    n->raw         = (json_str_t){ start, (uint32_t)(c->p - start) };
    return JSON_OK;
}

static int parse_value(pctx_t* c, unsigned depth, uint32_t* out)
{
    if (JSON_UNLIKELY(depth >= JSON_MAX_DEPTH)) return JSON_E_DEPTH;
    skip_ws(c);
    if (JSON_UNLIKELY(c->p >= c->end)) return JSON_E_SYNTAX;

    int rc = alloc_node(c, out);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    json_node_t* n = &c->d->nodes[*out];

    switch (*c->p) {
    case '{': return parse_container(c, depth, *out, true);
    case '[': return parse_container(c, depth, *out, false);

    case '"': {
        bool esc;
        rc = scan_str(c, &n->raw, &esc);
        if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
        n->type = JSON_T_STR;
        if (esc) n->flags |= JSON_F_ESC;
        return JSON_OK;
    }

    case 't': n->type = JSON_T_BOOL; return scan_lit(c, "true", 4, &n->raw);
    case 'f': n->type = JSON_T_BOOL; return scan_lit(c, "false", 5, &n->raw);
    case 'n': n->type = JSON_T_NULL; return scan_lit(c, "null", 4, &n->raw);

    default: {
        bool isint;
        rc = scan_num(c, &n->raw, &isint);
        if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
        n->type = JSON_T_NUM;
        if (isint) n->flags |= JSON_F_INT;
        return JSON_OK;
    }
    }
}

void json_doc_init(json_doc_t* d, json_node_t* nodes, uint32_t cap)
{
    if (d == NULL) return;
    d->nodes   = nodes;
    d->cap     = (nodes == NULL) ? 0 : cap;
    d->count   = 0;
    d->buf     = NULL;
    d->len     = 0;
    d->err_off = 0;
}

uint32_t json_nodes_for(size_t len)
{
    size_t n = len / 2 + 2;
    return n > UINT32_MAX ? UINT32_MAX : (uint32_t)n;
}

int json_parse(json_doc_t* d, const char* buf, size_t len)
{
    if (JSON_UNLIKELY(d == NULL || d->nodes == NULL || d->cap == 0 ||
                      buf == NULL || len > (size_t)INT_MAX))
        return JSON_E_INVAL;

    d->count   = 0;
    d->buf     = buf;
    d->len     = len;
    d->err_off = 0;

    pctx_t c = { d, buf, buf + len };
    /* RFC 8259 §8.1 forbids a byte order mark, but encoders emit one and
     * the document behind it is perfectly readable. */
    if (len >= 3 && (unsigned char)buf[0] == 0xEF &&
        (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF)
        c.p += 3;

    uint32_t root;
    int      rc = parse_value(&c, 0, &root);
    if (JSON_UNLIKELY(rc == JSON_OK)) {
        skip_ws(&c);
        if (JSON_UNLIKELY(c.p != c.end)) rc = JSON_E_TRAILING;
    }
    if (JSON_UNLIKELY(rc != JSON_OK)) {
        /* Nothing half-parsed is left readable, but where the scan gave
         * up is kept: it is the difference between "not JSON" and a
         * pointer at the byte that is not. */
        d->count   = 0;
        d->err_off = (size_t)(c.p - buf);
        return rc;
    }
    return JSON_OK;
}

/* ---- navigation ---- */

const json_node_t* json_root(const json_doc_t* d)
{
    if (JSON_UNLIKELY(d == NULL || d->count == 0)) return NULL;
    return &d->nodes[0];
}

const json_node_t* json_first(const json_doc_t* d, const json_node_t* n)
{
    if (JSON_UNLIKELY(d == NULL || n == NULL || n->first == 0 ||
                      n->first >= d->count))
        return NULL;
    return &d->nodes[n->first];
}

const json_node_t* json_next(const json_doc_t* d, const json_node_t* n)
{
    if (JSON_UNLIKELY(d == NULL || n == NULL || n->next == 0 ||
                      n->next >= d->count))
        return NULL;
    return &d->nodes[n->next];
}

/* Children are linked, not contiguous — a nested value sits between two
 * siblings in the pool — so this walks. Iterating with json_first() and
 * json_next() is the linear way round a whole container. */
const json_node_t* json_at(const json_doc_t* d, const json_node_t* n,
                           uint32_t i)
{
    if (JSON_UNLIKELY(n == NULL || i >= n->count)) return NULL;
    const json_node_t* c = json_first(d, n);
    for (; c != NULL && i > 0; i--)
        c = json_next(d, c);
    return c;
}

const json_node_t* json_get(const json_doc_t* d, const json_node_t* n,
                            const char* key, size_t klen)
{
    if (JSON_UNLIKELY(n == NULL || n->type != JSON_T_OBJ || key == NULL))
        return NULL;
    for (const json_node_t* c = json_first(d, n); c; c = json_next(d, c))
        if (json_body_eq(c->key, (c->flags & JSON_F_KESC) != 0, key, klen))
            return c;
    return NULL;
}

/* One reference token of a JSON Pointer, matched against an object. The
 * token's own escapes ("~1" for '/', "~0" for '~') are RFC 6901's, and
 * unrelated to the JSON escapes the stored member name may carry. */
static const json_node_t* ptr_member(const json_doc_t*  d,
                                     const json_node_t* obj, const char* tok,
                                     size_t n)
{
    char        buf[256];
    const char* key  = tok;
    size_t      klen = n;

    if (n != 0 && memchr(tok, '~', n) != NULL) {
        if (JSON_UNLIKELY(n > sizeof buf)) return NULL;
        size_t o = 0;
        for (size_t i = 0; i < n; i++) {
            if (tok[i] != '~') {
                buf[o++] = tok[i];
                continue;
            }
            /* RFC 6901 §3: '~' appears only as "~0" or "~1". */
            if (JSON_UNLIKELY(i + 1 >= n)) return NULL;
            if (tok[i + 1] == '0') buf[o++] = '~';
            else if (tok[i + 1] == '1') buf[o++] = '/';
            else return NULL;
            i++;
        }
        key  = buf;
        klen = o;
    }
    return json_get(d, obj, key, klen);
}

/* RFC 6901 §4: an array index is "0" or a digit string with no leading
 * zero. "-" addresses the slot after the last element, which nothing can
 * be read from. */
static const json_node_t* ptr_element(const json_doc_t*  d,
                                      const json_node_t* arr, const char* tok,
                                      size_t n)
{
    if (JSON_UNLIKELY(n == 0 || n > 9)) return NULL;
    if (JSON_UNLIKELY(tok[0] == '0' && n > 1)) return NULL;
    uint32_t i = 0;
    for (size_t k = 0; k < n; k++) {
        if (JSON_UNLIKELY(!json_is_digit(tok[k]))) return NULL;
        i = i * 10 + (uint32_t)(tok[k] - '0');
    }
    return json_at(d, arr, i);
}

const json_node_t* json_ptr(const json_doc_t* d, const char* ptr, size_t len)
{
    const json_node_t* n = json_root(d);
    if (JSON_UNLIKELY(n == NULL)) return NULL;
    if (len == 0) return n;
    if (JSON_UNLIKELY(ptr == NULL || *ptr != '/')) return NULL;

    const char* p   = ptr + 1;
    const char* end = ptr + len;
    for (;;) {
        const char* slash = memchr(p, '/', (size_t)(end - p));
        size_t      tlen  = (size_t)((slash ? slash : end) - p);

        if (n->type == JSON_T_OBJ) n = ptr_member(d, n, p, tlen);
        else if (n->type == JSON_T_ARR) n = ptr_element(d, n, p, tlen);
        else return NULL; /* a scalar has nothing under it */
        if (n == NULL) return NULL;

        if (slash == NULL) return n;
        p = slash + 1; /* a trailing '/' names the member called "" */
    }
}

/* ---- typed reads ---- */

int json_bool(const json_node_t* n, bool* out)
{
    if (JSON_UNLIKELY(n == NULL || out == NULL)) return JSON_E_INVAL;
    if (JSON_UNLIKELY(n->type != JSON_T_BOOL)) return JSON_E_TYPE;
    *out = (n->raw.len == 4); /* "true" / "false" */
    return JSON_OK;
}

int json_num(const json_node_t* n, double* out)
{
    if (JSON_UNLIKELY(n == NULL || out == NULL)) return JSON_E_INVAL;
    if (JSON_UNLIKELY(n->type != JSON_T_NUM)) return JSON_E_TYPE;
    double v;
    if (JSON_UNLIKELY(!json_dbl_parse(n->raw.p, n->raw.len, &v)))
        return JSON_E_SYNTAX;
    /* 1e400 is well-formed JSON and not a double; saying so beats
     * handing back an infinity that nothing downstream can encode. */
    if (JSON_UNLIKELY(!(v >= -DBL_MAX && v <= DBL_MAX))) return JSON_E_RANGE;
    *out = v;
    return JSON_OK;
}

int json_i64(const json_node_t* n, int64_t* out)
{
    if (JSON_UNLIKELY(n == NULL || out == NULL)) return JSON_E_INVAL;
    if (JSON_UNLIKELY(n->type != JSON_T_NUM)) return JSON_E_TYPE;

    if (n->flags & JSON_F_INT) {
        if (JSON_UNLIKELY(!i64_parse(n->raw.p, n->raw.len, out)))
            return JSON_E_RANGE;
        return JSON_OK;
    }

    /* "1.0" and "1e3" are integers a peer chose to spell differently;
     * "1.5" is not one, and rounding it silently is how a subscriber id
     * turns into someone else's. */
    double v;
    int    rc = json_num(n, &v);
    if (JSON_UNLIKELY(rc != JSON_OK)) return rc;
    if (JSON_UNLIKELY(v < -9223372036854775808.0 || v >= 9223372036854775808.0))
        return JSON_E_RANGE;
    int64_t i = (int64_t)v;
    if (JSON_UNLIKELY((double)i != v)) return JSON_E_RANGE;
    *out = i;
    return JSON_OK;
}

int json_str(const json_node_t* n, char* out, size_t cap, size_t* olen)
{
    if (JSON_UNLIKELY(n == NULL || olen == NULL)) return JSON_E_INVAL;
    if (JSON_UNLIKELY(n->type != JSON_T_STR)) return JSON_E_TYPE;
    return json_body_expand(n->raw, (n->flags & JSON_F_ESC) != 0, out, cap,
                            olen);
}

int json_key(const json_node_t* n, char* out, size_t cap, size_t* olen)
{
    if (JSON_UNLIKELY(n == NULL || olen == NULL)) return JSON_E_INVAL;
    return json_body_expand(n->key, (n->flags & JSON_F_KESC) != 0, out, cap,
                            olen);
}

bool json_key_eq(const json_node_t* n, const char* key, size_t klen)
{
    if (JSON_UNLIKELY(n == NULL || key == NULL)) return false;
    return json_body_eq(n->key, (n->flags & JSON_F_KESC) != 0, key, klen);
}

bool json_str_eq(const json_node_t* n, const char* s, size_t len)
{
    if (JSON_UNLIKELY(n == NULL || s == NULL || n->type != JSON_T_STR))
        return false;
    return json_body_eq(n->raw, (n->flags & JSON_F_ESC) != 0, s, len);
}

const char* json_type_name(json_type_t t)
{
    static const char* const k_name[] = { "null",   "boolean", "number",
                                          "string", "array",   "object" };
    return ((unsigned)t < sizeof k_name / sizeof k_name[0]) ? k_name[t] : "";
}
