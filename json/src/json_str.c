#include <string.h>

#include "json.h"
#include "json_intl.h"

/* Strings — the escape layer both directions share.
 *
 * A parsed string keeps the bytes it arrived with, so nothing is copied
 * or rewritten until a caller asks for the value. That makes the common
 * case (route on one member, hand the rest through) free, and it makes
 * the comparison helpers below the interesting path: json_get() matching
 * a member name never allocates, whether or not the name on the wire was
 * escaped. */

/* One code point as UTF-8; 4 bytes is the maximum RFC 3629 allows. */
static int utf8_enc(uint32_t cp, char out[4])
{
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* The four hex digits of a \uXXXX escape, or -1. */
static int hex4(const char* p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int h = json_hex(p[i]);
        if (JSON_UNLIKELY(h < 0)) return -1;
        v = (v << 4) | h;
    }
    return v;
}

int json_next_chr(const char** p, const char* end, char out[4])
{
    const char* s = *p;
    if (JSON_UNLIKELY(s >= end)) return -1;
    if (JSON_LIKELY(*s != '\\')) {
        out[0] = *s;
        *p     = s + 1;
        return 1;
    }
    if (JSON_UNLIKELY(end - s < 2)) return -1;

    char c = s[1];
    *p     = s + 2;
    switch (c) {
    case '"':
    case '\\':
    case '/':  out[0] = c; return 1;
    case 'b':  out[0] = '\b'; return 1;
    case 'f':  out[0] = '\f'; return 1;
    case 'n':  out[0] = '\n'; return 1;
    case 'r':  out[0] = '\r'; return 1;
    case 't':  out[0] = '\t'; return 1;
    case 'u':  break;
    default:   return -1;
    }

    if (JSON_UNLIKELY(end - s < 6)) return -1;
    int h = hex4(s + 2);
    if (JSON_UNLIKELY(h < 0)) return -1;
    uint32_t cp = (uint32_t)h;
    s += 6;

    /* RFC 8259 §7: a character outside the BMP is escaped as a UTF-16
     * surrogate pair. The pair is one character, so it is decoded as
     * one; a surrogate standing alone is not a character at all and
     * becomes U+FFFD rather than a half-encoded byte sequence or a
     * failed read of an otherwise fine document. */
    if (cp >= 0xD800 && cp <= 0xDBFF) {
        int lo =
            (end - s >= 6 && s[0] == '\\' && s[1] == 'u') ? hex4(s + 2) : -1;
        if (lo >= 0xDC00 && lo <= 0xDFFF) {
            cp = 0x10000u + ((cp - 0xD800u) << 10) + ((uint32_t)lo - 0xDC00u);
            s += 6;
        } else {
            cp = 0xFFFD;
        }
    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
        cp = 0xFFFD;
    }

    *p = s;
    return utf8_enc(cp, out);
}

bool json_body_eq(json_str_t body, bool esc, const char* s, size_t len)
{
    if (!esc)
        return body.len == len && (len == 0 || memcmp(body.p, s, len) == 0);

    /* An escaped body is never shorter than what it expands to, so a
     * shorter body cannot match; the walk below is the exact check. */
    if (body.len < len) return false;

    const char* p   = body.p;
    const char* end = body.p + body.len;
    size_t      i   = 0;
    while (p < end) {
        char chr[4];
        int  n = json_next_chr(&p, end, chr);
        if (JSON_UNLIKELY(n <= 0)) return false;
        if (i + (size_t)n > len || memcmp(s + i, chr, (size_t)n) != 0)
            return false;
        i += (size_t)n;
    }
    return i == len;
}

int json_body_expand(json_str_t body, bool esc, char* out, size_t cap,
                     size_t* olen)
{
    if (JSON_UNLIKELY(out == NULL && cap != 0)) return JSON_E_INVAL;

    if (!esc) {
        if (JSON_UNLIKELY(body.len > cap)) return JSON_E_OVERFLOW;
        if (body.len) memcpy(out, body.p, body.len);
        *olen = body.len;
        return JSON_OK;
    }

    const char* p   = body.p;
    const char* end = body.p + body.len;
    size_t      o   = 0;
    while (p < end) {
        char chr[4];
        int  n = json_next_chr(&p, end, chr);
        if (JSON_UNLIKELY(n <= 0)) return JSON_E_SYNTAX;
        if (JSON_UNLIKELY(o + (size_t)n > cap)) return JSON_E_OVERFLOW;
        memcpy(out + o, chr, (size_t)n);
        o += (size_t)n;
    }
    *olen = o;
    return JSON_OK;
}

bool json_utf8_valid(const char* s, size_t len)
{
    if (s == NULL) return len == 0;
    const unsigned char* p   = (const unsigned char*)s;
    const unsigned char* end = p + len;
    while (p < end) {
        unsigned c = *p++;
        if (c < 0x80) continue;

        /* Length, plus the range the leading byte's own bits must be in
         * for the encoding to be the shortest one (RFC 3629 §4 bans the
         * overlong forms, and D800..DFFF is not a character). */
        unsigned n, cp, min;
        if (c >= 0xC2 && c <= 0xDF) {
            n   = 1;
            cp  = c & 0x1Fu;
            min = 0x80;
        } else if (c >= 0xE0 && c <= 0xEF) {
            n   = 2;
            cp  = c & 0x0Fu;
            min = 0x800;
        } else if (c >= 0xF0 && c <= 0xF4) {
            n   = 3;
            cp  = c & 0x07u;
            min = 0x10000;
        } else {
            return false; /* continuation byte, or C0/C1/F5..FF */
        }

        if ((size_t)(end - p) < n) return false;
        for (unsigned i = 0; i < n; i++) {
            if ((*p & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (unsigned)(*p++ & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;
    }
    return true;
}
