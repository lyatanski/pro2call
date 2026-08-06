#ifndef JSON_INTL_H
#define JSON_INTL_H

/* Private helpers shared by the json sources. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"

#if defined(__GNUC__) || defined(__clang__)
#define JSON_LIKELY(x)   __builtin_expect(!!(x), 1)
#define JSON_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define JSON_LIKELY(x)   (x)
#define JSON_UNLIKELY(x) (x)
#endif

/* RFC 8259 §2: these four bytes, and only these, are whitespace
 * between tokens. */
static inline bool json_is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static inline bool json_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Value of a hex digit, or -1. */
static inline int json_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ---- json_str.c ---- */

/* Decode the next character of a JSON string body (the bytes between
 * the quotes, escapes intact) into out, which needs 4 bytes. *p is
 * advanced past whatever was consumed. Returns the number of bytes
 * written, or -1 when an escape is malformed — which a parsed node
 * never carries, the parser having validated every escape it stored.
 *
 * An escaped surrogate pair collapses into the one character it
 * encodes; a surrogate with no partner becomes U+FFFD, because one bad
 * character is not a reason to fail a whole read. */
int json_next_chr(const char** p, const char* end, char out[4]);

/* Compare a JSON string body against plain UTF-8 bytes, expanding the
 * body's escapes as it goes. esc false takes the memcmp path. */
bool json_body_eq(json_str_t body, bool esc, const char* s, size_t len);

/* Expand a JSON string body into out. Returns JSON_OK (with *olen set)
 * or JSON_E_OVERFLOW; cap >= body.len always suffices. */
int json_body_expand(json_str_t body, bool esc, char* out, size_t cap,
                     size_t* olen);

/* ---- json.c ---- */

/* A JSON number literal as a double, without libc's locale-dependent
 * decimal separator. len is the whole literal ("-1.5e-3"); the literal
 * is assumed well-formed (the parser checked it). */
bool json_dbl_parse(const char* p, size_t len, double* out);

#endif /* JSON_INTL_H */
