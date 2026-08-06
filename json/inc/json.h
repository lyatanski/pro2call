#ifndef JSON_H
#define JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* JSON codec — RFC 8259 (JSON) and RFC 6901 (JSON Pointer).
 *
 * The text counterpart to the binary codecs beside it: 5G SBI carries
 * every service operation as JSON over HTTP/2 (TS 29.500 §5.2), a PATCH
 * body is a JSON Patch whose member paths are JSON Pointers (RFC 6902),
 * and the tools driving these stacks read their configuration and write
 * their results in the same format.
 *
 * Decode is zero-copy and single-pass: json_parse() fills a node pool
 * the caller owns, and every string in it is a json_str_t slice
 * (pointer + length) into the caller's buffer. Nothing is allocated and
 * nothing is copied; the buffer must stay valid while the document (or
 * any slice taken from it) is in use. A string keeps the backslash
 * escapes it arrived with — json_str() expands them, on demand, into a
 * buffer the caller sizes (raw.len bytes is always enough, escapes only
 * ever shrink).
 *
 * The pool is the caller's because JSON payload sizes vary by orders of
 * magnitude — a 5-member SBI problem-details object and a paged
 * subscription list do not want the same fixed bound, which is why this
 * module takes an array rather than embedding one the way sdp_msg_t
 * does. json_nodes_for() gives the worst case for a text of some length;
 * a pool that turns out too small fails with JSON_E_NODES and nothing
 * else, so growing and re-parsing is a valid strategy.
 *
 * Nodes are a flat array in document order, linked parent to child
 * (first) and sibling to sibling (next), so iteration is a pointer walk
 * and no lookup allocates. Index 0 is always the root, which is why 0
 * doubles as the "no such node" link.
 *
 * Parsing is strict where the RFC is strict: no trailing commas, no
 * comments, no unquoted keys, no single quotes, no NaN/Infinity, no
 * leading '+' or '.5', no control character inside a string. A UTF-8
 * BOM is skipped (encoders emit one and it is not the sender's fault
 * the RFC forbids it), duplicate member names are kept in order with
 * json_get() returning the first, and byte sequences that are not valid
 * UTF-8 pass through untouched — json_utf8_valid() is there for a
 * caller that must know.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Overflow is sticky: once any write exceeds capacity every subsequent
 * call fails, so return codes can be chained and checked once at
 * json_end() (mirrors sdp_wbuf_t in sdp/inc/sdp.h). The writer tracks
 * the container stack, so commas, the ':' after a member name and the
 * indentation of a pretty-printed document are its business, not the
 * caller's — hand-written JSON gets exactly those wrong.
 */

/* Borrowed view into a buffer owned by someone else. Never
 * NUL-terminated; print with printf("%.*s", JSON_STR_ARG(s)). */
typedef struct {
    const char* p;
    uint32_t    len;
} json_str_t;

#define JSON_STR_ARG(s) (int)(s).len, (s).p

/* Nesting bound, for both directions. Deeper input is refused rather
 * than recursed into (JSON_E_DEPTH); RFC 8259 §9 explicitly allows a
 * limit and 5G SBI schemas nest a handful of levels. */
#ifndef JSON_MAX_DEPTH
#define JSON_MAX_DEPTH 32
#endif

typedef enum {
    JSON_OK         = 0,
    JSON_E_SYNTAX   = -1, /* not JSON: bad token, structure, escape    */
    JSON_E_NODES    = -2, /* node pool too small                       */
    JSON_E_DEPTH    = -3, /* nesting past JSON_MAX_DEPTH               */
    JSON_E_TRAILING = -4, /* a second value follows the first          */
    JSON_E_TYPE     = -5, /* node is not of the type asked for         */
    JSON_E_MISSING  = -6, /* no such member, element or pointer target */
    JSON_E_RANGE    = -7, /* number outside the target type            */
    JSON_E_OVERFLOW = -8, /* write buffer too small                    */
    JSON_E_STATE    = -9, /* writer misuse: key outside an object, a
                           * mismatched close, a second root value     */
    JSON_E_INVAL = -10    /* invalid argument                          */
} json_err_t;

typedef enum {
    JSON_T_NULL = 0,
    JSON_T_BOOL = 1,
    JSON_T_NUM  = 2,
    JSON_T_STR  = 3,
    JSON_T_ARR  = 4,
    JSON_T_OBJ  = 5
} json_type_t;

/* node.flags */
#define JSON_F_ESC  0x01 /* the value slice carries a backslash escape */
#define JSON_F_KESC 0x02 /* the key slice carries one                  */
#define JSON_F_INT  0x04 /* number written as an integer: no '.', no e */

/* One value. Slices point into the parsed buffer, so a node is only as
 * valid as the text it came from.
 *
 * raw is the value exactly as it appeared: a string without its quotes
 * and still escaped, a number's literal digits, "true"/"false"/"null",
 * or — for an array or an object — the whole bracketed span, which is
 * what json_put_frag() re-embeds without a re-encode. */
typedef struct {
    uint8_t    type;  /* json_type_t                                    */
    uint8_t    flags; /* JSON_F_*                                       */
    uint32_t   count; /* JSON_T_ARR/JSON_T_OBJ: children; else 0        */
    uint32_t   first; /* first child; 0 when there is none              */
    uint32_t   next;  /* next sibling; 0 on the last child              */
    json_str_t key;   /* member name, quotes off; empty unless the
                       * parent is an object                            */
    json_str_t raw;
} json_node_t;

/* A parsed document: the caller's node pool plus the text the slices
 * point into. Copying one is fine (it owns nothing); outliving either
 * the pool or the text is not. */
typedef struct {
    json_node_t* nodes;
    uint32_t     cap;
    uint32_t     count; /* nodes used; 0 before a successful parse */
    const char*  buf;
    size_t       len;
    /* Where the parse stopped when it failed — the offset to quote in a
     * log line, since "not JSON" about a 4 KiB body says nothing. 0 on
     * success. */
    size_t err_off;
} json_doc_t;

/* ---- Parse (zero-copy decode) ---- */

API_EXPORT void json_doc_init(json_doc_t* d, json_node_t* nodes, uint32_t cap);

/* Nodes a text of this length can possibly need — one per value, and
 * the densest JSON spends two bytes per value ("[0,0,0]"). Exact enough
 * to size a pool once and never see JSON_E_NODES; for anything but tiny
 * payloads a fraction of it plus a retry is the cheaper trade. */
API_EXPORT uint32_t json_nodes_for(size_t len);

/* Parse one JSON value (an SBI body, a config file, a metrics blob)
 * into d's pool. Returns JSON_OK or a negative json_err_t; d->count is
 * the number of nodes used. The text must stay valid while the document
 * is in use. */
API_EXPORT int json_parse(json_doc_t* d, const char* buf, size_t len);

/* ---- Navigation ----
 *
 * Every one of these returns NULL rather than an error code: a lookup
 * that finds nothing is the normal case for an optional member, and
 * NULL chains (json_get(d, json_get(d, root, ...), ...) is safe). */

API_EXPORT const json_node_t* json_root(const json_doc_t* d);

/* First child / next sibling. Walking an object visits its members in
 * wire order, each with its key set. */
API_EXPORT const json_node_t* json_first(const json_doc_t*  d,
                                         const json_node_t* n);
API_EXPORT const json_node_t* json_next(const json_doc_t*  d,
                                        const json_node_t* n);

/* i-th element of an array (or i-th member of an object), 0-based. */
API_EXPORT const json_node_t* json_at(const json_doc_t* d, const json_node_t* n,
                                      uint32_t i);

/* Member of an object by name. key is plain UTF-8 bytes as the caller
 * spells them; a stored name that arrived escaped is unescaped for the
 * comparison, so json_get(d, o, "a/b", 3) finds "a\/b". The first of
 * two members with the same name wins. */
API_EXPORT const json_node_t* json_get(const json_doc_t*  d,
                                       const json_node_t* n, const char* key,
                                       size_t klen);

/* RFC 6901 JSON Pointer, resolved from the root: "" is the root itself,
 * "/a/0/b" walks a member, an element and a member. "~1" is '/' and
 * "~0" is '~', as the RFC requires. A pointer that is malformed (no
 * leading '/', a non-numeric array index) finds nothing, the same as
 * one that points at an absent member — has-it-or-not is the only
 * question a caller can act on. */
API_EXPORT const json_node_t* json_ptr(const json_doc_t* d, const char* ptr,
                                       size_t len);

/* ---- Typed reads ----
 *
 * Each returns JSON_OK, JSON_E_TYPE for the wrong node type (or NULL),
 * or JSON_E_RANGE when the value does not fit. */

API_EXPORT int json_bool(const json_node_t* n, bool* out);

/* Any JSON number as a double. Locale-independent: the conversion is
 * this module's, not strtod()'s reading of a decimal separator. */
API_EXPORT int json_num(const json_node_t* n, double* out);

/* A number as an exact 64-bit integer. An integer literal is exact
 * whatever its width (a 19-digit charging counter survives); a literal
 * with a fraction or an exponent is accepted only when its value is
 * integral and in range ("1e3" is 1000, "1.5" is JSON_E_RANGE), so a
 * caller reading a subscriber id can never silently get a rounded one. */
API_EXPORT int json_i64(const json_node_t* n, int64_t* out);

/* String value with its escapes expanded, written into out (never
 * NUL-terminated; *olen is the length). cap >= n->raw.len is always
 * enough. \uXXXX becomes UTF-8, a surrogate pair becomes the one
 * character it encodes, and an unpaired surrogate becomes U+FFFD
 * rather than failing the whole read. */
API_EXPORT int json_str(const json_node_t* n, char* out, size_t cap,
                        size_t* olen);

/* The member name, same expansion and the same sizing rule. */
API_EXPORT int json_key(const json_node_t* n, char* out, size_t cap,
                        size_t* olen);

/* Does this node's member name equal these plain UTF-8 bytes? */
API_EXPORT bool json_key_eq(const json_node_t* n, const char* key, size_t klen);

/* Does this string node's value equal these plain UTF-8 bytes? False
 * for any other node type, so it is safe on a lookup that missed. */
API_EXPORT bool json_str_eq(const json_node_t* n, const char* s, size_t len);

/* ---- Names and helpers ---- */

/* "null", "boolean", "number", "string", "array", "object"; "" when the
 * type is out of range. */
API_EXPORT const char* json_type_name(json_type_t t);

/* Is this byte string well-formed UTF-8? The codec passes bytes
 * through untouched in both directions (RFC 8259 §8.1 makes UTF-8 the
 * encoding, but a peer's malformed byte is not a reason to refuse an
 * otherwise readable document); a caller that must not emit invalid
 * UTF-8 checks here first. */
API_EXPORT bool json_utf8_valid(const char* s, size_t len);

/* ---- Write (encode into caller's buffer) ---- */

/* Write buffer. off is the running length; err holds the first failure
 * and is sticky, so a whole document can be written and checked once at
 * json_end() — both for a buffer that ran out (JSON_E_OVERFLOW) and for
 * a misuse that would have produced malformed JSON (JSON_E_STATE).
 *
 * The container stack is what makes commas, the ':' separator and the
 * indentation the writer's business rather than the caller's — and what
 * makes a mismatched close or a member name outside an object a reported
 * error instead of output no parser accepts. */
typedef struct {
    char*   buf;
    size_t  cap;
    size_t  off;
    int     err;                   /* JSON_OK until something fails   */
    uint8_t indent;                /* spaces per level; 0 = compact   */
    uint8_t depth;                 /* open containers                 */
    bool    want_val;              /* a member name awaits its value  */
    bool    have_root;             /* the one top-level value is in   */
    uint8_t stack[JSON_MAX_DEPTH]; /* per level: kind + "not empty"   */
} json_wbuf_t;

API_EXPORT void json_wbuf_init(json_wbuf_t* w, char* buf, size_t cap);

/* Pretty-print with this many spaces per level (0 = compact, the
 * default, which is what goes on a wire). Set before writing. */
API_EXPORT void json_wbuf_indent(json_wbuf_t* w, unsigned spaces);

/* Every put returns JSON_OK or a negative json_err_t; after an overflow
 * all further puts return JSON_E_OVERFLOW. Values may only appear where
 * JSON allows one: once at the top level, after a member name inside an
 * object, anywhere inside an array. */
API_EXPORT int json_put_obj_begin(json_wbuf_t* w);
API_EXPORT int json_put_obj_end(json_wbuf_t* w);
API_EXPORT int json_put_arr_begin(json_wbuf_t* w);
API_EXPORT int json_put_arr_end(json_wbuf_t* w);

/* Member name; only inside an object, and only where a name is due. */
API_EXPORT int json_put_key(json_wbuf_t* w, const char* k, size_t klen);

/* String value, escaped as it is written ('"', '\', and everything
 * below 0x20); UTF-8 passes through. */
API_EXPORT int json_put_str(json_wbuf_t* w, const char* s, size_t len);

/* String value whose body is escaped already — a json_node_t raw slice
 * of a string, copied straight back out with its quotes. */
API_EXPORT int json_put_str_esc(json_wbuf_t* w, const char* s, size_t len);

/* Numbers. An integral double is written as an integer, so 1.0 is "1"
 * and a peer expecting an integer field gets one. NaN and both
 * infinities have no JSON representation and are JSON_E_RANGE rather
 * than a token no parser accepts. */
API_EXPORT int json_put_num(json_wbuf_t* w, double v);
API_EXPORT int json_put_int(json_wbuf_t* w, int64_t v);
API_EXPORT int json_put_bool(json_wbuf_t* w, bool v);
API_EXPORT int json_put_null(json_wbuf_t* w);

/* A pre-encoded value: a subtree's raw slice from a parsed document, or
 * a fragment some other layer produced. Copied verbatim — it is the
 * caller's word that it is one well-formed JSON value. */
API_EXPORT int json_put_frag(json_wbuf_t* w, const char* s, size_t len);

/* Member name plus value, the shape most call sites want. */
API_EXPORT int json_put_field_str(json_wbuf_t* w, const char* k, size_t klen,
                                  const char* s, size_t len);
API_EXPORT int json_put_field_num(json_wbuf_t* w, const char* k, size_t klen,
                                  double v);
API_EXPORT int json_put_field_int(json_wbuf_t* w, const char* k, size_t klen,
                                  int64_t v);
API_EXPORT int json_put_field_bool(json_wbuf_t* w, const char* k, size_t klen,
                                   bool v);
API_EXPORT int json_put_field_null(json_wbuf_t* w, const char* k, size_t klen);

/* Finish: the total document length, or a negative json_err_t —
 * JSON_E_OVERFLOW when it did not fit, JSON_E_STATE when a container is
 * still open or nothing was written at all. */
API_EXPORT int json_end(json_wbuf_t* w);

#ifdef __cplusplus
}
#endif

#endif /* JSON_H */
