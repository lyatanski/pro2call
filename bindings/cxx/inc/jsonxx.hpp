#ifndef JSONXX_HPP
#define JSONXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "json.h"

/* jsonxx — C++ facade over the C JSON codec (json/inc/json.h), written
 * to be wrapped by SWIG (bindings/swig/json.i) and driven from a
 * scripting language. Same rules as the other facades:
 *
 *   - value types: a Doc owns the text it parsed and every string it
 *     hands out is a copy, so nothing borrows from a wire buffer;
 *   - errors are exceptions (json::Error), never return codes;
 *   - the C layer's numeric ids stay numeric (json.T_OBJ, not "object").
 *
 * Two shapes, because JSON is read two ways:
 *
 *   - Doc addresses values by JSON Pointer (RFC 6901) and materializes
 *     only what is asked for — the right way round when a body has forty
 *     members and a caller wants three, which is most of 5G SBI;
 *   - Builder writes one document with the punctuation handled for it.
 *
 * The third way — a whole document as a native table — is the scripting
 * language's own, not C++'s, and lives in the SWIG layer (json.decode /
 * json.encode in Lua) where it can build the language's values directly
 * instead of going through an intermediate tree.
 *
 * A pointer that resolves to nothing is not an error: type() answers
 * T_NONE, has() answers false and the *_or() readers answer with the
 * caller's default. An optional member is the normal case in every JSON
 * schema, and a facade that threw for one would put a pcall around every
 * read. Asking for the wrong type (num() on a string) does throw — that
 * is a bug in the caller, not a property of the document.
 */

namespace json
{

/* Every failure surfaces as one of these; code() keeps the JSON_E_*
 * value that caused it. */
class Error : public std::runtime_error
{
  public:
    explicit Error(const std::string& what, int code = 0)
        : std::runtime_error(what), code_(code)
    {
    }
    int code() const
    {
        return code_;
    }

  private:
    int code_;
};

/* Value types, mirrored from json.h, plus T_NONE for a pointer that
 * resolves to nothing — which is a different thing from a member whose
 * value is null (T_NULL). */
enum Type {
    T_NONE = -1,
    T_NULL = JSON_T_NULL,
    T_BOOL = JSON_T_BOOL,
    T_NUM  = JSON_T_NUM,
    T_STR  = JSON_T_STR,
    T_ARR  = JSON_T_ARR,
    T_OBJ  = JSON_T_OBJ
};

/* Parse text into a caller-owned pool, growing it until the document
 * fits (json_nodes_for() bounds how far that can go). Throws Error on
 * anything the codec refuses. The nodes slice the text, which must
 * outlive them — that is why this takes a pointer rather than a string:
 * the binding layer parses straight out of the interpreter's own
 * (immutable, referenced) string and copies nothing. This is the
 * plumbing under Doc; a C++ caller wants Doc. */
void parse_pool(const char* text, size_t len, std::vector<json_node_t>& pool,
                json_doc_t& doc);

/* One parsed document, addressed by JSON Pointer.
 *
 * "" is the whole document, "/a/0/b" a member of an element of a
 * member. The text is copied in once and kept alive for as long as any
 * copy of the Doc, so a value read out of it can outlive the buffer it
 * arrived in.
 *
 * Reads are point lookups, so a loop that walks a large array with
 * at()-style pointers is quadratic where iterating with keys() is not;
 * for the member-count-then-read shape every SBI body wants, that never
 * comes up. */
class Doc
{
  public:
    /* Throws Error on anything that is not one JSON value: a syntax
     * error, a second value after the first, nesting past
     * JSON_MAX_DEPTH. */
    explicit Doc(const std::string& text);

    int  type(const std::string& ptr = "") const; /* Type; T_NONE if absent */
    bool has(const std::string& ptr = "") const;
    /* Present, and the value there is JSON null. An absent member is
     * not null — ask has() for that. */
    bool is_null(const std::string& ptr = "") const;

    /* Members of an object or elements of an array; 0 for a scalar and
     * for a pointer that resolves to nothing. */
    int count(const std::string& ptr = "") const;

    /* Member name of the i-th member of an object (wire order), or ""
     * when there is no such member. */
    std::string key_at(const std::string& ptr, int i) const;

    /* Pointer to the i-th child of a container, escaped as RFC 6901
     * requires — the safe way to walk an object whose member names the
     * caller has not seen, since a name may itself contain '/'. Empty
     * when there is no such child. */
    std::string child(const std::string& ptr, int i) const;

    /* Typed reads. Each throws Error when the pointer resolves to
     * nothing or the value is of another type. */
    std::string str(const std::string& ptr = "") const;
    double      num(const std::string& ptr = "") const;
    long long   integer(const std::string& ptr = "") const;
    bool        boolean(const std::string& ptr = "") const;

    /* The same reads with a default for "absent, or not that type" —
     * what an optional member with a documented default wants. */
    std::string str_or(const std::string& ptr,
                       const std::string& dflt = std::string()) const;
    double      num_or(const std::string& ptr, double dflt = 0.0) const;
    long long   int_or(const std::string& ptr, long long dflt = 0) const;
    bool        bool_or(const std::string& ptr, bool dflt = false) const;

    /* The value's source text: a whole subtree for a container, the
     * literal digits for a number (which is how a 19-digit identifier
     * survives a language whose numbers are all doubles), the escaped
     * body for a string. Feed a container's text back to
     * Builder::frag() to pass a subtree through untouched. Empty when
     * the pointer resolves to nothing. */
    std::string text(const std::string& ptr = "") const;

    /* Bytes parsed, and nodes the document needed — a size check for a
     * caller that pools documents rather than one-shot parses. */
    int size() const;
    int nodes() const;

  private:
    /* The text and the node pool live behind one shared handle: a node
     * is a pair of pointers into the text, so a copy of a Doc must not
     * copy either. Shared, not unique, because SWIG hands wrapped
     * objects around by value. */
    struct Body {
        std::string              text;
        std::vector<json_node_t> pool;
        json_doc_t               doc;
    };
    std::shared_ptr<const Body> b_;

    const json_node_t* find(const std::string& ptr) const;
    const json_node_t* need(const std::string& ptr, int type,
                            const char* what) const;
};

/* Parse text into a Doc. The free function reads better at a call site
 * and is what the scripting modules expose. */
Doc parse(const std::string& text);

/* Builds one document into a buffer that grows as it needs to; done()
 * returns the bytes and resets, so one Builder can write many documents
 * with no further allocation.
 *
 * The writer owns the punctuation: commas between members and elements,
 * the ':' after a member name, and — with indent > 0 — the newlines and
 * indentation of a pretty-printed document. What it will not do is
 * guess structure: a close that does not match its open, a member name
 * outside an object, or a value where a name is due all throw, because
 * each of them produces JSON a peer cannot parse.
 *
 * Calls chain: Builder().obj().field("supi", s).obj_end().done(). */
class Builder
{
  public:
    enum { DEFAULT_CAP = 4 * 1024 };

    /* cap is the initial buffer, not a limit; indent is spaces per
     * level, 0 (the default) being the compact form that goes on a
     * wire. */
    explicit Builder(size_t cap = DEFAULT_CAP, unsigned indent = 0);

    Builder& obj();
    Builder& obj_end();
    Builder& arr();
    Builder& arr_end();

    Builder& key(const std::string& k);

    Builder& str(const std::string& v);
    Builder& num(double v); /* an integral double writes as an integer */
    Builder& integer(long long v);
    Builder& boolean(bool v);
    Builder& null();
    /* A pre-encoded value: a subtree from Doc::text(), or a fragment
     * another layer produced. Copied verbatim, on the caller's word
     * that it is one well-formed JSON value. */
    Builder& frag(const std::string& v);

    /* Member name and value together — the shape most call sites want.
     * Distinct names rather than overloads on purpose: a scripting
     * language where a number is also a string would otherwise pick the
     * wrong one and quietly quote a number. */
    Builder& field(const std::string& k, const std::string& v);
    Builder& field_num(const std::string& k, double v);
    Builder& field_int(const std::string& k, long long v);
    Builder& field_bool(const std::string& k, bool v);
    Builder& field_null(const std::string& k);
    Builder& field_frag(const std::string& k, const std::string& v);

    /* The document, which must be complete: every container closed and
     * one value written. Resets, ready for the next one. */
    std::string done();

    /* Throw away a half-written document (after an error, or to reuse
     * one Builder for an unrelated body). */
    Builder& clear();

    size_t capacity() const
    {
        return cap_;
    }

  private:
    /* Runs one writer call, growing the buffer and running it again if
     * it did not fit. */
    template <typename F> void emit(F&& f, const char* what);
    void                       grow();

    /* Raw array, not std::vector<char>: vector value-initializes, which
     * costs a full memset of the capacity on every construction. */
    std::unique_ptr<char[]> buf_;
    size_t                  cap_;
    unsigned                indent_;
    json_wbuf_t             w_;
};

/* ---- helpers ---- */

/* "null", "boolean", "number", "string", "array", "object"; "none" for
 * T_NONE. */
std::string type_name(int type);

/* Is this byte string well-formed UTF-8? The codec passes bytes through
 * in both directions; a caller that must not put a malformed one on the
 * wire checks here. */
bool utf8_valid(const std::string& s);

} // namespace json

#endif /* JSONXX_HPP */
