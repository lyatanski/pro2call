#include "jsonxx.hpp"

#include <cstring>
#include <string>
#include <utility>

namespace json
{

namespace
{

[[noreturn]] void fail(const std::string& what, int code)
{
    std::string m = what;
    switch (code) {
    case JSON_E_SYNTAX:   m += ": not JSON"; break;
    case JSON_E_NODES:    m += ": too many values"; break;
    case JSON_E_DEPTH:    m += ": nested too deeply"; break;
    case JSON_E_TRAILING: m += ": trailing data after the value"; break;
    case JSON_E_TYPE:     m += ": wrong type"; break;
    case JSON_E_MISSING:  m += ": not present"; break;
    case JSON_E_RANGE:    m += ": out of range"; break;
    case JSON_E_OVERFLOW: m += ": buffer too small"; break;
    case JSON_E_STATE:    m += ": not valid here"; break;
    case JSON_E_INVAL:    m += ": invalid argument"; break;
    default:              m += ": failed"; break;
    }
    throw Error(m, code);
}

void check(int rc, const std::string& what)
{
    if (rc != JSON_OK) fail(what, rc);
}

/* A pointer named in an error message: the one piece of context that
 * turns "wrong type" into something a caller can act on. */
std::string at(const char* what, const std::string& ptr)
{
    return std::string(what) + " '" + ptr + "'";
}

/* A string value / member name with its escapes expanded. The raw
 * length is always enough room (escapes only ever shrink). */
std::string str_of(const json_node_t* n, const std::string& what)
{
    std::string s(n->raw.len, '\0');
    size_t      olen = 0;
    check(json_str(n, s.empty() ? nullptr : &s[0], s.size(), &olen), what);
    s.resize(olen);
    return s;
}

std::string key_of(const json_node_t* n)
{
    std::string s(n->key.len, '\0');
    size_t      olen = 0;
    check(json_key(n, s.empty() ? nullptr : &s[0], s.size(), &olen), "key_at");
    s.resize(olen);
    return s;
}

} // namespace

void parse_pool(const char* text, size_t len, std::vector<json_node_t>& pool,
                json_doc_t& doc)
{
    /* One node per value. The worst case is one node per two bytes
     * ("[0,0,0]"), which no real body comes near, so start at a
     * fraction of it and grow — a 200 KiB paged list would otherwise
     * reserve a hundred thousand nodes to hold a few hundred. */
    const uint32_t max = json_nodes_for(len);
    uint32_t       cap = (uint32_t)(len / 16) + 16;
    if (cap > max) cap = max;

    for (;;) {
        pool.resize(cap);
        json_doc_init(&doc, pool.data(), cap);
        int rc = json_parse(&doc, text, len);
        if (rc == JSON_OK) return;
        /* The offset is what makes a rejected 4 KiB body debuggable. */
        if (rc != JSON_E_NODES || cap >= max)
            fail("parse at byte " + std::to_string(doc.err_off), rc);
        cap = (cap > max / 2) ? max : cap * 2;
    }
}

/* ---- Doc ---- */

Doc::Doc(const std::string& text)
{
    auto b = std::make_shared<Body>();
    /* Parsed out of the copy, never out of the caller's string: every
     * node is a pair of pointers into whatever was parsed. */
    b->text = text;
    parse_pool(b->text.data(), b->text.size(), b->pool, b->doc);
    b_ = std::move(b);
}

const json_node_t* Doc::find(const std::string& ptr) const
{
    return json_ptr(&b_->doc, ptr.data(), ptr.size());
}

const json_node_t* Doc::need(const std::string& ptr, int type,
                             const char* what) const
{
    const json_node_t* n = find(ptr);
    if (n == nullptr) fail(at(what, ptr), JSON_E_MISSING);
    if (type >= 0 && n->type != type) fail(at(what, ptr), JSON_E_TYPE);
    return n;
}

int Doc::type(const std::string& ptr) const
{
    const json_node_t* n = find(ptr);
    return n ? (int)n->type : (int)T_NONE;
}

bool Doc::has(const std::string& ptr) const
{
    return find(ptr) != nullptr;
}

bool Doc::is_null(const std::string& ptr) const
{
    const json_node_t* n = find(ptr);
    return n != nullptr && n->type == JSON_T_NULL;
}

int Doc::count(const std::string& ptr) const
{
    const json_node_t* n = find(ptr);
    return n ? (int)n->count : 0;
}

std::string Doc::key_at(const std::string& ptr, int i) const
{
    const json_node_t* n = find(ptr);
    if (n == nullptr || i < 0) return std::string();
    const json_node_t* c = json_at(&b_->doc, n, (uint32_t)i);
    return c ? key_of(c) : std::string();
}

std::string Doc::child(const std::string& ptr, int i) const
{
    const json_node_t* n = find(ptr);
    if (n == nullptr || i < 0) return std::string();
    const json_node_t* c = json_at(&b_->doc, n, (uint32_t)i);
    if (c == nullptr) return std::string();
    if (n->type == JSON_T_ARR) return ptr + "/" + std::to_string(i);

    /* RFC 6901 §3: inside a reference token '~' is "~0" and '/' is
     * "~1". A member name containing either is rare and exactly what a
     * hand-built pointer gets wrong. */
    std::string out = ptr + "/";
    for (char ch : key_of(c)) {
        if (ch == '~') out += "~0";
        else if (ch == '/') out += "~1";
        else out += ch;
    }
    return out;
}

std::string Doc::str(const std::string& ptr) const
{
    return str_of(need(ptr, JSON_T_STR, "str"), at("str", ptr));
}

double Doc::num(const std::string& ptr) const
{
    double v = 0;
    check(json_num(need(ptr, JSON_T_NUM, "num"), &v), at("num", ptr));
    return v;
}

long long Doc::integer(const std::string& ptr) const
{
    int64_t v = 0;
    check(json_i64(need(ptr, JSON_T_NUM, "integer"), &v), at("integer", ptr));
    return (long long)v;
}

bool Doc::boolean(const std::string& ptr) const
{
    bool v = false;
    check(json_bool(need(ptr, JSON_T_BOOL, "boolean"), &v), at("boolean", ptr));
    return v;
}

std::string Doc::str_or(const std::string& ptr, const std::string& dflt) const
{
    const json_node_t* n = find(ptr);
    if (n == nullptr || n->type != JSON_T_STR) return dflt;
    return str_of(n, at("str_or", ptr));
}

double Doc::num_or(const std::string& ptr, double dflt) const
{
    const json_node_t* n = find(ptr);
    double             v;
    if (n == nullptr || json_num(n, &v) != JSON_OK) return dflt;
    return v;
}

long long Doc::int_or(const std::string& ptr, long long dflt) const
{
    const json_node_t* n = find(ptr);
    int64_t            v;
    if (n == nullptr || json_i64(n, &v) != JSON_OK) return dflt;
    return (long long)v;
}

bool Doc::bool_or(const std::string& ptr, bool dflt) const
{
    const json_node_t* n = find(ptr);
    bool               v;
    if (n == nullptr || json_bool(n, &v) != JSON_OK) return dflt;
    return v;
}

std::string Doc::text(const std::string& ptr) const
{
    const json_node_t* n = find(ptr);
    if (n == nullptr || n->raw.p == nullptr) return std::string();
    return std::string(n->raw.p, n->raw.len);
}

int Doc::size() const
{
    return (int)b_->doc.len;
}

int Doc::nodes() const
{
    return (int)b_->doc.count;
}

Doc parse(const std::string& text)
{
    return Doc(text);
}

/* ---- Builder ---- */

Builder::Builder(size_t cap, unsigned indent)
    : buf_(new char[cap ? cap : (size_t)DEFAULT_CAP]),
      cap_(cap ? cap : (size_t)DEFAULT_CAP), indent_(indent)
{
    clear();
}

Builder& Builder::clear()
{
    json_wbuf_init(&w_, buf_.get(), cap_);
    json_wbuf_indent(&w_, indent_);
    return *this;
}

void Builder::grow()
{
    size_t want = cap_ * 2;
    if (want < 256) want = 256;
    /* A document this side of 64 MiB is a bug in the caller, not a
     * buffer to allocate. */
    if (want > 64u * 1024u * 1024u) fail("builder", JSON_E_OVERFLOW);

    std::unique_ptr<char[]> nb(new char[want]);
    if (w_.off) std::memcpy(nb.get(), buf_.get(), w_.off);
    buf_ = std::move(nb);
    cap_ = want;
}

template <typename F> void Builder::emit(F&& f, const char* what)
{
    for (;;) {
        /* A put that runs out of room may have written part of what it
         * came to write (a member name is a quote, a body, a quote and
         * a colon), so the state it started from is restored before the
         * retry — replaying onto a partial write would duplicate it. */
        json_wbuf_t save = w_;
        int         rc   = f(&w_);
        if (rc != JSON_E_OVERFLOW) {
            check(rc, what);
            return;
        }
        grow();
        w_     = save;
        w_.buf = buf_.get();
        w_.cap = cap_;
    }
}

Builder& Builder::obj()
{
    emit([](json_wbuf_t* w) { return json_put_obj_begin(w); }, "obj");
    return *this;
}

Builder& Builder::obj_end()
{
    emit([](json_wbuf_t* w) { return json_put_obj_end(w); }, "obj_end");
    return *this;
}

Builder& Builder::arr()
{
    emit([](json_wbuf_t* w) { return json_put_arr_begin(w); }, "arr");
    return *this;
}

Builder& Builder::arr_end()
{
    emit([](json_wbuf_t* w) { return json_put_arr_end(w); }, "arr_end");
    return *this;
}

Builder& Builder::key(const std::string& k)
{
    emit([&](json_wbuf_t* w) { return json_put_key(w, k.data(), k.size()); },
         "key");
    return *this;
}

Builder& Builder::str(const std::string& v)
{
    emit([&](json_wbuf_t* w) { return json_put_str(w, v.data(), v.size()); },
         "str");
    return *this;
}

Builder& Builder::num(double v)
{
    emit([&](json_wbuf_t* w) { return json_put_num(w, v); }, "num");
    return *this;
}

Builder& Builder::integer(long long v)
{
    emit([&](json_wbuf_t* w) { return json_put_int(w, (int64_t)v); },
         "integer");
    return *this;
}

Builder& Builder::boolean(bool v)
{
    emit([&](json_wbuf_t* w) { return json_put_bool(w, v); }, "boolean");
    return *this;
}

Builder& Builder::null()
{
    emit([](json_wbuf_t* w) { return json_put_null(w); }, "null");
    return *this;
}

Builder& Builder::frag(const std::string& v)
{
    emit([&](json_wbuf_t* w) { return json_put_frag(w, v.data(), v.size()); },
         "frag");
    return *this;
}

Builder& Builder::field(const std::string& k, const std::string& v)
{
    return key(k).str(v);
}

Builder& Builder::field_num(const std::string& k, double v)
{
    return key(k).num(v);
}

Builder& Builder::field_int(const std::string& k, long long v)
{
    return key(k).integer(v);
}

Builder& Builder::field_bool(const std::string& k, bool v)
{
    return key(k).boolean(v);
}

Builder& Builder::field_null(const std::string& k)
{
    return key(k).null();
}

Builder& Builder::field_frag(const std::string& k, const std::string& v)
{
    return key(k).frag(v);
}

std::string Builder::done()
{
    int n = json_end(&w_);
    /* Reset either way: a half-written document is of no use to anyone,
     * and leaving it in place would leak its bytes into the next one. */
    if (n < 0) {
        clear();
        fail("done", n);
    }
    std::string out(buf_.get(), (size_t)n);
    clear();
    return out;
}

/* ---- helpers ---- */

std::string type_name(int type)
{
    if (type == T_NONE) return "none";
    return json_type_name((json_type_t)type);
}

bool utf8_valid(const std::string& s)
{
    return json_utf8_valid(s.data(), s.size());
}

} // namespace json
