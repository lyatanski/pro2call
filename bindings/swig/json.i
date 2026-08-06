/* SWIG interface for the JSON codec — wraps the jsonxx C++ facade
 * (bindings/cxx/inc/jsonxx.hpp) over the C codec (json/) into a Lua
 * module named `json`. Value types plus a fluent Builder, and two
 * hand-written converters that turn a document into Lua tables and back.
 *
 * Lua quick tour — the three ways a script wants JSON:
 *
 *   local json = require("json")
 *
 *   -- 1. a whole body as a table (the common case)
 *   local t = json.decode(body)
 *   print(t.supi, t.qosFlows[1].qfi)
 *   local out = json.encode{ supi = t.supi, pduSessionId = 5 }
 *
 *   -- 2. two members out of forty, without building any table
 *   local d = json.parse(body)
 *   if d:has("/sNssai/sst") then dnn = d:str_or("/dnn", "internet") end
 *
 *   -- 3. building one document, exactly (member order, integers, a
 *   --    subtree passed through byte for byte)
 *   local b = json.Builder():obj()
 *       :field("supi", supi):field_int("pduSessionId", 5)
 *       :field_frag("sNssai", d:text("/sNssai"))
 *   local body = b:obj_end():done()
 *
 * decode/encode are native (the block below), not SWIG-generated: a Lua
 * table is built straight out of the node pool and read straight into the
 * writer, so neither direction materializes an intermediate C++ tree.
 *
 * The four things a JSON-to-Lua mapping has to decide, and what this one
 * decided:
 *
 *   - **null** has no Lua value. It decodes to `json.null`, a unique
 *     sentinel, so a member that is present-but-null is distinguishable
 *     from one that is absent, and encodes back to null. Pass a second
 *     argument to decode to choose something else —
 *     `json.decode(body, nil)` drops null members, `json.decode(body,
 *     false)` makes them false.
 *   - **empty table**: `{}` encodes as an empty object, which is what
 *     `json.decode("{}")` produced. An empty array decodes with a marker
 *     that encodes back as `[]`, so a decode/encode round trip does not
 *     silently turn one into the other; `json.array{}` sets that marker
 *     by hand, and `json.object{}` the other way.
 *   - **array or object** for a non-empty table: keys 1..n make an
 *     array, anything else an object. A table that is both, or an array
 *     with a hole, is an error rather than a guess — silently dropping
 *     elements is the sort of thing that shows up as a peer's 400 much
 *     later.
 *   - **numbers** are all doubles in Lua 5.1, so an integral one is
 *     written as an integer ("5", not "5.0") and a 19-digit identifier
 *     that no double holds exactly is read with `d:text(ptr)`, which
 *     hands back its literal digits.
 *
 * Deliberately no %template for any std::vector: SWIG's Lua runtime keys
 * wrapped types in a registry SHARED by every module in one lua_State, so
 * a second module declaring std::vector<std::string> under a different
 * name fights with sip.i's StringList over the same C++ type.
 */

%module json

%{
#include "jsonxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <exception.i>

/* shared move-on-value-return typemap */
%include "common.i"

/* ---- exceptions: json::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const json::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script. */
%ignore json::Error;

/* The pool-growing parse is plumbing for Doc and for the converters
 * below; it hands out C node pointers, which is the one thing a facade
 * is here to avoid doing. */
%ignore json::parse_pool;

/* SWIG's Lua runtime keys class metatables in the registry by the
 * UNSCOPED class name, so two modules loaded into one interpreter must
 * not both wrap a class of the same name — sip and sdp both have a
 * Builder, which is why this one is registered as JsonBuilder and
 * aliased back below (the trick sdp.i and diam.i use). `Doc` is unique
 * across the modules as they stand; check before adding another, because
 * the failure mode is silent at both build and load time. */
%rename(JsonBuilder) json::Builder;

/* ---- fluent returns must not orphan the owner ----------------------
 *
 * See the same block in swig/sip.i, swig/sdp.i and swig/diam.i.
 * Builder's methods return *this; SWIG's default `out` typemap wraps
 * that reference in a FRESH, NON-owning userdata, so in the documented
 * idiom
 *
 *     local b = json.Builder():obj()
 *
 * the only owning handle is unreachable the moment obj() returns and the
 * next GC frees the Builder mid-chain. Hand back the caller's own
 * userdata so ownership survives the chain. */
#ifdef SWIGLUA
%typemap(out) json::Builder& %{
    lua_pushvalue(L, 1);
    SWIG_arg++;
%}
#endif

%include "jsonxx.hpp"

/* ---- native table converters ---------------------------------------
 *
 * SWIG cannot express "a Lua table of arbitrary shape", so decode and
 * encode are written against the Lua C API directly. The walks below
 * never call lua_error(): they throw json::Error and the two entry
 * points catch it, because a longjmp out of here would skip the
 * destructor of the node pool (decode) or the Builder (encode).
 *
 * This block lands in the wrapper's header section, after the SWIG type
 * table, so the runtime helpers are already in scope. */
#ifdef SWIGLUA
%{
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
#include <cstring>
#include <string>
#include <vector>

#if LUA_VERSION_NUM >= 502
#define JSONLUA_RAWLEN lua_rawlen
#else
#define JSONLUA_RAWLEN lua_objlen
#endif

/* Registry slots for the two Lua-side constants the converters need:
 * the null sentinel and the metatable that marks a table as an array.
 * Both are created in Lua (%luacode below) and handed over by
 * json.__bind, so every lua_State gets its own pair. */
static const char* const JSONLUA_NULL = "json.null";
static const char* const JSONLUA_AMT  = "json.arraymt";

static int jsonlua_bind(lua_State* L)
{
    lua_settop(L, 2);
    lua_setfield(L, LUA_REGISTRYINDEX, JSONLUA_AMT);
    lua_setfield(L, LUA_REGISTRYINDEX, JSONLUA_NULL);
    return 0;
}

static int jsonlua_null(lua_State* L)
{
    lua_getfield(L, LUA_REGISTRYINDEX, JSONLUA_NULL);
    return 1;
}

/* Is the value at idx (absolute) the null sentinel? */
static bool jsonlua_is_null(lua_State* L, int idx)
{
    lua_getfield(L, LUA_REGISTRYINDEX, JSONLUA_NULL);
    bool eq = lua_rawequal(L, idx, -1) != 0;
    lua_pop(L, 1);
    return eq;
}

/* ---- decode: nodes -> Lua values ---- */

/* A string node's value, expanded into scratch space Lua owns — so a
 * push that runs out of memory cannot leak it. */
static void jsonlua_push_body(lua_State* L, const json_node_t* n, bool key)
{
    json_str_t raw  = key ? n->key : n->raw;
    uint8_t    mask = key ? JSON_F_KESC : JSON_F_ESC;
    if (!(n->flags & mask)) {
        lua_pushlstring(L, raw.p ? raw.p : "", raw.len);
        return;
    }
    void*  tmp  = lua_newuserdata(L, raw.len ? raw.len : 1);
    size_t olen = 0;
    int    rc   = key ? json_key(n, (char*)tmp, raw.len, &olen)
                      : json_str(n, (char*)tmp, raw.len, &olen);
    if (rc != JSON_OK) throw json::Error("decode: bad string escape", rc);
    lua_pushlstring(L, (const char*)tmp, olen);
    lua_remove(L, -2); /* drop the scratch */
}

/* nulls is the stack index of the value JSON null becomes, or 0 for the
 * sentinel. */
static void jsonlua_push(lua_State* L, const json_doc_t* d,
                         const json_node_t* n, int nulls)
{
    if (!lua_checkstack(L, 6)) throw json::Error("decode: Lua stack full");

    switch (n->type) {
    case JSON_T_NULL:
        if (nulls) lua_pushvalue(L, nulls);
        else lua_getfield(L, LUA_REGISTRYINDEX, JSONLUA_NULL);
        return;

    case JSON_T_BOOL: {
        bool v = false;
        json_bool(n, &v);
        lua_pushboolean(L, v);
        return;
    }

    case JSON_T_NUM: {
#if LUA_VERSION_NUM >= 503
        /* An interpreter with an integer subtype keeps a 64-bit
         * identifier exact; 5.1 has only doubles and Doc::text() is the
         * way to read one there. */
        int64_t i;
        if ((n->flags & JSON_F_INT) && json_i64(n, &i) == JSON_OK) {
            lua_pushinteger(L, (lua_Integer)i);
            return;
        }
#endif
        double v = 0;
        int    rc = json_num(n, &v);
        if (rc != JSON_OK) throw json::Error("decode: number out of range", rc);
        lua_pushnumber(L, (lua_Number)v);
        return;
    }

    case JSON_T_STR: jsonlua_push_body(L, n, false); return;

    case JSON_T_ARR: {
        lua_createtable(L, (int)n->count, 0);
        int i = 1;
        for (const json_node_t* c = json_first(d, n); c; c = json_next(d, c)) {
            jsonlua_push(L, d, c, nulls);
            lua_rawseti(L, -2, i++);
        }
        /* An empty array is the one container whose kind its Lua form
         * does not record, so it carries the marker that encodes back
         * as [] rather than {}. */
        if (n->count == 0) {
            lua_getfield(L, LUA_REGISTRYINDEX, JSONLUA_AMT);
            if (lua_istable(L, -1)) lua_setmetatable(L, -2);
            else lua_pop(L, 1);
        }
        return;
    }

    case JSON_T_OBJ: {
        lua_createtable(L, 0, (int)n->count);
        for (const json_node_t* c = json_first(d, n); c; c = json_next(d, c)) {
            jsonlua_push_body(L, c, true);
            jsonlua_push(L, d, c, nulls);
            /* A null mapped to nil drops the member, which is what
             * asking for nil asked for. */
            lua_rawset(L, -3);
        }
        return;
    }

    default: throw json::Error("decode: unknown node type", JSON_E_SYNTAX);
    }
}

static int jsonlua_decode(lua_State* L)
{
    size_t      n = 0;
    const char* s = luaL_checklstring(L, 1, &n);
    /* An explicit second argument — nil included, which is why this
     * counts arguments rather than testing for nil. */
    int         nulls = (lua_gettop(L) >= 2) ? 2 : 0;
    int         top   = lua_gettop(L);
    std::string err;

    {
        try {
            /* Parsed straight out of the Lua string: it is immutable and
             * on the stack, so the slices stay valid for the walk. */
            std::vector<json_node_t> pool;
            json_doc_t               d;
            json::parse_pool(s, n, pool, d);
            jsonlua_push(L, &d, json_root(&d), nulls);
        } catch (const std::exception& e) {
            err = e.what();
        }
    }
    if (!err.empty()) {
        lua_settop(L, top);
        return luaL_error(L, "json.decode: %s", err.c_str());
    }
    return 1;
}

/* ---- encode: Lua values -> bytes ---- */

static void jsonlua_enc(lua_State* L, int idx, json::Builder& b);

/* Array (1) or object (0). An explicit marker wins; otherwise the keys
 * decide, and the shapes that are neither throw. */
static int jsonlua_table_kind(lua_State* L, int idx)
{
    if (lua_getmetatable(L, idx)) {
        lua_pushliteral(L, "__jsontype");
        lua_rawget(L, -2);
        const char* t    = lua_tostring(L, -1);
        int         kind = -1;
        if (t != NULL && std::strcmp(t, "array") == 0) kind = 1;
        else if (t != NULL && std::strcmp(t, "object") == 0) kind = 0;
        lua_pop(L, 2);
        if (kind >= 0) return kind;
    }

    size_t     nint = 0, nother = 0;
    lua_Number maxi = 0;
    lua_pushnil(L);
    while (lua_next(L, idx) != 0) {
        if (lua_type(L, -2) == LUA_TNUMBER) {
            lua_Number k = lua_tonumber(L, -2);
            if (k >= 1 && k == (lua_Number)(long long)k) {
                nint++;
                if (k > maxi) maxi = k;
            } else {
                nother++;
            }
        } else {
            nother++;
        }
        lua_pop(L, 1);
    }

    if (nint && nother)
        throw json::Error("encode: table has both array and object keys");
    if (nother) return 0;
    if (nint == 0) return 0; /* empty: an object, unless marked */
    if ((lua_Number)nint != maxi)
        throw json::Error("encode: array has a hole (" +
                          std::to_string((long long)nint) + " of " +
                          std::to_string((long long)maxi) + " elements)");
    return 1;
}

static void jsonlua_enc_table(lua_State* L, int idx, json::Builder& b)
{
    if (jsonlua_table_kind(L, idx) == 1) {
        size_t n = JSONLUA_RAWLEN(L, idx);
        b.arr();
        for (size_t i = 1; i <= n; i++) {
            lua_rawgeti(L, idx, (int)i);
            jsonlua_enc(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        b.arr_end();
        return;
    }

    b.obj();
    lua_pushnil(L);
    while (lua_next(L, idx) != 0) {
        int kt = lua_type(L, -2);
        if (kt == LUA_TSTRING) {
            size_t      kn = 0;
            const char* k  = lua_tolstring(L, -2, &kn);
            b.key(std::string(k, kn));
        } else if (kt == LUA_TNUMBER) {
            /* A number key becomes its decimal text. Converted on a
             * COPY: lua_tolstring rewrites the value in place, and doing
             * that to a key mid-traversal breaks lua_next. */
            lua_pushvalue(L, -2);
            size_t      kn = 0;
            const char* k  = lua_tolstring(L, -1, &kn);
            std::string key(k ? k : "", kn);
            lua_pop(L, 1);
            b.key(key);
        } else {
            throw json::Error(std::string("encode: cannot use a ") +
                              lua_typename(L, kt) + " as a member name");
        }
        jsonlua_enc(L, lua_gettop(L), b);
        lua_pop(L, 1); /* the value; the key stays for lua_next */
    }
    b.obj_end();
}

static void jsonlua_enc(lua_State* L, int idx, json::Builder& b)
{
    if (!lua_checkstack(L, 6)) throw json::Error("encode: Lua stack full");

    int t = lua_type(L, idx);
    switch (t) {
    case LUA_TNONE:
    case LUA_TNIL: b.null(); return;
    case LUA_TBOOLEAN: b.boolean(lua_toboolean(L, idx) != 0); return;
    case LUA_TNUMBER:
#if LUA_VERSION_NUM >= 503
        /* Where the interpreter has an integer subtype, keep it exact
         * past 2^53 rather than routing it through a double. */
        if (lua_isinteger(L, idx)) {
            b.integer((long long)lua_tointeger(L, idx));
            return;
        }
#endif
        b.num((double)lua_tonumber(L, idx));
        return;
    case LUA_TSTRING: {
        size_t      n = 0;
        const char* s = lua_tolstring(L, idx, &n); /* already a string */
        b.str(std::string(s, n));
        return;
    }
    default: break;
    }

    if (jsonlua_is_null(L, idx)) {
        b.null();
        return;
    }
    if (t == LUA_TTABLE) {
        jsonlua_enc_table(L, idx, b);
        return;
    }
    throw json::Error(std::string("encode: cannot encode a ") +
                      lua_typename(L, t));
}

static int jsonlua_encode(lua_State* L)
{
    unsigned indent = 0;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        indent = (unsigned)lua_tonumber(L, 2);
    } else if (lua_istable(L, 2)) {
        lua_getfield(L, 2, "indent");
        if (lua_isnumber(L, -1)) indent = (unsigned)lua_tonumber(L, -1);
        lua_pop(L, 1);
    }

    int         top = lua_gettop(L);
    std::string out, err;
    {
        try {
            json::Builder b((size_t)json::Builder::DEFAULT_CAP, indent);
            jsonlua_enc(L, 1, b);
            out = b.done();
        } catch (const std::exception& e) {
            err = e.what();
        }
    }
    lua_settop(L, top);
    if (!err.empty()) return luaL_error(L, "json.encode: %s", err.c_str());
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}
%}

%native(decode) int jsonlua_decode(lua_State* L);
%native(encode) int jsonlua_encode(lua_State* L);
%native(__bind) int jsonlua_bind(lua_State* L);
%native(__null) int jsonlua_null(lua_State* L);

%luacode %{
json.Builder = json.JsonBuilder

-- The two constants the native converters look up in the registry. The
-- sentinel is a table rather than a light userdata so it can print as
-- "null" and refuse to be written to; identity is what makes it work,
-- and there is exactly one per interpreter.
local null_mt = {
    __tostring = function() return "null" end,
    __newindex = function() error("json.null is a constant", 2) end,
    __metatable = "json.null",
}
json.null = setmetatable({}, null_mt)

local ARRAY  = { __jsontype = "array" }
local OBJECT = { __jsontype = "object" }
json.__bind(json.null, ARRAY)

-- Say which one an ambiguous table is: json.array{} encodes as [] and
-- json.object{} as {}. Both return the table, so they wrap a literal.
function json.array(t)  return setmetatable(t or {}, ARRAY)  end
function json.object(t) return setmetatable(t or {}, OBJECT) end

-- Is this the value a JSON null decoded to? Written out so a script
-- does not have to know whether it compares by identity or by type.
function json.is_null(v) return v == json.null end

-- Indented encode, for a log line or a fixture a human will read.
function json.pretty(v, indent) return json.encode(v, indent or 2) end
%}
#endif
