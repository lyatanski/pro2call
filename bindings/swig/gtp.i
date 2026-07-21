/* SWIG interface for the GTP stack — wraps the gtpxx C++ facade
 * (bindings/cxx) plus the gtp2 enum/constant surface.
 *
 * Two target languages, one facade:
 *
 *   - Python uses SWIG directors: scripting classes subclass the handler
 *     interfaces (EndpointHandler, UserPlaneEventHandler) directly.
 *   - Lua has no SWIG director support, so the callbacks are bridged by
 *     hand (see the SWIGLUA block below): the endpoint handler is a table
 *     of Lua functions, the user-plane event callback a bare function,
 *     and the C++ virtual calls trampoline into them.
 *
 * The event loop and UDP transport are the net module (net.Loop /
 * net.UdpSocket, bindings/swig/net.i); an Endpoint takes a net.Loop, so
 * a script requires both modules and shares one loop across the stacks.
 *
 * Python quick tour:
 *
 *   import gtp, net
 *   class Handler(gtp.EndpointHandler):
 *       def on_create_session_response(self, sess, rsp): ...
 *       def on_user_plane(self, sess, tun): ...
 *   loop = net.Loop(); ep = gtp.Endpoint(loop, "10.0.0.1")
 *   ep.set_handler(Handler())
 *
 * Lua quick tour:
 *
 *   local gtp = require("gtp")
 *   local net = require("net")
 *   local loop = net.Loop()
 *   local ep   = gtp.Endpoint(loop, "10.0.0.1")
 *   ep:set_handler({
 *       on_create_session_response = function(sess, rsp) ... end,
 *       on_user_plane = function(sess, tun) ... end,   -- install GTP-U here
 *   })
 *   local sess = ep:create_session(req, "10.0.0.2")
 *   loop:run()
 */

%module(directors="1") gtp

%{
#include "gtpxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <std_vector.i>
%include <std_except.i>
%include <exception.i>

/* ---- Lua callback bridge ----------------------------------------------
 *
 * SWIG cannot generate directors for Lua, so a Lua "handler" cannot
 * subclass the C++ interfaces. Instead these adapter classes hold a Lua
 * reference (a table of callbacks, or a single function) and forward each
 * virtual call into Lua. A raised Lua error becomes a gtp::Error, which
 * the loop's trampolines defer and re-raise from step()/run() exactly as
 * they do for a C++ exception — so a handler error still surfaces to the
 * script (see %exception below).
 *
 * This block lands in the wrapper's header section, after the SWIG type
 * table, so SWIG_TypeQuery()/SWIG_NewPointerObj() are already in scope. */
#ifdef SWIGLUA
%{
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
#include <memory>
#include <unordered_map>

/* Captured Lua callables (built by the typemaps below). */
struct GtpLuaFn    { lua_State* L; int ref; };
struct GtpLuaTable { lua_State* L; int ref; };

/* Hand a C++ object to Lua as a SWIG proxy: owned copies are collected by
 * Lua's GC; borrowed pointers (e.g. the endpoint-owned Session) are not. */
static void gtplua_owned (lua_State* L, void* p, const char* ty)
    { SWIG_NewPointerObj(L, p, SWIG_TypeQuery(ty), SWIG_POINTER_OWN); }
static void gtplua_borrow(lua_State* L, void* p, const char* ty)
    { SWIG_NewPointerObj(L, p, SWIG_TypeQuery(ty), 0); }

/* Owner registry so an adapter outlives the C++ object that borrows it:
 * one handler per endpoint. Function-local statics keep it to a single
 * definition. The single-function timer/io callbacks live in the net
 * module's bridge (bindings/swig/net.i) — scripts drive the loop through
 * net.Loop. */
class LuaEndpointHandler;
static std::unordered_map<gtp::Endpoint*, std::unique_ptr<LuaEndpointHandler>>& gtplua_handlers();

/* EndpointHandler backed by a Lua table; absent keys stay no-ops. */
class LuaEndpointHandler : public gtp::EndpointHandler {
    lua_State*  L_;
    int         ref_;
    const char* cur_ = "";

    /* Push table[name]; returns false (stack clean) if it is not a fn. */
    bool begin(const char* name) {
        cur_ = name;
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_);      /* table */
        lua_getfield(L_, -1, name);                    /* table, value */
        if (!lua_isfunction(L_, -1)) { lua_pop(L_, 2); return false; }
        return true;
    }
    void call(int nargs) {
        if (lua_pcall(L_, nargs, 0, 0) != 0) {
            std::string m = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "error";
            lua_pop(L_, 2);                             /* message, table */
            throw gtp::Error(std::string("lua handler '") + cur_ + "': " + m);
        }
        lua_pop(L_, 1);                                 /* table */
    }
    void pstr(const std::string& s) { lua_pushlstring(L_, s.data(), s.size()); }

public:
    LuaEndpointHandler(lua_State* L, int ref) : L_(L), ref_(ref) {}
    ~LuaEndpointHandler() override {
        if (L_ && ref_ != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref_);
    }

    void on_create_session_response(gtp::Session& s, const gtp::CreateSessionResponse& r) override {
        if (!begin("on_create_session_response")) return;
        gtplua_borrow(L_, &s, "gtp::Session *");
        gtplua_owned (L_, new gtp::CreateSessionResponse(r), "gtp::CreateSessionResponse *");
        call(2);
    }
    void on_modify_bearer_response(gtp::Session& s, const gtp::ModifyBearerResponse& r) override {
        if (!begin("on_modify_bearer_response")) return;
        gtplua_borrow(L_, &s, "gtp::Session *");
        gtplua_owned (L_, new gtp::ModifyBearerResponse(r), "gtp::ModifyBearerResponse *");
        call(2);
    }
    void on_delete_session_response(gtp::Session& s, const gtp::DeleteSessionResponse& r) override {
        if (!begin("on_delete_session_response")) return;
        gtplua_borrow(L_, &s, "gtp::Session *");
        gtplua_owned (L_, new gtp::DeleteSessionResponse(r), "gtp::DeleteSessionResponse *");
        call(2);
    }
    void on_user_plane(gtp::Session& s, const gtp::UserPlaneTunnel& t) override {
        if (!begin("on_user_plane")) return;
        gtplua_borrow(L_, &s, "gtp::Session *");
        gtplua_owned (L_, new gtp::UserPlaneTunnel(t), "gtp::UserPlaneTunnel *");
        call(2);
    }
    void on_timeout(gtp::Session& s, int message_type) override {
        if (!begin("on_timeout")) return;
        gtplua_borrow(L_, &s, "gtp::Session *");
        lua_pushinteger(L_, message_type);
        call(2);
    }
    void on_echo_request(const std::string& host, uint16_t port, int recovery) override {
        if (!begin("on_echo_request")) return;
        pstr(host); lua_pushinteger(L_, port); lua_pushinteger(L_, recovery);
        call(3);
    }
    void on_echo_response(const std::string& host, uint16_t port, int recovery) override {
        if (!begin("on_echo_response")) return;
        pstr(host); lua_pushinteger(L_, port); lua_pushinteger(L_, recovery);
        call(3);
    }
    void on_create_session_request(const gtp::CreateSessionRequest& req,
                                   const std::string& host, uint16_t port) override {
        if (!begin("on_create_session_request")) return;
        gtplua_owned(L_, new gtp::CreateSessionRequest(req), "gtp::CreateSessionRequest *");
        pstr(host); lua_pushinteger(L_, port);
        call(3);
    }
    void on_modify_bearer_request(const gtp::ModifyBearerRequest& req,
                                  const std::string& host, uint16_t port) override {
        if (!begin("on_modify_bearer_request")) return;
        gtplua_owned(L_, new gtp::ModifyBearerRequest(req), "gtp::ModifyBearerRequest *");
        pstr(host); lua_pushinteger(L_, port);
        call(3);
    }
    void on_delete_session_request(const gtp::DeleteSessionRequest& req,
                                   const std::string& host, uint16_t port) override {
        if (!begin("on_delete_session_request")) return;
        gtplua_owned(L_, new gtp::DeleteSessionRequest(req), "gtp::DeleteSessionRequest *");
        pstr(host); lua_pushinteger(L_, port);
        call(3);
    }
    void on_create_bearer_request(const gtp::CreateBearerRequest& req,
                                  const std::string& host, uint16_t port) override {
        if (!begin("on_create_bearer_request")) return;
        gtplua_owned(L_, new gtp::CreateBearerRequest(req), "gtp::CreateBearerRequest *");
        pstr(host); lua_pushinteger(L_, port);
        call(3);
    }
    void on_message(int message_type, const gtp::Bytes& wire,
                    const std::string& host, uint16_t port) override {
        if (!begin("on_message")) return;
        lua_pushinteger(L_, message_type);
        lua_pushlstring(L_, reinterpret_cast<const char*>(wire.data()), wire.size());
        pstr(host); lua_pushinteger(L_, port);
        call(4);
    }
};

/* Single-function handler: user-plane ring-buffer events. */
class LuaUpEvHandler : public gtp::UserPlaneEventHandler {
    lua_State* L_;
    int        ref_;
public:
    LuaUpEvHandler(lua_State* L, int ref) : L_(L), ref_(ref) {}   /* borrows ref */
    void on_event(int kind, uint32_t teid,
                  const std::string& src_addr, uint16_t src_port) override {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_);
        lua_pushinteger(L_, kind);
        lua_pushinteger(L_, (lua_Integer)teid);
        lua_pushlstring(L_, src_addr.data(), src_addr.size());
        lua_pushinteger(L_, src_port);
        if (lua_pcall(L_, 4, 0, 0) != 0) {
            std::string m = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "error";
            lua_pop(L_, 1);
            throw gtp::Error("lua event handler: " + m);
        }
    }
};

static std::unordered_map<gtp::Endpoint*, std::unique_ptr<LuaEndpointHandler>>& gtplua_handlers()
    { static std::unordered_map<gtp::Endpoint*, std::unique_ptr<LuaEndpointHandler>> m; return m; }

/* Drop every adapter (and its registry ref) while the lua_State is still
 * valid. Anchored in %init as a userdata __gc so it runs during
 * lua_close; otherwise this map — a C++ static that outlives the state —
 * would luaL_unref() against a freed lua_State at process teardown. */
static int gtplua_atclose(lua_State* L) {
    (void)L;
    gtplua_handlers().clear();
    return 0;
}
%}
#endif

/* ---- exceptions: gtp::Error -> scripting error ---- */

#ifdef SWIGPYTHON
%feature("director:except") {
    if ($error != NULL) {
        throw Swig::DirectorMethodException();
    }
}

%exception {
    try {
        $action
    } catch (Swig::DirectorException&) {
        SWIG_fail;   /* scripting exception already set */
    } catch (const gtp::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#else
%exception {
    try {
        $action
    } catch (const gtp::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#endif

/* ---- gtp::Bytes <-> native byte strings ---- */

#ifdef SWIGPYTHON
%typemap(in) const gtp::Bytes& (gtp::Bytes tmp) {
    Py_buffer view;
    if (PyObject_GetBuffer($input, &view, PyBUF_CONTIG_RO) != 0) {
        SWIG_exception_fail(SWIG_TypeError, "expected a bytes-like object");
    }
    const uint8_t* p = static_cast<const uint8_t*>(view.buf);
    tmp.assign(p, p + view.len);
    PyBuffer_Release(&view);
    $1 = &tmp;
}
%typemap(in) gtp::Bytes = const gtp::Bytes&;
%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING)
        const gtp::Bytes&, gtp::Bytes {
    $1 = PyObject_CheckBuffer($input) ? 1 : 0;
}
%typemap(out) gtp::Bytes {
    $result = PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>($1.data()),
        static_cast<Py_ssize_t>($1.size()));
}
%typemap(out) const gtp::Bytes& {
    $result = PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>($1->data()),
        static_cast<Py_ssize_t>($1->size()));
}
/* struct members of type Bytes: get returns bytes, set accepts them */
%typemap(in) gtp::Bytes* (gtp::Bytes tmp) {
    Py_buffer view;
    if (PyObject_GetBuffer($input, &view, PyBUF_CONTIG_RO) != 0) {
        SWIG_exception_fail(SWIG_TypeError, "expected a bytes-like object");
    }
    const uint8_t* p = static_cast<const uint8_t*>(view.buf);
    tmp.assign(p, p + view.len);
    PyBuffer_Release(&view);
    $1 = &tmp;
}
%typemap(memberin) gtp::Bytes { $1 = *$input; }
%typemap(out) gtp::Bytes* {
    $result = PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>($1->data()),
        static_cast<Py_ssize_t>($1->size()));
}
/* director callbacks receive bytes too */
%typemap(directorin) const gtp::Bytes& {
    $input = PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>($1.data()),
        static_cast<Py_ssize_t>($1.size()));
}
#endif

#ifdef SWIGLUA
/* Lua strings are byte buffers already (embedded NULs survive), so a
 * gtp::Bytes maps straight to/from a Lua string. */
%typemap(in, checkfn="lua_isstring") const gtp::Bytes& (gtp::Bytes tmp) {
    size_t len; const char* p = lua_tolstring(L, $input, &len);
    tmp.assign(p, p + len);
    $1 = &tmp;
}
%typemap(in) gtp::Bytes = const gtp::Bytes&;
%typemap(in, checkfn="lua_isstring") gtp::Bytes* (gtp::Bytes tmp) {
    size_t len; const char* p = lua_tolstring(L, $input, &len);
    tmp.assign(p, p + len);
    $1 = &tmp;
}
%typemap(memberin) gtp::Bytes { $1 = *$input; }
%typemap(out) gtp::Bytes
%{ lua_pushlstring(L, reinterpret_cast<const char*>($1.data()), $1.size()); SWIG_arg++; %}
%typemap(out) const gtp::Bytes&
%{ lua_pushlstring(L, reinterpret_cast<const char*>($1->data()), $1->size()); SWIG_arg++; %}
%typemap(out) gtp::Bytes*
%{ lua_pushlstring(L, reinterpret_cast<const char*>($1->data()), $1->size()); SWIG_arg++; %}
%typecheck(SWIG_TYPECHECK_STRING) const gtp::Bytes&, gtp::Bytes {
    $1 = lua_isstring(L, $input);
}

/* Captured Lua callables (see the bridge block above). */
struct GtpLuaFn;
struct GtpLuaTable;
%typemap(in, checkfn="lua_isfunction") GtpLuaFn {
    lua_pushvalue(L, $input);
    $1.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    $1.L   = L;
}
%typemap(in, checkfn="lua_istable") GtpLuaTable {
    lua_pushvalue(L, $input);
    $1.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    $1.L   = L;
}
/* The script-friendly methods below overload the C++ handler-pointer
 * signatures; these let SWIG's dispatcher tell a function/table apart
 * from a (never-passed-from-Lua) handler proxy. */
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) GtpLuaFn {
    $1 = lua_isfunction(L, $input);
}
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) GtpLuaTable {
    $1 = lua_istable(L, $input);
}
#endif

/* ---- directors (Python only; SWIG has no Lua director support) ---- */

#ifdef SWIGPYTHON
%feature("director") gtp::EndpointHandler;
%feature("director") gtp::UserPlaneEventHandler;
#endif

/* ---- pruning: internals that make no sense in a script ---- */

%ignore gtp::Error;

/* the C codec below is exposed for its enums and constants only */
%ignore gtp2_hdr_decode;   %ignore gtp2_hdr_encode;   %ignore gtp2_hdr_finalize;
%ignore gtp2_ie_iter_init; %ignore gtp2_ie_iter_next; %ignore gtp2_ie_iter_grouped;
%ignore gtp2_wbuf_init;    %ignore gtp2_ie_put;       %ignore gtp2_ie_begin;
%ignore gtp2_ie_end;       %ignore gtp2_ie_put_u8;    %ignore gtp2_ie_put_u16;
%ignore gtp2_ie_put_u32;
%ignore gtp2_fteid_decode; %ignore gtp2_fteid_put;
%ignore gtp2_bearer_qos_decode; %ignore gtp2_bearer_qos_put;
%ignore gtp2_paa_decode;   %ignore gtp2_paa_put;
%ignore gtp2_ambr_decode;  %ignore gtp2_ambr_put;
%ignore gtp2_hdr_t;        %ignore gtp2_ie_view_t;    %ignore gtp2_view_t;
%ignore gtp2_fteid_t;      %ignore gtp2_bearer_qos_t; %ignore gtp2_paa_t;
%ignore gtp2_ambr_t;

/* enums + constants: message types, IE types, causes, RAT/PDN/interface
 * types, error codes */
%include "gtp2.h"
%include "gtp2_ie.h"

/* ---- the facade itself ---- */

/* net::Loop lives in the net module; %import it (no wrappers generated)
 * so SWIG knows the type and gtp.Endpoint accepts a net.Loop proxy
 * through the shared cross-module type table. net::Error is not part of
 * gtp's surface — silence the "unknown base std::runtime_error" note the
 * header import raises for it (the net module wraps/ignores it itself). */
%warnfilter(401) net::Error;
%import "netxx.hpp"

%include "gtpxx.hpp"

/* value-type containers used in message structs */
%template(IeList)            std::vector<gtp::Ie>;
%template(FteidEntryList)    std::vector<gtp::FteidEntry>;
%template(BearerContextList) std::vector<gtp::BearerContext>;
%template(SessionList)       std::vector<gtp::Session*>;
%template(UserPlaneTunnelList) std::vector<gtp::UserPlaneTunnel>;

/* ---- Lua-friendly callback entry points ----
 *
 * These overload the C++ handler-pointer signatures (SWIG dispatches on
 * the argument type — see the GtpLuaFn/GtpLuaTable typechecks): a handler
 * is a table of callback functions, a timer/io/event callback a bare
 * function. The adapter that wraps each is owned by a registry keyed to
 * the C++ object that borrows it (endpoint / timer id / fd) so it lives
 * as long as needed; a one-shot timer drops its own entry when it fires.
 * cancel()/del_fd() keep the C++ signature (no handler argument), so a
 * cancelled timer or removed fd leaves its adapter in the registry until
 * the id/fd is reused — a bounded cost paid only on those paths. */
#ifdef SWIGLUA
%extend gtp::Endpoint {
    void set_handler(GtpLuaTable handler) {
        auto* h = new LuaEndpointHandler(handler.L, handler.ref);
        gtplua_handlers()[$self].reset(h);   /* frees any previous handler */
        $self->set_handler(h);
    }
}

%extend gtp::UserPlane {
    int poll_events(int timeout_ms, GtpLuaFn fn) {
        LuaUpEvHandler h(fn.L, fn.ref);       /* transient: freed below */
        int rc = $self->poll_events(timeout_ms, &h);
        luaL_unref(fn.L, LUA_REGISTRYINDEX, fn.ref);
        return rc;
    }
}
#endif

/* Anchor the registry-cleanup sentinel (see gtplua_atclose). */
#ifdef SWIGLUA
%init %{
{
    lua_newuserdata(L, 1);
    lua_newtable(L);
    lua_pushcfunction(L, gtplua_atclose);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);
    luaL_ref(L, LUA_REGISTRYINDEX);   /* keep it alive until lua_close */
}
%}
#endif

/* ---- keep borrowed objects alive from the Python side ----
 *
 * The C++ layer borrows handlers and the loop (see gtpxx.hpp); these
 * wrappers pin the Python objects to the proxy that needs them so the
 * garbage collector cannot free a handler the C++ side still calls. (The
 * Lua binding pins them in the registries defined in the bridge block.) */

#ifdef SWIGPYTHON
%pythoncode %{
def _gtp_pin(cls, method, pin):
    orig = getattr(cls, method)
    def wrapper(self, *a, **k):
        r = orig(self, *a, **k)
        pin(self, r, a)
        return r
    wrapper.__name__ = method
    wrapper.__doc__ = orig.__doc__
    setattr(cls, method, wrapper)

_gtp_pin(Endpoint, '__init__',
         lambda self, r, a: setattr(self, '_loop', a[0]))
_gtp_pin(Endpoint, 'set_handler',
         lambda self, r, a: setattr(self, '_handler', a[0]))
# Session proxies borrow from the Endpoint; keep it alive with them.
_gtp_pin(Endpoint, 'create_session',
         lambda self, r, a: setattr(r, '_ep', self))
_gtp_pin(Endpoint, 'session_by_teid',
         lambda self, r, a: r is not None and setattr(r, '_ep', self))
# The loop is a net.Loop (net module); Endpoint.__init__ above pins it as
# self._loop so the GC keeps it alive as long as the endpoint. Its timer/
# fd handlers are pinned by the net module's own wrappers.
del _gtp_pin
%}
#endif
