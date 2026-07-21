/* SWIG interface for the net transport layer — wraps the netxx C++
 * facade (bindings/cxx/inc/netxx.hpp) over the C net library (net/): the
 * epoll event loop and a non-blocking UDP socket.
 *
 * Two target languages, one facade (as in gtp.i):
 *
 *   - Python uses SWIG directors: a script subclasses TimerHandler /
 *     IoHandler directly.
 *   - Lua has no SWIG director support, so the callbacks are bridged by
 *     hand (see the SWIGLUA block below): a timer or fd callback is a
 *     bare Lua function, and the C++ virtual call trampolines into it. A
 *     raised Lua error becomes a net::Error, which the loop defers and
 *     re-raises from step()/run() exactly as it does for a C++ exception.
 *
 * Lua quick tour — a UDP socket driven by the loop:
 *
 *   local net  = require("net")
 *   local loop = net.Loop()
 *   local sock = net.UdpSocket("127.0.0.1", 0)      -- ephemeral port
 *   loop:add_fd(sock:fd(), net.NET_RD, function(fd, ev)
 *       local dg = sock:recv(-1)                     -- non-blocking drain
 *       print(dg.host, dg.port, dg.data)
 *       loop:stop()
 *   end)
 *   sock:sendto("ping", "127.0.0.1", sock:local_port())
 *   loop:run()
 */

%module(directors="1") net

%{
#include "netxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <std_vector.i>
%include <exception.i>

/* ---- Lua callback bridge ----------------------------------------------
 *
 * SWIG cannot generate directors for Lua, so a Lua callback cannot
 * subclass the C++ handler interfaces. Instead these adapters hold a Lua
 * function reference and forward each virtual call into Lua; a raised Lua
 * error becomes a net::Error that the loop's trampolines defer and
 * re-raise from step()/run() (see %exception below). Trimmed to the two
 * single-function handlers the loop needs — the gtp module's bridge
 * (bindings/swig/gtp.i) has the full version including a handler table.
 *
 * This block lands in the wrapper's header section, after the SWIG type
 * table, so SWIG_* helpers are already in scope. */
#ifdef SWIGLUA
%{
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
#include <memory>
#include <unordered_map>

/* A captured Lua callable (built by the typemap below). */
struct NetLuaFn { lua_State* L; int ref; };

/* Owner registries so an adapter outlives the C++ object that borrows
 * it: one per live timer, one per registered fd. Function-local statics
 * keep them to a single definition. */
class LuaTimerHandler;
class LuaIoHandler;
static std::unordered_map<uint64_t, std::unique_ptr<LuaTimerHandler>>& netlua_timers();
static std::unordered_map<int,      std::unique_ptr<LuaIoHandler>>&    netlua_ios();

/* One-shot timer: fires once, then drops its own registry entry. */
class LuaTimerHandler : public net::TimerHandler {
    lua_State* L_;
    int        ref_;
    uint64_t   id_ = 0;
public:
    LuaTimerHandler(lua_State* L, int ref) : L_(L), ref_(ref) {}
    ~LuaTimerHandler() override {
        if (L_ && ref_ != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref_);
    }
    void set_id(uint64_t id) { id_ = id; }
    void on_timer() override {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_);       /* the function */
        if (lua_pcall(L_, 0, 0, 0) != 0) {
            std::string m = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "error";
            lua_pop(L_, 1);
            throw net::Error("lua timer: " + m);
        }
        /* One-shot: drop our own registry entry. Move out first so the
         * delete of *this happens after erase() returns. */
        auto& m = netlua_timers();
        auto it = m.find(id_);
        if (it != m.end()) { auto keep = std::move(it->second); m.erase(it); }
    }
};

class LuaIoHandler : public net::IoHandler {
    lua_State* L_;
    int        ref_;
public:
    LuaIoHandler(lua_State* L, int ref) : L_(L), ref_(ref) {}
    ~LuaIoHandler() override {
        if (L_ && ref_ != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref_);
    }
    void on_io(int fd, unsigned events) override {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref_);
        lua_pushinteger(L_, fd);
        lua_pushinteger(L_, (lua_Integer)events);
        if (lua_pcall(L_, 2, 0, 0) != 0) {
            std::string m = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "error";
            lua_pop(L_, 1);
            throw net::Error("lua io handler: " + m);
        }
    }
};

static std::unordered_map<uint64_t, std::unique_ptr<LuaTimerHandler>>& netlua_timers()
    { static std::unordered_map<uint64_t, std::unique_ptr<LuaTimerHandler>> m; return m; }
static std::unordered_map<int, std::unique_ptr<LuaIoHandler>>& netlua_ios()
    { static std::unordered_map<int, std::unique_ptr<LuaIoHandler>> m; return m; }

/* Drop every adapter (and its registry ref) while the lua_State is still
 * valid. Anchored in %init as a userdata __gc so it runs during
 * lua_close; otherwise these maps — C++ statics that outlive the state —
 * would luaL_unref() against a freed lua_State at process teardown. */
static int netlua_atclose(lua_State* L) {
    (void)L;
    netlua_timers().clear();
    netlua_ios().clear();
    return 0;
}
%}
#endif

/* ---- exceptions: net::Error -> scripting error ---- */

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
    } catch (const net::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#else
%exception {
    try {
        $action
    } catch (const net::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#endif

/* ---- Lua: capture a callback function as a NetLuaFn ---- */

#ifdef SWIGLUA
struct NetLuaFn;
%typemap(in, checkfn="lua_isfunction") NetLuaFn {
    lua_pushvalue(L, $input);
    $1.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    $1.L   = L;
}
/* The script-friendly after()/add_fd() below overload the C++
 * handler-pointer signatures; this lets SWIG's dispatcher tell a Lua
 * function apart from a (never-passed-from-Lua) handler proxy. */
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) NetLuaFn {
    $1 = lua_isfunction(L, $input);
}
#endif

/* ---- directors (Python only; SWIG has no Lua director support) ---- */

#ifdef SWIGPYTHON
%feature("director") net::TimerHandler;
%feature("director") net::IoHandler;
#endif

/* ---- pruning: internals that make no sense in a script ---- */

%ignore net::Error;
%ignore net::Loop::raw;
%ignore net::Loop::life;
%ignore net::Loop::defer_exception;
%ignore net::Loop::rethrow_pending;

/* Loop event bits for add_fd() / on_io(). */
%constant int NET_RD = 1;
%constant int NET_WR = 2;
%constant int NET_ER = 4;

/* Return codes, also the negative values a raised error carries in
 * code() (Datagram.timed_out already flags the common recv() timeout). */
%constant int NET_OK      = 0;
%constant int NET_ERR     = -1;
%constant int NET_TIMEOUT = -2;

/* Record types for Resolver::resolve() (net_dns.h; SWIG does not parse
 * the #included header, so mirror the enum here). */
%constant int NET_DNS_A     = 1;
%constant int NET_DNS_AAAA  = 28;
%constant int NET_DNS_SRV   = 33;
%constant int NET_DNS_NAPTR = 35;

/* ---- the facade itself ---- */

%include "netxx.hpp"

/* Resolver::resolve() returns a vector of records (indexed list in Lua,
 * as gtp's IeList / UserPlaneTunnelList). */
%template(DnsRecordList) std::vector<net::DnsRecord>;

/* ---- Lua-friendly callback entry points ----
 *
 * These overload the C++ handler-pointer signatures (SWIG dispatches on
 * the argument type — see the NetLuaFn typecheck): a timer or fd
 * callback is a bare function. The adapter that wraps each is owned by a
 * registry keyed to the C++ object that borrows it (timer id / fd) so it
 * lives as long as needed; a one-shot timer drops its own entry when it
 * fires. cancel()/del_fd() keep the C++ signature (no function
 * argument), so a cancelled timer or removed fd leaves its adapter in
 * the registry until the id/fd is reused — a bounded cost. */
#ifdef SWIGLUA
%extend net::Loop {
    uint64_t after(uint64_t ms, NetLuaFn fn) {
        auto* h = new LuaTimerHandler(fn.L, fn.ref);
        uint64_t id = $self->after(ms, h);
        h->set_id(id);
        netlua_timers()[id].reset(h);
        return id;
    }
    void add_fd(int fd, unsigned events, NetLuaFn fn) {
        auto* h = new LuaIoHandler(fn.L, fn.ref);
        $self->add_fd(fd, events, h);
        netlua_ios()[fd].reset(h);            /* frees any previous handler */
    }
}
#endif

/* Anchor the registry-cleanup sentinel (see netlua_atclose). */
#ifdef SWIGLUA
%init %{
{
    lua_newuserdata(L, 1);
    lua_newtable(L);
    lua_pushcfunction(L, netlua_atclose);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);
    luaL_ref(L, LUA_REGISTRYINDEX);   /* keep it alive until lua_close */
}
%}
#endif

/* ---- keep borrowed handlers alive from the Python side ----
 *
 * The C++ layer borrows the timer/io handlers (see netxx.hpp); these
 * wrappers pin the Python objects to the Loop that needs them so the
 * garbage collector cannot free one the C++ side still calls. (The Lua
 * binding pins them in the registries defined in the bridge block.) */

#ifdef SWIGPYTHON
%pythoncode %{
def _net_pin(cls, method, pin):
    orig = getattr(cls, method)
    def wrapper(self, *a, **k):
        r = orig(self, *a, **k)
        pin(self, r, a)
        return r
    wrapper.__name__ = method
    wrapper.__doc__ = orig.__doc__
    setattr(cls, method, wrapper)

_net_pin(Loop, 'after',
         lambda self, r, a: self.__dict__.setdefault('_timers', {}).update({r: a[1]}))
_net_pin(Loop, 'cancel',
         lambda self, r, a: self.__dict__.get('_timers', {}).pop(a[0], None))
_net_pin(Loop, 'add_fd',
         lambda self, r, a: self.__dict__.setdefault('_ios', {}).update({a[0]: a[2]}))
_net_pin(Loop, 'del_fd',
         lambda self, r, a: self.__dict__.get('_ios', {}).pop(a[0], None))
del _net_pin
%}
#endif
