/* SWIG interface for the RTP/RTCP stack — wraps the rtpxx C++ facade
 * (bindings/cxx/inc/rtpxx.hpp) over the C codec (rtp/) into a Lua module
 * named `rtp`: the packet codec as a value type, and the media session
 * that drives one stream over a net_loop-registered socket pair.
 *
 * Two target languages, one facade (as in gtp.i / net.i):
 *
 *   - Python uses SWIG directors: a script subclasses StreamHandler.
 *   - Lua has no SWIG director support, so the callbacks are bridged by
 *     hand (see the SWIGLUA block below): the handler is a table of Lua
 *     functions and the C++ virtual calls trampoline into it. A raised
 *     Lua error becomes an rtp::Error, which the loop defers and
 *     re-raises from step()/run() exactly as it does for a C++ exception.
 *
 * The event loop is the net module's (net.Loop, bindings/swig/net.i) —
 * a Stream takes one, so a script requires both modules and gives its
 * media the same loop its GTP-C and SIP already run on. One loop:run()
 * then drives signalling and media together; there is no second loop to
 * starve.
 *
 * Lua quick tour — two sessions talking to each other on one loop:
 *
 *   local net = require("net")
 *   local rtp = require("rtp")
 *
 *   local loop = net.Loop()
 *   local a = rtp.Stream(loop, "127.0.0.1", 41000)
 *   local b = rtp.Stream(loop, "127.0.0.1", 41002)
 *   a:set_peer("127.0.0.1", b:rtp_port())
 *   b:set_peer("127.0.0.1", a:rtp_port())
 *
 *   b:set_handler({
 *       on_rtp = function(pkt, host, port) print(pkt.seq, #pkt.payload) end,
 *       on_receiver_report = function(ssrc, reports)
 *           for _, r in ipairs(reports) do print(r.fraction_lost, r.jitter) end
 *       end,
 *   })
 *
 *   a:send(("\0"):rep(160), 160)      -- one 20 ms G.711 packet
 *   loop:step(100)
 *   print(b:stats().rx_packets, a:stats().rtt_ms)
 *
 * Payloads are ordinary Lua strings (byte buffers), so building 160
 * bytes of PCMU is string.rep — the codec never interprets them.
 *
 * The class is `Stream`, not `Session`, and that is not a style choice:
 * SWIG's Lua runtime keys every wrapped class's metatable on its bare
 * name in a registry SHARED by all modules loaded into one lua_State
 * (swig_lua_class::fqname is "Session", not "rtp::Session"). A second
 * module wrapping a class of the same name silently replaces the first
 * one's metatable, and gtp::Session already owns that name — with
 * `Session` here, `require("gtp")` left every rtp method nil at runtime,
 * with no warning from SWIG at either build or load time. Do not rename
 * it back; the same trap applies to any new class added to this module.
 */

%module(directors="1") rtp

%{
#include "rtpxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <std_vector.i>
%include <exception.i>

/* shared move-on-value-return typemap */
%include "common.i"

/* ---- Lua callback bridge ----------------------------------------------
 *
 * SWIG cannot generate directors for Lua, so a Lua "handler" cannot
 * subclass rtp::StreamHandler. Instead this adapter holds a reference to
 * a Lua table of callbacks and forwards each virtual call into it; absent
 * keys stay no-ops, so a script that only wants on_rtp writes only that.
 *
 * Report blocks are handed over as a Lua array of ReportBlock proxies
 * rather than a vector proxy: `for _, r in ipairs(reports)` is what a
 * script wants to write, and the copies own their data (the C++ vector is
 * a temporary of the receive path).
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

/* A captured Lua table of callbacks (built by the typemap below). */
struct RtpLuaTable { lua_State* L; int ref; };

/* Hand a C++ object to Lua as a SWIG proxy; the copy is owned, so Lua's
 * GC collects it once the callback is done with it. */
static void rtplua_owned(lua_State* L, void* p, const char* ty)
    { SWIG_NewPointerObj(L, p, SWIG_TypeQuery(ty), SWIG_POINTER_OWN); }

/* Owner registry so an adapter outlives the session that borrows it: one
 * handler per session, keyed by its address. Re-setting a handler frees
 * the previous one, and so does a new session landing on a freed
 * session's address — which bounds this to the live sessions rather than
 * to every session a run ever made. Function-local static, so it stays a
 * single definition. */
class LuaStreamHandler;
static std::unordered_map<rtp::Stream*, std::unique_ptr<LuaStreamHandler>>& rtplua_handlers();

class LuaStreamHandler : public rtp::StreamHandler {
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
            throw rtp::Error(std::string("lua handler '") + cur_ + "': " + m);
        }
        lua_pop(L_, 1);                                 /* table */
    }
    void pstr(const std::string& s) { lua_pushlstring(L_, s.data(), s.size()); }

    /* One reception-report array, 1-based as Lua counts. */
    void preports(const std::vector<rtp::ReportBlock>& v) {
        lua_createtable(L_, (int)v.size(), 0);
        for (size_t i = 0; i < v.size(); i++) {
            rtplua_owned(L_, new rtp::ReportBlock(v[i]), "rtp::ReportBlock *");
            lua_rawseti(L_, -2, (int)i + 1);
        }
    }

public:
    LuaStreamHandler(lua_State* L, int ref) : L_(L), ref_(ref) {}
    ~LuaStreamHandler() override {
        if (L_ && ref_ != LUA_NOREF) luaL_unref(L_, LUA_REGISTRYINDEX, ref_);
    }

    void on_rtp(const rtp::Packet& p, const std::string& host, uint16_t port) override {
        if (!begin("on_rtp")) return;
        rtplua_owned(L_, new rtp::Packet(p), "rtp::Packet *");
        pstr(host); lua_pushinteger(L_, port);
        call(3);
    }
    void on_sender_report(uint32_t ssrc, const rtp::SenderInfo& si,
                          const std::vector<rtp::ReportBlock>& reports) override {
        if (!begin("on_sender_report")) return;
        lua_pushinteger(L_, (lua_Integer)ssrc);
        rtplua_owned(L_, new rtp::SenderInfo(si), "rtp::SenderInfo *");
        preports(reports);
        call(3);
    }
    void on_receiver_report(uint32_t ssrc,
                            const std::vector<rtp::ReportBlock>& reports) override {
        if (!begin("on_receiver_report")) return;
        lua_pushinteger(L_, (lua_Integer)ssrc);
        preports(reports);
        call(2);
    }
    void on_bye(uint32_t ssrc, const std::string& reason) override {
        if (!begin("on_bye")) return;
        lua_pushinteger(L_, (lua_Integer)ssrc);
        pstr(reason);
        call(2);
    }
};

static std::unordered_map<rtp::Stream*, std::unique_ptr<LuaStreamHandler>>& rtplua_handlers()
    { static std::unordered_map<rtp::Stream*, std::unique_ptr<LuaStreamHandler>> m; return m; }

/* Drop every adapter (and its registry ref) while the lua_State is still
 * valid. Anchored in %init as a userdata __gc so it runs during
 * lua_close; otherwise this map — a C++ static that outlives the state —
 * would luaL_unref() against a freed lua_State at process teardown. */
static int rtplua_atclose(lua_State* L) {
    (void)L;
    rtplua_handlers().clear();
    return 0;
}
%}
#endif

/* ---- exceptions: rtp::Error -> scripting error ---- */

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
    } catch (const rtp::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#else
%exception {
    try {
        $action
    } catch (const rtp::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}
#endif

/* ---- Lua: capture a handler table as an RtpLuaTable ---- */

#ifdef SWIGLUA
struct RtpLuaTable;
%typemap(in, checkfn="lua_istable") RtpLuaTable {
    lua_pushvalue(L, $input);
    $1.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    $1.L   = L;
}
/* The script-friendly set_handler below overloads the C++
 * handler-pointer signature; this lets SWIG's dispatcher tell a table
 * apart from a (never-passed-from-Lua) handler proxy. */
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) RtpLuaTable {
    $1 = lua_istable(L, $input);
}
#endif

/* ---- directors (Python only; SWIG has no Lua director support) ---- */

#ifdef SWIGPYTHON
%feature("director") rtp::StreamHandler;
#endif

/* ---- pruning ---- */

%ignore rtp::Error;

/* ---- the facade itself ---- */

/* net::Loop lives in the net module; %import it (no wrappers generated)
 * so SWIG knows the type and rtp.Stream accepts a net.Loop proxy
 * through the shared cross-module type table. net::Error is not part of
 * rtp's surface — silence the "unknown base std::runtime_error" note the
 * header import raises for it (the net module wraps/ignores it itself). */
%warnfilter(401) net::Error;
%import "netxx.hpp"

%include "rtpxx.hpp"

/* Value-type containers in the facade's surface: a packet's CSRC list and
 * the report blocks of an SR/RR. (The Lua handler bridge hands reports
 * over as a plain array; these make the vectors usable wherever one is
 * reached directly.) */
%template(U32List)         std::vector<uint32_t>;
%template(ReportBlockList) std::vector<rtp::ReportBlock>;

/* ---- Lua-friendly callback entry point ----
 *
 * Overloads the C++ handler-pointer signature (SWIG dispatches on the
 * argument type — see the RtpLuaTable typecheck): a handler is a table of
 * callback functions. The adapter that wraps it is owned by a registry
 * keyed to the session that borrows it, so it lives as long as needed. */
#ifdef SWIGLUA
%extend rtp::Stream {
    void set_handler(RtpLuaTable handler) {
        auto* h = new LuaStreamHandler(handler.L, handler.ref);
        rtplua_handlers()[$self].reset(h);   /* frees any previous handler */
        $self->set_handler(h);
    }
}
#endif

/* Anchor the registry-cleanup sentinel (see rtplua_atclose). */
#ifdef SWIGLUA
%init %{
{
    lua_newuserdata(L, 1);
    lua_newtable(L);
    lua_pushcfunction(L, rtplua_atclose);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);
    luaL_ref(L, LUA_REGISTRYINDEX);   /* keep it alive until lua_close */
}
%}
#endif

/* ---- keep borrowed objects alive from the Python side ----
 *
 * The C++ layer borrows the handler and the loop (see rtpxx.hpp); these
 * wrappers pin the Python objects to the proxy that needs them so the
 * garbage collector cannot free something the C++ side still calls. (The
 * Lua binding pins them in the registry defined in the bridge block.) */

#ifdef SWIGPYTHON
%pythoncode %{
def _rtp_pin(cls, method, pin):
    orig = getattr(cls, method)
    def wrapper(self, *a, **k):
        r = orig(self, *a, **k)
        pin(self, r, a)
        return r
    wrapper.__name__ = method
    wrapper.__doc__ = orig.__doc__
    setattr(cls, method, wrapper)

_rtp_pin(Stream, '__init__',
         lambda self, r, a: setattr(self, '_loop', a[0]))
_rtp_pin(Stream, 'set_handler',
         lambda self, r, a: setattr(self, '_handler', a[0]))
del _rtp_pin
%}
#endif
