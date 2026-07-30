/* SWIG interface for the SDP codec — wraps the sdpxx C++ facade
 * (bindings/cxx/inc/sdpxx.hpp) over the C codec (sdp/) into a Lua
 * module named `sdp`. Pure value types plus a fluent Builder; no
 * callbacks, so no directors.
 *
 * Lua quick tour — the whole offer/answer a UE placing a call needs:
 *
 *   local sdp = require("sdp")
 *
 *   local body = sdp.offer{ addr = ue_paa, port = 40000 }   -- into the INVITE
 *
 *   local a = sdp.parse(rsp.body)                           -- the 200 OK's SDP
 *   if a:has_audio() then
 *       local s = a:audio()
 *       if not s:rejected() then
 *           rtp_session:set_peer(s.addr, s.port)            -- s.addr is resolved
 *       end
 *   end
 *
 * Media types, transport protocols, attribute names and directions are
 * enum constants (sdp.M_AUDIO, sdp.P_RTP_AVP, sdp.A_RTPMAP,
 * sdp.DIR_SENDRECV), resolved during the parse, so scripts never match
 * SDP text by hand. An attribute the table has no id for arrives as
 * sdp.A_OTHER with its wire name preserved, reachable by
 * :attr_name("x-whatever").
 *
 * Two rules that are easy to get wrong are applied by the facade, not
 * by the caller: a media-level c= overrides the session-level one (so
 * `s.addr` is already the right host), and m= port 0 is a rejection,
 * surfaced as :rejected() rather than as a silent zero port.
 *
 * Deliberately no %template for any std::vector: SWIG's Lua runtime
 * keys wrapped types in a registry SHARED by every module in one
 * lua_State, so a second module declaring std::vector<std::string>
 * under a different name fights with sip.i's StringList over the same
 * C++ type. Everything a script iterates is exposed as a
 * count()/at(i) pair instead — the same shape sip.Msg uses for
 * headers, and one less way for two modules to break each other.
 */

%module sdp

%{
#include "sdpxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <exception.i>

/* shared move-on-value-return typemap */
%include "common.i"

/* ---- exceptions: sdp::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const sdp::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script. */
%ignore sdp::Error;

/* The backing vectors are the accessors' business; scripts walk them
 * with attr_count()/attr_at(), media_count()/media_at() and friends. */
%ignore sdp::Msg::medias;
%ignore sdp::Msg::attrs;
%ignore sdp::Msg::bws;
%ignore sdp::Media::attrs;
%ignore sdp::Media::fmts;
%ignore sdp::Media::bws;

/* SWIG's Lua runtime keys class metatables in the registry by the
 * UNSCOPED class name, so two modules loaded into one interpreter must
 * not both wrap a class called Msg or Builder — sip.i has both, and the
 * later module's objects would dispatch into the earlier one's methods
 * with no warning at build or load time. Register unique names and
 * alias the plain ones back below, so scripts keep writing sdp.Builder()
 * (the same trick diam.i uses). `Media`, `Attr`, `Conn`, `Origin`, `Bw`,
 * `Rtpmap` and `Offer` are unique across the modules as they stand;
 * check before adding another. */
%rename(SdpMsg)     sdp::Msg;
%rename(SdpBuilder) sdp::Builder;

/* ---- fluent returns must not orphan the owner ----------------------
 *
 * See the same block in swig/sip.i and swig/diam.i. Builder's setters
 * return *this; SWIG's default `out` typemap wraps that reference in a
 * FRESH, NON-owning userdata, so in the documented idiom
 *
 *     local b = sdp.Builder():version()
 *
 * the only owning handle is unreachable the moment version() returns
 * and the next GC frees the Builder mid-chain. Hand back the caller's
 * own userdata so ownership survives the chain. */
#ifdef SWIGLUA
%typemap(out) sdp::Builder& %{
    lua_pushvalue(L, 1);
    SWIG_arg++;
%}
#endif

%include "sdpxx.hpp"

#ifdef SWIGLUA
%luacode %{
sdp.Msg     = sdp.SdpMsg
sdp.Builder = sdp.SdpBuilder

-- offer() takes an sdp.Offer, but a table reads far better at a call
-- site that only sets two of eleven fields, so accept either. Unknown
-- keys are an error rather than a silent no-op: a typo'd `prt = 40000`
-- would otherwise offer port 0, which is a rejected stream.
local OFFER_FIELDS = {
    addr = true, port = true, pt = true, codec = true, rate = true,
    ptime = true, dir = true, id = true, version = true, user = true,
    name = true, addrtype = true,
}
local offer_struct = sdp.offer
function sdp.offer(t)
    if type(t) ~= "table" then return offer_struct(t) end
    local o = sdp.Offer()
    for k, v in pairs(t) do
        if not OFFER_FIELDS[k] then
            error("sdp.offer: unknown field '" .. tostring(k) .. "'", 2)
        end
        o[k] = v
    end
    return offer_struct(o)
end
%}
#endif
