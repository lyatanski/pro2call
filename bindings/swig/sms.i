/* SWIG interface for the SMS codec — wraps the smsxx C++ facade
 * (bindings/cxx/inc/smsxx.hpp) over the C codec (sms/) into a Lua module
 * named `sms`. Pure value types plus free functions; no callbacks, so no
 * directors.
 *
 * Lua quick tour — one SMS over IMS, both ends:
 *
 *   local sms = require("sms")
 *
 *   -- MO: the body of a SIP MESSAGE to the service centre PSI
 *   local body = sms.submit{ to = "+447700900123", text = "hi", srr = true }
 *   ue:send(sip.Builder():request(sip.M_MESSAGE, sc_uri)
 *       :hdr(sip.H_CONTENT_TYPE, sms.CONTENT_TYPE)  -- vnd.3gpp.sms
 *       ... :done(body))
 *
 *   -- MT: what arrives at the other UE
 *   local rp = sms.parse_rpdu(req.body, sms.DIR_SC_TO_MS)
 *   if rp.type == sms.RP_T_DATA then
 *       local t = rp:tpdu()                   -- direction handled for you
 *       print(t.addr:display(), t:text())     -- "+44...", "hi"
 *       ue:send(200_ok)                       -- the SIP hop
 *       ue:send(message_with(sms.ack(sms.DIR_MS_TO_SC, rp.mr)))
 *   end
 *
 * Message types, alphabets, causes and type-of-number are enum
 * constants (sms.T_SUBMIT, sms.ALPHA_UCS2, sms.RP_CAUSE_CONGESTION,
 * sms.TON_INTERNATIONAL), resolved during the parse, so scripts never
 * match SMS text or bit-twiddle a TP-DCS by hand.
 *
 * Three rules that are easy to get wrong are applied by the facade
 * rather than by the caller: the six TPDU types are flattened onto one
 * `Tpdu` with a `type` tag (no union arms to reach into), `Rpdu:tpdu()`
 * parses the contained TPDU with the direction the RPDU implies plus the
 * RP-ERROR modifier, and `Tpdu:text()` applies TP-DCS, TP-UDHI and
 * TP-UDL together — which is the only way to get the septet alignment
 * and the length units right at once.
 *
 * Bodies are byte strings throughout. std_string.i maps std::string with
 * its length, so an RPDU with an embedded 0x00 — which is every message
 * containing a GSM 7-bit '@', and every 8-bit payload — survives the
 * round trip. test_sms_bindings.lua asserts exactly that, because a
 * future typemap change would otherwise break SMS silently.
 *
 * Deliberately no %template for any std::vector: SWIG's Lua runtime keys
 * wrapped types in a registry SHARED by every module in one lua_State,
 * so a second module declaring std::vector<std::string> under a
 * different name fights with sip.i's StringList over the same C++ type.
 * Everything a script iterates is exposed as a count()/at(i) pair
 * instead — the same shape sip.Msg uses for headers.
 */

%module sms

%{
#include "smsxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <exception.i>

/* shared move-on-value-return typemap */
%include "common.i"

/* ---- exceptions: sms::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const sms::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script. */
%ignore sms::Error;

/* The backing vectors are Parts::at()'s business. */
%ignore sms::Parts::v_;
%ignore sms::Parts::tv_;

/* SWIG's Lua runtime keys class metatables in the registry by the
 * UNSCOPED class name, so two modules loaded into one interpreter must
 * not both wrap a class called Builder/Msg/Session/Addr — sip has the
 * first two, gtp the third, net the fourth. Of the names this module
 * introduces (Tpdu, Rpdu, Address, Timestamp, Dcs, UdhIe, Concat,
 * Submission, Delivery, Parts) all are unique across the modules as they
 * stand; `Address` deliberately is not `Addr`, which netxx already
 * wraps. Check before adding another — the failure mode is silent at
 * both build and load time, and test_sms_coexist.lua is what catches
 * it.
 *
 * The one collision is Timestamp vs nothing today, but rtpxx grows
 * report types; keep this list in sync. */

/* ---- SMS_ALPHA_AUTO is negative --------------------------------------
 *
 * sms::ALPHA_AUTO is -1 and lands in an `int` parameter, which SWIG's
 * Lua typemap accepts. Nothing to do here, but it is the one enum value
 * that is not a wire value, so it is worth naming: passing it asks the
 * encoder to choose GSM 7-bit or UCS2 the way a handset does. */

%include "smsxx.hpp"

#ifdef SWIGLUA
%luacode %{
-- submit()/deliver() take a struct, but a table reads far better at a
-- call site that sets two of a dozen fields, so accept either — the same
-- ergonomics as sdp.offer{}. Unknown keys are an error rather than a
-- silent no-op: a typo'd `txt = "hi"` would otherwise send an empty
-- message, which looks like a network fault.
local SUBMIT_FIELDS = {
    to = true, text = true, sc = true, alphabet = true, srr = true,
    rd = true, rp = true, mr = true, pid = true, cls = true,
    validity = true, udh = true,
}
local DELIVER_FIELDS = {
    from = true, text = true, sc = true, alphabet = true, sri = true,
    more = true, rp = true, mr = true, pid = true, cls = true,
    scts = true, tz = true, udh = true,
}

local function fill(ctor, fields, what, t)
    local o = ctor()
    for k, v in pairs(t) do
        if not fields[k] then
            error(what .. ": unknown field '" .. tostring(k) .. "'", 3)
        end
        o[k] = v
    end
    return o
end

local submit_struct  = sms.submit
local submit_tpdu_s  = sms.submit_tpdu
local deliver_struct = sms.deliver
local deliver_tpdu_s = sms.deliver_tpdu
local submit_parts_s = sms.submit_parts
local deliver_parts_s = sms.deliver_parts

local function as_submission(t)
    if type(t) ~= "table" then return t end
    return fill(sms.Submission, SUBMIT_FIELDS, "sms.submit", t)
end
local function as_delivery(t)
    if type(t) ~= "table" then return t end
    return fill(sms.Delivery, DELIVER_FIELDS, "sms.deliver", t)
end

sms.submission = as_submission
sms.delivery   = as_delivery

function sms.submit(t)       return submit_struct(as_submission(t))  end
function sms.submit_tpdu(t)  return submit_tpdu_s(as_submission(t))  end
function sms.deliver(t)      return deliver_struct(as_delivery(t))   end
function sms.deliver_tpdu(t) return deliver_tpdu_s(as_delivery(t))   end

function sms.submit_parts(t, ref, ref16)
    return submit_parts_s(as_submission(t), ref, ref16 or false)
end
function sms.deliver_parts(t, ref, ref16)
    return deliver_parts_s(as_delivery(t), ref, ref16 or false)
end

-- Parts:count()/:at(i) is the wrapped shape; a plain array is what a
-- script wants to loop over, and 1-based indexing is what Lua wants.
function sms.parts(p)
    local out = {}
    for i = 0, p:count() - 1 do out[i + 1] = p:at(i) end
    return out
end
%}
#endif
