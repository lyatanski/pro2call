/* SWIG interface for the Diameter codec — wraps the diamxx C++ facade
 * (bindings/cxx/inc/diamxx.hpp) and the generated dictionary
 * (diam/gen/inc/diam_dict.h) into a Lua module named `diam`. Pure
 * value types plus a fluent Builder; no callbacks, so no directors.
 *
 * Lua quick tour:
 *
 *   local diam = require("diam")
 *
 *   local wire = diam.Builder()
 *       :request(diam.CMD_CREDIT_CONTROL, diam.APP_CREDIT_CONTROL)
 *       :ids(1, 1)
 *       :put_str(diam.AVP_SESSION_ID, "gw.example.net;1;1")
 *       :put_u32(diam.AVP_CC_REQUEST_TYPE, diam.CC_REQUEST_TYPE_INITIAL_REQUEST)
 *       :begin_group(diam.AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
 *           :put_u32(diam.AVP_RATING_GROUP, 100)
 *       :end_group()
 *       :done()
 *
 *   local msg = diam.parse(wire)          -- raises on malformed input
 *   if msg.request and msg.cmd == diam.CMD_CREDIT_CONTROL then
 *       print(msg:name(), msg:str(diam.AVP_SESSION_ID))
 *   end
 *
 * All DIAM_* dictionary constants are exposed with the prefix stripped
 * (diam.AVP_SESSION_ID, diam.CMD_CREDIT_CONTROL, diam.APP_CX,
 * diam.VENDOR_3GPP, diam.CC_REQUEST_TYPE_INITIAL_REQUEST, ...), as are
 * the dictionary lookups (diam.avp_name(code, vendor), diam.cmd_name,
 * diam.app_name, diam.enum_name, diam.dict_get). Vendor ids and wire
 * flags of known AVPs are filled in by the Builder automatically. */

%module diam

%{
#include "diamxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <std_vector.i>
%include <exception.i>

/* ---- exceptions: diam::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const diam::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script. */
%ignore diam::Error;

/* Drop the DIAM_/diam_ prefix from the generated dictionary constants
 * and the C lookup helpers: DIAM_AVP_SESSION_ID -> diam.AVP_SESSION_ID,
 * diam_avp_name -> diam.avp_name. Names without the prefix (the C++
 * facade) pass through unchanged. */
%rename("%(regex:/^(?:DIAM_|diam_)(.+)$/\\1/)s") "";

/* SWIG's Lua runtime keys class metatables in the registry by the
 * unscoped class name, so two modules loaded into one interpreter must
 * not both wrap a class called Msg/Builder/Session (sip has the first
 * two, gtp the third) — the later module's objects would dispatch into
 * the earlier one's methods. Register unique names here and alias the
 * plain ones back below, so scripts keep writing diam.Builder(). */
%rename(DiamMsg)     diam::Msg;
%rename(DiamBuilder) diam::Builder;
%rename(DiamSession) diam::Session;

%luacode %{
diam.Msg     = diam.DiamMsg
diam.Builder = diam.DiamBuilder
diam.Session = diam.DiamSession
%}

%template(AvpList) std::vector<diam::Avp>;

/* Dictionary entries are read-only tables (the struct is an anonymous
 * typedef, so the member is matched unqualified). */
%immutable name;

/* Message payloads are byte strings: std_string.i maps std::string with
 * its length (embedded NULs preserved), so binary AVP data survives. */

%include "diam_dict.h"
%include "diamxx.hpp"
