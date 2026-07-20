/* SWIG interface for the SIP codec — wraps the sipxx C++ facade
 * (bindings/cxx/inc/sipxx.hpp) into a Lua module named `sip`. Pure
 * value types plus a fluent Builder; no callbacks, so no directors.
 *
 * Lua quick tour:
 *
 *   local sip = require("sip")
 *
 *   local wire = sip.Builder()
 *       :request(sip.INVITE, "sip:bob@biloxi.example.com")
 *       :header(sip.H_VIA, "SIP/2.0/UDP host;branch=z9hG4bK1")
 *       :header_u32(sip.H_MAX_FORWARDS, 70)
 *       :done("v=0\r\n")                 -- adds Content-Length itself
 *
 *   local msg = sip.parse(wire)          -- raises on malformed input
 *   if msg.request and msg.method == sip.INVITE then
 *       print(msg.uri, msg:call_id(), msg:cseq().number)
 *       print(msg:top_via().branch)      -- typed header accessors
 *   end
 *
 * Methods and header fields are enum constants (sip.INVITE, sip.H_VIA,
 * ...), resolved during the parse — a compact "v:" and a long "Via:"
 * are the same H_VIA, so scripts never string-match header names.
 */

%module sip

%{
#include "sipxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <std_vector.i>
%include <exception.i>

/* ---- exceptions: sip::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const sip::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script. */
%ignore sip::Error;

/* Scripts walk headers via header_count()/header_at()/header_values();
 * the backing vector stays an implementation detail. */
%ignore sip::Msg::hdrs;

%template(StringList) std::vector<std::string>;

/* Message bodies are byte strings: std_string.i maps std::string with
 * its length (embedded NULs preserved), so binary payloads survive. */

%include "sipxx.hpp"
