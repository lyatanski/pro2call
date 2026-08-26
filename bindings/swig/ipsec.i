/* SWIG interface for the IPsec/XFRM manipulation module — wraps the
 * ipsecxx C++ facade (bindings/cxx/inc/ipsecxx.hpp) into a Lua module
 * named `ipsec`. The facade is imperative (add/delete SAs and policies,
 * flush) with no callbacks, so unlike the gtp module it needs no
 * directors — a plain value-type binding.
 *
 * Lua quick tour:
 *
 *   local ipsec = require("ipsec")
 *
 *   local x = ipsec.Xfrm()               -- opens NETLINK_XFRM (needs root)
 *
 *   local sa = ipsec.Sa()
 *   sa.src, sa.dst = "10.0.0.1", "10.0.0.2"
 *   sa.spi   = 0x100
 *   sa.proto = ipsec.PROTO_ESP
 *   sa.mode  = ipsec.TUNNEL
 *   sa.reqid = 1
 *   sa.enc_alg,  sa.enc_key  = "cbc(aes)",     ("\0"):rep(16)
 *   sa.auth_alg, sa.auth_key = "hmac(sha256)", ("\0"):rep(32)
 *   x:sa_add(sa)                          -- raises on kernel error
 *
 * Keys and addresses are ordinary Lua strings; a key is the raw bytes,
 * so build it however you like (string.char, a literal, a file read).
 *
 * The four SAs of an IMS-AKA registration (TS 33.203 §6.3) are one
 * object rather than eight calls, because they are negotiated, raised
 * and torn down together:
 *
 *   local e = ipsec.Esp()
 *   e.ue,      e.pcscf  = "10.45.0.2", "10.10.0.20"
 *   e.port_uc, e.port_us = 5088, 5088       -- the UE's protected ports
 *   e.spi_uc,  e.spi_us  = 0x2001, 0x2002   -- and its inbound SPIs
 *   e.port_pc, e.port_ps = 6100, 6101       -- from the Security-Server
 *   e.spi_pc,  e.spi_ps  = 0x3001, 0x3002
 *   e.auth_key = ik                     -- ealg=null, so CK goes unused
 *
 *   local refused = e:establish(x)       -- 0 = all four SAs + policies in
 *   for i = 0, e:error_count() - 1 do print(e:error_at(i)) end
 *   e:release(x)                         -- deletes exactly what went in
 *
 * Iteration is a count()/at(i) pair rather than a wrapped vector: SWIG's
 * Lua runtime keys wrapped types in a registry SHARED by every module in
 * one lua_State, so a %template here would fight with another module's
 * over the same C++ type.
 */

%module ipsec

%{
#include "ipsecxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <exception.i>

/* shared move-on-value-return typemap */
%include "common.i"

/* ---- exceptions: ipsec::Error / std::exception -> Lua error ---- */

%exception {
    try {
        $action
    } catch (const ipsec::Error& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    } catch (const std::exception& e) {
        SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

/* Error carries data but is only ever thrown, never constructed from a
 * script; expose the class for the constants but not as a value type. */
%ignore ipsec::Error;

/* Keys are byte strings: std_string.i already maps std::string with its
 * length (embedded NULs preserved), so no custom typemaps are needed —
 * that is the whole reason the facade uses std::string for key bytes. */

%include "ipsecxx.hpp"
