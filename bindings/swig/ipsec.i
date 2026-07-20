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
 */

%module ipsec

%{
#include "ipsecxx.hpp"
%}

#define API_EXPORT

%include <stdint.i>
%include <std_string.i>
%include <exception.i>

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
