/* Typemaps shared by every module in this directory; each .i %includes
 * this before the facade header it wraps.
 *
 * ---- by-value returns move instead of copy --------------------------
 *
 * Every facade returns value types — that is the facade contract: no
 * object a script sees borrows from a wire buffer, so the C layer's
 * zero-copy slices are materialized exactly once. SWIG's default `out`
 * typemap for a class returned by value then heap-*copies* that local
 * for the script:
 *
 *     sip::Msg* resultptr = new sip::Msg(result);
 *
 * so a sip.parse() allocated its header vector and all of its strings
 * twice — once building the Msg, once copying it out — and the same for
 * every gtp decode() and diam parse(). Move-construct instead.
 *
 * std::move on a type with no move constructor binds to the copy
 * constructor, so this is correct for every wrapped type, including the
 * plain C aggregates from gtp2.h. The moved-from local is the wrapper's
 * own `result` and is never touched again. */

#ifdef SWIGLUA
%{
#include <utility>
%}

/* Brackets are {...} not %{...%}: `out` typemaps have no local-variable
 * section, so the resultptr declaration must land in the wrapper body
 * (see the stock typemap in swig/lua/luatypemaps.swg). */
%typemap(out) SWIGTYPE
{
  $&1_ltype resultptr = new $1_ltype(std::move($1));
  SWIG_NewPointerObj(L,(void *) resultptr,$&1_descriptor,1); SWIG_arg++;
}
#endif
