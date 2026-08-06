# Scripting bindings, all SWIG-generated from C++ facades over the C
#
# libraries:
#   gtp,   gtpxx,   swig/gtp.i,   GTP stack
#   ipsec, ipsecxx, swig/ipsec.i, IPsec/XFRM
#   sip,   sipxx,   swig/sip.i,   SIP stack
#   sdp,   sdpxx,   swig/sdp.i,   SDP codec (offer/answer)
#   sms,   smsxx,   swig/sms.i,   SMS codec (TPDU + RP layer)
#   diam,  diamxx,  swig/diam.i,  Diameter stack
#   rtp,   rtpxx,   swig/rtp.i,   RTP/RTCP media session
#   net,   netxx,   swig/net.i,   event loop + UDP socket
#   json,  jsonxx,  swig/json.i,  JSON codec (SBI bodies, config)
#
# Optional: without SWIG or lua's development files the whole directory is skipped

find_package(SWIG 4.0)
if(NOT SWIG_FOUND)
    message(STATUS "bindings: SWIG >= 4.0 not found; skipping")
    return()
endif()

find_package(Lua)
if(NOT Lua_FOUND)
    message(STATUS "bindings: no Lua development files found; skipping")
    return()
endif()

enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(UseSWIG)

# Everything linked into an extension module must be PIC. Applied here so
# the C libraries pay for it only when bindings build.
foreach(dep task net gtp2 gtpu xfrm rtnl sip sdp sms json diam rtp)
    set_target_properties(${dep} PROPERTIES POSITION_INDEPENDENT_CODE ON)
endforeach()

# --- gtp (gtpxx facade)
# The session layer (cxx/src/session.cpp) runs over net::Loop from the
# netxx facade, so gtpxx links netxx (which pulls in the C net library).
add_library(gtpxx STATIC
    cxx/src/util.cpp
    cxx/src/msg.cpp
    cxx/src/session.cpp
    cxx/src/userplane.cpp)
target_include_directories(gtpxx PUBLIC cxx/inc)
target_link_libraries(gtpxx PUBLIC gtp2 gtpu netxx net task)
set_target_properties(gtpxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/gtp.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/gtp.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# SWIG re-runs when the .i changes; the facade headers it %includes /
# %imports are not tracked automatically, so declare them or header-only
# edits are missed. gtp.i %imports netxx.hpp for the shared net::Loop and
# %includes the two gtp2 headers for their enums and constants.
set_property(SOURCE swig/gtp.i PROPERTY DEPENDS
    swig/common.i cxx/inc/gtpxx.hpp cxx/inc/netxx.hpp
    ${CMAKE_SOURCE_DIR}/gtp/v2/inc/gtp2.h
    ${CMAKE_SOURCE_DIR}/gtp/v2/inc/gtp2_ie.h)
# The CMake target is gtp_lua because `gtp` is the Python target; the
# loadable module is still gtp.so for `require("gtp")`.
swig_add_library(gtp_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/gtp.i)
set_target_properties(gtp_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME gtp
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(gtp_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(gtp_lua PRIVATE gtpxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(gtp_lua PRIVATE -w)   # generated wrapper code
endif()

# --- net (netxx facade)
# The event loop and UDP socket the gtp module embeds, exposed as a
# standalone module: net.Loop + net.UdpSocket for scripts that only need
# transport (put SIP/Diameter bytes on the wire, drive their own loop).
# It also fronts the rtnl netlink module (netlink/rtnl) for the interface
# address helpers (net.addr_add / net.addr_del), beside if_index/if_addr4,
# and the task library's address pool as net.IpPool.
add_library(netxx STATIC cxx/src/netxx.cpp)
target_include_directories(netxx PUBLIC cxx/inc)
# task carries the address pool behind net::IpPool (task/inc/ippool.h).
target_link_libraries(netxx PUBLIC net rtnl task)
set_target_properties(netxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/net.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/net.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# net_txq.h too: net.i mirrors NET_TXQ_BATCH as a %constant, so a change
# there must re-run SWIG rather than leave the Lua table stale.
set_property(SOURCE swig/net.i PROPERTY DEPENDS
    swig/common.i cxx/inc/netxx.hpp
    ${CMAKE_SOURCE_DIR}/net/inc/net_txq.h)
# The CMake target is net_lua because `net` is the C library; the
# loadable module is still net.so for `require("net")`.
swig_add_library(net_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/net.i)
set_target_properties(net_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME net
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(net_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(net_lua PRIVATE netxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(net_lua PRIVATE -w)   # generated wrapper code
endif()

# --- ipsec (ipsecxx facade)
# Milenage/MD5 (bindings/cxx/src/milenage.cpp) reuse OpenSSL's libcrypto,
# already pulled in by the net library.
find_package(OpenSSL REQUIRED)
add_library(ipsecxx STATIC cxx/src/ipsec.cpp cxx/src/milenage.cpp)
target_include_directories(ipsecxx PUBLIC cxx/inc)
target_link_libraries(ipsecxx PUBLIC xfrm OpenSSL::Crypto)
set_target_properties(ipsecxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/ipsec.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/ipsec.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
set_property(SOURCE swig/ipsec.i PROPERTY DEPENDS
    swig/common.i cxx/inc/ipsecxx.hpp)
swig_add_library(ipsec
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/ipsec.i)
# Lua loads `require("ipsec")` from ipsec.so (no leading underscore,
# unlike Python); drop the lib prefix and force the name.
set_target_properties(ipsec PROPERTIES
    PREFIX ""
    OUTPUT_NAME ipsec
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(ipsec PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(ipsec PRIVATE ipsecxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(ipsec PRIVATE -w)   # generated wrapper code
endif()

# --- sip (sipxx facade)
add_library(sipxx STATIC cxx/src/sip.cpp)
target_include_directories(sipxx PUBLIC cxx/inc)
target_link_libraries(sipxx PUBLIC sip)
set_target_properties(sipxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/sip.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/sip.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# sipxx.hpp %includes the facade; the SIP state-machine headers it pulls
# in (sip_fsm.h transactions, sip_dialog.h dialog/usage machines) are not
# tracked automatically, so declare them or their edits are missed.
set_property(SOURCE swig/sip.i PROPERTY DEPENDS
    swig/common.i cxx/inc/sipxx.hpp
    ${CMAKE_SOURCE_DIR}/sip/inc/sip_fsm.h
    ${CMAKE_SOURCE_DIR}/sip/inc/sip_dialog.h)
# The CMake target is sip_lua because `sip` is the C library; the
# loadable module is still sip.so for `require("sip")`.
swig_add_library(sip_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/sip.i)
set_target_properties(sip_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME sip
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(sip_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(sip_lua PRIVATE sipxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(sip_lua PRIVATE -w)   # generated wrapper code
endif()

# --- sdp (sdpxx facade)
# The offer/answer half of a call: sip carries the body, this parses and
# builds it. Nothing but the C codec behind it — no loop, no socket.
add_library(sdpxx STATIC cxx/src/sdp.cpp)
target_include_directories(sdpxx PUBLIC cxx/inc)
target_link_libraries(sdpxx PUBLIC sdp)
set_target_properties(sdpxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/sdp.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/sdp.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# The C codec header carries the enums and pool bounds the facade
# mirrors, so a change there must re-run SWIG rather than leave the Lua
# constant table stale.
set_property(SOURCE swig/sdp.i PROPERTY DEPENDS
    swig/common.i cxx/inc/sdpxx.hpp
    ${CMAKE_SOURCE_DIR}/sdp/inc/sdp.h)
# The CMake target is sdp_lua because `sdp` is the C library; the
# loadable module is still sdp.so for `require("sdp")`.
swig_add_library(sdp_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/sdp.i)
set_target_properties(sdp_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME sdp
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(sdp_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(sdp_lua PRIVATE sdpxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(sdp_lua PRIVATE -w)   # generated wrapper code
endif()

# --- sms (smsxx facade)
# The payload half of SMS over IMS: sip carries the RPDU in a MESSAGE
# body, this parses and builds it. Nothing but the C codec behind it —
# no loop, no socket.
add_library(smsxx STATIC cxx/src/sms.cpp)
target_include_directories(smsxx PUBLIC cxx/inc)
target_link_libraries(smsxx PUBLIC sms)
set_target_properties(smsxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/sms.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/sms.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# Both C codec headers carry the enums, causes and limits the facade
# mirrors, so a change there must re-run SWIG rather than leave the Lua
# constant table stale.
set_property(SOURCE swig/sms.i PROPERTY DEPENDS
    swig/common.i cxx/inc/smsxx.hpp
    ${CMAKE_SOURCE_DIR}/sms/inc/sms.h
    ${CMAKE_SOURCE_DIR}/sms/inc/sms_rp.h)
# The CMake target is sms_lua because `sms` is the C library; the
# loadable module is still sms.so for `require("sms")`.
swig_add_library(sms_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/sms.i)
set_target_properties(sms_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME sms
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(sms_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(sms_lua PRIVATE smsxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(sms_lua PRIVATE -w)   # generated wrapper code
endif()

# --- json (jsonxx facade)
# The text-payload codec: 5G SBI bodies, JSON Patch pointers, and the
# configuration/results the scripts themselves read and write. Nothing but
# the C codec behind it — no loop, no socket. The Lua module adds two
# hand-written converters (json.decode / json.encode) that build native
# tables straight from the node pool, so they live in swig/json.i rather
# than in the facade.
add_library(jsonxx STATIC cxx/src/json.cpp)
target_include_directories(jsonxx PUBLIC cxx/inc)
target_link_libraries(jsonxx PUBLIC json)
set_target_properties(jsonxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/json.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/json.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# The C codec header carries the node flags, error codes and depth bound
# the facade and the converters use, so a change there must re-run SWIG
# rather than leave the Lua constant table stale.
set_property(SOURCE swig/json.i PROPERTY DEPENDS
    swig/common.i cxx/inc/jsonxx.hpp
    ${CMAKE_SOURCE_DIR}/json/inc/json.h)
# The CMake target is json_lua because `json` is the C library; the
# loadable module is still json.so for `require("json")`.
swig_add_library(json_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/json.i)
set_target_properties(json_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME json
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(json_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(json_lua PRIVATE jsonxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(json_lua PRIVATE -w)   # generated wrapper code
endif()

# --- rtp (rtpxx facade)
# The media session (cxx/src/rtp.cpp) registers its socket pair and its
# report timer with net::Loop from the netxx facade — the same loop the
# gtp session layer uses — so rtpxx links netxx (and the C net library
# behind it) beside the rtp codec.
add_library(rtpxx STATIC cxx/src/rtp.cpp)
target_include_directories(rtpxx PUBLIC cxx/inc)
target_link_libraries(rtpxx PUBLIC rtp netxx net task)
set_target_properties(rtpxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/rtp.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/rtp.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# rtp.i %imports netxx.hpp for the shared net::Loop; the C codec header
# carries the payload types and RTCP constants the facade mirrors, so a
# change there must re-run SWIG rather than leave the Lua table stale.
set_property(SOURCE swig/rtp.i PROPERTY DEPENDS
    swig/common.i cxx/inc/rtpxx.hpp cxx/inc/netxx.hpp
    ${CMAKE_SOURCE_DIR}/rtp/inc/rtp.h)
# The CMake target is rtp_lua because `rtp` is the C library; the
# loadable module is still rtp.so for `require("rtp")`.
swig_add_library(rtp_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/rtp.i)
set_target_properties(rtp_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME rtp
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(rtp_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(rtp_lua PRIVATE rtpxx ${LUA_LIBRARIES})
if(NOT MSVC)
    target_compile_options(rtp_lua PRIVATE -w)   # generated wrapper code
endif()

# --- diam (diamxx facade)
add_library(diamxx STATIC cxx/src/diam.cpp)
target_include_directories(diamxx PUBLIC cxx/inc)
target_link_libraries(diamxx PUBLIC diam)
set_target_properties(diamxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/diam.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/diam.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
# diam.i %includes both the facade and the generated dictionary header
# (application ids, AVP codes, enum constants); list both or a dictionary
# change rebuilds the C library without re-running SWIG, leaving the Lua
# module's constant table stale.
set_property(SOURCE swig/diam.i PROPERTY DEPENDS
    swig/common.i cxx/inc/diamxx.hpp ${CMAKE_BINARY_DIR}/diam/gen/inc/diam_dict.h)
# The CMake target is diam_lua because `diam` is the C library; the
# loadable module is still diam.so for `require("diam")`.
swig_add_library(diam_lua
    TYPE MODULE
    LANGUAGE lua
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/lua
    SOURCES swig/diam.i)
set_target_properties(diam_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME diam
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lua)
target_include_directories(diam_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(diam_lua PRIVATE diamxx ${LUA_LIBRARIES})
# diam.i %includes diam_dict.h, which the diam target generates into its
# build tree; make the SWIG step wait for it. UseSWIG only creates the
# <name>_swig_compilation target for generators that need explicit
# timestamps (Makefiles); Ninja tracks the depfile itself and the target
# is absent, so order the module target instead — either way the SWIG
# command inherits the ordering dependency.
if(TARGET diam_lua_swig_compilation)
    add_dependencies(diam_lua_swig_compilation diam)
else()
    add_dependencies(diam_lua diam)
endif()
if(NOT MSVC)
    target_compile_options(diam_lua PRIVATE -w)   # generated wrapper code
endif()

# SWIG wrapper code is generated; keep clang-tidy (ENABLE_CLANG_TIDY)
# off those targets. The facade libraries above stay covered.
foreach(mod gtp_lua ipsec sip_lua sdp_lua sms_lua json_lua diam_lua rtp_lua net_lua)
    set_target_properties(${mod} PROPERTIES C_CLANG_TIDY "" CXX_CLANG_TIDY "")
endforeach()

# --- tests
find_program(LUA_INTERPRETER NAMES lua lua5.4 lua5.3 luajit)
if(BUILD_TESTING AND Lua_FOUND AND LUA_INTERPRETER)
    add_test(NAME bindings_lua
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_bindings.lua)
    set_tests_properties(bindings_lua PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_sip
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_sip_bindings.lua)
    set_tests_properties(bindings_lua_sip PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_gtp
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_gtp_bindings.lua)
    set_tests_properties(bindings_lua_gtp PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_diam
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_diam_bindings.lua)
    set_tests_properties(bindings_lua_diam PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_net
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_net_bindings.lua)
    set_tests_properties(bindings_lua_net PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    # Two RTP sessions on ONE net.Loop shared with a gtp.Endpoint — the
    # loop unification is the point of the test as much as the codec is.
    add_test(NAME bindings_lua_rtp
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_rtp_bindings.lua)
    set_tests_properties(bindings_lua_rtp PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_sdp
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_sdp_bindings.lua)
    set_tests_properties(bindings_lua_sdp PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    add_test(NAME bindings_lua_sms
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_sms_bindings.lua)
    set_tests_properties(bindings_lua_sms PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    # The table converters are hand-written Lua C rather than SWIG
    # output, so this covers both them and the wrapped Doc/Builder — and
    # loads json beside sip/sdp/diam/net at the end, which is the
    # class-name collision check for the types it introduces.
    add_test(NAME bindings_lua_json
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_json_bindings.lua)
    set_tests_properties(bindings_lua_json PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    # sdp and sip both wrap a class called Msg and one called Builder;
    # SWIG's Lua type registry is shared across modules and keyed by the
    # unscoped name, so loading both into one interpreter is exactly the
    # collision swig/sdp.i renames around. Test it, or the next module
    # to add a Msg reintroduces it silently.
    add_test(NAME bindings_lua_sdp_sip
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_sdp_sip_coexist.lua)
    set_tests_properties(bindings_lua_sdp_sip PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")

    # sms beside sip, sdp, diam and net — the four modules ipsmgw.lua
    # loads together. sms was named to avoid the clash (Address, not the
    # Addr netxx wraps; Tpdu/Rpdu, not Msg), so this is the assertion
    # that the next type added to smsxx.hpp has not silently collided.
    # It also checks a binary RPDU through both the SIP body and an
    # SM-RP-UI AVP, which is what would break if a typemap ever went
    # NUL-terminated.
    add_test(NAME bindings_lua_sms_coexist
             COMMAND ${LUA_INTERPRETER}
                     ${CMAKE_CURRENT_SOURCE_DIR}/test/test_sms_coexist.lua)
    set_tests_properties(bindings_lua_sms_coexist PROPERTIES
        ENVIRONMENT "LUA_CPATH=${CMAKE_CURRENT_BINARY_DIR}/lua/?.so")
endif()
