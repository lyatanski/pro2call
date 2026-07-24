# Scripting bindings, all SWIG-generated from C++ facades over the C
#
# libraries:
#   gtp,   gtpxx,   swig/gtp.i,   GTP stack
#   ipsec, ipsecxx, swig/ipsec.i, IPsec/XFRM
#   sip,   sipxx,   swig/sip.i,   SIP stack
#   diam,  diamxx,  swig/diam.i,  Diameter stack
#   net,   netxx,   swig/net.i,   event loop + UDP socket
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
foreach(dep task net gtp2 gtpu xfrm rtnl sip diam)
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
# edits are missed. gtp.i %imports netxx.hpp for the shared net::Loop.
set_property(SOURCE swig/gtp.i PROPERTY DEPENDS
    cxx/inc/gtpxx.hpp cxx/inc/netxx.hpp)
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
# address helpers (net.addr_add / net.addr_del), beside if_index/if_addr4.
add_library(netxx STATIC cxx/src/netxx.cpp)
target_include_directories(netxx PUBLIC cxx/inc)
target_link_libraries(netxx PUBLIC net rtnl)
set_target_properties(netxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/net.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/net.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
set_property(SOURCE swig/net.i PROPERTY DEPENDS cxx/inc/netxx.hpp)
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
set_property(SOURCE swig/ipsec.i PROPERTY DEPENDS cxx/inc/ipsecxx.hpp)
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
    cxx/inc/sipxx.hpp
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

# --- diam (diamxx facade)
add_library(diamxx STATIC cxx/src/diam.cpp)
target_include_directories(diamxx PUBLIC cxx/inc)
target_link_libraries(diamxx PUBLIC diam)
set_target_properties(diamxx PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_property(SOURCE swig/diam.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE swig/diam.i PROPERTY USE_TARGET_INCLUDE_DIRECTORIES ON)
set_property(SOURCE swig/diam.i PROPERTY DEPENDS cxx/inc/diamxx.hpp)
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
# build tree; make the SWIG step wait for it.
add_dependencies(diam_lua_swig_compilation diam)
if(NOT MSVC)
    target_compile_options(diam_lua PRIVATE -w)   # generated wrapper code
endif()

# SWIG wrapper code is generated; keep clang-tidy (ENABLE_CLANG_TIDY)
# off those targets. The facade libraries above stay covered.
foreach(mod gtp_lua ipsec sip_lua diam_lua net_lua)
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
endif()
