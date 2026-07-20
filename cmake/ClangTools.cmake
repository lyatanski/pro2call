# clang-format / clang-tidy integration.
#
# Adds manual targets when the tools are present; never required for a
# normal build (missing tools are reported with a STATUS message, like
# the SWIG bindings):
#
#   format        re-format all first-party C/C++ sources in place
#   format-check  fail if any file deviates from .clang-format
#   tidy          run clang-tidy over the compilation database
#
# Configuring with -DENABLE_CLANG_TIDY=ON additionally runs clang-tidy
# on every translation unit as it compiles (CMAKE_<LANG>_CLANG_TIDY).
#
# Generated code is excluded everywhere: the committed generator output
# under diam/gen and gtp/v*/gen is filtered from the format globs and
# carries a .clang-tidy that disables all checks, and the SWIG wrapper
# targets opt out of CMAKE_<LANG>_CLANG_TIDY where they are defined
# (bindings/CMakeLists.txt).
#
# Include this before any add_subdirectory() so CMAKE_<LANG>_CLANG_TIDY
# reaches every target.

option(ENABLE_CLANG_TIDY "Run clang-tidy alongside every compile" OFF)

# The manual `tidy` target reads compile flags from the compilation
# database in the build directory.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CLANG_FORMAT NAMES clang-format
             clang-format-21 clang-format-20 clang-format-19 clang-format-18)
find_program(CLANG_TIDY NAMES clang-tidy
             clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18)
find_program(RUN_CLANG_TIDY NAMES run-clang-tidy
             run-clang-tidy-21 run-clang-tidy-20 run-clang-tidy-19
             run-clang-tidy-18)

# First-party sources: every module plus the C++ binding facades. The
# gen/ trees (committed generator output) are excluded.
file(GLOB_RECURSE CLANG_TOOL_SOURCES CONFIGURE_DEPENDS
     ${PROJECT_SOURCE_DIR}/task/*.[ch]
     ${PROJECT_SOURCE_DIR}/net/*.[ch]
     ${PROJECT_SOURCE_DIR}/sip/*.[ch]
     ${PROJECT_SOURCE_DIR}/sdp/*.[ch]
     ${PROJECT_SOURCE_DIR}/rtp/*.[ch]
     ${PROJECT_SOURCE_DIR}/xfrm/*.[ch]
     ${PROJECT_SOURCE_DIR}/diam/*.[ch]
     ${PROJECT_SOURCE_DIR}/gtp/*.[ch]
     ${PROJECT_SOURCE_DIR}/bindings/cxx/*.cpp
     ${PROJECT_SOURCE_DIR}/bindings/cxx/*.hpp)
list(FILTER CLANG_TOOL_SOURCES EXCLUDE REGEX "/gen/")

if(CLANG_FORMAT)
    list(LENGTH CLANG_TOOL_SOURCES n_sources)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i ${CLANG_TOOL_SOURCES}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "clang-format: reformatting ${n_sources} files"
        VERBATIM)
    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT} --dry-run --Werror ${CLANG_TOOL_SOURCES}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "clang-format: checking ${n_sources} files"
        VERBATIM)
else()
    message(STATUS "clang-format not found; format/format-check targets unavailable")
endif()

if(ENABLE_CLANG_TIDY)
    if(NOT CLANG_TIDY)
        message(FATAL_ERROR "ENABLE_CLANG_TIDY=ON but clang-tidy was not found")
    endif()
    set(CMAKE_C_CLANG_TIDY   ${CLANG_TIDY} --quiet)
    set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY} --quiet)
endif()

if(RUN_CLANG_TIDY AND CLANG_TIDY)
    # run-clang-tidy selects database entries by path regex, so only
    # translation units that actually configured are analyzed (SWIG
    # wrappers live in the build tree and never match).
    add_custom_target(tidy
        COMMAND ${RUN_CLANG_TIDY} -quiet -p ${CMAKE_BINARY_DIR}
                -clang-tidy-binary ${CLANG_TIDY}
                "${PROJECT_SOURCE_DIR}/.*\\.(c|cpp)$"
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "clang-tidy: analyzing the compilation database"
        VERBATIM)
elseif(CLANG_TIDY)
    # Fallback without the run-clang-tidy driver: the always-built C
    # modules, one process. The BPF object (gtp/u/bpf) and the binding
    # facades are skipped — the former never enters the database, the
    # latter only when SWIG and Lua are found.
    set(tidy_sources ${CLANG_TOOL_SOURCES})
    list(FILTER tidy_sources INCLUDE REGEX "\\.c$")
    list(FILTER tidy_sources EXCLUDE REGEX "/bpf/")
    add_custom_target(tidy
        COMMAND ${CLANG_TIDY} --quiet -p ${CMAKE_BINARY_DIR} ${tidy_sources}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "clang-tidy: analyzing C modules"
        VERBATIM)
else()
    message(STATUS "clang-tidy not found; tidy target unavailable")
endif()
