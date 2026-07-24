cmake_minimum_required(VERSION 3.25)
project(pro2call LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4)
    add_compile_definitions(API_EXPORT=__declspec(dllexport))
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -fstack-protector-strong)
    add_compile_definitions(API_EXPORT=)
endif()

include(CTest)

# Optional clang-format/clang-tidy targets (format, format-check, tidy)
# and the -DENABLE_CLANG_TIDY=ON per-compile mode. Must come before the
# subdirectories so CMAKE_<LANG>_CLANG_TIDY reaches every target.
include(cmake/ClangTools.cmake)

add_subdirectory(task)
add_subdirectory(gtp)
add_subdirectory(diam)
add_subdirectory(net)
add_subdirectory(sip)
add_subdirectory(rtp)
add_subdirectory(nlmsg)

# Scripting bindings: gtpxx C++ facade + SWIG Python module. Optional;
# skipped with a status message when SWIG or the Python development
# files are missing.
add_subdirectory(bindings)

