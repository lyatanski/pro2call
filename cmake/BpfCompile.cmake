# BPF compilation support (PLAN.md §13.2).
#
# add_bpf_object(<target> <src.c>) compiles a BPF C source with
# `clang -target bpf -g -O2` (BTF included via -g), strips DWARF with
# llvm-strip (BTF is kept), and runs `bpftool gen skeleton` to produce
# <target>.skel.h in the current binary dir. The result is an INTERFACE
# library carrying the include path of the generated skeleton; consumers
# just target_link_libraries() against <target>.
#
# check_bpf_toolchain(<out_var>) sets <out_var> to TRUE when clang,
# bpftool and libbpf are all present and the running kernel is >= 5.4;
# the reason for failure is reported with a WARNING otherwise.

function(check_bpf_toolchain out)
    set(${out} FALSE PARENT_SCOPE)

    execute_process(COMMAND uname -r
                    OUTPUT_VARIABLE kver
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "^[0-9]+\\.[0-9]+" kver_short "${kver}")
    if(kver_short VERSION_LESS "5.4")
        message(WARNING "BPF: kernel ${kver} < 5.4, eBPF datapath disabled")
        return()
    endif()

    find_program(BPF_CLANG clang)
    if(NOT BPF_CLANG)
        message(WARNING "BPF: clang not found, eBPF datapath disabled")
        return()
    endif()

    find_program(BPF_BPFTOOL bpftool)
    if(NOT BPF_BPFTOOL)
        message(WARNING "BPF: bpftool not found, eBPF datapath disabled")
        return()
    endif()

    find_program(BPF_STRIP NAMES llvm-strip llvm-strip-21 llvm-strip-18 llvm-strip-17)

    find_package(PkgConfig QUIET)
    if(NOT PkgConfig_FOUND)
        message(WARNING "BPF: pkg-config not found, eBPF datapath disabled")
        return()
    endif()
    pkg_check_modules(LIBBPF QUIET IMPORTED_TARGET libbpf>=1.0)
    if(NOT LIBBPF_FOUND)
        message(WARNING "BPF: libbpf >= 1.0 not found, eBPF datapath disabled")
        return()
    endif()

    set(${out} TRUE PARENT_SCOPE)
endfunction()

function(add_bpf_object target src)
    get_filename_component(src_abs ${src} ABSOLUTE)
    set(obj  ${CMAKE_CURRENT_BINARY_DIR}/${target}.bpf.o)
    set(skel ${CMAKE_CURRENT_BINARY_DIR}/${target}.skel.h)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(bpf_arch arm64)
    else()
        set(bpf_arch x86)
    endif()

    # `clang -target bpf` does not search the multiarch include dir, which
    # holds <asm/*.h> on Debian/Ubuntu.
    set(multiarch_inc)
    if(CMAKE_LIBRARY_ARCHITECTURE)
        set(multiarch_inc -idirafter /usr/include/${CMAKE_LIBRARY_ARCHITECTURE})
    endif()

    if(BPF_STRIP)
        set(strip_cmd COMMAND ${BPF_STRIP} --strip-debug ${obj})
    else()
        set(strip_cmd)
    endif()

    add_custom_command(
        OUTPUT ${obj}
        COMMAND ${BPF_CLANG} -target bpf -g -O2 -D__TARGET_ARCH_${bpf_arch}
                -Wall -Wextra
                -I${CMAKE_CURRENT_SOURCE_DIR}/inc
                ${multiarch_inc}
                -MD -MF ${obj}.d
                -c ${src_abs} -o ${obj}
        ${strip_cmd}
        DEPENDS ${src_abs}
        DEPFILE ${obj}.d
        COMMENT "Compiling BPF object ${target}.bpf.o"
        VERBATIM)

    add_custom_command(
        OUTPUT ${skel}
        COMMAND ${BPF_BPFTOOL} gen skeleton ${obj} > ${skel}
        DEPENDS ${obj}
        COMMENT "Generating BPF skeleton ${target}.skel.h"
        VERBATIM)

    add_custom_target(${target}_gen DEPENDS ${skel})
    add_library(${target} INTERFACE)
    add_dependencies(${target} ${target}_gen)
    target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
endfunction()
