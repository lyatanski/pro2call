set(name gtpu)  # directory is gtp/u; library keeps the protocol name

include(${CMAKE_SOURCE_DIR}/cmake/BpfCompile.cmake)
check_bpf_toolchain(GTPU_BPF)

file(GLOB src src/*.c src/*/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)
target_compile_definitions(${name} PRIVATE _DEFAULT_SOURCE)  # syscall(2)

find_package(Threads REQUIRED)
target_link_libraries(${name} PRIVATE task Threads::Threads)

if(GTPU_BPF)
    add_bpf_object(gtpu_kern bpf/gtpu_kern.c)
    target_link_libraries(${name} PRIVATE gtpu_kern PUBLIC PkgConfig::LIBBPF)
else()
    # API stays linkable; gtpu_ebpf_open() reports GTPU_E_UNSUPPORTED and
    # callers fall back to the userspace datapath.
    target_compile_definitions(${name} PRIVATE GTPU_EBPF_DISABLED)
endif()

add_subdirectory(test)
