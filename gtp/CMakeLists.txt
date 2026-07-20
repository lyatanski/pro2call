# GTP family: the three protocol modules share one directory so the
# tree mirrors how they relate on the wire.
#
#   v1  GTP-C control plane, TS 29.060    (target gtp1)
#   v2  GTP-C control plane, TS 29.274    (target gtp2)
#   u   GTP-U eBPF datapath, TS 29.281    (target gtpu)
#
# The v1/v2 message layers are generated at build time by gen/ (Go,
# no module dependencies) from the checked-in spec docx
#   cd gen && go run . -version 1 # TS 29.060
#   cd gen && go run . -version 2 # TS 29.274
find_program(GO_EXECUTABLE go REQUIRED)

set(gtpgen_dir ${CMAKE_CURRENT_SOURCE_DIR}/gen)

# gtpgen(<version>): generate gtp-c messages under the
# calling directory's build tree. Sets gtp<version>_gen_src and
# gtp<version>_gen_inc in the caller, whose library target must list the
# source so compilation depends on generation.
function(gtpgen version)
    set(out ${CMAKE_CURRENT_BINARY_DIR}/gen)
    add_custom_command(
        OUTPUT ${out}/src/gtp${version}_msg.c ${out}/inc/gtp${version}_msg.h
        COMMAND ${GO_EXECUTABLE} run . -version ${version} -out ${out}
        WORKING_DIRECTORY ${gtpgen_dir}
        COMMENT "gtpgen: generating gtp${version} message layer"
        VERBATIM)
    set(gtp${version}_gen_src ${out}/src/gtp${version}_msg.c PARENT_SCOPE)
    set(gtp${version}_gen_inc ${out}/inc PARENT_SCOPE)
endfunction()

add_subdirectory(v1)
add_subdirectory(v2)
add_subdirectory(u)
