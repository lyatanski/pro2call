set(name diam)

# The dictionary layer is generated at build time by gen/ (Go, no
# module dependencies) from the Diameter dictionary files committed
# under gen/dict; the generated sources exist only in the build tree.
find_program(GO_EXECUTABLE go REQUIRED)

file(GLOB diamgen_deps CONFIGURE_DEPENDS
     gen/*.go gen/templates/*.tmpl gen/dict/*.xml)
set(gen_out ${CMAKE_CURRENT_BINARY_DIR}/gen)
add_custom_command(
    OUTPUT ${gen_out}/src/diam_dict.c ${gen_out}/inc/diam_dict.h
    COMMAND ${GO_EXECUTABLE} run . ${gen_out}
    DEPENDS ${diamgen_deps}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/gen
    COMMENT "diamgen: generating diameter dictionary layer"
    VERBATIM)

add_library(${name}
    src/diam.c
    src/diam_fsm.c
    ${gen_out}/src/diam_dict.c)
target_include_directories(${name} PUBLIC inc ${gen_out}/inc)
target_link_libraries(${name} PUBLIC task)  # zero-copy TLV codec (tlv.h), FSM engine (fsm.h)

add_subdirectory(test)
