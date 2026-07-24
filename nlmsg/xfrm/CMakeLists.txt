get_filename_component(name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

file(GLOB src src/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)
target_compile_definitions(${name} PUBLIC _DEFAULT_SOURCE)

# task provides the shared TLV codec (task/inc/tlv.h, header-only) used
# to build and parse the netlink attribute run.
target_link_libraries(${name} PUBLIC task)

add_subdirectory(test)
