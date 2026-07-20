set(name gtp2)

gtpgen(2)
add_library(${name} src/gtp2.c src/gtp2_ie.c ${gtp2_gen_src})
target_include_directories(${name} PUBLIC ${gtp2_gen_inc} inc)
target_link_libraries(${name} PUBLIC task)  # tlv.{c,h} + endian.h

add_subdirectory(test)
