set(name gtp1)  # directory is gtp/v1; library keeps the protocol name

gtpgen(1)
file(GLOB src src/*.c)
add_library(${name} ${src} ${gtp1_gen_src})
target_include_directories(${name} PUBLIC inc ${gtp1_gen_inc})
target_link_libraries(${name} PUBLIC task)  # tlv.{c,h} + endian.h

add_subdirectory(test)
