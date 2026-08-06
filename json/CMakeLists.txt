get_filename_component(name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

file(GLOB src src/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)

add_subdirectory(test)
