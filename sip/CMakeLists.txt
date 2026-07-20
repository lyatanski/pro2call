get_filename_component(name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

file(GLOB src src/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)
target_link_libraries(${name} PUBLIC task)  # FSM engine (fsm.h)

add_subdirectory(test)
