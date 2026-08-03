get_filename_component(name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

file(GLOB src src/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)
# task carries the FSM engine behind sms_fsm.h (task/inc/fsm.h).
target_link_libraries(${name} PUBLIC task)

add_subdirectory(test)
