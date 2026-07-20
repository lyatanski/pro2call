get_filename_component(name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

file(GLOB src src/*.c src/*/*.c)
add_library(${name} ${src})
target_include_directories(${name} PUBLIC inc)
target_compile_definitions(${name} PUBLIC _DEFAULT_SOURCE)

find_package(OpenSSL REQUIRED)
target_link_libraries(${name} PUBLIC OpenSSL::SSL)

add_subdirectory(test)
