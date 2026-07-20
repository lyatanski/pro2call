add_executable(test_gtp2 test_gtp2.c)
target_link_libraries(test_gtp2 PRIVATE gtp2)
add_test(NAME gtp2 COMMAND test_gtp2)

add_executable(test_gtp2_msg test_gtp2_msg.c)
target_link_libraries(test_gtp2_msg PRIVATE gtp2)
add_test(NAME gtp2_msg COMMAND test_gtp2_msg)

