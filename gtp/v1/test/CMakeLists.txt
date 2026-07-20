add_executable(test_gtp1 test_gtp1.c)
target_link_libraries(test_gtp1 PRIVATE gtp1 task)
add_test(NAME gtp1 COMMAND test_gtp1)
