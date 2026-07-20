add_executable(test_rtp test_rtp.c)
target_link_libraries(test_rtp PRIVATE rtp task)
add_test(NAME rtp COMMAND test_rtp)
