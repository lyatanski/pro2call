add_executable(test_sdp test_sdp.c)
target_link_libraries(test_sdp PRIVATE sdp task)
add_test(NAME sdp COMMAND test_sdp)
