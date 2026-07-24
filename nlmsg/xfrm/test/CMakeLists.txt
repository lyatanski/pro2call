add_executable(test_xfrm test_xfrm.c)
target_link_libraries(test_xfrm PRIVATE xfrm task)
add_test(NAME xfrm COMMAND test_xfrm)
