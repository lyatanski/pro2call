add_executable(test_rtnl test_rtnl.c)
target_link_libraries(test_rtnl PRIVATE rtnl task)
add_test(NAME rtnl COMMAND test_rtnl)
