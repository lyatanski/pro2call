add_executable(test_diam test_diam.c)
target_link_libraries(test_diam PRIVATE diam task)
add_test(NAME diam COMMAND test_diam)

add_executable(test_diam_dict test_diam_dict.c)
target_link_libraries(test_diam_dict PRIVATE diam task)
add_test(NAME diam_dict COMMAND test_diam_dict)

add_executable(test_diam_fsm test_diam_fsm.c)
target_link_libraries(test_diam_fsm PRIVATE diam task)
add_test(NAME diam_fsm COMMAND test_diam_fsm)
