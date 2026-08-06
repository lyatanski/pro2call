add_executable(test_json test_json.c)
target_link_libraries(test_json PRIVATE json task)
add_test(NAME json COMMAND test_json)

add_executable(test_json_write test_json_write.c)
target_link_libraries(test_json_write PRIVATE json task)
add_test(NAME json_write COMMAND test_json_write)
