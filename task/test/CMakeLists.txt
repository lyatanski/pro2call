add_executable(test_tlv test_tlv.c)
target_link_libraries(test_tlv PRIVATE task)
add_test(NAME tlv COMMAND test_tlv)

add_executable(test_fsm test_fsm.c)
target_link_libraries(test_fsm PRIVATE task)
add_test(NAME fsm COMMAND test_fsm)

add_executable(test_ippool test_ippool.c)
target_link_libraries(test_ippool PRIVATE task)
add_test(NAME ippool COMMAND test_ippool)
