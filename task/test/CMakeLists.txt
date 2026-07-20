add_executable(test_tlv test_tlv.c)
target_link_libraries(test_tlv PRIVATE task)
add_test(NAME tlv COMMAND test_tlv)

add_executable(test_fsm test_fsm.c)
target_link_libraries(test_fsm PRIVATE task)
add_test(NAME fsm COMMAND test_fsm)
