add_executable(test_sms_tpdu test_sms_tpdu.c)
target_link_libraries(test_sms_tpdu PRIVATE sms task)
add_test(NAME sms_tpdu COMMAND test_sms_tpdu)

add_executable(test_sms_ud test_sms_ud.c)
target_link_libraries(test_sms_ud PRIVATE sms task)
add_test(NAME sms_ud COMMAND test_sms_ud)

add_executable(test_sms_rp test_sms_rp.c)
target_link_libraries(test_sms_rp PRIVATE sms task)
add_test(NAME sms_rp COMMAND test_sms_rp)

add_executable(test_sms_fsm test_sms_fsm.c)
target_link_libraries(test_sms_fsm PRIVATE sms task)
add_test(NAME sms_fsm COMMAND test_sms_fsm)
