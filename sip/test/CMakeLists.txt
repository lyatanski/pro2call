add_executable(test_sip test_sip.c)
target_link_libraries(test_sip PRIVATE sip task)
add_test(NAME sip COMMAND test_sip)

add_executable(test_sip_fsm test_sip_fsm.c)
target_link_libraries(test_sip_fsm PRIVATE sip task)
add_test(NAME sip_fsm COMMAND test_sip_fsm)

add_executable(test_sip_dialog test_sip_dialog.c)
target_link_libraries(test_sip_dialog PRIVATE sip task)
add_test(NAME sip_dialog COMMAND test_sip_dialog)
