add_executable(test_net_addr test_net_addr.c)
target_link_libraries(test_net_addr PRIVATE net task)
add_test(NAME net_addr COMMAND test_net_addr)

add_executable(test_net_loop test_net_loop.c)
target_link_libraries(test_net_loop PRIVATE net task)
add_test(NAME net_loop COMMAND test_net_loop)

add_executable(test_net_sock test_net_sock.c)
target_link_libraries(test_net_sock PRIVATE net task)
add_test(NAME net_sock COMMAND test_net_sock)

add_executable(test_net_tls test_net_tls.c)
target_link_libraries(test_net_tls PRIVATE net task)
add_test(NAME net_tls COMMAND test_net_tls)

add_executable(test_net_dns test_net_dns.c)
target_link_libraries(test_net_dns PRIVATE net task)
add_test(NAME net_dns COMMAND test_net_dns)
