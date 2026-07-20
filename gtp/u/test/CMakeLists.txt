add_executable(test_gtpu test_gtpu.c)
target_link_libraries(test_gtpu PRIVATE gtpu task)
add_test(NAME gtpu COMMAND test_gtpu)

if(GTPU_BPF)
    add_executable(test_gtpu_bpf test_gtpu_bpf.c)
    target_link_libraries(test_gtpu_bpf PRIVATE gtpu task PkgConfig::LIBBPF)
    add_test(NAME gtpu_bpf COMMAND test_gtpu_bpf)
endif()
