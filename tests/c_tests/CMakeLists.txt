cmake_minimum_required(VERSION 3.10)

# Currently no C tests are defined
message(STATUS "No C tests are currently defined in the c_tests directory.")

# When adding C tests, you can use this template:
# add_executable(test_name test_source.c)
# target_link_libraries(test_name tiny-frpc tiny_yamux tiny_yamux_port)
# add_test(NAME test_name COMMAND test_name)
