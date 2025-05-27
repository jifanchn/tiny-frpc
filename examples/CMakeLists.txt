cmake_minimum_required(VERSION 3.10)

# Add example executables
add_executable(simple_client simple_client.c)
target_link_libraries(simple_client tiny-frpc tiny_yamux)

# Advanced client example with threading support
add_executable(advanced_client advanced_client.c)
target_link_libraries(advanced_client tiny-frpc tiny_yamux pthread)

# Add installation rules
install(TARGETS simple_client advanced_client
        RUNTIME DESTINATION bin/examples)
