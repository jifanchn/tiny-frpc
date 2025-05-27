cmake_minimum_required(VERSION 3.10)

# Find Go executable
find_program(GO_EXECUTABLE go)
if(NOT GO_EXECUTABLE)
    message(FATAL_ERROR "Go executable not found, required for CGO tests")
endif()

message(STATUS "Found Go: ${GO_EXECUTABLE}")

# Build CGO test binary
add_custom_target(frpc_cgo_test ALL
    COMMAND ${CMAKE_COMMAND} -E echo "Building FRP CGO tests..."
    COMMAND ${GO_EXECUTABLE} build -o ${CMAKE_BINARY_DIR}/frpc_cgo_test .
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building frpc CGO tests"
    VERBATIM
)

# Add dependencies
add_dependencies(frpc_cgo_test tiny-frpc)

# Add test to CTest
add_test(
    NAME frpc_cgo_test
    COMMAND ${CMAKE_BINARY_DIR}/frpc_cgo_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Copy necessary libraries to test directory if needed
# add_custom_command(TARGET frpc_cgo_test POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:tiny-frpc> ${CMAKE_CURRENT_BINARY_DIR}/
# )

message(STATUS "CGO tests configured")
