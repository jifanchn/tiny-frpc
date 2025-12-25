#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../tiny-frpc/include/frpc-bindings.h"

// Test helper macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return -1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, message) \
    do { \
        if ((expected) != (actual)) { \
            fprintf(stderr, "FAIL: %s (expected: %d, actual: %d)\n", message, (int)(expected), (int)(actual)); \
            return -1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(expected, actual, message) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            fprintf(stderr, "FAIL: %s (expected: %s, actual: %s)\n", message, (expected), (actual)); \
            return -1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

// Global variables for testing callbacks
static frpc_error_t g_last_error;
static bool g_error_callback_called = false;
static bool g_log_callback_called = false;
static int g_log_callback_count = 0;

// Test error callback
void test_error_callback(const frpc_error_t* error, void* user_data) {
    g_error_callback_called = true;
    frpc_error_copy(&g_last_error, error);
    
    // Verify user_data
    int* test_data = (int*)user_data;
    if (test_data && *test_data == 12345) {
        printf("Error callback received correct user data\n");
    }
}

// Test log callback
void test_log_callback(int level, const char* message) {
    (void)level;
    (void)message;
    g_log_callback_called = true;
    g_log_callback_count++;
}

// Test error initialization
int test_error_init() {
    printf("\n=== Testing frpc_error_init ===\n");
    
    frpc_error_t error;
    frpc_error_init(&error);
    
    TEST_ASSERT_EQ(FRPC_SUCCESS, error.code, "Error code should be FRPC_SUCCESS");
    TEST_ASSERT(error.message == NULL, "Message should be NULL");
    TEST_ASSERT(error.context == NULL, "Context should be NULL");
    TEST_ASSERT(error.protocol_name == NULL, "Protocol name should be NULL");
    TEST_ASSERT(error.file == NULL, "File should be NULL");
    TEST_ASSERT(error.function == NULL, "Function should be NULL");
    TEST_ASSERT_EQ(0, error.tunnel_id, "Tunnel ID should be 0");
    TEST_ASSERT_EQ(0, error.line, "Line should be 0");
    TEST_ASSERT(error.timestamp > 0, "Timestamp should be set");
    
    frpc_error_cleanup(&error);
    return 0;
}

// Test error setting
int test_error_set() {
    printf("\n=== Testing frpc_error_set ===\n");
    
    frpc_error_t error;
    frpc_error_init(&error);
    
    frpc_error_set(&error, FRPC_ERROR_NETWORK, "Network connection failed", 
                  "TCP connect to server", 123, "TCP", "test.c", 42, "test_function");
    
    TEST_ASSERT_EQ(FRPC_ERROR_NETWORK, error.code, "Error code should be FRPC_ERROR_NETWORK");
    TEST_ASSERT_STR_EQ("Network connection failed", error.message, "Message should match");
    TEST_ASSERT_STR_EQ("TCP connect to server", error.context, "Context should match");
    TEST_ASSERT_STR_EQ("TCP", error.protocol_name, "Protocol name should match");
    TEST_ASSERT_STR_EQ("test.c", error.file, "File should match");
    TEST_ASSERT_STR_EQ("test_function", error.function, "Function should match");
    TEST_ASSERT_EQ(123, error.tunnel_id, "Tunnel ID should match");
    TEST_ASSERT_EQ(42, error.line, "Line should match");
    
    frpc_error_cleanup(&error);
    return 0;
}

// Test error copying
int test_error_copy() {
    printf("\n=== Testing frpc_error_copy ===\n");
    
    frpc_error_t src, dest;
    frpc_error_init(&src);
    frpc_error_init(&dest);
    
    // Set up source error
    frpc_error_set(&src, FRPC_ERROR_AUTH, "Authentication failed", 
                  "Invalid token", 456, "STCP", "auth.c", 100, "authenticate");
    
    // Copy error
    frpc_error_copy(&dest, &src);
    
    // Verify copy
    TEST_ASSERT_EQ(src.code, dest.code, "Error codes should match");
    TEST_ASSERT_STR_EQ(src.message, dest.message, "Messages should match");
    TEST_ASSERT_STR_EQ(src.context, dest.context, "Contexts should match");
    TEST_ASSERT_STR_EQ(src.protocol_name, dest.protocol_name, "Protocol names should match");
    TEST_ASSERT_STR_EQ(src.file, dest.file, "Files should match");
    TEST_ASSERT_STR_EQ(src.function, dest.function, "Functions should match");
    TEST_ASSERT_EQ(src.tunnel_id, dest.tunnel_id, "Tunnel IDs should match");
    TEST_ASSERT_EQ(src.line, dest.line, "Lines should match");
    TEST_ASSERT_EQ(src.timestamp, dest.timestamp, "Timestamps should match");
    
    frpc_error_cleanup(&src);
    frpc_error_cleanup(&dest);
    return 0;
}

// Test error code to string conversion
int test_error_code_to_string() {
    printf("\n=== Testing frpc_error_code_to_string ===\n");
    
    TEST_ASSERT_STR_EQ("Success", frpc_error_code_to_string(FRPC_SUCCESS), 
                      "FRPC_SUCCESS should return 'Success'");
    TEST_ASSERT_STR_EQ("Invalid parameter", frpc_error_code_to_string(FRPC_ERROR_INVALID_PARAM), 
                      "FRPC_ERROR_INVALID_PARAM should return 'Invalid parameter'");
    TEST_ASSERT_STR_EQ("Memory allocation error", frpc_error_code_to_string(FRPC_ERROR_MEMORY), 
                      "FRPC_ERROR_MEMORY should return 'Memory allocation error'");
    TEST_ASSERT_STR_EQ("Network error", frpc_error_code_to_string(FRPC_ERROR_NETWORK), 
                      "FRPC_ERROR_NETWORK should return 'Network error'");
    TEST_ASSERT_STR_EQ("Authentication error", frpc_error_code_to_string(FRPC_ERROR_AUTH), 
                      "FRPC_ERROR_AUTH should return 'Authentication error'");
    TEST_ASSERT_STR_EQ("Stream not writable", frpc_error_code_to_string(FRPC_ERROR_STREAM_NOT_WRITABLE), 
                      "FRPC_ERROR_STREAM_NOT_WRITABLE should return 'Stream not writable'");
    TEST_ASSERT_STR_EQ("Unknown error", frpc_error_code_to_string((frpc_error_code_t)9999), 
                      "Unknown error code should return 'Unknown error'");
    
    return 0;
}

// Test global error callback
int test_global_error_callback() {
    printf("\n=== Testing global error callback ===\n");
    
    // Initialize global error state
    frpc_error_init(&g_last_error);
    g_error_callback_called = false;
    
    // Set up callback with user data
    int test_user_data = 12345;
    frpc_set_global_error_callback(test_error_callback, &test_user_data);
    
    // Trigger an error
    FRPC_REPORT_ERROR(FRPC_ERROR_TIMEOUT, "Connection timed out", 
                     "Server connection", 789, "HTTP");
    
    // Verify callback was called
    TEST_ASSERT(g_error_callback_called, "Error callback should have been called");
    TEST_ASSERT_EQ(FRPC_ERROR_TIMEOUT, g_last_error.code, "Error code should match");
    TEST_ASSERT_STR_EQ("Connection timed out", g_last_error.message, "Error message should match");
    TEST_ASSERT_STR_EQ("Server connection", g_last_error.context, "Error context should match");
    TEST_ASSERT_STR_EQ("HTTP", g_last_error.protocol_name, "Protocol name should match");
    TEST_ASSERT_EQ(789, g_last_error.tunnel_id, "Tunnel ID should match");
    
    // Clean up
    frpc_error_cleanup(&g_last_error);
    frpc_set_global_error_callback(NULL, NULL);
    
    return 0;
}

// Test error reporting macro
int test_error_reporting_macro() {
    printf("\n=== Testing error reporting macro ===\n");
    
    // Initialize global error state
    frpc_error_init(&g_last_error);
    g_error_callback_called = false;
    
    // Set up callback
    frpc_set_global_error_callback(test_error_callback, NULL);
    
    // Use the macro to report an error
    FRPC_REPORT_ERROR(FRPC_ERROR_PROTO, "Invalid protocol version", 
                     "Protocol negotiation", 999, "WebSocket");
    
    // Verify the error was reported correctly
    TEST_ASSERT(g_error_callback_called, "Error callback should have been called");
    TEST_ASSERT_EQ(FRPC_ERROR_PROTO, g_last_error.code, "Error code should match");
    TEST_ASSERT_STR_EQ("Invalid protocol version", g_last_error.message, "Error message should match");
    TEST_ASSERT_STR_EQ("Protocol negotiation", g_last_error.context, "Error context should match");
    TEST_ASSERT_STR_EQ("WebSocket", g_last_error.protocol_name, "Protocol name should match");
    TEST_ASSERT_EQ(999, g_last_error.tunnel_id, "Tunnel ID should match");
    
    // Verify file, line, and function are set by macro
    TEST_ASSERT(g_last_error.file != NULL, "File should be set by macro");
    TEST_ASSERT(g_last_error.line > 0, "Line should be set by macro");
    TEST_ASSERT(g_last_error.function != NULL, "Function should be set by macro");
    
    // Clean up
    frpc_error_cleanup(&g_last_error);
    frpc_set_global_error_callback(NULL, NULL);
    
    return 0;
}

// Test enhanced config validation error reporting
int test_config_validation_error_reporting() {
    printf("\n=== Testing config validation error reporting ===\n");
    
    // Initialize global error state
    frpc_error_init(&g_last_error);
    g_error_callback_called = false;
    
    // Set up callback
    frpc_set_global_error_callback(test_error_callback, NULL);
    
    // Test invalid configuration
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Missing server address should trigger error
    config.tunnel_name = strdup("test");
    config.secret_key = strdup("secret");
    
    int result = frpc_tunnel_config_validate(&config);
    
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, result, "Should return FRPC_ERROR_INVALID_PARAM");
    TEST_ASSERT(g_error_callback_called, "Error callback should have been called");
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, g_last_error.code, "Error code should match");
    TEST_ASSERT_STR_EQ("Server address is required", g_last_error.message, "Error message should match");
    
    // Clean up
    frpc_tunnel_config_cleanup(&config);
    frpc_error_cleanup(&g_last_error);
    frpc_set_global_error_callback(NULL, NULL);
    
    return 0;
}

// Test frpc_trigger_error logging + callback branches
int test_trigger_error_logging() {
    printf("\n=== Testing frpc_trigger_error logging ===\n");

    frpc_error_t err;
    frpc_error_init(&err);

    // Case 1: both log + error callback set
    g_log_callback_called = false;
    g_log_callback_count = 0;
    g_error_callback_called = false;
    frpc_error_init(&g_last_error);

    frpc_set_log_callback(test_log_callback);
    frpc_set_global_error_callback(test_error_callback, NULL);

    frpc_error_set(&err, FRPC_ERROR_INTERNAL, "boom", "ctx", 1, "STCP", NULL, 0, NULL);
    frpc_trigger_error(&err);

    TEST_ASSERT(g_log_callback_called, "Log callback should be called when set");
    TEST_ASSERT(g_error_callback_called, "Error callback should be called when set");

    // Case 2: log callback only (error callback cleared)
    g_log_callback_called = false;
    g_log_callback_count = 0;
    g_error_callback_called = false;
    frpc_set_global_error_callback(NULL, NULL);

    frpc_error_cleanup(&err);
    frpc_error_init(&err); // leave fields mostly NULL to cover default strings
    frpc_trigger_error(&err);
    TEST_ASSERT(g_log_callback_called, "Log callback should be called when error callback is NULL");

    // Case 3: error callback only (log callback cleared)
    g_log_callback_called = false;
    g_log_callback_count = 0;
    g_error_callback_called = false;
    frpc_set_log_callback(NULL);
    frpc_set_global_error_callback(test_error_callback, NULL);
    frpc_error_set(&err, FRPC_ERROR_TIMEOUT, "timeout", NULL, 2, NULL, NULL, 0, NULL);
    frpc_trigger_error(&err);
    TEST_ASSERT(g_error_callback_called, "Error callback should be called when log callback is NULL");

    // Cleanup
    frpc_error_cleanup(&err);
    frpc_error_cleanup(&g_last_error);
    frpc_set_global_error_callback(NULL, NULL);
    frpc_set_log_callback(NULL);
    return 0;
}

// Main test runner
int main() {
    printf("Running error handling tests...\n");
    
    // Initialize FRPC library for testing
    frpc_init();
    
    int failed_tests = 0;
    
    if (test_error_init() != 0) failed_tests++;
    if (test_error_set() != 0) failed_tests++;
    if (test_error_copy() != 0) failed_tests++;
    if (test_error_code_to_string() != 0) failed_tests++;
    if (test_global_error_callback() != 0) failed_tests++;
    if (test_error_reporting_macro() != 0) failed_tests++;
    if (test_config_validation_error_reporting() != 0) failed_tests++;
    if (test_trigger_error_logging() != 0) failed_tests++;
    
    // Cleanup FRPC library
    frpc_cleanup();
    
    printf("\n=== Test Results ===\n");
    if (failed_tests == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) failed!\n", failed_tests);
        return 1;
    }
}