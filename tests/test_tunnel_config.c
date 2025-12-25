#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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

// Test tunnel options initialization
int test_tunnel_options_init() {
    printf("\n=== Testing frpc_tunnel_options_init ===\n");
    
    frpc_tunnel_options_t options;
    frpc_tunnel_options_init(&options);
    
    // Test default values
    TEST_ASSERT_EQ(true, options.enable_multiplexing, "Default enable_multiplexing should be true");
    TEST_ASSERT_EQ(10, options.connection_pool_size, "Default connection_pool_size should be 10");
    TEST_ASSERT_EQ(100, options.max_connections, "Default max_connections should be 100");
    TEST_ASSERT_EQ(0, options.bandwidth_limit_mbps, "Default bandwidth_limit_mbps should be 0 (no limit)");
    TEST_ASSERT_EQ(false, options.enable_tls, "Default enable_tls should be false");
    TEST_ASSERT_EQ(true, options.tls_verify_peer, "Default tls_verify_peer should be true");
    TEST_ASSERT_EQ(64 * 1024, options.buffer_size, "Default buffer_size should be 64KB");
    TEST_ASSERT_EQ(false, options.enable_compression, "Default enable_compression should be false");
    TEST_ASSERT_EQ(6, options.compression_level, "Default compression_level should be 6");
    TEST_ASSERT_EQ(false, options.ws_enable_compression, "Default ws_enable_compression should be false");
    TEST_ASSERT_EQ(1024 * 1024, options.ws_max_message_size, "Default ws_max_message_size should be 1MB");
    TEST_ASSERT_EQ(30, options.ws_ping_interval, "Default ws_ping_interval should be 30 seconds");
    TEST_ASSERT_EQ(1, options.weight, "Default weight should be 1");
    
    // Test that pointers are initialized to NULL
    TEST_ASSERT(options.host_header_rewrite == NULL, "host_header_rewrite should be NULL");
    TEST_ASSERT(options.http_user == NULL, "http_user should be NULL");
    TEST_ASSERT(options.http_password == NULL, "http_password should be NULL");
    TEST_ASSERT(options.tls_cert_path == NULL, "tls_cert_path should be NULL");
    TEST_ASSERT(options.tls_key_path == NULL, "tls_key_path should be NULL");
    TEST_ASSERT(options.tls_ca_cert_path == NULL, "tls_ca_cert_path should be NULL");
    TEST_ASSERT(options.group_name == NULL, "group_name should be NULL");
    TEST_ASSERT(options.group_key == NULL, "group_key should be NULL");
    
    TEST_ASSERT_EQ(0, options.custom_domain_count, "custom_domain_count should be 0");
    TEST_ASSERT_EQ(0, options.location_count, "location_count should be 0");
    
    frpc_tunnel_options_cleanup(&options);
    return 0;
}

// Test tunnel config initialization
int test_tunnel_config_init() {
    printf("\n=== Testing frpc_tunnel_config_init ===\n");
    
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Test default values
    TEST_ASSERT_EQ(7000, config.server_port, "Default server_port should be 7000");
    TEST_ASSERT_EQ(false, config.use_tls, "Default use_tls should be false");
    TEST_ASSERT_EQ(FRPC_TUNNEL_STCP_SERVER, config.tunnel_type, "Default tunnel_type should be STCP_SERVER");
    TEST_ASSERT_EQ(0, config.local_port, "Default local_port should be 0");
    TEST_ASSERT_EQ(0, config.bind_port, "Default bind_port should be 0");
    
    // Test that pointers are initialized to NULL
    TEST_ASSERT(config.server_addr == NULL, "server_addr should be NULL");
    TEST_ASSERT(config.token == NULL, "token should be NULL");
    TEST_ASSERT(config.tunnel_name == NULL, "tunnel_name should be NULL");
    TEST_ASSERT(config.secret_key == NULL, "secret_key should be NULL");
    TEST_ASSERT(config.local_addr == NULL, "local_addr should be NULL");
    TEST_ASSERT(config.remote_name == NULL, "remote_name should be NULL");
    TEST_ASSERT(config.bind_addr == NULL, "bind_addr should be NULL");
    
    // Test that options are properly initialized
    TEST_ASSERT_EQ(true, config.options.enable_multiplexing, "Options should be initialized");
    
    frpc_tunnel_config_cleanup(&config);
    return 0;
}

// Test tunnel config validation - valid STCP server config
int test_tunnel_config_validate_stcp_server() {
    printf("\n=== Testing frpc_tunnel_config_validate - STCP Server ===\n");
    
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Set up valid STCP server configuration
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test_stcp_server");
    config.secret_key = strdup("test_secret");
    config.tunnel_type = FRPC_TUNNEL_STCP_SERVER;
    config.local_addr = strdup("127.0.0.1");
    config.local_port = 8080;
    
    int result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(0, result, "Valid STCP server config should pass validation");
    
    frpc_tunnel_config_cleanup(&config);
    return 0;
}

// Test tunnel config validation - invalid configs
int test_tunnel_config_validate_invalid() {
    printf("\n=== Testing frpc_tunnel_config_validate - Invalid Configs ===\n");
    
    frpc_tunnel_config_t config;
    int result;
    
    // Test NULL config
    result = frpc_tunnel_config_validate(NULL);
    TEST_ASSERT_EQ(-1, result, "NULL config should fail validation");
    
    // Test missing server address
    frpc_tunnel_config_init(&config);
    config.tunnel_name = strdup("test");
    config.secret_key = strdup("secret");
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "Missing server address should fail validation");
    frpc_tunnel_config_cleanup(&config);
    
    // Test invalid server port
    frpc_tunnel_config_init(&config);
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 0;
    config.tunnel_name = strdup("test");
    config.secret_key = strdup("secret");
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "Invalid server port should fail validation");
    frpc_tunnel_config_cleanup(&config);
    
    // Test missing tunnel name
    frpc_tunnel_config_init(&config);
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.secret_key = strdup("secret");
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "Missing tunnel name should fail validation");
    frpc_tunnel_config_cleanup(&config);
    
    // Test invalid tunnel type
    frpc_tunnel_config_init(&config);
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test");
    config.secret_key = strdup("secret");
    config.tunnel_type = 999; // Invalid type
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "Invalid tunnel type should fail validation");
    frpc_tunnel_config_cleanup(&config);
    
    // Test STCP without secret key
    frpc_tunnel_config_init(&config);
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test");
    config.tunnel_type = FRPC_TUNNEL_STCP_SERVER;
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "STCP without secret key should fail validation");
    frpc_tunnel_config_cleanup(&config);
    
    return 0;
}

// Test tunnel config validation - TCP tunnel
int test_tunnel_config_validate_tcp() {
    printf("\n=== Testing frpc_tunnel_config_validate - TCP Tunnel ===\n");
    
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Set up valid TCP configuration
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test_tcp");
    config.tunnel_type = FRPC_TUNNEL_TCP;
    config.local_port = 8080;
    
    int result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(0, result, "Valid TCP config should pass validation");
    
    // Test TCP without local port
    config.local_port = 0;
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "TCP without local port should fail validation");
    
    frpc_tunnel_config_cleanup(&config);
    return 0;
}

// Test tunnel config validation - HTTP tunnel
int test_tunnel_config_validate_http() {
    printf("\n=== Testing frpc_tunnel_config_validate - HTTP Tunnel ===\n");
    
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Set up valid HTTP configuration with custom domain
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test_http");
    config.tunnel_type = FRPC_TUNNEL_HTTP;
    config.options.custom_domains[0] = strdup("example.com");
    config.options.custom_domain_count = 1;
    
    int result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(0, result, "Valid HTTP config with custom domain should pass validation");
    
    frpc_tunnel_config_cleanup(&config);
    return 0;
}

// Test tunnel config validation - TLS configuration
int test_tunnel_config_validate_tls() {
    printf("\n=== Testing frpc_tunnel_config_validate - TLS Configuration ===\n");
    
    frpc_tunnel_config_t config;
    frpc_tunnel_config_init(&config);
    
    // Set up configuration with TLS enabled but missing cert/key
    config.server_addr = strdup("127.0.0.1");
    config.server_port = 7000;
    config.tunnel_name = strdup("test_tls");
    config.tunnel_type = FRPC_TUNNEL_HTTPS;
    config.options.enable_tls = true;
    config.options.custom_domains[0] = strdup("example.com");
    config.options.custom_domain_count = 1;
    
    int result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(-1, result, "TLS enabled without cert/key should fail validation");
    
    // Add cert and key paths
    config.options.tls_cert_path = strdup("/path/to/cert.pem");
    config.options.tls_key_path = strdup("/path/to/key.pem");
    
    result = frpc_tunnel_config_validate(&config);
    TEST_ASSERT_EQ(0, result, "TLS with cert/key should pass validation");
    
    frpc_tunnel_config_cleanup(&config);
    return 0;
}

// Main test runner
int main() {
    printf("Running tunnel configuration tests...\n");
    
    // Initialize FRPC library for testing
    frpc_init();
    
    int failed_tests = 0;
    
    if (test_tunnel_options_init() != 0) failed_tests++;
    if (test_tunnel_config_init() != 0) failed_tests++;
    if (test_tunnel_config_validate_stcp_server() != 0) failed_tests++;
    if (test_tunnel_config_validate_invalid() != 0) failed_tests++;
    if (test_tunnel_config_validate_tcp() != 0) failed_tests++;
    if (test_tunnel_config_validate_http() != 0) failed_tests++;
    if (test_tunnel_config_validate_tls() != 0) failed_tests++;
    
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