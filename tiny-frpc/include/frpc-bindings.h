#ifndef FRPC_BINDINGS_H
#define FRPC_BINDINGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

// Reuse core FRPC error codes to avoid duplicated enumerators.
#include "frpc.h"

#ifdef __cplusplus
extern "C" {
#endif

// Simplified C API for language bindings
// This provides a more straightforward interface for other languages

// Opaque handle types for language bindings
typedef void* frpc_handle_t;
typedef void* frpc_tunnel_handle_t;

// Callback function types for language bindings
typedef void (*frpc_log_callback_t)(int level, const char* message);
typedef void (*frpc_data_callback_t)(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len, void* user_data);
typedef void (*frpc_connection_callback_t)(frpc_tunnel_handle_t tunnel, int connected, int error_code, void* user_data);

// Log levels
#define FRPC_LOG_DEBUG   0
#define FRPC_LOG_INFO    1
#define FRPC_LOG_WARN    2
#define FRPC_LOG_ERROR   3

// Error codes (alias to core enum).
typedef enum frpc_error_code frpc_error_code_t;

// Error context structure
typedef struct {
    frpc_error_code_t code;
    char* message;
    char* context;
    time_t timestamp;
    uint32_t tunnel_id;
    char* protocol_name;
    char* file;
    int line;
    char* function;
} frpc_error_t;

// Error callback function type
typedef void (*frpc_error_callback_t)(const frpc_error_t* error, void* user_data);

// Tunnel types
#define FRPC_TUNNEL_STCP_SERVER   0
#define FRPC_TUNNEL_STCP_VISITOR  1
#define FRPC_TUNNEL_TCP           2
#define FRPC_TUNNEL_UDP           3
#define FRPC_TUNNEL_HTTP          4
#define FRPC_TUNNEL_HTTPS         5
#define FRPC_TUNNEL_WEBSOCKET     6

// Maximum number of custom domains
#define FRPC_MAX_CUSTOM_DOMAINS   16
#define FRPC_MAX_DOMAIN_LENGTH    256
#define FRPC_MAX_PATH_LENGTH      512

// Protocol-specific options structure
typedef struct {
    // HTTP/HTTPS specific options
    char* host_header_rewrite;
    char* custom_domains[FRPC_MAX_CUSTOM_DOMAINS];
    size_t custom_domain_count;
    bool enable_websocket;
    char* http_user;
    char* http_password;
    char* locations[FRPC_MAX_CUSTOM_DOMAINS];
    size_t location_count;
    
    // TCP/UDP specific options
    bool enable_multiplexing;
    uint32_t connection_pool_size;
    uint32_t max_connections;
    uint32_t bandwidth_limit_mbps;
    
    // Security options
    bool enable_tls;
    char* tls_cert_path;
    char* tls_key_path;
    char* tls_ca_cert_path;
    bool tls_verify_peer;
    
    // Performance options
    uint32_t buffer_size;
    bool enable_compression;
    uint32_t compression_level;
    
    // WebSocket specific options
    bool ws_enable_compression;
    uint32_t ws_max_message_size;
    uint32_t ws_ping_interval;
    
    // Load balancing options
    char* group_name;
    char* group_key;
    uint32_t weight;
} frpc_tunnel_options_t;

// Configuration structure for language bindings
typedef struct {
    // Server connection
    const char* server_addr;
    uint16_t server_port;
    const char* token;
    bool use_tls;
    
    // Tunnel configuration
    int tunnel_type;
    const char* tunnel_name;
    const char* secret_key;
    
    // Local configuration
    const char* local_addr;
    uint16_t local_port;
    
    // Remote configuration (for visitors)
    const char* remote_name;
    const char* bind_addr;
    uint16_t bind_port;
    
    // Protocol-specific options
    frpc_tunnel_options_t options;
    
    // Callbacks
    frpc_log_callback_t log_callback;
    frpc_data_callback_t data_callback;
    frpc_connection_callback_t connection_callback;
    
    // User data pointer
    void* user_data;
} frpc_tunnel_config_t;

// Configuration management functions
void frpc_tunnel_config_init(frpc_tunnel_config_t* config);
void frpc_tunnel_config_cleanup(frpc_tunnel_config_t* config);
int frpc_tunnel_config_validate(const frpc_tunnel_config_t* config);
void frpc_tunnel_options_init(frpc_tunnel_options_t* options);
void frpc_tunnel_options_cleanup(frpc_tunnel_options_t* options);

// Error handling functions
void frpc_error_init(frpc_error_t* error);
void frpc_error_cleanup(frpc_error_t* error);
void frpc_error_set(frpc_error_t* error, frpc_error_code_t code, const char* message, 
                   const char* context, uint32_t tunnel_id, const char* protocol_name,
                   const char* file, int line, const char* function);
void frpc_error_copy(frpc_error_t* dest, const frpc_error_t* src);
const char* frpc_error_code_to_string(frpc_error_code_t code);
void frpc_set_global_error_callback(frpc_error_callback_t callback, void* user_data);
void frpc_trigger_error(const frpc_error_t* error);

// Error reporting macros
#define FRPC_SET_ERROR(error, code, msg, ctx, tunnel_id, protocol) \
    frpc_error_set((error), (code), (msg), (ctx), (tunnel_id), (protocol), __FILE__, __LINE__, __func__)

#define FRPC_REPORT_ERROR(code, msg, ctx, tunnel_id, protocol) \
    do { \
        frpc_error_t _err; \
        frpc_error_init(&_err); \
        FRPC_SET_ERROR(&_err, (code), (msg), (ctx), (tunnel_id), (protocol)); \
        frpc_trigger_error(&_err); \
        frpc_error_cleanup(&_err); \
    } while(0)

// Initialize the FRPC library
int frpc_init(void);

// Cleanup the FRPC library
void frpc_cleanup(void);

// Set global log callback
void frpc_set_log_callback(frpc_log_callback_t callback);

// Create a new FRPC client instance
frpc_handle_t frpc_create(const char* server_addr, uint16_t server_port, const char* token);

// Destroy FRPC client instance
void frpc_destroy(frpc_handle_t handle);

// Connect to FRP server
int frpc_connect(frpc_handle_t handle);

// Disconnect from FRP server
int frpc_disconnect(frpc_handle_t handle);

// Create a tunnel
frpc_tunnel_handle_t frpc_create_tunnel(frpc_handle_t handle, const frpc_tunnel_config_t* config);

// Destroy a tunnel
void frpc_destroy_tunnel(frpc_tunnel_handle_t tunnel);

// Start a tunnel
int frpc_start_tunnel(frpc_tunnel_handle_t tunnel);

// Stop a tunnel
int frpc_stop_tunnel(frpc_tunnel_handle_t tunnel);

// Send data through tunnel
int frpc_send_data(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len);

// Process events (call periodically)
int frpc_process_events(frpc_handle_t handle);

// Get tunnel statistics
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t connections_active;
    uint32_t connections_total;
    uint64_t last_activity_time;
} frpc_tunnel_stats_t;

int frpc_get_tunnel_stats(frpc_tunnel_handle_t tunnel, frpc_tunnel_stats_t* stats);

// Get error message for error code
const char* frpc_get_error_message(int error_code);

// Utility functions for language bindings
bool frpc_is_connected(frpc_handle_t handle);
bool frpc_is_tunnel_active(frpc_tunnel_handle_t tunnel);

// Inject a raw Yamux frame into the tunnel's STCP/Yamux session.
//
// Notes:
// - This is a low-level API mainly for language-binding unit tests (e.g. to trigger data_callback),
//   or advanced use cases where the caller integrates the underlying network I/O manually.
// - `data` must be a complete Yamux frame (12-byte header + payload), in network byte order (big-endian).
// - Return value: >= 0 means number of bytes consumed; < 0 means FRPC_ERROR_*.
int frpc_tunnel_inject_yamux_frame(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // FRPC_BINDINGS_H