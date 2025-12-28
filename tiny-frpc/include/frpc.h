#ifndef FRPC_H
#define FRPC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// FRP client configuration structure
typedef struct frpc_config_s {
    const char* server_addr;       // FRP server address
    uint16_t server_port;          // FRP server port
    const char* token;             // Authentication token (if required)
    uint32_t heartbeat_interval;   // Heartbeat interval (seconds)
    bool tls_enable;               // Whether to enable TLS
    bool use_encryption;           // Whether to use encryption after login (default: true)
} frpc_config_t;

// FRP client instance (opaque pointer)
typedef struct frpc_client frpc_client_t;

// Error codes
enum frpc_error_code {
    FRPC_SUCCESS = 0,
    FRPC_ERROR_INVALID_PARAM = -1,
    FRPC_ERROR_MEMORY = -2,
    FRPC_ERROR_NETWORK = -3,
    FRPC_ERROR_AUTH = -4,
    FRPC_ERROR_TIMEOUT = -5,
    FRPC_ERROR_PROTO = -6,
    FRPC_ERROR_INTERNAL = -7,
    FRPC_ERROR_CONNECTION_CLOSED = -8,
    FRPC_ERROR_CONNECTION_CLOSED_BY_REMOTE = -9,
    FRPC_ERROR_STREAM_NOT_WRITABLE = -10 // Stream is not writable
};

// Callback function types
// Called when network events (connect, disconnect, etc.) occur
typedef void (*frpc_event_callback)(void* user_ctx, int event_type, void* event_data);

// Create FRP client instance
frpc_client_t* frpc_client_new(const frpc_config_t* config, void* user_ctx);

// Free FRP client instance
void frpc_client_free(frpc_client_t* client);

// Set encryption mode for the client (before connect)
void frpc_client_set_encryption(frpc_client_t* client, bool enabled);

// Connect to FRP server
int frpc_client_connect(frpc_client_t* client);

// Disconnect from FRP server
int frpc_client_disconnect(frpc_client_t* client);

// Handle received data
int frpc_client_receive(frpc_client_t* client, const uint8_t* data, size_t len);

// Called periodically to handle heartbeat and other timed tasks
int frpc_client_tick(frpc_client_t* client);

// Set event callback
void frpc_client_set_event_callback(frpc_client_t* client, frpc_event_callback callback);

// Send raw bytes over the connection to frps
// Returns number of bytes sent or negative error code
int frpc_client_send_raw_bytes(frpc_client_t* client, const uint8_t* data, size_t len);

// Legacy API for backwards compatibility (deprecated, use frpc_client_send_raw_bytes)
int frpc_client_send_yamux_frame_bytes(frpc_client_t* client, const uint8_t* data, size_t len);

// Send FRP protocol message (type byte + 8-byte length + JSON body)
// Returns 0 on success, negative error code on failure
int frpc_client_send_msg(frpc_client_t* client, uint8_t type, const char* json, size_t json_len);

// Read FRP protocol message (type byte + 8-byte length + JSON body)
// Caller must free *json_out after use
// Returns 0 on success, negative error code on failure
int frpc_client_read_msg(frpc_client_t* client, uint8_t* type_out, char** json_out, size_t* json_len_out, int timeout_ms);

// Get client run_id (assigned by frps after login)
const char* frpc_client_get_run_id(frpc_client_t* client);

// Get client token
const char* frpc_client_get_token(frpc_client_t* client);

// Get server address and port from client config
const char* frpc_client_get_server_addr(frpc_client_t* client);
uint16_t frpc_client_get_server_port(frpc_client_t* client);

// Check if there is data available on the control connection (non-blocking)
bool frpc_client_has_data(frpc_client_t* client);

// Dial a new TCP connection to the FRP server (for visitor/work connections)
// Returns file descriptor on success, negative error code on failure
int frpc_dial_server(frpc_client_t* client);

// Send FRP message on a specific file descriptor (for visitor connections)
int frpc_send_msg_on_fd(int fd, uint8_t type, const char* json, size_t json_len);

// Read FRP message from a specific file descriptor (for visitor connections)
// Caller must free *json_out after use
int frpc_read_msg_from_fd(int fd, uint8_t* type_out, char** json_out, size_t* json_len_out, int timeout_ms);

#endif // FRPC_H 