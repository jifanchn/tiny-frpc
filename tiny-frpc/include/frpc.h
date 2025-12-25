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
    FRPC_ERROR_STREAM_NOT_WRITABLE = -10 // Corresponds to yamux -6
};

// Callback function types
// Called when network events (connect, disconnect, etc.) occur
typedef void (*frpc_event_callback)(void* user_ctx, int event_type, void* event_data);

// Create FRP client instance
frpc_client_t* frpc_client_new(const frpc_config_t* config, void* user_ctx);

// Free FRP client instance
void frpc_client_free(frpc_client_t* client);

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

// Send Yamux frame bytes (used by Yamux write_fn)
// These bytes are sent to the frps connection, frps routes them to the work conn peer
int frpc_client_send_yamux_frame_bytes(frpc_client_t* client, const uint8_t* data, size_t len);

#endif // FRPC_H 