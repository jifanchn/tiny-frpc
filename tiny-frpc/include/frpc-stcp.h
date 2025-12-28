#ifndef FRPC_STCP_H
#define FRPC_STCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "frpc.h"   // Include basic FRP client definitions

// STCP proxy role types
typedef enum {
    FRPC_STCP_ROLE_SERVER = 0,  // STCP server
    FRPC_STCP_ROLE_VISITOR = 1  // STCP visitor
} frpc_stcp_role_t;

// STCP proxy configuration
typedef struct frpc_stcp_config_s {
    frpc_stcp_role_t role;       // Proxy role (server or visitor)
    const char* proxy_name;      // Proxy name
    const char* sk;              // Shared secret key
    
    // Server-specific configuration
    const char* local_addr;      // Local service address
    uint16_t local_port;         // Local service port
    
    // Visitor-specific configuration
    const char* server_name;     // Name of the server to connect to
    const char* bind_addr;       // Local bind address
    uint16_t bind_port;          // Local bind port
    
    // Callback functions
    int (*on_data)(void* user_ctx, uint8_t* data, size_t len);
    int (*on_write)(void* user_ctx, uint8_t* data, size_t len);
    void (*on_connection)(void* user_ctx, int connected, int error_code);
} frpc_stcp_config_t;

// STCP proxy instance (opaque pointer)
typedef struct frpc_stcp_proxy frpc_stcp_proxy_t;

// Create STCP proxy
frpc_stcp_proxy_t* frpc_stcp_proxy_new(frpc_client_t* client, 
                                       const frpc_stcp_config_t* config, 
                                       void* user_ctx);

// Free STCP proxy
void frpc_stcp_proxy_free(frpc_stcp_proxy_t* proxy);

// Start STCP proxy
int frpc_stcp_proxy_start(frpc_stcp_proxy_t* proxy);

// Stop STCP proxy
int frpc_stcp_proxy_stop(frpc_stcp_proxy_t* proxy);

// Send data (for visitor)
int frpc_stcp_send(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len);

// Handle received data
int frpc_stcp_receive(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len);

// Handle periodic tasks
int frpc_stcp_tick(frpc_stcp_proxy_t* proxy);

// Visitor-specific interface
// Establish connection to server
int frpc_stcp_visitor_connect(frpc_stcp_proxy_t* proxy);

// Close connection to server
int frpc_stcp_visitor_disconnect(frpc_stcp_proxy_t* proxy);

// Server-specific interface
// Register local service
int frpc_stcp_server_register(frpc_stcp_proxy_t* proxy);

// Set allowed user list
int frpc_stcp_server_set_allow_users(frpc_stcp_proxy_t* proxy, const char** users, size_t count);

// Data transport configuration
typedef struct frpc_stcp_transport_config_s {
    bool use_encryption;         // Whether to use encryption
    bool use_compression;        // Whether to use compression
} frpc_stcp_transport_config_t;

// Set transport configuration
int frpc_stcp_set_transport_config(frpc_stcp_proxy_t* proxy, const frpc_stcp_transport_config_t* config);

#endif // FRPC_STCP_H 