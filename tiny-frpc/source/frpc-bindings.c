#include "frpc-bindings.h"
#include "frpc.h"
#include "frpc-stcp.h"
#include "yamux.h"
#include "tools.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// Internal structures
typedef struct frpc_client_wrapper {
    frpc_client_t* client;
    frpc_config_t config;
    bool connected;
    frpc_log_callback_t log_callback;
} frpc_client_wrapper_t;

typedef struct frpc_tunnel_wrapper {
    frpc_client_wrapper_t* client_wrapper;
    frpc_stcp_proxy_t* stcp_proxy;
    frpc_tunnel_config_t config;
    frpc_tunnel_stats_t stats;
    bool active;
    time_t created_time;
} frpc_tunnel_wrapper_t;

// Global state
static frpc_log_callback_t g_log_callback = NULL;
static frpc_error_callback_t g_error_callback = NULL;
static void* g_error_callback_user_data = NULL;
static bool g_initialized = false;

// Internal logging function
static void internal_log(int level, const char* format, ...) {
    if (!g_log_callback) return;
    
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    g_log_callback(level, buffer);
}

// STCP callback implementations
static int stcp_data_callback(void* user_ctx, uint8_t* data, size_t len) {
    frpc_tunnel_wrapper_t* tunnel = (frpc_tunnel_wrapper_t*)user_ctx;
    if (!tunnel || !tunnel->config.data_callback) {
        return -1;
    }
    
    tunnel->stats.bytes_received += len;
    tunnel->config.data_callback((frpc_tunnel_handle_t)tunnel, data, len, tunnel->config.user_data);
    return len;
}

static int stcp_write_callback(void* user_ctx, uint8_t* data, size_t len) {
    frpc_tunnel_wrapper_t* tunnel = (frpc_tunnel_wrapper_t*)user_ctx;
    if (!tunnel) {
        return -1;
    }
    
    tunnel->stats.bytes_sent += len;
    // This is handled internally by the STCP implementation
    return len;
}

static void stcp_connection_callback(void* user_ctx, int connected, int error_code) {
    frpc_tunnel_wrapper_t* tunnel = (frpc_tunnel_wrapper_t*)user_ctx;
    if (!tunnel) {
        return;
    }
    
    if (connected) {
        tunnel->stats.connections_active++;
        tunnel->stats.connections_total++;
        tunnel->active = true;
    } else {
        if (tunnel->stats.connections_active > 0) {
            tunnel->stats.connections_active--;
        }
        tunnel->active = false;
    }
    
    tunnel->stats.last_activity_time = time(NULL);
    
    if (tunnel->config.connection_callback) {
        tunnel->config.connection_callback((frpc_tunnel_handle_t)tunnel, connected, error_code, tunnel->config.user_data);
    }
}

// Configuration management implementations
void frpc_tunnel_config_init(frpc_tunnel_config_t* config) {
    if (!config) return;
    
    memset(config, 0, sizeof(frpc_tunnel_config_t));
    
    // Set default values
    config->server_port = 7000;
    config->use_tls = false;
    config->tunnel_type = FRPC_TUNNEL_STCP_SERVER;
    config->local_port = 0;
    config->bind_port = 0;
    
    // Initialize options
    frpc_tunnel_options_init(&config->options);
}

void frpc_tunnel_config_cleanup(frpc_tunnel_config_t* config) {
    if (!config) return;
    
    // Free allocated strings
    free((void*)config->server_addr);
    free((void*)config->token);
    free((void*)config->tunnel_name);
    free((void*)config->secret_key);
    free((void*)config->local_addr);
    free((void*)config->remote_name);
    free((void*)config->bind_addr);
    
    // Cleanup options
    frpc_tunnel_options_cleanup(&config->options);
    
    // Clear the structure
    memset(config, 0, sizeof(frpc_tunnel_config_t));
}

int frpc_tunnel_config_validate(const frpc_tunnel_config_t* config) {
    if (!config) {
        FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, "Configuration is NULL", 
                         "frpc_tunnel_config_validate", 0, "config");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Validate server address
    if (!config->server_addr || strlen(config->server_addr) == 0) {
        FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, "Server address is required", 
                         "server_addr validation", 0, "config");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Validate server port
    if (config->server_port == 0 || config->server_port > 65535) {
        char port_msg[64];
        snprintf(port_msg, sizeof(port_msg), "Invalid server port: %d", config->server_port);
        FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, port_msg, 
                         "server_port validation", 0, "config");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Validate tunnel name
    if (!config->tunnel_name || strlen(config->tunnel_name) == 0) {
        FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, "Tunnel name is required", 
                         "tunnel_name validation", 0, "config");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Validate tunnel type
    if (config->tunnel_type < FRPC_TUNNEL_STCP_SERVER || config->tunnel_type > FRPC_TUNNEL_WEBSOCKET) {
        char type_msg[64];
        snprintf(type_msg, sizeof(type_msg), "Invalid tunnel type: %d", config->tunnel_type);
        FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, type_msg, 
                         "tunnel_type validation", 0, "config");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Type-specific validation
    switch (config->tunnel_type) {
        case FRPC_TUNNEL_STCP_SERVER:
        case FRPC_TUNNEL_STCP_VISITOR:
            if (!config->secret_key || strlen(config->secret_key) == 0) {
                FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, "Secret key is required for STCP tunnels", 
                                 "STCP secret_key validation", 0, "STCP");
                return FRPC_ERROR_INVALID_PARAM;
            }
            break;
            
        case FRPC_TUNNEL_TCP:
        case FRPC_TUNNEL_UDP:
            if (config->local_port == 0) {
                FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, "Local port is required for TCP/UDP tunnels", 
                                 "TCP/UDP local_port validation", 0, 
                                 config->tunnel_type == FRPC_TUNNEL_TCP ? "TCP" : "UDP");
                return FRPC_ERROR_INVALID_PARAM;
            }
            break;
            
        case FRPC_TUNNEL_HTTP:
        case FRPC_TUNNEL_HTTPS:
        case FRPC_TUNNEL_WEBSOCKET:
            if (config->options.custom_domain_count == 0 && 
                (!config->tunnel_name || strlen(config->tunnel_name) == 0)) {
                const char* protocol = (config->tunnel_type == FRPC_TUNNEL_HTTP) ? "HTTP" :
                                      (config->tunnel_type == FRPC_TUNNEL_HTTPS) ? "HTTPS" : "WebSocket";
                FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, 
                                 "Custom domain or subdomain is required for HTTP/HTTPS/WebSocket tunnels", 
                                 "HTTP/HTTPS/WebSocket domain validation", 0, protocol);
                return FRPC_ERROR_INVALID_PARAM;
            }
            break;
    }
    
    // Validate TLS configuration if enabled
    if (config->options.enable_tls) {
        if (!config->options.tls_cert_path || !config->options.tls_key_path) {
            FRPC_REPORT_ERROR(FRPC_ERROR_INVALID_PARAM, 
                             "TLS certificate and key paths are required when TLS is enabled", 
                             "TLS configuration validation", 0, "TLS");
            return FRPC_ERROR_INVALID_PARAM;
        }
    }
    
    internal_log(FRPC_LOG_DEBUG, "Configuration validation passed for tunnel: %s", config->tunnel_name);
    return FRPC_SUCCESS;
}

void frpc_tunnel_options_init(frpc_tunnel_options_t* options) {
    if (!options) return;
    
    memset(options, 0, sizeof(frpc_tunnel_options_t));
    
    // Set default values
    options->enable_multiplexing = true;
    options->connection_pool_size = 10;
    options->max_connections = 100;
    options->bandwidth_limit_mbps = 0; // No limit
    options->enable_tls = false;
    options->tls_verify_peer = true;
    options->buffer_size = 64 * 1024; // 64KB
    options->enable_compression = false;
    options->compression_level = 6;
    options->ws_enable_compression = false;
    options->ws_max_message_size = 1024 * 1024; // 1MB
    options->ws_ping_interval = 30; // 30 seconds
    options->weight = 1;
}

void frpc_tunnel_options_cleanup(frpc_tunnel_options_t* options) {
    if (!options) return;
    
    // Free allocated strings
    free(options->host_header_rewrite);
    free(options->http_user);
    free(options->http_password);
    free(options->tls_cert_path);
    free(options->tls_key_path);
    free(options->tls_ca_cert_path);
    free(options->group_name);
    free(options->group_key);
    
    // Free custom domains array
    for (size_t i = 0; i < options->custom_domain_count && i < FRPC_MAX_CUSTOM_DOMAINS; i++) {
        free(options->custom_domains[i]);
    }
    
    // Free locations array
    for (size_t i = 0; i < options->location_count && i < FRPC_MAX_CUSTOM_DOMAINS; i++) {
        free(options->locations[i]);
    }
    
    // Clear the structure
    memset(options, 0, sizeof(frpc_tunnel_options_t));
}

// Error handling implementations
void frpc_error_init(frpc_error_t* error) {
    if (!error) return;
    
    memset(error, 0, sizeof(frpc_error_t));
    error->code = FRPC_SUCCESS;
    error->timestamp = time(NULL);
}

void frpc_error_cleanup(frpc_error_t* error) {
    if (!error) return;
    
    free(error->message);
    free(error->context);
    free(error->protocol_name);
    free(error->file);
    free(error->function);
    
    memset(error, 0, sizeof(frpc_error_t));
}

void frpc_error_set(frpc_error_t* error, frpc_error_code_t code, const char* message, 
                   const char* context, uint32_t tunnel_id, const char* protocol_name,
                   const char* file, int line, const char* function) {
    if (!error) return;
    
    // Clean up existing data
    frpc_error_cleanup(error);
    
    // Set new error data
    error->code = code;
    error->timestamp = time(NULL);
    error->tunnel_id = tunnel_id;
    error->line = line;
    
    // Copy strings
    if (message) {
        error->message = strdup(message);
    }
    if (context) {
        error->context = strdup(context);
    }
    if (protocol_name) {
        error->protocol_name = strdup(protocol_name);
    }
    if (file) {
        error->file = strdup(file);
    }
    if (function) {
        error->function = strdup(function);
    }
}

void frpc_error_copy(frpc_error_t* dest, const frpc_error_t* src) {
    if (!dest || !src) return;
    
    frpc_error_set(dest, src->code, src->message, src->context, 
                  src->tunnel_id, src->protocol_name, 
                  src->file, src->line, src->function);
    dest->timestamp = src->timestamp;
}

const char* frpc_error_code_to_string(frpc_error_code_t code) {
    switch (code) {
        case FRPC_SUCCESS: return "Success";
        case FRPC_ERROR_INVALID_PARAM: return "Invalid parameter";
        case FRPC_ERROR_MEMORY: return "Memory allocation error";
        case FRPC_ERROR_NETWORK: return "Network error";
        case FRPC_ERROR_AUTH: return "Authentication error";
        case FRPC_ERROR_TIMEOUT: return "Timeout error";
        case FRPC_ERROR_PROTO: return "Protocol error";
        case FRPC_ERROR_INTERNAL: return "Internal error";
        case FRPC_ERROR_CONNECTION_CLOSED: return "Connection closed";
        case FRPC_ERROR_CONNECTION_CLOSED_BY_REMOTE: return "Connection closed by remote";
        case FRPC_ERROR_STREAM_NOT_WRITABLE: return "Stream not writable";
        default: return "Unknown error";
    }
}

void frpc_set_global_error_callback(frpc_error_callback_t callback, void* user_data) {
    g_error_callback = callback;
    g_error_callback_user_data = user_data;
}

void frpc_trigger_error(const frpc_error_t* error) {
    if (!error) return;
    
    // Log the error
    if (g_log_callback) {
        char log_buffer[2048];
        snprintf(log_buffer, sizeof(log_buffer), 
                "Error %d (%s): %s [Context: %s, Tunnel: %u, Protocol: %s, Location: %s:%d in %s()]",
                error->code, 
                frpc_error_code_to_string(error->code),
                error->message ? error->message : "No message",
                error->context ? error->context : "No context",
                error->tunnel_id,
                error->protocol_name ? error->protocol_name : "Unknown",
                error->file ? error->file : "Unknown",
                error->line,
                error->function ? error->function : "Unknown");
        g_log_callback(FRPC_LOG_ERROR, log_buffer);
    }
    
    // Trigger error callback if set
    if (g_error_callback) {
        g_error_callback(error, g_error_callback_user_data);
    }
}

// Public API implementation
int frpc_init(void) {
    if (g_initialized) {
        return 0;
    }
    
    // Initialize any global state here
    g_initialized = true;
    internal_log(FRPC_LOG_INFO, "FRPC library initialized");
    return 0;
}

void frpc_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    g_log_callback = NULL;
    g_initialized = false;
    internal_log(FRPC_LOG_INFO, "FRPC library cleaned up");
}

void frpc_set_log_callback(frpc_log_callback_t callback) {
    g_log_callback = callback;
}

frpc_handle_t frpc_create(const char* server_addr, uint16_t server_port, const char* token) {
    if (!g_initialized) {
        frpc_init();
    }
    
    frpc_client_wrapper_t* wrapper = malloc(sizeof(frpc_client_wrapper_t));
    if (!wrapper) {
        internal_log(FRPC_LOG_ERROR, "Failed to allocate memory for client wrapper");
        return NULL;
    }
    
    memset(wrapper, 0, sizeof(frpc_client_wrapper_t));
    
    // Setup configuration
    wrapper->config.server_addr = strdup(server_addr);
    wrapper->config.server_port = server_port;
    wrapper->config.token = token ? strdup(token) : NULL;
    wrapper->config.heartbeat_interval = 30;
    wrapper->config.tls_enable = false;
    wrapper->config.use_encryption = true;  // Default to true for real frps compatibility
    
    // Create FRP client
    wrapper->client = frpc_client_new(&wrapper->config, wrapper);
    if (!wrapper->client) {
        free((void*)wrapper->config.server_addr);
        free((void*)wrapper->config.token);
        free(wrapper);
        internal_log(FRPC_LOG_ERROR, "Failed to create FRP client");
        return NULL;
    }
    
    wrapper->connected = false;
    internal_log(FRPC_LOG_INFO, "Created FRP client for %s:%d", server_addr, server_port);
    
    return (frpc_handle_t)wrapper;
}

void frpc_set_encryption(frpc_handle_t handle, bool enabled) {
    if (!handle) return;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    wrapper->config.use_encryption = enabled;
    
    // Also update the client's internal config
    if (wrapper->client) {
        frpc_client_set_encryption(wrapper->client, enabled);
    }
    
    internal_log(FRPC_LOG_DEBUG, "Encryption %s", enabled ? "enabled" : "disabled");
}

void frpc_destroy(frpc_handle_t handle) {
    if (!handle) return;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    
    if (wrapper->connected) {
        frpc_disconnect(handle);
    }
    
    if (wrapper->client) {
        frpc_client_free(wrapper->client);
    }
    
    free((void*)wrapper->config.server_addr);
    free((void*)wrapper->config.token);
    free(wrapper);
    
    internal_log(FRPC_LOG_INFO, "Destroyed FRP client");
}

int frpc_connect(frpc_handle_t handle) {
    if (!handle) return -1;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    
    int ret = frpc_client_connect(wrapper->client);
    if (ret == 0) {
        wrapper->connected = true;
        internal_log(FRPC_LOG_INFO, "Connected to FRP server");
    } else {
        internal_log(FRPC_LOG_ERROR, "Failed to connect to FRP server: %d", ret);
    }
    
    return ret;
}

int frpc_disconnect(frpc_handle_t handle) {
    if (!handle) return -1;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    
    int ret = frpc_client_disconnect(wrapper->client);
    wrapper->connected = false;
    
    internal_log(FRPC_LOG_INFO, "Disconnected from FRP server");
    return ret;
}

frpc_tunnel_handle_t frpc_create_tunnel(frpc_handle_t handle, const frpc_tunnel_config_t* config) {
    if (!handle || !config) return NULL;
    
    frpc_client_wrapper_t* client_wrapper = (frpc_client_wrapper_t*)handle;
    
    frpc_tunnel_wrapper_t* tunnel = malloc(sizeof(frpc_tunnel_wrapper_t));
    if (!tunnel) {
        internal_log(FRPC_LOG_ERROR, "Failed to allocate memory for tunnel");
        return NULL;
    }
    
    memset(tunnel, 0, sizeof(frpc_tunnel_wrapper_t));
    tunnel->client_wrapper = client_wrapper;
    tunnel->config = *config; // Copy configuration
    tunnel->created_time = time(NULL);
    
    // Duplicate string fields
    if (config->tunnel_name) {
        tunnel->config.tunnel_name = strdup(config->tunnel_name);
    }
    if (config->secret_key) {
        tunnel->config.secret_key = strdup(config->secret_key);
    }
    if (config->local_addr) {
        tunnel->config.local_addr = strdup(config->local_addr);
    }
    if (config->remote_name) {
        tunnel->config.remote_name = strdup(config->remote_name);
    }
    if (config->bind_addr) {
        tunnel->config.bind_addr = strdup(config->bind_addr);
    }
    
    // Create STCP proxy based on tunnel type
    if (config->tunnel_type == FRPC_TUNNEL_STCP_SERVER || config->tunnel_type == FRPC_TUNNEL_STCP_VISITOR) {
        frpc_stcp_config_t stcp_config;
        memset(&stcp_config, 0, sizeof(stcp_config));
        
        stcp_config.role = (config->tunnel_type == FRPC_TUNNEL_STCP_SERVER) ? 
                          FRPC_STCP_ROLE_SERVER : FRPC_STCP_ROLE_VISITOR;
        stcp_config.proxy_name = tunnel->config.tunnel_name;
        stcp_config.sk = tunnel->config.secret_key;
        
        if (config->tunnel_type == FRPC_TUNNEL_STCP_SERVER) {
            stcp_config.local_addr = tunnel->config.local_addr;
            stcp_config.local_port = tunnel->config.local_port;
        } else {
            stcp_config.server_name = tunnel->config.remote_name;
            stcp_config.bind_addr = tunnel->config.bind_addr;
            stcp_config.bind_port = tunnel->config.bind_port;
        }
        
        // Set callbacks
        stcp_config.on_data = stcp_data_callback;
        stcp_config.on_write = stcp_write_callback;
        stcp_config.on_connection = stcp_connection_callback;
        
        tunnel->stcp_proxy = frpc_stcp_proxy_new(client_wrapper->client, &stcp_config, tunnel);
        if (!tunnel->stcp_proxy) {
            frpc_destroy_tunnel((frpc_tunnel_handle_t)tunnel);
            internal_log(FRPC_LOG_ERROR, "Failed to create STCP proxy");
            return NULL;
        }
    }
    
    internal_log(FRPC_LOG_INFO, "Created tunnel: %s (type: %d)", 
                config->tunnel_name ? config->tunnel_name : "unnamed", config->tunnel_type);
    
    return (frpc_tunnel_handle_t)tunnel;
}

void frpc_destroy_tunnel(frpc_tunnel_handle_t tunnel) {
    if (!tunnel) return;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    
    if (t->active) {
        frpc_stop_tunnel(tunnel);
    }
    
    if (t->stcp_proxy) {
        frpc_stcp_proxy_free(t->stcp_proxy);
    }
    
    // Free duplicated strings
    free((void*)t->config.tunnel_name);
    free((void*)t->config.secret_key);
    free((void*)t->config.local_addr);
    free((void*)t->config.remote_name);
    free((void*)t->config.bind_addr);
    
    free(t);
    
    internal_log(FRPC_LOG_INFO, "Destroyed tunnel");
}

int frpc_start_tunnel(frpc_tunnel_handle_t tunnel) {
    if (!tunnel) return -1;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    
    if (!t->stcp_proxy) {
        internal_log(FRPC_LOG_ERROR, "No STCP proxy available for tunnel");
        return -1;
    }
    
    int ret = frpc_stcp_proxy_start(t->stcp_proxy);
    if (ret == 0) {
        t->active = true;
        t->stats.last_activity_time = time(NULL);
        internal_log(FRPC_LOG_INFO, "Started tunnel: %s", t->config.tunnel_name);
        
        // Additional setup based on tunnel type
        if (t->config.tunnel_type == FRPC_TUNNEL_STCP_SERVER) {
            ret = frpc_stcp_server_register(t->stcp_proxy);
        } else if (t->config.tunnel_type == FRPC_TUNNEL_STCP_VISITOR) {
            ret = frpc_stcp_visitor_connect(t->stcp_proxy);
        }
    } else {
        internal_log(FRPC_LOG_ERROR, "Failed to start tunnel: %d", ret);
    }
    
    return ret;
}

int frpc_stop_tunnel(frpc_tunnel_handle_t tunnel) {
    if (!tunnel) return -1;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    
    if (!t->stcp_proxy) {
        return -1;
    }
    
    int ret = frpc_stcp_proxy_stop(t->stcp_proxy);
    t->active = false;
    
    internal_log(FRPC_LOG_INFO, "Stopped tunnel: %s", t->config.tunnel_name);
    return ret;
}

int frpc_send_data(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len) {
    if (!tunnel || !data || len == 0) return -1;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    
    if (!t->active || !t->stcp_proxy) {
        return -1;
    }
    
    int ret = frpc_stcp_send(t->stcp_proxy, data, len);
    if (ret > 0) {
        t->stats.bytes_sent += ret;
        t->stats.last_activity_time = time(NULL);
    }
    
    return ret;
}

int frpc_process_events(frpc_handle_t handle) {
    if (!handle) return -1;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    
    // Process client events
    int ret = frpc_client_tick(wrapper->client);
    
    return ret;
}

int frpc_tunnel_tick(frpc_tunnel_handle_t tunnel) {
    if (!tunnel) return -1;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    
    if (!t->stcp_proxy) {
        return -1;
    }
    
    // Process tunnel events (handles ReqWorkConn for servers, polls work connection for data)
    int ret = frpc_stcp_tick(t->stcp_proxy);
    
    return ret;
}


int frpc_get_tunnel_stats(frpc_tunnel_handle_t tunnel, frpc_tunnel_stats_t* stats) {
    if (!tunnel || !stats) return -1;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    *stats = t->stats;
    
    return 0;
}

const char* frpc_get_error_message(int error_code) {
    return frpc_error_code_to_string((frpc_error_code_t)error_code);
}

bool frpc_is_connected(frpc_handle_t handle) {
    if (!handle) return false;
    
    frpc_client_wrapper_t* wrapper = (frpc_client_wrapper_t*)handle;
    return wrapper->connected;
}

bool frpc_is_tunnel_active(frpc_tunnel_handle_t tunnel) {
    if (!tunnel) return false;
    
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    return t->active;
}

int frpc_tunnel_inject_yamux_frame(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len) {
    if (!tunnel || !data || len == 0) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    frpc_tunnel_wrapper_t* t = (frpc_tunnel_wrapper_t*)tunnel;
    if (!t->stcp_proxy) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    // Feed raw bytes into the STCP/Yamux parser; it will dispatch to data_callback if applicable.
    return frpc_stcp_receive(t->stcp_proxy, data, len);
}