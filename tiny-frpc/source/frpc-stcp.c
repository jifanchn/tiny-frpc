#include "../include/frpc-stcp.h"
#include "../include/frpc.h"
#include "../include/tools.h"
#include "wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Quiet by default; set TINY_FRPC_VERBOSE=1 to enable extra debug logs.
static int frpc_stcp_verbose_enabled(void) {
    static int inited = 0;
    static int enabled = 0;
    if (!inited) {
        const char* v = getenv("TINY_FRPC_VERBOSE");
        enabled = (v && v[0] != '\0' && v[0] != '0');
        inited = 1;
    }
    return enabled;
}

// STCP proxy structure
struct frpc_stcp_proxy {
    frpc_stcp_config_t config;
    frpc_client_t* client;
    void* user_ctx;
    
    // Transport config
    bool use_encryption;
    bool use_compression;
    
    // Server-only fields
    char** allow_users;
    size_t allow_users_count;
    
    // State flags
    bool is_started;
    bool is_connected;
    bool is_registered;    // server role: whether it has been registered to frps
    
    // Connection file descriptors
    int visitor_fd;        // Visitor: connection to FRPS for data transfer
    int work_conn_fds[10]; // Server: work connection fds (MAX 10)
    bool work_conn_active[10]; // Server: true if StartWorkConn received
};


// Create an STCP proxy
frpc_stcp_proxy_t* frpc_stcp_proxy_new(frpc_client_t* client, 
                                       const frpc_stcp_config_t* config, 
                                       void* user_ctx) {
    if (!client || !config) {
        fprintf(stderr, "Error: Invalid STCP proxy parameters\n");
        return NULL;
    }
    
    struct frpc_stcp_proxy* proxy = (struct frpc_stcp_proxy*)malloc(sizeof(struct frpc_stcp_proxy));
    if (!proxy) {
        fprintf(stderr, "Error: Failed to allocate memory for STCP proxy\n");
        return NULL;
    }
    
    memset(proxy, 0, sizeof(struct frpc_stcp_proxy));
    proxy->config = *config;
    proxy->client = client;
    proxy->user_ctx = user_ctx;
    proxy->visitor_fd = -1;    // Initialize as invalid
    for (int i = 0; i < 10; i++) {
        proxy->work_conn_fds[i] = -1;
        proxy->work_conn_active[i] = false;
    }
    
    // Duplicate string fields
    proxy->config.proxy_name = strdup(config->proxy_name);
    proxy->config.sk = strdup(config->sk);
    
    if (config->role == FRPC_STCP_ROLE_SERVER) {
        if (config->local_addr) {
            proxy->config.local_addr = strdup(config->local_addr);
        }
    } else { // VISITOR
        if (config->server_name) {
            proxy->config.server_name = strdup(config->server_name);
        }
        if (config->bind_addr) {
            proxy->config.bind_addr = strdup(config->bind_addr);
        }
    }
    
    return proxy;
}

// Free an STCP proxy
void frpc_stcp_proxy_free(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return;
    
    // Stop the proxy first
    if (proxy->is_started) {
        frpc_stcp_proxy_stop(proxy);
    }
    
    // Free duplicated strings
    if (proxy->config.proxy_name) free((void*)proxy->config.proxy_name);
    if (proxy->config.sk) free((void*)proxy->config.sk);
    
    if (proxy->config.role == FRPC_STCP_ROLE_SERVER) {
        if (proxy->config.local_addr) free((void*)proxy->config.local_addr);
        
        // Free allow-users list
        if (proxy->allow_users) {
            for (size_t i = 0; i < proxy->allow_users_count; i++) {
                if (proxy->allow_users[i]) {
                    free(proxy->allow_users[i]);
                }
            }
            free(proxy->allow_users);
        }
    } else { // VISITOR
        if (proxy->config.server_name) free((void*)proxy->config.server_name);
        if (proxy->config.bind_addr) free((void*)proxy->config.bind_addr);
    }
    
    free(proxy);
}

// Compute visitor sign key (equivalent to Go: util.GetAuthKey(sk, timestamp)).
static int stcp_get_sign_key(const char* sk, int64_t timestamp, char out_hex[33]) {
    return tools_get_auth_key(sk, timestamp, out_hex);
}

// Start STCP Visitor proxy
static int stcp_visitor_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->config.server_name) {
        fprintf(stderr, "Error: STCP visitor missing server_name\n");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Validate bind_addr and bind_port
    if (!proxy->config.bind_addr || proxy->config.bind_port == 0) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "Warning: STCP visitor missing bind_addr or bind_port, using defaults\n");
        }
        if (!proxy->config.bind_addr) {
            // Set default bind address
            proxy->config.bind_addr = strdup("127.0.0.1");
            if (!proxy->config.bind_addr) {
                return FRPC_ERROR_MEMORY;
            }
        }
        if (proxy->config.bind_port == 0) {
            // Set default port
            proxy->config.bind_port = 10000;
        }
    }
    
    fprintf(stdout, "Starting STCP visitor for server: %s\n", proxy->config.server_name);
    
    proxy->is_started = true;
    return FRPC_SUCCESS;
}

// Start STCP Server proxy
static int stcp_server_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->config.local_addr) {
        fprintf(stderr, "Error: STCP server missing local_addr\n");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Currently only basic functionality is implemented.
    fprintf(stdout, "Starting STCP server for local service: %s:%d\n", 
            proxy->config.local_addr, proxy->config.local_port);
    
    proxy->is_started = true;
    return FRPC_SUCCESS;
}

// Start STCP proxy
int frpc_stcp_proxy_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (proxy->is_started) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "Warning: STCP proxy already started\n");
        }
        return FRPC_SUCCESS;
    }
    
    // Start per role
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
        return stcp_visitor_start(proxy);
    } else {
        return stcp_server_start(proxy);
    }
}

// Stop STCP proxy
int frpc_stcp_proxy_stop(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        return FRPC_SUCCESS;
    }
    
    // Stop per role
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
        // Disconnect from server
        if (proxy->is_connected) {
            frpc_stcp_visitor_disconnect(proxy);
        }
    } else {
        // Unregister service
        if (proxy->is_registered) {
            // TODO: send unregister message to frps
            // ...
            proxy->is_registered = false;
        }
    }
    
    // Close visitor connection
    if (proxy->visitor_fd >= 0) {
        wrapped_close(proxy->visitor_fd);
        proxy->visitor_fd = -1;
    }
    
    // Close work connections (server role)
    for (int i = 0; i < 10; i++) {
        if (proxy->work_conn_fds[i] >= 0) {
            wrapped_close(proxy->work_conn_fds[i]);
            proxy->work_conn_fds[i] = -1;
            proxy->work_conn_active[i] = false;
        }
    }
    
    proxy->is_started = false;
    proxy->is_connected = false;
    
    return FRPC_SUCCESS;
}

// STCP Visitor: establish connection to server
int frpc_stcp_visitor_connect(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_VISITOR) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP visitor not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    if (proxy->is_connected) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "Warning: STCP visitor already connected\n");
        }
        return FRPC_SUCCESS;
    }
    
    // 1) Ensure FRP client is connected (for run_id)
    int ret = frpc_client_connect(proxy->client);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to connect FRP client to server\n");
        return ret;
    }
    
    // 2) Dial a NEW connection to frps for visitor
    int visitor_fd = frpc_dial_server(proxy->client);
    if (visitor_fd < 0) {
        fprintf(stderr, "Error: Failed to dial new visitor connection\n");
        return FRPC_ERROR_NETWORK;
    }
    proxy->visitor_fd = visitor_fd;
    
    fprintf(stdout, "Visitor dialed new connection to frps, fd=%d\n", visitor_fd);
    
    // 3) Build NewVisitorConn message
    int64_t timestamp = (int64_t)wrapped_time(NULL);
    
    char sign_key[33] = {0};
    if (stcp_get_sign_key(proxy->config.sk, timestamp, sign_key) != 0) {
        fprintf(stderr, "Error: Failed to generate sign key\n");
        wrapped_close(visitor_fd);
        proxy->visitor_fd = -1;
        return FRPC_ERROR_INTERNAL;
    }
    
    fprintf(stdout, "Connecting to server '%s' with sign key: %s, timestamp: %lld\n", 
            proxy->config.server_name, sign_key, (long long)timestamp);
    
    const char* run_id = frpc_client_get_run_id(proxy->client);
    if (!run_id) {
        run_id = "";
    }
    
    char msg_json[1024];
    int msg_len = snprintf(msg_json, sizeof(msg_json),
        "{\"run_id\":\"%s\",\"proxy_name\":\"%s\",\"sign_key\":\"%s\","
        "\"timestamp\":%lld,\"use_encryption\":%s,\"use_compression\":%s}",
        run_id,
        proxy->config.server_name ? proxy->config.server_name : proxy->config.proxy_name,
        sign_key,
        (long long)timestamp,
        proxy->use_encryption ? "true" : "false",
        proxy->use_compression ? "true" : "false");
    
    if (msg_len <= 0 || (size_t)msg_len >= sizeof(msg_json)) {
        fprintf(stderr, "Error: NewVisitorConn message too long\n");
        wrapped_close(visitor_fd);
        proxy->visitor_fd = -1;
        return FRPC_ERROR_INTERNAL;
    }
    
    fprintf(stdout, "Sending NewVisitorConn message for proxy: %s\n", proxy->config.proxy_name);
    
    // 4) Send NewVisitorConn on the new visitor connection (TypeNewVisitorConn = 'v')
    ret = frpc_send_msg_on_fd(visitor_fd, (uint8_t)'v', msg_json, (size_t)msg_len);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to send NewVisitorConn message\n");
        wrapped_close(visitor_fd);
        proxy->visitor_fd = -1;
        return ret;
    }
    
    // 5) Read NewVisitorConnResp (TypeNewVisitorConnResp = '3')
    uint8_t resp_type = 0;
    char* resp_json = NULL;
    size_t resp_len = 0;
    ret = frpc_read_msg_from_fd(visitor_fd, &resp_type, &resp_json, &resp_len, 10000);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to read NewVisitorConnResp\n");
        wrapped_close(visitor_fd);
        proxy->visitor_fd = -1;
        return ret;
    }
    
    if (resp_type != (uint8_t)'3') {
        fprintf(stderr, "Error: Unexpected response type %c, expected '3'\n", (char)resp_type);
        free(resp_json);
        wrapped_close(visitor_fd);
        proxy->visitor_fd = -1;
        return FRPC_ERROR_PROTO;
    }
    
    // Check for error in response (simple JSON parsing)
    // Look for "error":"xxx" pattern
    if (resp_json && strstr(resp_json, "\"error\":\"") != NULL) {
        char* err_start = strstr(resp_json, "\"error\":\"") + 9;
        char* err_end = strchr(err_start, '"');
        if (err_end && err_end > err_start) {
            size_t err_len = (size_t)(err_end - err_start);
            if (err_len > 0) {
                fprintf(stderr, "Error: NewVisitorConnResp error: %.*s\n", (int)err_len, err_start);
                free(resp_json);
                wrapped_close(visitor_fd);
                proxy->visitor_fd = -1;
                return FRPC_ERROR_AUTH;
            }
        }
    }
    
    fprintf(stdout, "NewVisitorConnResp received successfully\n");
    free(resp_json);
    
    // Direct TCP mode (tcpMux=false)
    // visitor_fd is already connected and ready for data transfer
    fprintf(stdout, "STCP Visitor '%s': Connected and ready for data transfer on fd=%d (direct TCP mode)\n",
            proxy->config.proxy_name, proxy->visitor_fd);
    
    proxy->is_connected = true;
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);
    }
        
    return FRPC_SUCCESS;
}


// Disconnect from server
int frpc_stcp_visitor_disconnect(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_VISITOR) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_connected) {
        return FRPC_SUCCESS;
    }

    // Close visitor connection
    if (proxy->visitor_fd >= 0) {
        wrapped_close(proxy->visitor_fd);
        proxy->visitor_fd = -1;
    }
    
    // Notify disconnection
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_CONNECTION_CLOSED);
    }

    proxy->is_connected = false;
    
    return FRPC_SUCCESS;
}

// STCP Server: register local service
int frpc_stcp_server_register(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_SERVER) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP server not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    if (proxy->is_registered) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "Warning: STCP server already registered\n");
        }
        return FRPC_SUCCESS;
    }
    
    // 1. Ensure FRP client is connected
    int ret = frpc_client_connect(proxy->client);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to connect FRP client to server\n");
        return ret;
    }
    
    fprintf(stdout, "Registering STCP server '%s' for local service: %s:%d\n", 
            proxy->config.proxy_name, proxy->config.local_addr, proxy->config.local_port);
    
    // 2. Build NewProxy message (TypeNewProxy = 'p')
    // Format: {"proxy_name":"xxx","proxy_type":"stcp","sk":"xxx","allow_users":["*"]}
    char allow_users_json[256] = "[\"*\"]";  // Default: allow all users
    if (proxy->allow_users && proxy->allow_users_count > 0) {
        // Build allow_users JSON array
        size_t offset = 0;
        allow_users_json[offset++] = '[';
        for (size_t i = 0; i < proxy->allow_users_count && offset < sizeof(allow_users_json) - 10; i++) {
            if (i > 0) {
                allow_users_json[offset++] = ',';
            }
            int written = snprintf(allow_users_json + offset, sizeof(allow_users_json) - offset, 
                                   "\"%s\"", proxy->allow_users[i] ? proxy->allow_users[i] : "*");
            if (written > 0) {
                offset += (size_t)written;
            }
        }
        allow_users_json[offset++] = ']';
        allow_users_json[offset] = '\0';
    }
    
    char new_proxy_json[1024];
    int msg_len = snprintf(new_proxy_json, sizeof(new_proxy_json),
        "{\"proxy_name\":\"%s\",\"proxy_type\":\"stcp\",\"sk\":\"%s\","
        "\"use_encryption\":%s,\"use_compression\":%s,\"allow_users\":%s}",
        proxy->config.proxy_name,
        proxy->config.sk ? proxy->config.sk : "",
        proxy->use_encryption ? "true" : "false",
        proxy->use_compression ? "true" : "false",
        allow_users_json);
    
    if (msg_len <= 0 || (size_t)msg_len >= sizeof(new_proxy_json)) {
        fprintf(stderr, "Error: NewProxy message too long\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "Sending NewProxy message: %s\n", new_proxy_json);
    }
    
    // 3. Send NewProxy message
    ret = frpc_client_send_msg(proxy->client, (uint8_t)'p', new_proxy_json, (size_t)msg_len);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to send NewProxy message\n");
        return ret;
    }
    
    // 4. Wait for NewProxyResp (TypeNewProxyResp = '2')
    uint8_t resp_type = 0;
    char* resp_json = NULL;
    size_t resp_len = 0;
    ret = frpc_client_read_msg(proxy->client, &resp_type, &resp_json, &resp_len, 10000);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to read NewProxyResp\n");
        return ret;
    }
    
    if (resp_type != (uint8_t)'2') {
        fprintf(stderr, "Error: Unexpected response type '%c', expected '2'\n", (char)resp_type);
        free(resp_json);
        return FRPC_ERROR_PROTO;
    }
    
    // Check for error in response
    if (resp_json && strstr(resp_json, "\"error\":\"") != NULL) {
        char* err_start = strstr(resp_json, "\"error\":\"") + 9;
        char* err_end = strchr(err_start, '"');
        if (err_end && err_end > err_start) {
            size_t err_len = (size_t)(err_end - err_start);
            if (err_len > 0) {
                fprintf(stderr, "Error: NewProxyResp error: %.*s\n", (int)err_len, err_start);
                free(resp_json);
                return FRPC_ERROR_AUTH;
            }
        }
    }
    
    fprintf(stdout, "NewProxyResp received successfully for '%s'\n", proxy->config.proxy_name);
    free(resp_json);
    
    // Mark as registered
    proxy->is_registered = true;
    
    // Callback to notify successful connection
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);
    }
    
    return FRPC_SUCCESS;
}

// Set allowed user list
int frpc_stcp_server_set_allow_users(frpc_stcp_proxy_t* proxy, const char** users, size_t count) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_SERVER) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // Free old user list
    if (proxy->allow_users) {
        for (size_t i = 0; i < proxy->allow_users_count; i++) {
            if (proxy->allow_users[i]) {
                free(proxy->allow_users[i]);
            }
        }
        free(proxy->allow_users);
        proxy->allow_users = NULL;
        proxy->allow_users_count = 0;
    }
    
    // Copy new user list
    if (count > 0 && users) {
        proxy->allow_users = (char**)malloc(count * sizeof(char*));
        if (!proxy->allow_users) {
            fprintf(stderr, "Error: Failed to allocate memory for allow users\n");
            return FRPC_ERROR_MEMORY;
        }
        
        for (size_t i = 0; i < count; i++) {
            if (users[i]) {
                proxy->allow_users[i] = strdup(users[i]);
                if (!proxy->allow_users[i]) {
                    // Free allocated memory
                    for (size_t j = 0; j < i; j++) {
                        free(proxy->allow_users[j]);
                    }
                    free(proxy->allow_users);
                    proxy->allow_users = NULL;
                    return FRPC_ERROR_MEMORY;
                }
            } else {
                proxy->allow_users[i] = NULL;
            }
        }
        
        proxy->allow_users_count = count;
    }
    
    return FRPC_SUCCESS;
}

// Set transport configuration
int frpc_stcp_set_transport_config(frpc_stcp_proxy_t* proxy, const frpc_stcp_transport_config_t* config) {
    if (!proxy || !config) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    proxy->use_encryption = config->use_encryption;
    proxy->use_compression = config->use_compression;
    
    return FRPC_SUCCESS;
}

// Send data (for visitor and server)
int frpc_stcp_send(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len) {
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stderr, "DEBUG: frpc_stcp_send CALLED for proxy '%s'\n", proxy ? proxy->config.proxy_name : "NULL_PROXY");
        fflush(stderr);
    }

    uint64_t current_ts_ms = tools_get_time_ms();
    int final_ret = FRPC_ERROR_INTERNAL;

    if (!proxy || !data) {
        final_ret = FRPC_ERROR_INVALID_PARAM;
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] Exit frpc_stcp_send for proxy '%s' (param error) with result: %d\n",
                    (unsigned long long)current_ts_ms, proxy ? proxy->config.proxy_name : "NULL_PROXY", final_ret);
        }
        return final_ret;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] Enter frpc_stcp_send for proxy '%s', len: %zu, is_started: %d, is_connected: %d\n",
                (unsigned long long)current_ts_ms, proxy->config.proxy_name, len, proxy->is_started, proxy->is_connected);
    }

    if (!proxy->is_started) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "[%llu] Error: STCP proxy '%s' not started\n", (unsigned long long)current_ts_ms, proxy->config.proxy_name);
        }
        final_ret = FRPC_ERROR_INTERNAL;
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] Exit frpc_stcp_send for proxy '%s' (not started) with result: %d\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, final_ret);
        }
        return final_ret;
    }
    
    // Direct TCP mode: send on visitor_fd (for visitor) or work_conn_fds (for server)
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR && proxy->visitor_fd >= 0) {
        int direct_fd = proxy->visitor_fd;
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] STCP Visitor Proxy '%s': Sending %zu bytes directly on fd=%d\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, len, direct_fd);
        }
        
        size_t total_sent = 0;
        while (total_sent < len) {
            ssize_t sent = wrapped_write(direct_fd, data + total_sent, len - total_sent);
            if (sent < 0) {
                int err = wrapped_get_errno();
                if (err == WRAPPED_EINTR) {
                    continue;
                }
                fprintf(stderr, "[%llu] Error: Failed to write to fd=%d for proxy '%s', errno=%d\n",
                        (unsigned long long)current_ts_ms, direct_fd, proxy->config.proxy_name, err);
                final_ret = FRPC_ERROR_NETWORK;
                break;
            }
            if (sent == 0) {
                fprintf(stderr, "[%llu] Error: Connection closed while writing to fd=%d for proxy '%s'\n",
                        (unsigned long long)current_ts_ms, direct_fd, proxy->config.proxy_name);
                final_ret = FRPC_ERROR_CONNECTION_CLOSED;
                break;
            }
            total_sent += (size_t)sent;
        }
        if (total_sent == len) final_ret = (int)total_sent;

    } else if (proxy->config.role == FRPC_STCP_ROLE_SERVER) {
        // Server: Broadcast to all active work connections
        int success_count = 0;
        for (int i = 0; i < 10; i++) {
            int sfd = proxy->work_conn_fds[i];
            if (sfd >= 0 && proxy->work_conn_active[i]) {
                // Best effort send to each
                size_t total_sent = 0;
                bool failed = false;
                while (total_sent < len) {
                    ssize_t sent = wrapped_write(sfd, data + total_sent, len - total_sent);
                    if (sent <= 0) {
                        failed = true;
                        break;
                    }
                    total_sent += sent;
                }
                if (!failed && total_sent == len) success_count++;
            }
        }
        if (success_count > 0) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[%llu] STCP Server Proxy '%s': Broadcast %zu bytes to %d clients\n",
                        (unsigned long long)current_ts_ms, proxy->config.proxy_name, len, success_count);
            }
            final_ret = (int)len;
        } else {
            final_ret = FRPC_ERROR_NETWORK;
        }
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] Exit frpc_stcp_send for proxy '%s' with result: %d\n",
                (unsigned long long)current_ts_ms, proxy->config.proxy_name, final_ret);
    }
    return final_ret;
}


// Handle received data
int frpc_stcp_receive(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len) {
    uint64_t ts = tools_get_time_ms();
    if (!proxy || !data) return FRPC_ERROR_INVALID_PARAM;

    // Identify if this is server or visitor proxy instance for logging
    const char* proxy_role_str = (proxy->config.role == FRPC_STCP_ROLE_SERVER) ? "SERVER" : "VISITOR";

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] %s PROXY '%s': ENTER frpc_stcp_receive, received %zu bytes of data\n",
                ts, proxy_role_str, proxy->config.proxy_name, len);
    }
    
    if (!proxy->is_started) {
        fprintf(stderr, "[%llu] %s PROXY '%s': Error: STCP proxy not started in frpc_stcp_receive\n", (unsigned long long)ts, proxy_role_str, proxy->config.proxy_name);
        return FRPC_ERROR_INTERNAL;
    }
    
    // Direct TCP mode: pass data directly to callback
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] %s PROXY '%s': Calling on_data callback directly (direct TCP mode).\n",
                ts, proxy_role_str, proxy->config.proxy_name);
    }
    if (proxy->config.on_data) {
        return proxy->config.on_data(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    return FRPC_SUCCESS;
}

// Forward declaration
static int frpc_stcp_handle_req_work_conn(frpc_stcp_proxy_t* proxy);
static int frpc_stcp_poll_work_conn(frpc_stcp_proxy_t* proxy);

// Handle ReqWorkConn: create new connection to FRPS and send NewWorkConn
static int frpc_stcp_handle_req_work_conn(frpc_stcp_proxy_t* proxy) {
    if (!proxy || !proxy->client) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Handling ReqWorkConn for proxy '%s'\n", proxy->config.proxy_name);
    }
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < 10; i++) {
        if (proxy->work_conn_fds[i] < 0) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[SERVER] Work connection pool full (10), ignoring ReqWorkConn\n");
        }
        return FRPC_SUCCESS; // Ignore, can't handle more
    }
    
    // 1. Dial new connection to FRPS
    int fd = frpc_dial_server(proxy->client);
    if (fd < 0) {
        fprintf(stderr, "[SERVER] Failed to dial FRPS for work connection\n");
        return FRPC_ERROR_NETWORK;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Dialed new work connection to FRPS, fd=%d (slot %d)\n", fd, slot);
    }
    
    // 2. Build NewWorkConn message
    // Format: {"run_id":"xxx","privilege_key":"xxx","timestamp":xxx}
    const char* run_id = frpc_client_get_run_id(proxy->client);
    if (!run_id || run_id[0] == '\0') {
        fprintf(stderr, "[SERVER] No run_id available for NewWorkConn\n");
        wrapped_close(fd);
        return FRPC_ERROR_INTERNAL;
    }
    
    int64_t ts = (int64_t)wrapped_time(NULL);
    char privilege_key[33] = {0};
    const char* token = frpc_client_get_token(proxy->client);
    const char* token_str = (token && token[0] != '\0') ? token : "";
    
    if (tools_get_auth_key(token_str, ts, privilege_key) != 0) {
        fprintf(stderr, "[SERVER] Failed to compute privilege_key for NewWorkConn\n");
        wrapped_close(fd);
        return FRPC_ERROR_INTERNAL;
    }
    
    char new_work_conn_json[512];
    int msg_len = snprintf(new_work_conn_json, sizeof(new_work_conn_json),
        "{\"run_id\":\"%s\",\"privilege_key\":\"%s\",\"timestamp\":%lld}",
        run_id, privilege_key, (long long)ts);
    
    if (msg_len <= 0 || (size_t)msg_len >= sizeof(new_work_conn_json)) {
        fprintf(stderr, "[SERVER] NewWorkConn message too long\n");
        wrapped_close(fd);
        return FRPC_ERROR_INTERNAL;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Sending NewWorkConn: %s\n", new_work_conn_json);
    }
    
    // 3. Send NewWorkConn message (type='w')
    // Note: This is a NEW connection, not encrypted yet
    int ret = frpc_send_msg_on_fd(fd, (uint8_t)'w', new_work_conn_json, (size_t)msg_len);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "[SERVER] Failed to send NewWorkConn message\n");
        wrapped_close(fd);
        return ret;
    }
    
    // Non-blocking: We do NOT wait for StartWorkConn here. 
    // We add it to the poll list and wait for 's' message in poll loop.
    
    // 5. Store work connection fd
    proxy->work_conn_fds[slot] = fd;
    proxy->work_conn_active[slot] = false; // Waiting for handshake
    proxy->is_connected = true; // Mark logic as connected (at least pending)
    
    // Notify connection established (technically pending, but for now we signal OK)
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);
    }
    
    fprintf(stdout, "[SERVER] Work connection pending for proxy '%s' on fd=%d (slot %d) - Waiting for StartWorkConn\n", 
            proxy->config.proxy_name, fd, slot);
    
    return FRPC_SUCCESS;
}

// Poll work connection for incoming data
static int frpc_stcp_poll_work_conn(frpc_stcp_proxy_t* proxy) {
    if (!proxy) {
        return FRPC_SUCCESS;
    }
    
    // Check available data on all active work connections
    fd_set rfds;
    FD_ZERO(&rfds);
    int max_fd = -1;
    int active_cnt = 0;
    
    for (int i = 0; i < 10; i++) {
        int fd = proxy->work_conn_fds[i];
        if (fd >= 0) {
            FD_SET(fd, &rfds);
            if (fd > max_fd) max_fd = fd;
            active_cnt++;
        }
    }


    if (active_cnt == 0 || max_fd < 0) {
        return FRPC_SUCCESS;
    }
    
    wrapped_timeval_t tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;  // Non-blocking check
    
    int sel = wrapped_select(max_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        if (wrapped_get_errno() == WRAPPED_EINTR) {
            return FRPC_SUCCESS;
        }
        return FRPC_ERROR_NETWORK;
    }
    
    if (sel == 0) {
        return FRPC_SUCCESS;  // No data available
    }

    // Check each FD
    for (int i = 0; i < 10; i++) {
        int fd = proxy->work_conn_fds[i];
        if (fd >= 0 && FD_ISSET(fd, &rfds)) {
            if (!proxy->work_conn_active[i]) {
                // Handshake phase: Waiting for StartWorkConn ('s')
                // Note: we just use a small timeout since we know data is available
                uint8_t resp_type = 0;
                char* resp_json = NULL;
                size_t resp_len = 0;
                int ret = frpc_read_msg_from_fd(fd, &resp_type, &resp_json, &resp_len, 100); 
                
                if (ret != FRPC_SUCCESS) {
                    if (ret == FRPC_ERROR_TIMEOUT) {
                        continue; // Partial data?
                    }
                    fprintf(stderr, "[SERVER] Failed to read StartWorkConn on fd %d (error=%d)\n", fd, ret);
                    wrapped_close(fd);
                    proxy->work_conn_fds[i] = -1;
                    continue;
                }
                
                if (resp_type == (uint8_t)'s') {
                    if (frpc_stcp_verbose_enabled()) {
                        fprintf(stdout, "[SERVER] Received StartWorkConn on fd %d: %s\n", fd, resp_json ? resp_json : "{}");
                    }
                    // Mark active
                    proxy->work_conn_active[i] = true;
                    if (resp_json) free(resp_json);
                } else {
                    fprintf(stderr, "[SERVER] Unexpected response type '%c' on fd %d during handshake\n", (char)resp_type, fd);
                    if (resp_json) free(resp_json);
                    wrapped_close(fd);
                    proxy->work_conn_fds[i] = -1;
                    continue;
                }
            } else {
                // Streaming phase: Read available data
                uint8_t buffer[4096];
                ssize_t n = wrapped_read(fd, buffer, sizeof(buffer));
                if (n < 0) {
                    if (wrapped_get_errno() == WRAPPED_EINTR || wrapped_get_errno() == WRAPPED_EAGAIN) {
                        continue;
                    }
                    if (frpc_stcp_verbose_enabled()) {
                        fprintf(stderr, "[SERVER] Work connection read error on fd %d\n", fd);
                    }
                    wrapped_close(fd);
                    proxy->work_conn_fds[i] = -1;
                    proxy->work_conn_active[i] = false;
                    continue;
                }
                
                if (n == 0) {
                    // Connection closed
                    if (frpc_stcp_verbose_enabled()) {
                        fprintf(stdout, "[SERVER] Work connection closed by remote on fd %d\n", fd);
                    }
                    wrapped_close(fd);
                    proxy->work_conn_fds[i] = -1;
                    proxy->work_conn_active[i] = false;
                    continue;
                }
                
                // Deliver data to callback
                if (frpc_stcp_verbose_enabled()) {
                    fprintf(stdout, "[SERVER] Received %zd bytes on work connection fd %d\n", n, fd);
                }
                
                if (proxy->config.on_data) {
                    proxy->config.on_data(proxy->user_ctx, buffer, (size_t)n);
                }
            }
        }
    }
    
    // Update is_connected status
    bool any_connected = false;
    for (int i = 0; i < 10; i++) {
        if (proxy->work_conn_fds[i] >= 0) {
            any_connected = true;
            break;
        }
    }
    proxy->is_connected = any_connected;
    
    return FRPC_SUCCESS;
}

// Poll visitor connection for incoming data
static int frpc_stcp_poll_visitor_conn(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_SUCCESS;
    
    int fd = proxy->visitor_fd;
    if (fd < 0) return FRPC_SUCCESS;
    
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    
    wrapped_timeval_t tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    int sel = wrapped_select(fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        if (wrapped_get_errno() == WRAPPED_EINTR) return FRPC_SUCCESS;
        return FRPC_ERROR_NETWORK;
    }
    
    if (sel > 0 && FD_ISSET(fd, &rfds)) {
        uint8_t buffer[4096];
        ssize_t n = wrapped_read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR || wrapped_get_errno() == WRAPPED_EAGAIN) {
                return FRPC_SUCCESS;
            }
            if (frpc_stcp_verbose_enabled()) {
                 fprintf(stderr, "Visitor poll: read failed on fd %d\n", fd);
            }
            wrapped_close(fd);
            proxy->visitor_fd = -1;
            proxy->is_connected = false;
            // Notify disconnect
            if (proxy->config.on_connection) {
                proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_NETWORK);
            }
            return FRPC_ERROR_NETWORK;
        }
        
        if (n == 0) {
             if (frpc_stcp_verbose_enabled()) {
                 fprintf(stdout, "Visitor poll: connection closed by remote on fd %d\n", fd);
            }
            wrapped_close(fd);
            proxy->visitor_fd = -1;
            proxy->is_connected = false;
            // Notify disconnect
            if (proxy->config.on_connection) {
                proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_CONNECTION_CLOSED_BY_REMOTE);
            }
            return FRPC_SUCCESS;
        }
        
        if (frpc_stcp_verbose_enabled()) {
             fprintf(stdout, "Visitor poll: received %zd bytes on fd %d\n", n, fd);
        }

        if (proxy->config.on_data) {
            proxy->config.on_data(proxy->user_ctx, buffer, (size_t)n);
        }
    }
    
    return FRPC_SUCCESS;
}

// Poll control connection for messages (ReqWorkConn, Pong, etc.)
static int frpc_stcp_poll_control_conn(frpc_stcp_proxy_t* proxy) {
    if (!proxy || !proxy->client) {
        return FRPC_SUCCESS;
    }
    
    // Only for server role - check for ReqWorkConn
    if (proxy->config.role != FRPC_STCP_ROLE_SERVER || !proxy->is_registered) {
        return FRPC_SUCCESS;
    }
    
    // Check if data is available on control connection
    if (!frpc_client_has_data(proxy->client)) {
        return FRPC_SUCCESS;
    }
    
    // Read message from control connection
    uint8_t msg_type = 0;
    char* msg_json = NULL;
    size_t msg_len = 0;
    
    int ret = frpc_client_read_msg(proxy->client, &msg_type, &msg_json, &msg_len, 0);
    if (ret != FRPC_SUCCESS) {
        if (ret == FRPC_ERROR_TIMEOUT) {
            return FRPC_SUCCESS;  // No message available, that's fine
        }
        return ret;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Received control message type='%c', len=%zu\n", (char)msg_type, msg_len);
    }
    
    // Handle message based on type
    switch (msg_type) {
        case 'r':  // TypeReqWorkConn
            free(msg_json);
            return frpc_stcp_handle_req_work_conn(proxy);
            
        case '4':  // TypePong
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[SERVER] Received Pong\n");
            }
            break;
            
        default:
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[SERVER] Ignoring unknown message type '%c'\n", (char)msg_type);
            }
            break;
    }
    
    free(msg_json);
    return FRPC_SUCCESS;
}

// Handle periodic tasks
int frpc_stcp_tick(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        return FRPC_SUCCESS;
    }
    
    // Handle FRP client periodic tasks (heartbeat)
    if (proxy->client) {
        int ret = frpc_client_tick(proxy->client);
        if (ret != FRPC_SUCCESS) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "Warning: FRP client tick failed with code: %d\n", ret);
            }
        }
    }
    
    // For server role: poll control connection for ReqWorkConn
    if (proxy->config.role == FRPC_STCP_ROLE_SERVER && proxy->is_registered) {
        int ret = frpc_stcp_poll_control_conn(proxy);
        if (ret != FRPC_SUCCESS && ret != FRPC_ERROR_TIMEOUT) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "Warning: Poll control connection failed: %d\n", ret);
            }
        }
        
        // Poll work connection for incoming data
        ret = frpc_stcp_poll_work_conn(proxy);
        if (ret != FRPC_SUCCESS) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "Warning: Poll work connection failed: %d\n", ret);
            }
        }
    } else if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
        // Poll visitor connection for incoming data
        int ret = frpc_stcp_poll_visitor_conn(proxy);
        if (ret != FRPC_SUCCESS) {
             if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "Warning: Poll visitor connection failed: %d\n", ret);
             }
        }
    }
    
    return FRPC_SUCCESS;
}
