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
    
    // Yamux-related fields
    yamux_session_t* yamux_session;
    uint32_t active_stream_id;
    
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
    int work_conn_fd;      // Server: work connection fd for data transfer with visitor
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
    proxy->work_conn_fd = -1;  // Initialize as invalid
    
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

// Yamux session callbacks

// NEW: Callback for new streams (primarily for server role)
static int on_new_stream_wrapper(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stderr, "SERVER: ENTERED on_new_stream_wrapper. session_user_data: %p, p_stream_val_at_addr: %p, input_stream_addr: %p",
            session_user_data,
            (void*)(p_stream ? *p_stream : NULL),
            (void*)p_stream);
        if (p_stream && *p_stream) {
            fprintf(stderr, ", stream_id: %u", yamux_stream_get_id(*p_stream));
        }
        fprintf(stderr, "\n");
        fflush(stderr);
    }

    frpc_stcp_proxy_t* proxy = NULL;
    if (session_user_data) {
        proxy = (frpc_stcp_proxy_t*)session_user_data;
    }

    uint64_t ts = tools_get_time_ms();

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] SERVER: Yamux: New incoming stream ID %u for STCP proxy '%s' (role: %d)\n",
                ts, (p_stream && *p_stream ? yamux_stream_get_id(*p_stream) : 0), proxy ? proxy->config.proxy_name : "NULL_PROXY", proxy ? proxy->config.role : -1);
    }

    if (proxy && proxy->config.role == FRPC_STCP_ROLE_SERVER) {
        if (proxy->active_stream_id != 0 && proxy->active_stream_id != (p_stream && *p_stream ? yamux_stream_get_id(*p_stream) : 0)) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "[%llu] SERVER Warning: STCP Server proxy '%s' already has active stream %u, rejecting new stream %u\n",
                        ts, proxy->config.proxy_name, proxy->active_stream_id, (p_stream && *p_stream ? yamux_stream_get_id(*p_stream) : 0));
                fprintf(stdout, "[%llu] SERVER: EXITING on_new_stream_wrapper (rejecting stream - already active)\n", (unsigned long long)ts);
            }
             return 0;
        }
        
        proxy->active_stream_id = (p_stream && *p_stream ? yamux_stream_get_id(*p_stream) : 0);
        *p_stream_user_data_out = proxy; 
        proxy->is_connected = false; 

        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] SERVER: STCP Server: Accepted new stream ID %u, set as active. stream_user_data_out set to %p. Waiting for establishment.\n",
                    ts, proxy->active_stream_id, *p_stream_user_data_out);
            fprintf(stdout, "[%llu] SERVER: EXITING on_new_stream_wrapper (accepting stream)\n", (unsigned long long)ts);
        }
        return 1;
    } else {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "[%llu] SERVER Warning: on_new_stream_wrapper called for STCP proxy '%s' but role is VISITOR (%d) with stream ID %u. Unexpected.\n",
                    ts, proxy ? proxy->config.proxy_name : "NULL_PROXY", proxy ? proxy->config.role : -1, (p_stream && *p_stream ? yamux_stream_get_id(*p_stream) : 0));
        }
        if (p_stream_user_data_out) *p_stream_user_data_out = NULL;
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] SERVER: EXITING on_new_stream_wrapper (rejecting stream - wrong role)\n", (unsigned long long)ts);
        }
        return 0;
    }
}

static int on_stream_data_wrapper(void* stream_user_data, const uint8_t* data, size_t len) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)stream_user_data;
    if (!proxy) {
        fprintf(stderr, "Error: on_stream_data_wrapper called with NULL stream_user_data\n");
        return -1; // Indicate error
    }
    
    int result = 0;
    
    // Invoke user-provided data callback.
    if (proxy->config.on_data) {
        result = proxy->config.on_data(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    // After processing data, send WindowUpdate to restore the receive window.
    // This is essential for flow control to work properly.
    if (proxy->yamux_session && proxy->active_stream_id != 0 && len > 0) {
        int wu_ret = yamux_stream_window_update(proxy->yamux_session, proxy->active_stream_id, (uint32_t)len);
        if (wu_ret != 0 && frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "Warning: yamux_stream_window_update failed for stream %u: %d\n", 
                    proxy->active_stream_id, wu_ret);
        }
    }
    
    return result;
}

static void on_stream_established_wrapper(void* stream_user_data) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)stream_user_data;
    uint64_t current_ts_ms = tools_get_time_ms(); 

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] ENTERED on_stream_established_wrapper, stream_user_data_ptr: %p\n",
                (unsigned long long)current_ts_ms, stream_user_data);
    }

    if (!proxy) { // This will be true if stream_user_data is NULL from yamux.c
        fprintf(stderr, "[%llu] Error in on_stream_established_wrapper: stream_user_data is NULL. Cannot proceed.\n", (unsigned long long)current_ts_ms); 
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] EXITING on_stream_established_wrapper due to NULL proxy.\n", (unsigned long long)current_ts_ms);
        }
        return;
    }

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] In on_stream_established_wrapper for proxy_name: '%s', active_stream_id: %u\n",
                (unsigned long long)current_ts_ms, proxy->config.proxy_name, proxy->active_stream_id);
    }

    if (proxy->active_stream_id == 0) { 
         if (frpc_stcp_verbose_enabled()) {
             fprintf(stderr, "[%llu] Warning: on_stream_established_wrapper called but active_stream_id is 0 for proxy '%s'. Ignoring.\n",
                     (unsigned long long)current_ts_ms, proxy->config.proxy_name);
             fprintf(stdout, "[%llu] EXITING on_stream_established_wrapper due to active_stream_id being 0.\n", (unsigned long long)current_ts_ms);
         }
         return;
    }

    // This logic is correct IF proxy is valid.
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] Yamux stream ID %u established (callback for proxy '%s', active_stream_id: %u)\n",
                (unsigned long long)current_ts_ms, proxy->active_stream_id, proxy->config.proxy_name, proxy->active_stream_id);
    }

    if (!proxy->is_connected) {
        proxy->is_connected = true;
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] STCP Proxy '%s' (role %d): Connection established by on_stream_established for stream ID %u. Setting is_connected=true.\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, proxy->config.role, proxy->active_stream_id);
        }
        if (proxy->config.on_connection) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[%llu] STCP Proxy '%s': Invoking on_connection(1,0) callback from on_stream_established.\n",
                        (unsigned long long)current_ts_ms, proxy->config.proxy_name);
            }
            proxy->config.on_connection(proxy->user_ctx, 1, 0); 
        }
    } else {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] STCP Proxy '%s': Stream %u established via on_stream_established, but proxy already marked as connected. No action.\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, proxy->active_stream_id);
        }
    }
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] EXITING on_stream_established_wrapper\n", (unsigned long long)current_ts_ms);
    }
}

static void on_stream_close_wrapper(void* stream_user_data, bool by_remote, uint32_t error_code) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)stream_user_data;
    uint64_t current_ts_ms = tools_get_time_ms(); 

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] ENTERED on_stream_close_wrapper, stream_user_data_ptr: %p, by_remote: %d, error_code: %u\n",
                (unsigned long long)current_ts_ms, stream_user_data, by_remote, error_code);
    }

    // Keep NULL check for safety, but for debugging, proceed carefully.
    // if (!proxy) {
    //     fprintf(stderr, "[%llu] Error: on_stream_close_wrapper called with NULL stream_user_data\n", (unsigned long long)current_ts_ms);
    //     return;
    // }
    
    uint32_t closed_stream_id = proxy ? proxy->active_stream_id : 0; // Safely access active_stream_id

    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] In on_stream_close_wrapper for proxy_name: '%s', closed_stream_id_val: %u\n",
                 (unsigned long long)current_ts_ms, proxy ? proxy->config.proxy_name : "NULL_PROXY", closed_stream_id);
    }

    if (proxy && closed_stream_id == 0 && stream_user_data != NULL) { // only print if proxy is not null but stream id is 0
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] Yamux stream close callback for proxy '%s', but active_stream_id is 0. (by_remote: %d, error: %u)\n",
                (unsigned long long)current_ts_ms, proxy->config.proxy_name, by_remote, error_code);
        }
        // return; // Don't return yet, allow exit log
    }

    if (proxy) { // Check proxy before dereferencing for main logic
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] Yamux stream ID %u closed for proxy '%s' (by_remote: %d, error_code: %u, current active_stream_id: %u)\n",
                    (unsigned long long)current_ts_ms, closed_stream_id, proxy->config.proxy_name, by_remote, error_code, proxy->active_stream_id);
        }

        if (proxy->is_connected) { 
            proxy->is_connected = false;
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[%llu] STCP Proxy '%s': Connection closed for stream ID %u\n",
                        (unsigned long long)current_ts_ms, proxy->config.proxy_name, closed_stream_id);
            }
            if (proxy->config.on_connection) {
                int frpc_err = by_remote ? FRPC_ERROR_CONNECTION_CLOSED_BY_REMOTE : FRPC_ERROR_CONNECTION_CLOSED;
                if (error_code != 0 && error_code != YAMUX_GOAWAY_NORMAL) { 
                     frpc_err = FRPC_ERROR_INTERNAL; 
                }
                proxy->config.on_connection(proxy->user_ctx, 0, frpc_err);
            }
        }
        proxy->active_stream_id = 0; 
    }
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] EXITING on_stream_close_wrapper\n", (unsigned long long)current_ts_ms);
    }
}

static int on_write_wrapper(void* user_conn_ctx, const uint8_t* data, size_t len) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)user_conn_ctx;
    if (!proxy) return -1;
    
    // Invoke user-provided write callback first (if any).
    if (proxy->config.on_write) {
        return proxy->config.on_write(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    // For Visitor: use visitor_fd (new connection for NewVisitorConn)
    // For Server: will use work_conn_fd (to be implemented)
    int fd = proxy->visitor_fd;
    if (fd < 0) {
        // Fallback: no dedicated fd, cannot send
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "on_write_wrapper: no valid fd for proxy '%s'\n", proxy->config.proxy_name);
        }
        return -1;
    }
    
    // Send data via wrapper layer (portable)
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = wrapped_write(fd, data + total_sent, len - total_sent);
        if (sent < 0) {
            int err = wrapped_get_errno();
            if (err == WRAPPED_EINTR) {
                continue;
            }
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "on_write_wrapper: write failed, errno=%d\n", err);
            }
            return -1;
        }
        if (sent == 0) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "on_write_wrapper: connection closed\n");
            }
            return -1;
        }
        total_sent += (size_t)sent;
    }
    
    return (int)total_sent;
}

// Initialize Yamux session
static yamux_session_t* init_yamux_session(frpc_stcp_proxy_t* proxy, bool is_client) {
    if (!proxy) return NULL;
    
    // Build Yamux config
    yamux_config_t config;
    memset(&config, 0, sizeof(config));
    
    // Set default config values
    config.enable_keepalive = true;
    config.keepalive_interval_ms = 30000; // 30s
    config.max_stream_window_size = 256 * 1024;
    config.initial_stream_window_size = 128 * 1024;
    config.max_streams = 32;
    
    // Set callbacks
    config.on_stream_data = on_stream_data_wrapper;
    config.on_stream_close = on_stream_close_wrapper;
    config.on_new_stream = on_new_stream_wrapper;
    config.on_stream_established = on_stream_established_wrapper;
    config.write_fn = on_write_wrapper;
    config.user_conn_ctx = proxy; // use proxy as user_conn_ctx (for write_fn, on_session_close, and on_new_stream's session_ctx)
    
    // Create Yamux session
    yamux_session_t* session = yamux_session_new(&config, is_client, proxy);
    
    return session;
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
    
    // Close Yamux session (if any)
    if (proxy->yamux_session) {
        // Close active stream first (if any) to keep session_free state consistent.
        // NOTE: Do not clear active_stream_id here; the close callback maintains state.
        if (proxy->active_stream_id) {
            yamux_stream_close(proxy->yamux_session, proxy->active_stream_id, 0);  // 0 = graceful close (FIN), not RST
        }
        yamux_session_free(proxy->yamux_session);
        proxy->yamux_session = NULL;
    }
    
    proxy->is_started = false;
    proxy->is_connected = false;
    // Safety: ensure active_stream_id is cleared
    proxy->active_stream_id = 0;
    
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
    
    // For tcpMux=false mode, we use direct TCP without Yamux
    // The visitor_fd is already set up for data transfer
    // Note: In tcpMux=true mode, we would initialize Yamux here
    
    // Check if client uses yamux (tcpMux)
    // For now, we assume tcpMux=false (no yamux) when use_encryption is set
    // This is a simplification - proper implementation would check client config
    bool use_yamux = false;  // TODO: Get from client config when tcpMux support is added
    
    if (use_yamux) {
        // Initialize Yamux client session
        if (!proxy->yamux_session) {
            proxy->yamux_session = init_yamux_session(proxy, true);
            if (!proxy->yamux_session) {
                fprintf(stderr, "Error: Failed to initialize yamux client session\n");
                return FRPC_ERROR_INTERNAL;
            }
        }
        
        // Open a stream for data transport
        void* p_stream_user_data = proxy;
        uint32_t stream_id = yamux_session_open_stream(proxy->yamux_session, &p_stream_user_data);
        if (stream_id == 0) {
            fprintf(stderr, "Error: Failed to open yamux stream for proxy '%s'\n", proxy->config.proxy_name);
            return FRPC_ERROR_INTERNAL;
        }
        
        proxy->active_stream_id = stream_id;
        fprintf(stdout, "STCP Visitor Proxy '%s': Opened stream ID %u for data communication. Waiting for establishment.\n", 
                proxy->config.proxy_name, stream_id);
                
        if (!proxy->is_connected) {
            proxy->is_connected = true; 
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "STCP Visitor Proxy '%s': Marking as connected after opening stream %u.\n",
                        proxy->config.proxy_name, stream_id);
            }
            if (proxy->config.on_connection) {
                proxy->config.on_connection(proxy->user_ctx, 1, 0);
            }
        }
    } else {
        // Direct TCP mode (tcpMux=false)
        // visitor_fd is already connected and ready for data transfer
        fprintf(stdout, "STCP Visitor '%s': Connected and ready for data transfer on fd=%d (direct TCP mode)\n",
                proxy->config.proxy_name, proxy->visitor_fd);
        
        proxy->is_connected = true;
        if (proxy->config.on_connection) {
            proxy->config.on_connection(proxy->user_ctx, 1, 0);
        }
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

    // NOTE: Do not call on_connection(0, ...) here.
    // yamux_session_free() triggers on_stream_close for all streams, and on_stream_close_wrapper
    // is responsible for clearing is_connected and calling on_connection(0, FRPC_ERROR_CONNECTION_CLOSED).
    // Calling it here as well would result in duplicate disconnect notifications.
    
    // Close active stream
    if (proxy->yamux_session && proxy->active_stream_id) {
        yamux_stream_close(proxy->yamux_session, proxy->active_stream_id, 0);  // 0 = graceful close (FIN), not RST
        // Do not clear active_stream_id here; the close callback maintains it and avoids noisy logs.
    }
    
    // Close Yamux session
    if (proxy->yamux_session) {
        yamux_session_close(proxy->yamux_session);
        yamux_session_free(proxy->yamux_session);
        proxy->yamux_session = NULL;
    }
    
    // TODO: send disconnect message to frps
    // ...

    // Safety: ensure state is cleared (callbacks should already do this).
    proxy->is_connected = false;
    proxy->active_stream_id = 0;
    
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
    
    // 5. Initialize yamux server session (for work connection handling)
    // Note: The actual work connection will come later via ReqWorkConn
    if (!proxy->yamux_session) {
        proxy->yamux_session = init_yamux_session(proxy, false);
        if (!proxy->yamux_session) {
            fprintf(stderr, "Error: Failed to initialize yamux server session\n");
            return FRPC_ERROR_INTERNAL;
        }
    }
    
    fprintf(stdout, "Yamux server session initialized for STCP server\n");
    
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
        fprintf(stdout, "[%llu] Enter frpc_stcp_send for proxy '%s', len: %zu, is_started: %d, is_connected: %d, active_stream_id: %u\n",
                (unsigned long long)current_ts_ms, proxy->config.proxy_name, len, proxy->is_started, proxy->is_connected, proxy->active_stream_id);
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
    
    // Non-Yamux mode: send directly on visitor_fd (for visitor) or work_conn_fd (for server)
    // This is used when tcpMux=false
    int direct_fd = -1;
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR && proxy->visitor_fd >= 0) {
        direct_fd = proxy->visitor_fd;
    } else if (proxy->config.role == FRPC_STCP_ROLE_SERVER && proxy->work_conn_fd >= 0) {
        direct_fd = proxy->work_conn_fd;
    }
    
    // If Yamux session exists and has active stream, use Yamux
    if (proxy->yamux_session && proxy->active_stream_id != 0) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] STCP Proxy '%s': Sending %zu bytes via Yamux stream %u\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, len, proxy->active_stream_id);
        }
        
        int ret = yamux_stream_write(proxy->yamux_session, proxy->active_stream_id, data, len);
        if (ret < 0) {
            fprintf(stderr, "[%llu] Error: Failed to write to yamux stream %u for proxy '%s', yamux error code: %d\n", 
                    (unsigned long long)current_ts_ms, proxy->active_stream_id, proxy->config.proxy_name, ret); 
            if (ret == -6) { 
                final_ret = FRPC_ERROR_STREAM_NOT_WRITABLE;
            } else {
                final_ret = FRPC_ERROR_INTERNAL; 
            }
        } else {
            if ((size_t)ret < len) {
                fprintf(stderr, "[%llu] Warning: STCP Proxy '%s': Only sent %d of %zu bytes to stream %u (may need flow control)\n", 
                        (unsigned long long)current_ts_ms, proxy->config.proxy_name, ret, len, proxy->active_stream_id);
            } else {
                if (frpc_stcp_verbose_enabled()) {
                    fprintf(stdout, "[%llu] STCP Proxy '%s': Successfully sent %d bytes to stream %u\n",
                            (unsigned long long)current_ts_ms, proxy->config.proxy_name, ret, proxy->active_stream_id);
                }
            }
            final_ret = ret; 
        }
    } else if (direct_fd >= 0) {
        // Direct TCP send (non-Yamux mode)
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] STCP Proxy '%s': Sending %zu bytes directly on fd=%d\n",
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
        
        if (total_sent == len) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "[%llu] STCP Proxy '%s': Successfully sent %zu bytes directly on fd=%d\n",
                        (unsigned long long)current_ts_ms, proxy->config.proxy_name, total_sent, direct_fd);
            }
            final_ret = (int)total_sent;
        }
    } else {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "[%llu] Error: No active connection for STCP proxy '%s' (yamux: %p, stream_id: %u, visitor_fd: %d, work_conn_fd: %d)\n",
                    (unsigned long long)current_ts_ms, proxy->config.proxy_name, 
                    (void*)proxy->yamux_session, proxy->active_stream_id,
                    proxy->visitor_fd, proxy->work_conn_fd);
        }
        final_ret = FRPC_ERROR_INTERNAL;
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
        
    if (proxy->yamux_session) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] %s PROXY '%s': Passing %zu bytes to yamux_session_receive\n",
                    ts, proxy_role_str, proxy->config.proxy_name, len);
        }
        int ret = yamux_session_receive(proxy->yamux_session, data, len);
        if (ret < 0) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stderr, "[%llu] %s PROXY '%s': Error: Yamux session receive failed with code: %d\n",
                        ts, proxy_role_str, proxy->config.proxy_name, ret);
            }
            return FRPC_ERROR_INTERNAL;
        }
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[%llu] %s PROXY '%s': Yamux processed %d bytes of data. Exiting frpc_stcp_receive.\n",
                    ts, proxy_role_str, proxy->config.proxy_name, ret);
        }
        return ret;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[%llu] %s PROXY '%s': No yamux session, calling on_data callback directly. Exiting frpc_stcp_receive.\n",
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
    
    // If we already have an active work connection, ignore new ReqWorkConn
    // FRPS sends multiple ReqWorkConn to build connection pool, but we only need one
    if (proxy->work_conn_fd >= 0 && proxy->is_connected) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[SERVER] Already have work connection fd=%d, ignoring ReqWorkConn\n", proxy->work_conn_fd);
        }
        return FRPC_SUCCESS;
    }
    
    // Close any stale work connection
    if (proxy->work_conn_fd >= 0) {
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[SERVER] Closing stale work connection fd=%d\n", proxy->work_conn_fd);
        }
        wrapped_close(proxy->work_conn_fd);
        proxy->work_conn_fd = -1;
    }

    
    // 1. Dial new connection to FRPS
    int fd = frpc_dial_server(proxy->client);
    if (fd < 0) {
        fprintf(stderr, "[SERVER] Failed to dial FRPS for work connection\n");
        return FRPC_ERROR_NETWORK;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Dialed new work connection to FRPS, fd=%d\n", fd);
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
    
    // 4. Read StartWorkConn response (type='s')
    uint8_t resp_type = 0;
    char* resp_json = NULL;
    size_t resp_len = 0;
    ret = frpc_read_msg_from_fd(fd, &resp_type, &resp_json, &resp_len, 10000);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "[SERVER] Failed to read StartWorkConn response (error=%d)\n", ret);
        wrapped_close(fd);
        return ret;
    }
    
    if (resp_type != (uint8_t)'s') {
        fprintf(stderr, "[SERVER] Unexpected response type '%c', expected 's'\n", (char)resp_type);
        free(resp_json);
        wrapped_close(fd);
        return FRPC_ERROR_PROTO;
    }
    
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Received StartWorkConn: %s\n", resp_json ? resp_json : "{}");
    }
    
    // Check for error in response
    if (resp_json && strstr(resp_json, "\"error\":\"") != NULL) {
        char* err_start = strstr(resp_json, "\"error\":\"") + 9;
        char* err_end = strchr(err_start, '"');
        if (err_end && err_end > err_start) {
            size_t err_len = (size_t)(err_end - err_start);
            if (err_len > 0) {
                fprintf(stderr, "[SERVER] StartWorkConn error: %.*s\n", (int)err_len, err_start);
                free(resp_json);
                wrapped_close(fd);
                return FRPC_ERROR_PROTO;
            }
        }
    }
    
    free(resp_json);
    
    // 5. Store work connection fd
    proxy->work_conn_fd = fd;
    proxy->is_connected = true;
    
    // Notify connection established
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);
    }
    
    fprintf(stdout, "[SERVER] Work connection established for proxy '%s' on fd=%d\n", 
            proxy->config.proxy_name, fd);
    
    return FRPC_SUCCESS;
}

// Poll work connection for incoming data
static int frpc_stcp_poll_work_conn(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->work_conn_fd < 0) {
        return FRPC_SUCCESS;
    }
    
    // Check if data is available (non-blocking)
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(proxy->work_conn_fd, &rfds);
    
    wrapped_timeval_t tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;  // Non-blocking check
    
    int sel = wrapped_select(proxy->work_conn_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        if (wrapped_get_errno() == WRAPPED_EINTR) {
            return FRPC_SUCCESS;
        }
        return FRPC_ERROR_NETWORK;
    }
    
    if (sel == 0) {
        return FRPC_SUCCESS;  // No data available
    }
    
    // Read available data
    uint8_t buffer[4096];
    ssize_t n = wrapped_read(proxy->work_conn_fd, buffer, sizeof(buffer));
    if (n < 0) {
        if (wrapped_get_errno() == WRAPPED_EINTR || wrapped_get_errno() == WRAPPED_EAGAIN) {
            return FRPC_SUCCESS;
        }
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stderr, "[SERVER] Work connection read error\n");
        }
        return FRPC_ERROR_NETWORK;
    }
    
    if (n == 0) {
        // Connection closed
        if (frpc_stcp_verbose_enabled()) {
            fprintf(stdout, "[SERVER] Work connection closed by remote\n");
        }
        wrapped_close(proxy->work_conn_fd);
        proxy->work_conn_fd = -1;
        proxy->is_connected = false;
        
        if (proxy->config.on_connection) {
            proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_CONNECTION_CLOSED_BY_REMOTE);
        }
        return FRPC_SUCCESS;
    }
    
    // Deliver data to callback
    if (frpc_stcp_verbose_enabled()) {
        fprintf(stdout, "[SERVER] Received %zd bytes on work connection\n", n);
    }
    
    if (proxy->config.on_data) {
        proxy->config.on_data(proxy->user_ctx, buffer, (size_t)n);
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
    }
    
    // Handle yamux session periodic tasks
    if (proxy->yamux_session) {
        yamux_session_tick(proxy->yamux_session);
        
        // Check if session is closed
        if (yamux_session_is_closed(proxy->yamux_session)) {
            if (frpc_stcp_verbose_enabled()) {
                fprintf(stdout, "Yamux session closed for proxy '%s', active_stream_id: %u, is_connected: %d\n",
                        proxy->config.proxy_name, proxy->active_stream_id, proxy->is_connected);
            }
            
            if (proxy->is_connected && proxy->active_stream_id != 0) {
                 if (frpc_stcp_verbose_enabled()) {
                     fprintf(stdout, "Warning: Yamux session for proxy '%s' closed while STCP connection (stream %u) was still marked active. Forcing disconnect notification.\n",
                             proxy->config.proxy_name, proxy->active_stream_id);
                 }
                 if (proxy->config.on_connection) {
                     proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_CONNECTION_CLOSED);
                 }
            }
            proxy->is_connected = false;
            
            // Free session
            yamux_session_free(proxy->yamux_session);
            proxy->yamux_session = NULL;
            proxy->active_stream_id = 0;
        }
    }
    
    return FRPC_SUCCESS;
} 