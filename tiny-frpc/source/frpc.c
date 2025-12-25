#include "../include/frpc.h"
#include "../include/tools.h"
#include "wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// FRP uses golib/msg/json framing: 1 byte type + 8 bytes big-endian int64 length + JSON payload
#define FRPC_MAX_MSG_LENGTH 10240

// Quiet by default; set TINY_FRPC_VERBOSE=1 to enable extra debug logs.
static int frpc_verbose_enabled(void) {
    static int inited = 0;
    static int enabled = 0;
    if (!inited) {
        const char* v = getenv("TINY_FRPC_VERBOSE");
        enabled = (v && v[0] != '\0' && v[0] != '0');
        inited = 1;
    }
    return enabled;
}

static void frpc_write_be64(uint8_t out[8], int64_t v);
static int64_t frpc_read_be64(const uint8_t in[8]);
static int frpc_write_all(int fd, const void* buf, size_t len);
static int frpc_wait_readable(int fd, int timeout_ms);
static int frpc_read_exact_timeout(int fd, void* buf, size_t len, int timeout_ms);
static int frpc_send_msg_fd(int fd, uint8_t type, const char* json, size_t json_len);
static int frpc_read_msg_fd(int fd, uint8_t* type_out, char** json_out, size_t* json_len_out, int timeout_ms);
static int frpc_json_get_string(const char* json, size_t json_len, const char* key, char* out, size_t out_cap);
static int frpc_dial_tcp(const char* host, uint16_t port);

static void frpc_write_be64(uint8_t out[8], int64_t v) {
    // Big-endian
    uint64_t u = (uint64_t)v;
    out[0] = (uint8_t)((u >> 56) & 0xFF);
    out[1] = (uint8_t)((u >> 48) & 0xFF);
    out[2] = (uint8_t)((u >> 40) & 0xFF);
    out[3] = (uint8_t)((u >> 32) & 0xFF);
    out[4] = (uint8_t)((u >> 24) & 0xFF);
    out[5] = (uint8_t)((u >> 16) & 0xFF);
    out[6] = (uint8_t)((u >> 8) & 0xFF);
    out[7] = (uint8_t)(u & 0xFF);
}

static int64_t frpc_read_be64(const uint8_t in[8]) {
    uint64_t u = ((uint64_t)in[0] << 56) |
                 ((uint64_t)in[1] << 48) |
                 ((uint64_t)in[2] << 40) |
                 ((uint64_t)in[3] << 32) |
                 ((uint64_t)in[4] << 24) |
                 ((uint64_t)in[5] << 16) |
                 ((uint64_t)in[6] << 8) |
                 ((uint64_t)in[7]);
    return (int64_t)u;
}

static int frpc_write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = wrapped_write(fd, p + off, len - off);
        if (n < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int frpc_wait_readable(int fd, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    struct timeval tv;
    struct timeval* ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ptv = &tv;
    }

    int ret;
    do {
        ret = wrapped_select(fd + 1, &rfds, NULL, NULL, ptv);
    } while (ret < 0 && wrapped_get_errno() == WRAPPED_EINTR);
    return ret; // 0 timeout, 1 ready, <0 error
}

static int frpc_read_exact_timeout(int fd, void* buf, size_t len, int timeout_ms) {
    uint8_t* p = (uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        int sel = frpc_wait_readable(fd, timeout_ms);
        if (sel == 0) {
            wrapped_set_errno(WRAPPED_ETIMEDOUT);
            return -1;
        }
        if (sel < 0) {
            return -1;
        }

        ssize_t n = wrapped_read(fd, p + off, len - off);
        if (n < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            wrapped_set_errno(WRAPPED_ECONNRESET);
            return -1; // closed
        }
        off += (size_t)n;
    }
    return 0;
}

static int frpc_send_msg_fd(int fd, uint8_t type, const char* json, size_t json_len) {
    uint8_t len_be[8];
    frpc_write_be64(len_be, (int64_t)json_len);

    if (frpc_write_all(fd, &type, 1) != 0) return -1;
    if (frpc_write_all(fd, len_be, sizeof(len_be)) != 0) return -1;
    if (json_len > 0 && json) {
        if (frpc_write_all(fd, json, json_len) != 0) return -1;
    }
    return 0;
}

static int frpc_read_msg_fd(int fd, uint8_t* type_out, char** json_out, size_t* json_len_out, int timeout_ms) {
    if (!type_out || !json_out || !json_len_out) return -1;

    uint8_t type = 0;
    uint8_t len_be[8];
    if (frpc_read_exact_timeout(fd, &type, 1, timeout_ms) != 0) return -1;
    if (frpc_read_exact_timeout(fd, len_be, sizeof(len_be), timeout_ms) != 0) return -1;

    int64_t msg_len = frpc_read_be64(len_be);
    if (msg_len < 0 || msg_len > FRPC_MAX_MSG_LENGTH) {
        return -1;
    }

    char* payload = (char*)malloc((size_t)msg_len + 1);
    if (!payload) return -1;

    if (msg_len > 0) {
        if (frpc_read_exact_timeout(fd, payload, (size_t)msg_len, timeout_ms) != 0) {
            free(payload);
            return -1;
        }
    }
    payload[msg_len] = '\0';

    *type_out = type;
    *json_out = payload;
    *json_len_out = (size_t)msg_len;
    return 0;
}

static int frpc_json_get_string(const char* json, size_t json_len, const char* key, char* out, size_t out_cap) {
    if (!json || !key || !out || out_cap == 0) return -1;

    char pattern[128];
    int n = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    if (n <= 0 || (size_t)n >= sizeof(pattern)) return -1;

    const char* p = strstr(json, pattern);
    if (!p) return -1;

    p += strlen(pattern);
    const char* end = json + json_len;
    while (p < end && wrapped_isspace((unsigned char)*p)) p++;
    if (p >= end || *p != '"') return -1;
    p++; // skip opening quote

    size_t w = 0;
    while (p < end) {
        char ch = *p++;
        if (ch == '"') {
            if (w >= out_cap) return -1;
            out[w] = '\0';
            return 0;
        }
        if (ch == '\\') {
            if (p >= end) return -1;
            char esc = *p++;
            switch (esc) {
                case '"': ch = '"'; break;
                case '\\': ch = '\\'; break;
                case '/': ch = '/'; break;
                case 'b': ch = '\b'; break;
                case 'f': ch = '\f'; break;
                case 'n': ch = '\n'; break;
                case 'r': ch = '\r'; break;
                case 't': ch = '\t'; break;
                default:
                    // Incomplete support for \\uXXXX; fall back to writing the raw escape char.
                    ch = esc;
                    break;
            }
        }
        if (w + 1 >= out_cap) return -1;
        out[w++] = ch;
    }
    return -1;
}

static int frpc_dial_tcp(const char* host, uint16_t port) {
    if (!host || port == 0) return -1;

    char service[16];
    snprintf(service, sizeof(service), "%u", (unsigned int)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo* res = NULL;
    if (wrapped_getaddrinfo(host, service, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* rp = res; rp != NULL; rp = rp->ai_next) {
        fd = wrapped_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (wrapped_connect(fd, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
            break;
        }
        wrapped_close(fd);
        fd = -1;
    }

    wrapped_freeaddrinfo(res);
    return fd;
}

// FRP client structure
struct frpc_client {
    frpc_config_t config;
    void* user_ctx;
    frpc_event_callback event_callback;
    
    // Network connection fields
    int socket_fd;
    uint8_t* recv_buffer;
    size_t recv_buffer_size;
    size_t recv_buffer_len;
    char* run_id; // run_id allocated by frps (received after successful login)
    
    // State flags
    bool is_connected;
    uint64_t last_heartbeat_time;
};


// Create a new FRP client instance
frpc_client_t* frpc_client_new(const frpc_config_t* config, void* user_ctx) {
    if (!config || !config->server_addr) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "Error: Invalid FRP client configuration\n");
        }
        return NULL;
    }
    
    struct frpc_client* client = (struct frpc_client*)malloc(sizeof(struct frpc_client));
    if (!client) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "Error: Failed to allocate memory for FRP client\n");
        }
        return NULL;
    }
    
    memset(client, 0, sizeof(struct frpc_client));
    client->config = *config;
    client->user_ctx = user_ctx;
    
    // Duplicate server address and token
    client->config.server_addr = strdup(config->server_addr);
    if (config->token) {
        client->config.token = strdup(config->token);
    }
    
    // Initialize receive buffer
    client->recv_buffer_size = 4096;  // default buffer size
    client->recv_buffer = (uint8_t*)malloc(client->recv_buffer_size);
    if (!client->recv_buffer) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "Error: Failed to allocate receive buffer\n");
        }
        free((void*)client->config.server_addr);
        if (client->config.token) {
            free((void*)client->config.token);
        }
        free(client);
        return NULL;
    }
    
    client->socket_fd = -1;  // initialize as invalid
    client->recv_buffer_len = 0;
    client->run_id = NULL;
    
    return client;
}

// Free an FRP client instance
void frpc_client_free(frpc_client_t* client) {
    if (!client) return;
    
    // Disconnect first
    if (client->is_connected) {
        frpc_client_disconnect(client);
    }
    
    // Free receive buffer
    if (client->recv_buffer) {
        free(client->recv_buffer);
    }
    if (client->run_id) {
        free(client->run_id);
        client->run_id = NULL;
    }
    
    // Free duplicated strings
    if (client->config.server_addr) {
        free((void*)client->config.server_addr);
    }
    if (client->config.token) {
        free((void*)client->config.token);
    }
    
    free(client);
}

// Connect to FRP server
int frpc_client_connect(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (client->is_connected) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "Warning: FRP client already connected\n");
        }
        return FRPC_SUCCESS;
    }

    fprintf(stdout, "Connecting to FRP server: %s:%d\n",
            client->config.server_addr, client->config.server_port);

    int fd = frpc_dial_tcp(client->config.server_addr, client->config.server_port);
    if (fd < 0) {
        fprintf(stderr, "frpc_client_connect: dial failed\n");
        return FRPC_ERROR_NETWORK;
    }
    fprintf(stdout, "frpc_client_connect: dial ok, fd=%d\n", fd);

    // Login message (TypeLogin = 'o')
    int64_t ts = (int64_t)wrapped_time(NULL);
    char privilege_key[33] = {0};
    if (client->config.token && client->config.token[0] != '\0') {
        if (tools_get_auth_key(client->config.token, ts, privilege_key) != 0) {
            wrapped_close(fd);
            return FRPC_ERROR_INTERNAL;
        }
    } else {
        // Empty token is allowed in some setups, but token-auth in tests expects non-empty.
        privilege_key[0] = '\0';
    }

    // Set PoolCount=0 to avoid frps sending many ReqWorkConn immediately after login (simplifies embedded bring-up).
    char login_json[512];
    int login_len = snprintf(login_json, sizeof(login_json),
                             "{\"version\":\"tiny-frpc\",\"os\":\"darwin\",\"arch\":\"arm64\","
                             "\"user\":\"\",\"timestamp\":%lld,\"privilege_key\":\"%s\","
                             "\"run_id\":\"\",\"pool_count\":0}",
                             (long long)ts, privilege_key);
    if (login_len <= 0 || (size_t)login_len >= sizeof(login_json)) {
        wrapped_close(fd);
        return FRPC_ERROR_INTERNAL;
    }

    if (frpc_send_msg_fd(fd, (uint8_t)'o', login_json, (size_t)login_len) != 0) {
        fprintf(stderr, "frpc_client_connect: send login failed (errno=%d)\n", wrapped_get_errno());
        wrapped_close(fd);
        return FRPC_ERROR_NETWORK;
    }
    fprintf(stdout, "frpc_client_connect: login sent (%d bytes)\n", login_len);

    uint8_t resp_type = 0;
    char* resp_json = NULL;
    size_t resp_len = 0;
    if (frpc_read_msg_fd(fd, &resp_type, &resp_json, &resp_len, 10000) != 0) {
        fprintf(stderr, "frpc_client_connect: read loginresp failed (errno=%d)\n", wrapped_get_errno());
        wrapped_close(fd);
        return FRPC_ERROR_NETWORK;
    }
    fprintf(stdout, "frpc_client_connect: loginresp received (type=%c, len=%zu)\n", (char)resp_type, resp_len);
    fprintf(stdout, "frpc_client_connect: loginresp json=%s\n", resp_json ? resp_json : "(null)");

    int ret = FRPC_SUCCESS;
    if (resp_type != (uint8_t)'1') { // TypeLoginResp = '1'
        fprintf(stderr, "frpc_client_connect: unexpected resp type: %c\n", (char)resp_type);
        ret = FRPC_ERROR_PROTO;
        goto out_login_resp;
    }

    char err_str[512] = {0};
    if (frpc_json_get_string(resp_json, resp_len, "error", err_str, sizeof(err_str)) == 0) {
        if (err_str[0] != '\0') {
            fprintf(stderr, "frpc_client_connect: login error: %s\n", err_str);
            ret = FRPC_ERROR_AUTH;
            goto out_login_resp;
        }
    }

    char run_id[128] = {0};
    if (frpc_json_get_string(resp_json, resp_len, "run_id", run_id, sizeof(run_id)) != 0) {
        fprintf(stderr, "frpc_client_connect: missing run_id in LoginResp\n");
        ret = FRPC_ERROR_PROTO;
        goto out_login_resp;
    }

    if (client->run_id) {
        free(client->run_id);
    }
    client->run_id = strdup(run_id);
    if (!client->run_id) {
        ret = FRPC_ERROR_MEMORY;
        goto out_login_resp;
    }

    client->socket_fd = fd;
    client->is_connected = true;
    client->recv_buffer_len = 0;
    client->last_heartbeat_time = tools_get_time_ms();

    // Notify connection event
    if (client->event_callback) {
        client->event_callback(client->user_ctx, 1, NULL); // 1 = connected
    }

    fprintf(stdout, "login to server success, run_id=%s\n", client->run_id);

out_login_resp:
    free(resp_json);
    if (ret != FRPC_SUCCESS) {
        wrapped_close(fd);
    }
    return ret;
}

// Disconnect from FRP server
int frpc_client_disconnect(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        return FRPC_SUCCESS;
    }
    
    // For tests we only update state.
    // A real implementation should close the socket.
    fprintf(stdout, "Disconnecting from FRP server\n");
    
    client->is_connected = false;
    
    // Notify disconnect event
    if (client->event_callback) {
        client->event_callback(client->user_ctx, 0, NULL); // 0 = disconnected
    }
    
    return FRPC_SUCCESS;
}

// Handle received bytes
int frpc_client_receive(frpc_client_t* client, const uint8_t* data, size_t len) {
    if (!client || !data) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "Error: FRP client not connected\n");
        }
        return FRPC_ERROR_INTERNAL;
    }
    
    // For now, just print received bytes length (debug).
    fprintf(stdout, "Received %zu bytes of data\n", len);
    
    // TODO: parse and handle FRP protocol messages.
    // ...
    
    return FRPC_SUCCESS;
}

// Periodic tick (heartbeat and other timers)
int frpc_client_tick(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        return FRPC_SUCCESS;
    }
    
    uint64_t current_time = tools_get_time_ms();
    
    // Check whether we should send a heartbeat
    if (client->config.heartbeat_interval > 0 && 
        current_time - client->last_heartbeat_time >= client->config.heartbeat_interval * 1000) {
        
        // Send heartbeat message
        fprintf(stdout, "Sending heartbeat to FRP server\n");
        
        // TODO: construct and send heartbeat message
        // ...
        
        client->last_heartbeat_time = current_time;
    }
    
    return FRPC_SUCCESS;
}

// Set event callback
void frpc_client_set_event_callback(frpc_client_t* client, frpc_event_callback callback) {
    if (!client) return;
    
    client->event_callback = callback;
}

// Send raw Yamux frame bytes (used by Yamux write_fn).
// These bytes should be sent over the connection to frps; frps routes them to the other side of the work connection.
int frpc_client_send_yamux_frame_bytes(frpc_client_t* client, const uint8_t* data, size_t len) {
    if (!client || !data || len == 0) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "frpc_client_send_yamux_frame_bytes: Invalid parameters\n");
        }
        return FRPC_ERROR_INVALID_PARAM;
    }

    if (!client->is_connected) {
        if (frpc_verbose_enabled()) {
            fprintf(stderr, "frpc_client_send_yamux_frame_bytes: Client not connected\n");
        }
        return FRPC_ERROR_NETWORK; // Or a more specific error like NOT_CONNECTED
    }

    // TODO: Implement actual sending of these bytes over client->socket_fd
    // This should be a raw TCP send. frps will interpret these bytes as Yamux frames
    // arriving on the work connection associated with this client for this STCP proxy.
    
    if (frpc_verbose_enabled()) {
        fprintf(stdout, "FRPC_CLIENT_SEND_YAMUX_BYTES: Client %p, len %zu. Data (first 16 bytes hex): ", (void*)client, len);
        for (size_t i = 0; i < len && i < 16; ++i) {
            fprintf(stdout, "%02x ", data[i]);
        }
        fprintf(stdout, "\n");
        fflush(stdout); // Ensure log is visible immediately
    }

    // For now, pretend success. In a real implementation, this would be the return value of send().
    return (int)len; 
} 