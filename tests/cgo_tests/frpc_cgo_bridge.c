/*
 * Note: When compiling, ensure libtiny-frpc.a is available in the correct path
 * The correct library path is /Users/jifan/CascadeProjects/tiny-frpc/build
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frpc.h"
#include "frpc_visitor.h"
#include "frpc_cgo_bridge.h"

// Callback wrapper functions
extern int go_read_callback(void *ctx, void *buf, size_t len);
extern int go_write_callback(void *ctx, const void *buf, size_t len);
extern void go_visitor_callback(void *ctx, const char *proxy_name, const char *server_name, uint16_t bind_port, void *user_data);
extern int go_workconn_callback(void *ctx, const char *proxy_name, void *client_conn, void *user_data);

// Read callback wrapper
int c_read_wrapper(void *ctx, unsigned char *buf, size_t len) {
    return go_read_callback(ctx, (void*)buf, len);
}

// Write callback wrapper
int c_write_wrapper(void *ctx, const unsigned char *buf, size_t len) {
    return go_write_callback(ctx, (const void*)buf, len);
}

// Visitor callback wrapper
void c_visitor_callback(void *ctx, const char *proxy_name, const char *server_name, uint16_t bind_port, void *user_data) {
    go_visitor_callback(ctx, proxy_name, server_name, bind_port, user_data);
}

// Work connection callback wrapper
int c_workconn_callback(void *ctx, const char *proxy_name, void *client_conn, void *user_data) {
    return go_workconn_callback(ctx, proxy_name, client_conn, user_data);
}

// Initialize frpc with go callbacks
void* tiny_frpc_init(uintptr_t ctx, const char* server_addr, uint16_t server_port, const char* token) {
    frpc_config_t config;
    memset(&config, 0, sizeof(config));
    
    config.server_addr = server_addr;
    config.server_port = server_port;
    config.token = token;
    config.heartbeat_interval = 30;
    
    void* frpc = frpc_init(c_read_wrapper, c_write_wrapper, (void*)ctx, &config);
    
    // Set up visitor callbacks
    if (frpc) {
        frpc_set_visitor_callbacks(frpc, c_visitor_callback, c_workconn_callback, (void*)ctx);
    }
    
    return frpc;
}

// Add TCP proxy
int tiny_frpc_add_tcp_proxy(void* frpc, const char* name, const char* local_ip,
                           uint16_t local_port, uint16_t remote_port) {
    frpc_proxy_config_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    
    proxy.name = name;
    proxy.type = FRPC_PROXY_TYPE_TCP;
    proxy.local_ip = local_ip;
    proxy.local_port = local_port;
    proxy.remote_port = remote_port;
    
    return frpc_add_proxy(frpc, &proxy);
}

// Set debug mode
void tiny_frpc_set_debug(void* frpc, int debug) {
    frpc_set_debug(frpc, debug);
}

// Add STCP server proxy
int tiny_frpc_add_stcp_server(void* frpc, const char* name, const char* local_ip, 
                             uint16_t local_port, const char* sk) {
    frpc_proxy_config_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    
    proxy.name = name;
    proxy.type = FRPC_PROXY_TYPE_STCP;
    proxy.local_ip = local_ip;
    proxy.local_port = local_port;
    proxy.sk = sk;
    proxy.is_visitor = 0; // server mode
    
    return frpc_add_proxy(frpc, &proxy);
}

// Add STCP visitor proxy
int tiny_frpc_add_stcp_visitor(void* frpc, const char* name, const char* server_name, 
                              const char* sk, uint16_t bind_port) {
    frpc_proxy_config_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    
    proxy.name = name;
    proxy.type = FRPC_PROXY_TYPE_STCP;
    proxy.server_name = server_name;
    proxy.sk = sk;
    proxy.bind_port = bind_port;
    proxy.is_visitor = 1; // visitor mode
    
    return frpc_add_proxy(frpc, &proxy);
}

// Add XTCP server proxy
int tiny_frpc_add_xtcp_server(void* frpc, const char* name, const char* local_ip, 
                             uint16_t local_port, const char* sk) {
    frpc_proxy_config_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    
    proxy.name = name;
    proxy.type = FRPC_PROXY_TYPE_XTCP;
    proxy.local_ip = local_ip;
    proxy.local_port = local_port;
    proxy.sk = sk;
    proxy.is_visitor = 0; // server mode
    
    return frpc_add_proxy(frpc, &proxy);
}

// Add XTCP visitor proxy
int tiny_frpc_add_xtcp_visitor(void* frpc, const char* name, const char* server_name, 
                              const char* sk, uint16_t bind_port) {
    frpc_proxy_config_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    
    proxy.name = name;
    proxy.type = FRPC_PROXY_TYPE_XTCP;
    proxy.server_name = server_name;
    proxy.sk = sk;
    proxy.bind_port = bind_port;
    proxy.is_visitor = 1; // visitor mode
    
    return frpc_add_proxy(frpc, &proxy);
}

// Notify client connection to visitor port
int tiny_frpc_visitor_new_connection(const char *proxy_name, void *client_conn) {
    return frpc_visitor_new_connection(proxy_name, client_conn);
}
