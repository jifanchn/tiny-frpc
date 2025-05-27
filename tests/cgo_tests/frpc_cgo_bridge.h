#ifndef FRPC_CGO_BRIDGE_H
#define FRPC_CGO_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Read/Write callback wrappers
int c_read_wrapper(void *ctx, unsigned char *buf, size_t len);
int c_write_wrapper(void *ctx, const unsigned char *buf, size_t len);

// Visitor callback wrappers
void c_visitor_callback(void *ctx, const char *proxy_name, const char *server_name, uint16_t bind_port, void *user_data);
int c_workconn_callback(void *ctx, const char *proxy_name, void *client_conn, void *user_data);

// Initialize frpc with go callbacks
void* tiny_frpc_init(uintptr_t ctx, const char* server_addr, uint16_t server_port, const char* token);

// Add TCP proxy
int tiny_frpc_add_tcp_proxy(void* frpc, const char* name, const char* local_ip,
                           uint16_t local_port, uint16_t remote_port);

// Set debug mode
void tiny_frpc_set_debug(void* frpc, int debug);

// Add STCP server proxy
int tiny_frpc_add_stcp_server(void* frpc, const char* name, const char* local_ip, 
                             uint16_t local_port, const char* sk);

// Add STCP visitor proxy
int tiny_frpc_add_stcp_visitor(void* frpc, const char* name, const char* server_name, 
                              const char* sk, uint16_t bind_port);

// Add XTCP server proxy
int tiny_frpc_add_xtcp_server(void* frpc, const char* name, const char* local_ip, 
                             uint16_t local_port, const char* sk);

// Add XTCP visitor proxy
int tiny_frpc_add_xtcp_visitor(void* frpc, const char* name, const char* server_name, 
                              const char* sk, uint16_t bind_port);

// Notify client connection to visitor port
int tiny_frpc_visitor_new_connection(const char *proxy_name, void *client_conn);

#ifdef __cplusplus
}
#endif

#endif /* FRPC_CGO_BRIDGE_H */
