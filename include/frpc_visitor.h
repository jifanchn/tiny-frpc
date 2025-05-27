/**
 * @file frpc_visitor.h
 * @brief Lightweight STCP visitor interface for tiny-frpc
 */

#ifndef FRPC_VISITOR_H
#define FRPC_VISITOR_H

#include <stdint.h>
#include <stddef.h>
#include "frpc_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create and add a new STCP visitor
 * 
 * @param ctx FRPC context
 * @param proxy_name Proxy name
 * @param server_name Server name
 * @param bind_port Bind port
 * @return 0 on success, -1 on error
 */
int frpc_create_stcp_visitor(frpc_ctx_t *ctx, const char *proxy_name, 
                             const char *server_name, uint16_t bind_port);

/**
 * @brief Remove a STCP visitor
 * 
 * @param proxy_name Proxy name
 * @return 0 on success, -1 on error
 */
int frpc_remove_stcp_visitor(const char *proxy_name);

/**
 * @brief Get visitor info by port
 * 
 * @param bind_port Bind port
 * @param proxy_name Output buffer for proxy name
 * @param proxy_name_size Size of proxy name buffer
 * @param server_name Output buffer for server name
 * @param server_name_size Size of server name buffer
 * @return Visitor context or NULL if not found
 */
frpc_ctx_t* frpc_get_visitor_by_port(uint16_t bind_port, 
                                    char *proxy_name, size_t proxy_name_size,
                                    char *server_name, size_t server_name_size);

/**
 * @brief Create a work connection for a visitor based on proxy name
 * 
 * This function should be called when a client connects to a visitor port.
 * The function will establish a new work connection to the server.
 * 
 * @param proxy_name Name of the proxy
 * @param user_conn User connection handle
 * @return 0 on success, -1 on error
 */
int frpc_create_visitor_workconn(const char *proxy_name, void *user_conn);

/**
 * @brief Clean up all visitors
 */
void frpc_cleanup_visitors(void);

#ifdef __cplusplus
}
#endif

#endif /* FRPC_VISITOR_H */
