/**
 * @file frpc_tcp_listener.h
 * @brief TCP listener interface for STCP visitor mode
 */

#ifndef FRPC_TCP_LISTENER_H
#define FRPC_TCP_LISTENER_H

#include <stdint.h>
#include "frpc_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the TCP listener subsystem
 * 
 * @return 0 on success, -1 on error
 */
int frpc_tcp_listener_init(void);

/**
 * @brief Cleanup the TCP listener subsystem
 */
void frpc_tcp_listener_cleanup(void);

/**
 * @brief Create a new STCP visitor listener
 * 
 * @param ctx FRPC context
 * @param proxy_name Proxy name
 * @param server_name Server name
 * @param bind_port Bind port
 * @return 0 on success, -1 on error
 */
int frpc_create_stcp_visitor_listener(frpc_ctx_t *ctx, const char *proxy_name, 
                                     const char *server_name, uint16_t bind_port);

/**
 * @brief Stop and remove a STCP visitor listener
 * 
 * @param proxy_name Proxy name
 * @return 0 on success, -1 on error
 */
int frpc_remove_stcp_visitor_listener(const char *proxy_name);

#ifdef __cplusplus
}
#endif

#endif /* FRPC_TCP_LISTENER_H */
