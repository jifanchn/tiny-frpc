/**
 * @file frpc_handler.h
 * @brief FRP protocol message handlers
 */

#ifndef FRPC_HANDLER_H
#define FRPC_HANDLER_H

#include <stdint.h>
#include <stddef.h>
#include "frpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration of frpc context */
typedef struct frpc_context frpc_ctx_t;

/* Login status */
typedef enum {
    FRPC_LOGIN_STATUS_IDLE = 0,
    FRPC_LOGIN_STATUS_PENDING,
    FRPC_LOGIN_STATUS_SUCCESS,
    FRPC_LOGIN_STATUS_FAILED
} frpc_login_status_t;

/**
 * @brief Handle an incoming message from the frps server
 * 
 * @param ctx frpc client context
 * @param type Message type
 * @param seq Message sequence number
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
int frpc_handle_message(frpc_ctx_t *ctx, uint8_t type, uint64_t seq, const uint8_t *data, size_t len);

/**
 * @brief Send login message to frps server
 * 
 * @param ctx frpc client context
 * @return 0 on success, -1 on error
 */
int frpc_send_login(frpc_ctx_t *ctx);

/**
 * @brief Send a ping message to frps server
 * 
 * @param ctx frpc client context
 * @return 0 on success, -1 on error
 */
int frpc_send_ping(frpc_ctx_t *ctx);

/**
 * @brief Send a new proxy message to frps server
 * 
 * @param ctx frpc client context
 * @param proxy Proxy configuration
 * @return 0 on success, -1 on error
 */
int frpc_send_new_proxy(frpc_ctx_t *ctx, const frpc_proxy_config_t *proxy);

#ifdef __cplusplus
}
#endif

#endif /* FRPC_HANDLER_H */
