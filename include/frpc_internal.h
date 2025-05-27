#ifndef FRPC_INTERNAL_H
#define FRPC_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include "frpc.h"
#include "frpc_protocol.h"
#include "frpc_handler.h"

/* Error handling */
void set_error(const char *fmt, ...);

/**
 * @brief Visitor changed callback function type
 * 
 * This callback is invoked when a visitor is added or removed
 * 
 * @param ctx FRPC context
 * @param proxy_name Proxy name (visitor name)
 * @param server_name Server name (NULL if visitor is being removed)
 * @param bind_port Bind port (0 if visitor is being removed)
 * @param user_data User data pointer
 */
typedef void (*frpc_visitors_changed_cb)(void *ctx, const char *proxy_name, 
                                       const char *server_name, uint16_t bind_port, 
                                       void *user_data);

/**
 * @brief Work connection callback function type
 * 
 * This callback is invoked when a new client connects to a visitor port.
 * The host application should create a new work connection to handle the client.
 * 
 * @param ctx FRPC context
 * @param proxy_name Proxy name (visitor name)
 * @param client_conn User-defined handle for the client connection
 * @param user_data User data pointer
 * @return 0 on success, -1 on error
 */
typedef int (*frpc_workconn_cb)(void *ctx, const char *proxy_name,
                               void *client_conn, void *user_data);

/* Internal frpc structure, shared between modules */
struct frpc_context {
    frpc_config_t config;                  /* Client configuration */
    frpc_read_fn read_fn;                  /* Read callback */
    frpc_write_fn write_fn;                /* Write callback */
    void *io_ctx;                          /* I/O context */
    void *yamux_session;                   /* Yamux session */
    void *control_stream;                  /* Control stream for frps communication */
    uint64_t seq;                          /* Current message sequence */
    int connected;                         /* Connection status */
    int debug;                             /* Debug mode flag */
    frpc_login_status_t login_status;      /* Login status */
    time_t last_heartbeat;                 /* Last heartbeat time */
    time_t last_pong;                      /* Last pong received time */
    struct proxy_list *proxies;            /* List of proxies */
    frpc_visitors_changed_cb visitors_changed_cb; /* Visitor changed callback */
    frpc_workconn_cb workconn_cb;          /* Work connection callback */
    void *user_data;                       /* User data for callbacks */
};

/* Proxy list node */
typedef struct proxy_list {
    frpc_proxy_config_t config;            /* Proxy configuration */
    struct proxy_list *next;               /* Next proxy in list */
} proxy_list_t;

/* yamux related functions */
int yamux_write_all(void *stream, const uint8_t *buffer, size_t length);

#endif /* FRPC_INTERNAL_H */
