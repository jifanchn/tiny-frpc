/**
 * @file frpc.h
 * @brief Main API header for tiny-frpc client library
 * 
 * This file contains the public API for tiny-frpc, a C implementation
 * of the frp client protocol compatible with the Go frps server.
 */

#ifndef TINY_FRPC_H
#define TINY_FRPC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Proxy types supported by tiny-frpc
 */
typedef enum {
    FRPC_PROXY_TYPE_TCP = 0,    /**< TCP forwarding */
    FRPC_PROXY_TYPE_UDP,        /**< UDP forwarding */
    FRPC_PROXY_TYPE_HTTP,       /**< HTTP forwarding */
    FRPC_PROXY_TYPE_HTTPS,      /**< HTTPS forwarding */
    FRPC_PROXY_TYPE_STCP,       /**< STCP (Secret TCP) forwarding */
    FRPC_PROXY_TYPE_XTCP,       /**< XTCP (P2P) forwarding */
    FRPC_PROXY_TYPE_TCPMUX      /**< TCP multiplexing */
} frpc_proxy_type_t;

/**
 * @brief Configuration for frpc client
 */
typedef struct {
    const char *server_addr;     /**< frps server address */
    uint16_t server_port;        /**< frps server port */
    const char *token;           /**< Authentication token (optional) */
    const char *user;            /**< User name (optional) */
    int use_tls;                 /**< Whether to use TLS for connection */
    int heartbeat_interval;      /**< Heartbeat interval in seconds (default: 30) */
    int heartbeat_timeout;       /**< Heartbeat timeout in seconds (default: 90) */
} frpc_config_t;

/**
 * @brief Configuration for a proxy
 */
typedef struct {
    const char *name;            /**< Proxy name, must be unique */
    frpc_proxy_type_t type;      /**< Proxy type */
    
    /* Common fields */
    const char *local_ip;        /**< Local IP to forward to */
    uint16_t local_port;         /**< Local port to forward to */
    uint16_t remote_port;        /**< Remote port to expose on frps */
    
    /* HTTP/HTTPS specific */
    const char *custom_domain;   /**< Custom domain name */
    const char *subdomain;       /**< Subdomain name */
    
    /* STCP/XTCP specific */
    const char *sk;              /**< Secret key for STCP/XTCP */
    int is_visitor;              /**< Flag for visitor mode */
    const char *server_name;     /**< Server name for visitor mode */
    uint16_t bind_port;          /**< Bind port for visitor mode */
    
    /* Advanced options */
    int use_compression;         /**< Whether to use compression */
    int use_encryption;          /**< Whether to use encryption */
} frpc_proxy_config_t;

/**
 * @brief I/O read callback function type
 * 
 * @param ctx User context passed to frpc_init
 * @param buf Buffer to read into
 * @param len Maximum number of bytes to read
 * @return Number of bytes read on success, 0 on EOF, -1 on error
 */
typedef int (*frpc_read_fn)(void *ctx, uint8_t *buf, size_t len);

/**
 * @brief I/O write callback function type
 * 
 * @param ctx User context passed to frpc_init
 * @param buf Buffer to write from
 * @param len Number of bytes to write
 * @return Number of bytes written on success, 0 if no bytes written, -1 on error
 */
typedef int (*frpc_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/**
 * @brief Memory allocation function type
 */
typedef void* (*frpc_malloc_fn)(size_t size);

/**
 * @brief Memory free function type
 */
typedef void (*frpc_free_fn)(void* ptr);

/**
 * @brief Visitor changed callback function type
 * 
 * This callback is invoked when a visitor is added or removed.
 * The host application should use this to create or destroy actual 
 * network listeners on the specified port.
 * 
 * @param ctx FRPC context provided to frpc_init
 * @param proxy_name Proxy name (visitor name)
 * @param server_name Server name (NULL if visitor is being removed)
 * @param bind_port Bind port (0 if visitor is being removed)
 * @param user_data User data pointer provided to frpc_set_visitor_callback
 */
typedef void (*frpc_visitor_callback_fn)(void *ctx, const char *proxy_name, 
                                       const char *server_name, uint16_t bind_port, 
                                       void *user_data);

/**
 * @brief Work connection callback function type
 * 
 * This callback is invoked when a new client connects to a visitor port.
 * The host application should create a new work connection to handle the client.
 * 
 * @param ctx FRPC context provided to frpc_init
 * @param proxy_name Proxy name (visitor name)
 * @param client_conn User-defined handle for the client connection
 * @param user_data User data pointer provided to frpc_set_visitor_callback
 * @return 0 on success, -1 on error
 */
typedef int (*frpc_workconn_callback_fn)(void *ctx, const char *proxy_name,
                                       void *client_conn, void *user_data);

/**
 * @brief Set custom memory allocators
 * 
 * @param malloc_fn Custom malloc function
 * @param free_fn Custom free function
 */
void frpc_set_allocators(frpc_malloc_fn malloc_fn, frpc_free_fn free_fn);

/**
 * @brief Initialize frpc client
 * 
 * @param read_fn Read callback function
 * @param write_fn Write callback function
 * @param io_ctx Context to pass to read/write callbacks
 * @param config Client configuration
 * @return Opaque handle to frpc instance, NULL on error
 */
void* frpc_init(frpc_read_fn read_fn, frpc_write_fn write_fn, 
               void *io_ctx, const frpc_config_t *config);

/**
 * @brief Add a proxy to the frpc client
 * 
 * @param frpc frpc handle returned by frpc_init
 * @param proxy_config Proxy configuration
 * @return 0 on success, -1 on error
 */
int frpc_add_proxy(void *frpc, const frpc_proxy_config_t *proxy_config);

/**
 * @brief Remove a proxy from the frpc client
 * 
 * @param frpc frpc handle returned by frpc_init
 * @param name Name of the proxy to remove
 * @return 0 on success, -1 if proxy not found
 */
int frpc_remove_proxy(void *frpc, const char *name);

/**
 * @brief Start the frpc client
 * 
 * This initiates the connection to the frps server.
 * 
 * @param frpc frpc handle returned by frpc_init
 * @return 0 on success, -1 on error
 */
int frpc_start(void *frpc);

/**
 * @brief Stop the frpc client
 * 
 * This closes the connection to the frps server.
 * 
 * @param frpc frpc handle returned by frpc_init
 */
void frpc_stop(void *frpc);

/**
 * @brief Process frpc events
 * 
 * This function should be called regularly to handle
 * incoming data, process protocol messages, and manage timeouts.
 * 
 * @param frpc frpc handle returned by frpc_init
 * @return 0 on success, -1 on error
 */
int frpc_process(void *frpc);

/**
 * @brief Destroy frpc client and free resources
 * 
 * @param frpc frpc handle returned by frpc_init
 */
void frpc_destroy(void *frpc);

/**
 * @brief Get the last error message
 * 
 * @return Null-terminated error string, or NULL if no error
 */
const char* frpc_get_error(void);

/**
 * @brief Get the connection status
 * 
 * @param frpc frpc handle returned by frpc_init
 * @return 1 if connected, 0 if not connected
 */
int frpc_is_connected(void *frpc);

/**
 * @brief Set debug mode
 * 
 * @param frpc frpc handle returned by frpc_init
 * @param debug 0 for no debug output, 1 for debug output
 */
void frpc_set_debug(void *frpc, int debug);

/**
 * @brief Set visitor callback functions
 * 
 * @param frpc frpc handle returned by frpc_init
 * @param visitor_cb Callback function for visitor changes
 * @param workconn_cb Callback function for work connections
 * @param user_data User data to pass to callbacks
 */
void frpc_set_visitor_callbacks(void *frpc, 
                                frpc_visitor_callback_fn visitor_cb,
                                frpc_workconn_callback_fn workconn_cb,
                                void *user_data);

/**
 * @brief Notify client connection to visitor port
 * 
 * The host application should call this function when a client connects
 * to a visitor port. This will create a new work connection.
 * 
 * @param proxy_name Name of the visitor proxy
 * @param client_conn User-defined handle for the client connection
 * @return 0 on success, -1 on error
 */
int frpc_visitor_new_connection(const char *proxy_name, void *client_conn);

/**
 * @brief Get library version
 * 
 * @return Version string
 */
const char* frpc_version(void);

#ifdef __cplusplus
}
#endif

#endif /* TINY_FRPC_H */
