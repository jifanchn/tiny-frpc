/**
 * @file frpc_visitor.c
 * @brief Lightweight STCP visitor implementation for tiny-frpc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frpc_internal.h"
#include "frpc_protocol.h"

/* Buffer for message handling */
#define VISITOR_BUFFER_SIZE 4096
static uint8_t visitor_buffer[VISITOR_BUFFER_SIZE];

/* STCP visitor context structure */
typedef struct stcp_visitor {
    char *proxy_name;           /**< Proxy name */
    char *server_name;          /**< Server name */
    uint16_t bind_port;         /**< Bind port */
    frpc_ctx_t *ctx;            /**< FRPC context */
    struct stcp_visitor *next;  /**< Next visitor in list */
} stcp_visitor_t;

/* Global list of active visitors */
static stcp_visitor_t *g_visitors = NULL;

/**
 * @brief Find a visitor by proxy name
 * 
 * @param proxy_name Proxy name
 * @return Visitor pointer or NULL if not found
 */
static stcp_visitor_t* find_visitor(const char *proxy_name) {
    stcp_visitor_t *curr = g_visitors;
    while (curr) {
        if (strcmp(curr->proxy_name, proxy_name) == 0) {
            return curr;
        }
        curr = curr->next;
    }
    
    return NULL;
}

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
                             const char *server_name, uint16_t bind_port) {
    if (!ctx || !proxy_name || !server_name || bind_port == 0) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* Check if visitor already exists */
    if (find_visitor(proxy_name)) {
        set_error("Visitor for proxy '%s' already exists", proxy_name);
        return -1;
    }
    
    /* Create visitor structure */
    stcp_visitor_t *visitor = (stcp_visitor_t*)malloc(sizeof(stcp_visitor_t));
    if (!visitor) {
        set_error("Memory allocation failed");
        return -1;
    }
    
    memset(visitor, 0, sizeof(stcp_visitor_t));
    visitor->bind_port = bind_port;
    visitor->ctx = ctx;
    visitor->proxy_name = strdup(proxy_name);
    visitor->server_name = strdup(server_name);
    
    if (!visitor->proxy_name || !visitor->server_name) {
        if (visitor->proxy_name) free(visitor->proxy_name);
        if (visitor->server_name) free(visitor->server_name);
        free(visitor);
        set_error("Memory allocation failed");
        return -1;
    }
    
    /* Add to list */
    visitor->next = g_visitors;
    g_visitors = visitor;
    
    if (ctx->debug) {
        fprintf(stderr, "Debug: STCP Visitor registered for %s on port %d\n", 
                proxy_name, bind_port);
    }
    
    /* Register with host application via callbacks */
    if (ctx->visitors_changed_cb) {
        ctx->visitors_changed_cb(ctx, proxy_name, server_name, bind_port, ctx->user_data);
    }
    
    return 0;
}

/**
 * @brief Remove a STCP visitor
 * 
 * @param proxy_name Proxy name
 * @return 0 on success, -1 on error
 */
int frpc_remove_stcp_visitor(const char *proxy_name) {
    if (!proxy_name) {
        set_error("Invalid parameters");
        return -1;
    }
    
    stcp_visitor_t *prev = NULL;
    stcp_visitor_t *curr = g_visitors;
    
    while (curr) {
        if (strcmp(curr->proxy_name, proxy_name) == 0) {
            /* Remove from list */
            if (prev) {
                prev->next = curr->next;
            } else {
                g_visitors = curr->next;
            }
            
            /* Register with host application via callbacks */
            if (curr->ctx && curr->ctx->visitors_changed_cb) {
                curr->ctx->visitors_changed_cb(
                    curr->ctx, 
                    proxy_name, 
                    NULL, /* server_name = NULL indicates removal */
                    0,    /* bind_port = 0 indicates removal */
                    curr->ctx->user_data
                );
            }
            
            /* Free resources */
            if (curr->proxy_name) {
                free(curr->proxy_name);
            }
            
            if (curr->server_name) {
                free(curr->server_name);
            }
            
            free(curr);
            
            return 0;
        }
        
        prev = curr;
        curr = curr->next;
    }
    
    set_error("Visitor for proxy '%s' not found", proxy_name);
    return -1;
}

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
                                    char *server_name, size_t server_name_size) {
    stcp_visitor_t *curr = g_visitors;
    while (curr) {
        if (curr->bind_port == bind_port) {
            if (proxy_name && proxy_name_size > 0) {
                strncpy(proxy_name, curr->proxy_name, proxy_name_size - 1);
                proxy_name[proxy_name_size - 1] = '\0';
            }
            
            if (server_name && server_name_size > 0) {
                strncpy(server_name, curr->server_name, server_name_size - 1);
                server_name[server_name_size - 1] = '\0';
            }
            
            return curr->ctx;
        }
        curr = curr->next;
    }
    
    return NULL;
}

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
int frpc_create_visitor_workconn(const char *proxy_name, void *user_conn) {
    if (!proxy_name || !user_conn) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* Find visitor */
    stcp_visitor_t *visitor = find_visitor(proxy_name);
    if (!visitor || !visitor->ctx) {
        set_error("Visitor '%s' not found", proxy_name);
        return -1;
    }
    
    /* Store connection handle for later use */
    /* Note: In a real implementation, you would create a connection context
     * and track it in a list */
    
    /* Create work connection message */
    frpc_msg_header_t header;
    int len = frpc_protocol_create_work_conn(visitor_buffer, VISITOR_BUFFER_SIZE, 
                                           visitor->ctx->seq, &header);
    if (len < 0) {
        set_error("Failed to create work connection message");
        return -1;
    }
    
    /* Send work connection message */
    if (yamux_write_all(visitor->ctx->control_stream, visitor_buffer, len) != len) {
        set_error("Failed to send work connection message");
        return -1;
    }
    
    /* Update sequence number */
    visitor->ctx->seq = header.seq + 1;
    
    /* In a real implementation, you would create a yamux stream for data transfer */
    
    if (visitor->ctx->debug) {
        fprintf(stderr, "Debug: Created work connection for visitor '%s'\n", proxy_name);
    }
    
    return 0;
}

/**
 * @brief Clean up all visitors
 */
void frpc_cleanup_visitors(void) {
    stcp_visitor_t *curr = g_visitors;
    
    while (curr) {
        stcp_visitor_t *next = curr->next;
        
        /* Free resources */
        if (curr->proxy_name) {
            free(curr->proxy_name);
        }
        
        if (curr->server_name) {
            free(curr->server_name);
        }
        
        free(curr);
        curr = next;
    }
    
    g_visitors = NULL;
}
