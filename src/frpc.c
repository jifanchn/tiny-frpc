/**
 * @file frpc.c
 * @brief Implementation of tiny-frpc client library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "frpc.h"
#include "frpc_protocol.h"
#include "frpc_handler.h"
#include "frpc_internal.h"
#include "frpc_visitor.h"

/* Include tiny-yamux header */
#include "../externals/tiny-yamux/include/yamux.h"

/* Error buffer */
static char error_buffer[256] = {0};

/* Custom memory allocators and callbacks */
static frpc_malloc_fn custom_malloc = NULL;
static frpc_free_fn custom_free = NULL;

/* Allocation functions */
static void* frpc_malloc(size_t size) {
    if (custom_malloc) {
        return custom_malloc(size);
    }
    return malloc(size);
}

static void frpc_free(void *ptr) {
    if (custom_free) {
        custom_free(ptr);
    } else {
        free(ptr);
    }
}

/* Set the error message */
void set_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(error_buffer, sizeof(error_buffer) - 1, fmt, args);
    va_end(args);
}

/* Initialize frpc client */
void* frpc_init(frpc_read_fn read_fn, frpc_write_fn write_fn, 
               void *io_ctx, const frpc_config_t *config) {
    if (!read_fn || !write_fn || !config || !config->server_addr) {
        set_error("Invalid parameters for frpc_init");
        return NULL;
    }
    
    frpc_ctx_t *ctx = frpc_malloc(sizeof(frpc_ctx_t));
    if (!ctx) {
        set_error("Memory allocation failed");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(frpc_ctx_t));
    
    /* Copy configuration */
    ctx->config = *config;
    
    /* Set default values if not provided */
    if (ctx->config.heartbeat_interval <= 0) {
        ctx->config.heartbeat_interval = 30;
    }
    
    if (ctx->config.heartbeat_timeout <= 0) {
        ctx->config.heartbeat_timeout = 90;
    }
    
    /* Copy server address */
    ctx->config.server_addr = strdup(config->server_addr);
    
    /* Copy token if provided */
    if (config->token) {
        ctx->config.token = strdup(config->token);
    }
    
    /* Copy user if provided */
    if (config->user) {
        ctx->config.user = strdup(config->user);
    }
    
    /* Store callbacks */
    ctx->read_fn = read_fn;
    ctx->write_fn = write_fn;
    ctx->io_ctx = io_ctx;
    ctx->login_status = FRPC_LOGIN_STATUS_IDLE;
    ctx->debug = 0; /* Default is no debug output */
    
    return ctx;
}

/* Add a proxy to the frpc client */
int frpc_add_proxy(void *handle, const frpc_proxy_config_t *proxy_config) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx || !proxy_config || !proxy_config->name) {
        set_error("Invalid parameters for frpc_add_proxy");
        return -1;
    }
    
    /* Create new proxy node */
    proxy_list_t *proxy = frpc_malloc(sizeof(proxy_list_t));
    if (!proxy) {
        set_error("Memory allocation failed");
        return -1;
    }
    
    /* Copy proxy configuration */
    memset(proxy, 0, sizeof(proxy_list_t));
    proxy->config = *proxy_config;
    
    /* Copy strings */
    proxy->config.name = strdup(proxy_config->name);
    
    if (proxy_config->local_ip) {
        proxy->config.local_ip = strdup(proxy_config->local_ip);
    }
    
    if (proxy_config->custom_domain) {
        proxy->config.custom_domain = strdup(proxy_config->custom_domain);
    }
    
    if (proxy_config->subdomain) {
        proxy->config.subdomain = strdup(proxy_config->subdomain);
    }
    
    if (proxy_config->sk) {
        proxy->config.sk = strdup(proxy_config->sk);
    }
    
    if (proxy_config->server_name) {
        proxy->config.server_name = strdup(proxy_config->server_name);
    }
    
    /* Add to list */
    proxy->next = ctx->proxies;
    ctx->proxies = proxy;
    
    return 0;
}

/* Remove a proxy from the frpc client */
int frpc_remove_proxy(void *handle, const char *name) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx || !name) {
        set_error("Invalid parameters for frpc_remove_proxy");
        return -1;
    }
    
    proxy_list_t *prev = NULL;
    proxy_list_t *curr = ctx->proxies;
    
    while (curr) {
        if (strcmp(curr->config.name, name) == 0) {
            /* Remove from list */
            if (prev) {
                prev->next = curr->next;
            } else {
                ctx->proxies = curr->next;
            }
            
            /* Free strings */
            free((void*)curr->config.name);
            
            if (curr->config.local_ip) {
                free((void*)curr->config.local_ip);
            }
            
            if (curr->config.custom_domain) {
                free((void*)curr->config.custom_domain);
            }
            
            if (curr->config.subdomain) {
                free((void*)curr->config.subdomain);
            }
            
            if (curr->config.sk) {
                free((void*)curr->config.sk);
            }
            
            if (curr->config.server_name) {
                free((void*)curr->config.server_name);
            }
            
            /* Free node */
            frpc_free(curr);
            
            return 0;
        }
        
        prev = curr;
        curr = curr->next;
    }
    
    set_error("Proxy '%s' not found", name);
    return -1;
}

/* Start the frpc client */
int frpc_start(void *handle) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx) {
        set_error("Invalid handle for frpc_start");
        return -1;
    }
    
    /* Initialize yamux session */
    ctx->yamux_session = yamux_init(ctx->read_fn, ctx->write_fn, 
                                   ctx->io_ctx, 1); /* 1 for client mode */
    
    if (!ctx->yamux_session) {
        set_error("Failed to initialize yamux session");
        return -1;
    }
    
    /* Open control stream */
    ctx->control_stream = yamux_open_stream(ctx->yamux_session);
    if (!ctx->control_stream) {
        set_error("Failed to open control stream");
        yamux_destroy(ctx->yamux_session);
        ctx->yamux_session = NULL;
        return -1;
    }
    
    /* Send login to frps server */
    ctx->login_status = FRPC_LOGIN_STATUS_PENDING;
    if (frpc_send_login(ctx) < 0) {
        set_error("Failed to send login message");
        yamux_close_stream(ctx->control_stream, 0);
        ctx->control_stream = NULL;
        yamux_destroy(ctx->yamux_session);
        ctx->yamux_session = NULL;
        return -1;
    }
    
    ctx->connected = 1;
    ctx->last_heartbeat = time(NULL);
    ctx->last_pong = time(NULL);
    
    return 0;
}

/* Stop the frpc client */
void frpc_stop(void *handle) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx) {
        return;
    }
    
    /* Close control stream */
    if (ctx->control_stream) {
        yamux_close_stream(ctx->control_stream, 0); /* 0 for graceful close */
        ctx->control_stream = NULL;
    }
    
    /* Destroy yamux session */
    if (ctx->yamux_session) {
        yamux_destroy(ctx->yamux_session);
        ctx->yamux_session = NULL;
    }
    
    ctx->connected = 0;
    ctx->login_status = FRPC_LOGIN_STATUS_IDLE;
}

/* Process frpc events */
int frpc_process(void *handle) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx) {
        set_error("Invalid handle for frpc_process");
        return -1;
    }
    
    /* If not connected, do nothing */
    if (!ctx->connected) {
        return 0;
    }
    
    /* Process yamux session */
    if (ctx->yamux_session) {
        int result = yamux_process(ctx->yamux_session);
        if (result < 0) {
            set_error("Yamux process failed");
            ctx->connected = 0;
            return -1;
        }
    }
    
    /* Process incoming control messages */
    if (ctx->control_stream) {
        static uint8_t header_buf[13]; /* Header is 13 bytes */
        static uint8_t content_buf[4096]; /* Content buffer */
        static int header_len = 0;
        static int content_len = 0;
        static int expected_content_len = 0;
        
        /* Read header if needed */
        if (header_len < 13) {
            int n = yamux_read(ctx->control_stream, header_buf + header_len, 13 - header_len);
            if (n < 0) {
                set_error("Failed to read message header");
                ctx->connected = 0;
                return -1;
            }
            
            header_len += n;
            
            /* If we have a complete header, parse it */
            if (header_len == 13) {
                frpc_msg_header_t header;
                if (frpc_protocol_read_header(header_buf, &header) < 0) {
                    set_error("Invalid message header");
                    ctx->connected = 0;
                    return -1;
                }
                
                expected_content_len = header.content_length;
                
                /* If no content, handle the message now */
                if (expected_content_len == 0) {
                    if (frpc_handle_message(ctx, header.type, header.seq, NULL, 0) < 0) {
                        /* Error already set by handler */
                        ctx->connected = 0;
                        return -1;
                    }
                    
                    /* Reset for next message */
                    header_len = 0;
                }
            }
        }
        
        /* Read content if needed */
        if (header_len == 13 && content_len < expected_content_len) {
            int n = yamux_read(ctx->control_stream, content_buf + content_len, 
                              expected_content_len - content_len);
            if (n < 0) {
                set_error("Failed to read message content");
                ctx->connected = 0;
                return -1;
            }
            
            content_len += n;
            
            /* If we have all content, handle the message */
            if (content_len == expected_content_len) {
                frpc_msg_header_t header;
                if (frpc_protocol_read_header(header_buf, &header) < 0) {
                    set_error("Invalid message header");
                    ctx->connected = 0;
                    return -1;
                }
                
                if (frpc_handle_message(ctx, header.type, header.seq, content_buf, content_len) < 0) {
                    /* Error already set by handler */
                    ctx->connected = 0;
                    return -1;
                }
                
                /* Reset for next message */
                header_len = 0;
                content_len = 0;
                expected_content_len = 0;
            }
        }
    }
    
    /* Check login status */
    if (ctx->login_status == FRPC_LOGIN_STATUS_PENDING) {
        /* Wait for login response */
        /* Timeout handling could be added here */
    } else if (ctx->login_status == FRPC_LOGIN_STATUS_FAILED) {
        set_error("Authentication failed");
        ctx->connected = 0;
        return -1;
    }
    
    /* Check if we need to send heartbeat */
    time_t now = time(NULL);
    if (now - ctx->last_heartbeat >= ctx->config.heartbeat_interval) {
        /* Send ping for heartbeat */
        if (frpc_send_ping(ctx) < 0) {
            set_error("Failed to send ping");
            ctx->connected = 0;
            return -1;
        }
        
        ctx->last_heartbeat = now;
    }
    
    /* Check if we've received pongs (timeout check) */
    if (now - ctx->last_pong >= ctx->config.heartbeat_timeout) {
        set_error("Heartbeat timeout");
        ctx->connected = 0;
        return -1;
    }
    
    return 0;
}

/* Set debug mode */
void frpc_set_debug(void *handle, int debug) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (ctx) {
        ctx->debug = debug;
    }
}

/* Set visitor callbacks */
void frpc_set_visitor_callbacks(void *handle, 
                               frpc_visitor_callback_fn visitor_cb,
                               frpc_workconn_callback_fn workconn_cb,
                               void *user_data) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (ctx) {
        ctx->visitors_changed_cb = visitor_cb;
        ctx->workconn_cb = workconn_cb;
        ctx->user_data = user_data;
        
        if (ctx->debug) {
            fprintf(stderr, "Debug: Visitor callbacks registered\n");
        }
    }
}

/* Notify client connection to visitor port */
int frpc_visitor_new_connection(const char *proxy_name, void *client_conn) {
    if (!proxy_name || !client_conn) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* Forward to visitor system */
    return frpc_create_visitor_workconn(proxy_name, client_conn);
}

/* Destroy frpc client */
void frpc_destroy(void *handle) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx) {
        return;
    }
    
    /* Stop client if running */
    frpc_stop(ctx);
    
    /* Free configuration strings */
    if (ctx->config.server_addr) {
        free((void*)ctx->config.server_addr);
    }
    
    if (ctx->config.token) {
        free((void*)ctx->config.token);
    }
    
    if (ctx->config.user) {
        free((void*)ctx->config.user);
    }
    
    /* Free proxies */
    proxy_list_t *curr = ctx->proxies;
    while (curr) {
        proxy_list_t *next = curr->next;
        
        /* Free strings */
        free((void*)curr->config.name);
        
        if (curr->config.local_ip) {
            free((void*)curr->config.local_ip);
        }
        
        if (curr->config.custom_domain) {
            free((void*)curr->config.custom_domain);
        }
        
        if (curr->config.subdomain) {
            free((void*)curr->config.subdomain);
        }
        
        if (curr->config.sk) {
            free((void*)curr->config.sk);
        }
        
        if (curr->config.server_name) {
            free((void*)curr->config.server_name);
        }
        
        /* Free node */
        frpc_free(curr);
        
        curr = next;
    }
    
    /* Free context */
    frpc_free(ctx);
}

/* Set custom memory allocators */
void frpc_set_allocators(frpc_malloc_fn malloc_fn, frpc_free_fn free_fn) {
    custom_malloc = malloc_fn;
    custom_free = free_fn;
}

/* Get the last error message */
const char* frpc_get_error(void) {
    return error_buffer[0] ? error_buffer : NULL;
}

/* Get the connection status */
int frpc_is_connected(void *handle) {
    frpc_ctx_t *ctx = (frpc_ctx_t *)handle;
    
    if (!ctx) {
        return 0;
    }
    
    return ctx->connected;
}

/* Get library version */
const char* frpc_version(void) {
    return FRPC_VERSION;
}
