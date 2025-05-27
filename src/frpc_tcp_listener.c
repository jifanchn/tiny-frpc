/**
 * @file frpc_tcp_listener.c
 * @brief TCP listener implementation for STCP visitor mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define SOCKET_ERROR (-1)
#define close closesocket
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
typedef int socket_t;
#define SOCKET_ERROR (-1)
#endif

#include "frpc_internal.h"

/**
 * @brief STCP Visitor listener structure
 */
typedef struct stcp_listener {
    socket_t listen_fd;        /**< Listening socket */
    uint16_t bind_port;        /**< Port to bind to */
    int running;               /**< Running flag */
    pthread_t thread;          /**< Listener thread */
    frpc_ctx_t *ctx;           /**< FRPC context */
    char *proxy_name;          /**< Proxy name */
    char *server_name;         /**< Server name */
    struct stcp_listener *next; /**< Next listener in list */
} stcp_listener_t;

/* Global list of active listeners */
static stcp_listener_t *g_listeners = NULL;

/* Mutex for protecting the listener list */
static pthread_mutex_t g_listener_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Initialize the TCP listener subsystem
 * 
 * @return 0 on success, -1 on error
 */
int frpc_tcp_listener_init(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        set_error("WSAStartup failed");
        return -1;
    }
#endif
    return 0;
}

/**
 * @brief Cleanup the TCP listener subsystem
 */
void frpc_tcp_listener_cleanup(void) {
    /* Stop and free all listeners */
    pthread_mutex_lock(&g_listener_mutex);
    
    stcp_listener_t *curr = g_listeners;
    while (curr) {
        stcp_listener_t *next = curr->next;
        
        /* Stop the listener */
        curr->running = 0;
        
        /* Close the socket to unblock accept() */
        if (curr->listen_fd != SOCKET_ERROR) {
            close(curr->listen_fd);
            curr->listen_fd = SOCKET_ERROR;
        }
        
        /* Wait for thread to exit */
        if (curr->thread) {
            pthread_join(curr->thread, NULL);
        }
        
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
    
    g_listeners = NULL;
    pthread_mutex_unlock(&g_listener_mutex);
    
#ifdef _WIN32
    WSACleanup();
#endif
}

/**
 * @brief Thread function for accepting connections
 * 
 * @param arg Listener context
 * @return NULL
 */
static void* listener_thread(void *arg) {
    stcp_listener_t *listener = (stcp_listener_t*)arg;
    
    if (!listener || !listener->ctx) {
        return NULL;
    }
    
    while (listener->running) {
        /* Accept a new connection */
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        socket_t client_fd = accept(listener->listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        
        if (client_fd == SOCKET_ERROR) {
            /* Check if we're still running */
            if (!listener->running) {
                break;
            }
            
            /* Log error */
            if (listener->ctx->debug) {
                fprintf(stderr, "STCP Visitor accept error\n");
            }
            
            continue;
        }
        
        /* Handle the new connection */
        /* This should create a new work connection to the server and start forwarding data */
        /* For now, we'll just close the connection until we implement the full forwarding logic */
        close(client_fd);
    }
    
    return NULL;
}

/**
 * @brief Find a listener by proxy name
 * 
 * @param proxy_name Proxy name
 * @return Listener pointer or NULL if not found
 */
static stcp_listener_t* find_listener(const char *proxy_name) {
    pthread_mutex_lock(&g_listener_mutex);
    
    stcp_listener_t *curr = g_listeners;
    while (curr) {
        if (strcmp(curr->proxy_name, proxy_name) == 0) {
            pthread_mutex_unlock(&g_listener_mutex);
            return curr;
        }
        curr = curr->next;
    }
    
    pthread_mutex_unlock(&g_listener_mutex);
    return NULL;
}

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
                                     const char *server_name, uint16_t bind_port) {
    if (!ctx || !proxy_name || !server_name || bind_port == 0) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* Check if listener already exists */
    if (find_listener(proxy_name)) {
        set_error("Listener for proxy '%s' already exists", proxy_name);
        return -1;
    }
    
    /* Create listener structure */
    stcp_listener_t *listener = (stcp_listener_t*)malloc(sizeof(stcp_listener_t));
    if (!listener) {
        set_error("Memory allocation failed");
        return -1;
    }
    
    memset(listener, 0, sizeof(stcp_listener_t));
    listener->listen_fd = SOCKET_ERROR;
    listener->bind_port = bind_port;
    listener->ctx = ctx;
    listener->proxy_name = strdup(proxy_name);
    listener->server_name = strdup(server_name);
    
    if (!listener->proxy_name || !listener->server_name) {
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Memory allocation failed");
        return -1;
    }
    
    /* Create socket */
    listener->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener->listen_fd == SOCKET_ERROR) {
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Failed to create socket");
        return -1;
    }
    
    /* Set socket options */
    int opt = 1;
    if (setsockopt(listener->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
        close(listener->listen_fd);
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Failed to set socket options");
        return -1;
    }
    
    /* Bind to port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(bind_port);
    
    if (bind(listener->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listener->listen_fd);
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Failed to bind to port %d", bind_port);
        return -1;
    }
    
    /* Start listening */
    if (listen(listener->listen_fd, SOMAXCONN) < 0) {
        close(listener->listen_fd);
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Failed to listen on port %d", bind_port);
        return -1;
    }
    
    /* Mark as running */
    listener->running = 1;
    
    /* Create thread */
    if (pthread_create(&listener->thread, NULL, listener_thread, listener) != 0) {
        close(listener->listen_fd);
        if (listener->proxy_name) free(listener->proxy_name);
        if (listener->server_name) free(listener->server_name);
        free(listener);
        set_error("Failed to create listener thread");
        return -1;
    }
    
    /* Add to list */
    pthread_mutex_lock(&g_listener_mutex);
    listener->next = g_listeners;
    g_listeners = listener;
    pthread_mutex_unlock(&g_listener_mutex);
    
    if (ctx->debug) {
        fprintf(stderr, "STCP Visitor listener started on port %d\n", bind_port);
    }
    
    return 0;
}

/**
 * @brief Stop and remove a STCP visitor listener
 * 
 * @param proxy_name Proxy name
 * @return 0 on success, -1 on error
 */
int frpc_remove_stcp_visitor_listener(const char *proxy_name) {
    if (!proxy_name) {
        set_error("Invalid parameters");
        return -1;
    }
    
    pthread_mutex_lock(&g_listener_mutex);
    
    stcp_listener_t *prev = NULL;
    stcp_listener_t *curr = g_listeners;
    
    while (curr) {
        if (strcmp(curr->proxy_name, proxy_name) == 0) {
            /* Remove from list */
            if (prev) {
                prev->next = curr->next;
            } else {
                g_listeners = curr->next;
            }
            
            /* Stop the listener */
            curr->running = 0;
            
            /* Close the socket to unblock accept() */
            if (curr->listen_fd != SOCKET_ERROR) {
                close(curr->listen_fd);
                curr->listen_fd = SOCKET_ERROR;
            }
            
            pthread_mutex_unlock(&g_listener_mutex);
            
            /* Wait for thread to exit */
            if (curr->thread) {
                pthread_join(curr->thread, NULL);
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
    
    pthread_mutex_unlock(&g_listener_mutex);
    
    set_error("Listener for proxy '%s' not found", proxy_name);
    return -1;
}
