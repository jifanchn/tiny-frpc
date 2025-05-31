/**
 * @file stcp_visitor_client_example.c
 * @brief STCP Visitor Client Example
 * 
 * This example demonstrates how to create an STCP Visitor to connect to
 * embedded device STCP servers, implementing remote shell functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include "frpc.h"

#define BUFFER_SIZE 4096
#define DEFAULT_FRPS_PORT 7000
#define VISITOR_BIND_PORT 18022  // Local bind port, clients will connect to this port

static int running = 1;
static void *frpc_handle = NULL;

/* Socket implementation for I/O callbacks */
typedef struct {
    int fd;
    pthread_mutex_t lock;
} socket_ctx_t;

/* Read callback for frpc */
static int socket_read(void *ctx, uint8_t *buf, size_t len) {
    socket_ctx_t *sock_ctx = (socket_ctx_t *)ctx;
    
    pthread_mutex_lock(&sock_ctx->lock);
    int ret = recv(sock_ctx->fd, buf, len, 0);
    pthread_mutex_unlock(&sock_ctx->lock);
    
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* No data available */
        }
        perror("recv");
        return -1;
    }
    
    return ret;
}

/* Write callback for frpc */
static int socket_write(void *ctx, const uint8_t *buf, size_t len) {
    socket_ctx_t *sock_ctx = (socket_ctx_t *)ctx;
    
    pthread_mutex_lock(&sock_ctx->lock);
    int ret = send(sock_ctx->fd, buf, len, 0);
    pthread_mutex_unlock(&sock_ctx->lock);
    
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* Buffer full, try again later */
        }
        perror("send");
        return -1;
    }
    
    return ret;
}

/* TCP proxy server structure */
typedef struct {
    int server_fd;
    uint16_t bind_port;
    pthread_t thread;
    volatile int running;
} tcp_proxy_server_t;

/* Client connection handling structure */
typedef struct {
    int client_fd;
    char client_addr[32];
    uint16_t client_port;
    const char *proxy_name;
} client_conn_ctx_t;

/**
 * @brief Thread to handle individual client connections
 */
static void *handle_client_thread(void *arg) {
    client_conn_ctx_t *ctx = (client_conn_ctx_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    printf("[Client] New connection from %s:%d\n", ctx->client_addr, ctx->client_port);
    
    // Notify frpc of new work connection
    if (frpc_visitor_new_connection(ctx->proxy_name, (void*)(intptr_t)ctx->client_fd) < 0) {
        printf("[Client] Failed to create work connection\n");
        close(ctx->client_fd);
        free(ctx);
        return NULL;
    }
    
    printf("[Client] Shell session started, type 'exit' to quit\n");
    printf("embedded_device> ");
    fflush(stdout);
    
    // Simple interactive loop
    while (running) {
        fd_set read_fds;
        struct timeval tv;
        
        FD_ZERO(&read_fds);
        FD_SET(ctx->client_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int max_fd = (ctx->client_fd > STDIN_FILENO) ? ctx->client_fd : STDIN_FILENO;
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ret < 0) {
            perror("select");
            break;
        } else if (ret == 0) {
            continue; // timeout
        }
        
        // Read response from device
        if (FD_ISSET(ctx->client_fd, &read_fds)) {
            bytes = recv(ctx->client_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                if (bytes == 0) {
                    printf("\n[Client] Connection closed by device\n");
                } else {
                    perror("recv from device");
                }
                break;
            }
            
            buffer[bytes] = '\0';
            printf("%s", buffer);
            if (buffer[bytes-1] != '\n') {
                printf("\n");
            }
            printf("embedded_device> ");
            fflush(stdout);
        }
        
        // Read commands from standard input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                // Remove newline character
                size_t len = strlen(buffer);
                if (len > 0 && buffer[len-1] == '\n') {
                    buffer[len-1] = '\0';
                    len--;
                }
                
                // Check exit commands
                if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
                    printf("[Client] Exiting shell session\n");
                    break;
                }
                
                // Send command to device
                if (len > 0) {
                    strcat(buffer, "\n"); // Add newline character
                    if (send(ctx->client_fd, buffer, strlen(buffer), 0) < 0) {
                        perror("send to device");
                        break;
                    }
                }
            }
        }
    }
    
    printf("[Client] Client thread ending\n");
    close(ctx->client_fd);
    free(ctx);
    return NULL;
}

/**
 * @brief TCP proxy server thread
 * Listen on specified port and accept client connections
 */
static void *tcp_proxy_server_thread(void *arg) {
    tcp_proxy_server_t *server = (tcp_proxy_server_t *)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    printf("[Proxy] TCP proxy server listening on port %d\n", server->bind_port);
    printf("[Proxy] Connect to this port to access the embedded device shell\n");
    printf("[Proxy] Example: telnet localhost %d\n", server->bind_port);
    
    while (server->running && running) {
        /* Accept client connection */
        int client_fd = accept(server->server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); /* 10ms */
                continue;
            }
            
            if (server->running) {
                perror("accept");
            }
            break;
        }
        
        /* Create client connection context */
        client_conn_ctx_t *ctx = malloc(sizeof(client_conn_ctx_t));
        if (!ctx) {
            printf("[Proxy] Memory allocation failed\n");
            close(client_fd);
            continue;
        }
        
        ctx->client_fd = client_fd;
        strcpy(ctx->client_addr, inet_ntoa(client_addr.sin_addr));
        ctx->client_port = ntohs(client_addr.sin_port);
        ctx->proxy_name = "embedded_shell_visitor";
        
        /* Create handling thread for each client */
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client_thread, ctx) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(ctx);
            continue;
        }
        
        /* Detach thread to let it clean up itself */
        pthread_detach(client_thread);
    }
    
    return NULL;
}

/**
 * @brief Start TCP proxy server
 */
static int start_tcp_proxy_server(tcp_proxy_server_t *server, uint16_t bind_port) {
    /* Create socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }
    
    /* Set socket options */
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }
    
    /* Set non-blocking */
    int flags = fcntl(server_fd, F_GETFL, 0);
    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
    
    /* Bind to local port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(bind_port);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }
    
    /* Listen for connections */
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }
    
    server->server_fd = server_fd;
    server->bind_port = bind_port;
    server->running = 1;
    
    /* Create server thread */
    if (pthread_create(&server->thread, NULL, tcp_proxy_server_thread, server) != 0) {
        perror("pthread_create");
        close(server_fd);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Stop TCP proxy server
 */
static void stop_tcp_proxy_server(tcp_proxy_server_t *server) {
    server->running = 0;
    
    if (server->server_fd >= 0) {
        close(server->server_fd);
        server->server_fd = -1;
    }
    
    pthread_join(server->thread, NULL);
}

/**
 * @brief Visitor change callback
 */
static void visitor_callback(void *ctx, const char *proxy_name, 
                           const char *server_name, uint16_t bind_port, 
                           void *user_data) {
    static tcp_proxy_server_t proxy_server = {.server_fd = -1};
    
    if (server_name != NULL) {
        printf("[Visitor] Visitor '%s' connected to server '%s', binding to port %d\n", 
               proxy_name, server_name, bind_port);
        
        /* Start TCP proxy server */
        if (start_tcp_proxy_server(&proxy_server, bind_port) < 0) {
            printf("[Visitor] Failed to start TCP proxy server\n");
        }
    } else {
        printf("[Visitor] Visitor '%s' disconnected\n", proxy_name);
        
        /* Stop TCP proxy server */
        stop_tcp_proxy_server(&proxy_server);
    }
}

/**
 * @brief Work connection callback
 */
static int workconn_callback(void *ctx, const char *proxy_name,
                           void *client_conn, void *user_data) {
    printf("[Visitor] New work connection for proxy '%s'\n", proxy_name);
    
    /* Here client_conn is actually the client socket file descriptor */
    int client_fd = (intptr_t)client_conn;
    
    printf("[Visitor] Work connection established with client fd %d\n", client_fd);
    
    return 0;
}

/* Signal handler for clean shutdown */
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <frps_server_ip> <shared_secret_key> [token]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.100 embedded_device_secret_key_123456 my_token\n", argv[0]);
        return 1;
    }
    
    const char *frps_addr = argv[1];
    const char *secret_key = argv[2];
    const char *token = argc > 3 ? argv[3] : NULL;
    
    printf("STCP Visitor Client for Embedded Device Shell\n");
    printf("Connecting to frps at %s:%d\n", frps_addr, DEFAULT_FRPS_PORT);
    printf("Secret key: %s\n", secret_key);
    if (token) {
        printf("Using authentication token\n");
    }
    
    /* Create socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    /* Set non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    /* Connect to frps */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(frps_addr);
    addr.sin_port = htons(DEFAULT_FRPS_PORT);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("connect");
            close(sock);
            return 1;
        }
    }
    
    /* Wait for connection completion */
    fd_set write_fds;
    struct timeval tv;
    
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    int ret = select(sock + 1, NULL, &write_fds, NULL, &tv);
    if (ret <= 0) {
        if (ret == 0) {
            fprintf(stderr, "Connection timeout\n");
        } else {
            perror("select");
        }
        close(sock);
        return 1;
    }
    
    /* Check if connection succeeded */
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        perror("getsockopt");
        close(sock);
        return 1;
    }
    
    if (error != 0) {
        fprintf(stderr, "Connection failed: %s\n", strerror(error));
        close(sock);
        return 1;
    }
    
    printf("Connected to frps server\n");
    
    /* Create socket context */
    socket_ctx_t sock_ctx = {
        .fd = sock,
        .lock = PTHREAD_MUTEX_INITIALIZER
    };
    
    /* Initialize frpc client */
    frpc_config_t config = {
        .server_addr = frps_addr,
        .server_port = DEFAULT_FRPS_PORT,
        .token = token,
        .user = "visitor_client",
        .heartbeat_interval = 30
    };
    
    frpc_handle = frpc_init(socket_read, socket_write, &sock_ctx, &config);
    if (!frpc_handle) {
        fprintf(stderr, "Failed to initialize frpc client\n");
        close(sock);
        return 1;
    }
    
    /* Set visitor callbacks */
    frpc_set_visitor_callbacks(frpc_handle, visitor_callback, workconn_callback, NULL);
    
    /* Add STCP visitor proxy */
    frpc_proxy_config_t proxy = {
        .name = "embedded_shell_visitor",
        .type = FRPC_PROXY_TYPE_STCP,
        .server_name = "embedded_shell",  // Must match embedded device server name
        .sk = secret_key,
        .bind_port = VISITOR_BIND_PORT,
        .is_visitor = 1  // visitor mode
    };
    
    if (frpc_add_proxy(frpc_handle, &proxy) < 0) {
        fprintf(stderr, "Failed to add STCP visitor proxy\n");
        frpc_destroy(frpc_handle);
        close(sock);
        return 1;
    }
    
    /* Set signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Start frpc client */
    if (frpc_start(frpc_handle) < 0) {
        fprintf(stderr, "Failed to start frpc client\n");
        frpc_destroy(frpc_handle);
        close(sock);
        return 1;
    }
    
    printf("STCP Visitor started successfully\n");
    printf("Waiting for embedded device connection...\n");
    printf("Once connected, you can access the device shell on port %d\n", VISITOR_BIND_PORT);
    
    /* Main event loop */
    while (running) {
        /* Process frpc events */
        if (frpc_process(frpc_handle) < 0) {
            printf("frpc_process failed, connection may be lost\n");
            break;
        }
        
        usleep(10000); /* 10ms */
    }
    
    printf("Shutting down...\n");
    
    /* Clean up resources */
    if (frpc_handle) {
        frpc_stop(frpc_handle);
        frpc_destroy(frpc_handle);
    }
    
    close(sock);
    
    printf("STCP Visitor client stopped\n");
    return 0;
}

/* =============================================================================
 * Usage Instructions
 * ============================================================================= 
 * 
 * 1. Compile this program:
 *    gcc -o stcp_visitor_client stcp_visitor_client_example.c -ltiny-frpc -ltiny_yamux -lpthread
 * 
 * 2. Ensure there is an frps server running at the specified address
 * 
 * 3. Ensure the embedded device is running STCP server with the same secret key
 * 
 * 4. Run this program:
 *    ./stcp_visitor_client 192.168.1.100 embedded_device_secret_key_123456 my_token
 * 
 * 5. The program will listen for connections on local port 18022
 * 
 * 6. Use telnet or other tools to connect to the device:
 *    telnet localhost 18022
 * 
 * 7. Now you can send shell commands to the embedded device!
 * 
 * Workflow:
 * 1. STCP Visitor connects to frps server
 * 2. Embedded device STCP server also connects to the same frps server
 * 3. frps server coordinates both to establish STCP connection
 * 4. Visitor creates TCP listener locally
 * 5. Client connects to Visitor's local port
 * 6. Data is forwarded through STCP tunnel to embedded device
 * 7. Embedded device processes commands and returns responses
 * 
 * ============================================================================= */ 