/**
 * @file advanced_client.c
 * @brief Advanced example of using tiny-frpc with custom handlers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include "frpc.h"

#define BUFFER_SIZE 4096
#define DEFAULT_FRPS_PORT 7000

static int running = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* Socket implementation for I/O callbacks */
typedef struct {
    int fd;
    pthread_mutex_t *lock;
} socket_ctx_t;

/* Read callback for frpc */
static int socket_read(void *ctx, uint8_t *buf, size_t len) {
    socket_ctx_t *sock_ctx = (socket_ctx_t *)ctx;
    
    pthread_mutex_lock(sock_ctx->lock);
    int ret = recv(sock_ctx->fd, buf, len, 0);
    pthread_mutex_unlock(sock_ctx->lock);
    
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
    
    pthread_mutex_lock(sock_ctx->lock);
    int ret = send(sock_ctx->fd, buf, len, 0);
    pthread_mutex_unlock(sock_ctx->lock);
    
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* Buffer full, try again later */
        }
        perror("send");
        return -1;
    }
    
    return ret;
}

/* Local TCP server for handling incoming connections */
typedef struct {
    int server_fd;
    int local_port;
    const char *proxy_name;
    void *frpc;
} local_server_ctx_t;

/* Local TCP server thread */
static void *local_server_thread(void *arg) {
    local_server_ctx_t *ctx = (local_server_ctx_t *)arg;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    printf("Local server for proxy '%s' listening on port %d\n", ctx->proxy_name, ctx->local_port);
    
    while (running) {
        /* Accept client connection */
        int client_fd = accept(ctx->server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No connection available */
                usleep(10000); /* 10ms */
                continue;
            }
            
            perror("accept");
            break;
        }
        
        printf("New client connection for proxy '%s' from %s:%d\n",
               ctx->proxy_name, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        /* Handle client connection */
        /* TODO: Create work connection to frps and relay data */
        /* For this example, just close the connection */
        close(client_fd);
    }
    
    return NULL;
}

/* Start a local TCP server for handling incoming connections */
static int start_local_server(local_server_ctx_t *ctx) {
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
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 */
    addr.sin_port = htons(ctx->local_port);
    
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
    
    ctx->server_fd = server_fd;
    
    /* Create thread for local server */
    pthread_t thread;
    if (pthread_create(&thread, NULL, local_server_thread, ctx) != 0) {
        perror("pthread_create");
        close(server_fd);
        return -1;
    }
    
    /* Detach thread */
    pthread_detach(thread);
    
    return 0;
}

/* Signal handler for clean shutdown */
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <frps_server_ip> <local_port_to_expose> <remote_port> [token]\n", argv[0]);
        return 1;
    }
    
    const char *frps_addr = argv[1];
    int local_port = atoi(argv[2]);
    int remote_port = atoi(argv[3]);
    const char *token = argc > 4 ? argv[4] : NULL;
    
    if (local_port <= 0 || local_port > 65535) {
        fprintf(stderr, "Invalid local port: %d\n", local_port);
        return 1;
    }
    
    if (remote_port <= 0 || remote_port > 65535) {
        fprintf(stderr, "Invalid remote port: %d\n", remote_port);
        return 1;
    }
    
    printf("Connecting to frps at %s:%d\n", frps_addr, DEFAULT_FRPS_PORT);
    printf("Exposing local port %d as remote port %d\n", local_port, remote_port);
    if (token) {
        printf("Using authentication token\n");
    }
    
    /* Set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
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
    
    /* Wait for connection to complete */
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
        .lock = &lock
    };
    
    /* Initialize frpc client */
    frpc_config_t config = {
        .server_addr = frps_addr,
        .server_port = DEFAULT_FRPS_PORT,
        .token = token,
        .user = "advanced_example",
        .heartbeat_interval = 30
    };
    
    void *frpc = frpc_init(socket_read, socket_write, &sock_ctx, &config);
    if (!frpc) {
        fprintf(stderr, "Failed to initialize frpc client: %s\n", frpc_get_error());
        close(sock);
        return 1;
    }
    
    /* Enable debug output */
    frpc_set_debug(frpc, 1);
    
    /* Add TCP proxy */
    frpc_proxy_config_t proxy = {
        .name = "example_proxy",
        .type = FRPC_PROXY_TYPE_TCP,
        .local_ip = "127.0.0.1",
        .local_port = local_port,
        .remote_port = remote_port
    };
    
    if (frpc_add_proxy(frpc, &proxy) < 0) {
        fprintf(stderr, "Failed to add proxy: %s\n", frpc_get_error());
        frpc_destroy(frpc);
        close(sock);
        return 1;
    }
    
    /* Start local server for handling incoming connections */
    local_server_ctx_t server_ctx = {
        .local_port = local_port,
        .proxy_name = proxy.name,
        .frpc = frpc
    };
    
    if (start_local_server(&server_ctx) < 0) {
        fprintf(stderr, "Failed to start local server\n");
        frpc_destroy(frpc);
        close(sock);
        return 1;
    }
    
    /* Start frpc client */
    if (frpc_start(frpc) < 0) {
        fprintf(stderr, "Failed to start frpc client: %s\n", frpc_get_error());
        frpc_destroy(frpc);
        close(sock);
        return 1;
    }
    
    printf("frpc client started. Press Ctrl+C to stop.\n");
    
    /* Main loop */
    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100ms */
        
        pthread_mutex_lock(&lock);
        ret = select(sock + 1, &read_fds, NULL, NULL, &tv);
        pthread_mutex_unlock(&lock);
        
        if (ret > 0) {
            if (FD_ISSET(sock, &read_fds)) {
                /* Data available, let frpc process it */
                if (frpc_process(frpc) < 0) {
                    fprintf(stderr, "frpc process failed: %s\n", frpc_get_error());
                    break;
                }
            }
        } else if (ret < 0 && errno != EINTR) {
            perror("select");
            break;
        }
        
        /* Regular processing */
        if (frpc_process(frpc) < 0) {
            fprintf(stderr, "frpc process failed: %s\n", frpc_get_error());
            break;
        }
        
        /* Check connection status */
        if (!frpc_is_connected(frpc)) {
            fprintf(stderr, "Connection to frps lost\n");
            break;
        }
        
        usleep(10000); /* 10ms */
    }
    
    printf("Shutting down...\n");
    
    /* Clean up */
    frpc_stop(frpc);
    frpc_destroy(frpc);
    close(sock);
    if (server_ctx.server_fd > 0) {
        close(server_ctx.server_fd);
    }
    
    return 0;
}
