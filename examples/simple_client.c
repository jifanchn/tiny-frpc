/**
 * @file simple_client.c
 * @brief Simple example of using tiny-frpc to establish a TCP proxy
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

#include "frpc.h"

#define BUFFER_SIZE 4096
#define DEFAULT_FRPS_PORT 7000

static int running = 1;

/* Socket implementation for I/O callbacks */
typedef struct {
    int fd;
} socket_ctx_t;

/* Read callback for frpc */
static int socket_read(void *ctx, uint8_t *buf, size_t len) {
    socket_ctx_t *sock_ctx = (socket_ctx_t *)ctx;
    
    int ret = recv(sock_ctx->fd, buf, len, 0);
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
    
    int ret = send(sock_ctx->fd, buf, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* Buffer full, try again later */
        }
        perror("send");
        return -1;
    }
    
    return ret;
}

/* Signal handler for clean shutdown */
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <frps_server_ip> <local_port_to_expose> [remote_port] [token]\n", argv[0]);
        return 1;
    }
    
    const char *frps_addr = argv[1];
    int local_port = atoi(argv[2]);
    int remote_port = argc > 3 ? atoi(argv[3]) : local_port;
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
        .fd = sock
    };
    
    /* Initialize frpc client */
    frpc_config_t config = {
        .server_addr = frps_addr,
        .server_port = DEFAULT_FRPS_PORT,
        .token = token,
        .user = "example_user",
        .heartbeat_interval = 30
    };
    
    void *frpc = frpc_init(socket_read, socket_write, &sock_ctx, &config);
    if (!frpc) {
        fprintf(stderr, "Failed to initialize frpc client: %s\n", frpc_get_error());
        close(sock);
        return 1;
    }
    
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
    
    /* Set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
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
        
        ret = select(sock + 1, &read_fds, NULL, NULL, &tv);
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
    }
    
    printf("Shutting down...\n");
    
    /* Clean up */
    frpc_stop(frpc);
    frpc_destroy(frpc);
    close(sock);
    
    return 0;
}
