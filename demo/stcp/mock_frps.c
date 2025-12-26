#include "common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "wrapper.h"

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [--listen-addr ADDR] [--listen-port PORT] [--run-id RUN_ID]\n"
            "\n"
            "This is a tiny FRPS mock for demo/testing purposes.\n"
            "It handles FRP Login (type 'o') -> LoginResp (type '1')\n"
            "and NewProxy (type 'p') -> NewProxyResp (type '2').\n",
            argv0);
}

static void write_be64(uint8_t out[8], int64_t v) {
    uint64_t u = (uint64_t)v;
    out[0] = (uint8_t)((u >> 56) & 0xFF);
    out[1] = (uint8_t)((u >> 48) & 0xFF);
    out[2] = (uint8_t)((u >> 40) & 0xFF);
    out[3] = (uint8_t)((u >> 32) & 0xFF);
    out[4] = (uint8_t)((u >> 24) & 0xFF);
    out[5] = (uint8_t)((u >> 16) & 0xFF);
    out[6] = (uint8_t)((u >> 8) & 0xFF);
    out[7] = (uint8_t)(u & 0xFF);
}

static int send_message(int fd, uint8_t type, const char* json, size_t json_len) {
    uint8_t len_be[8];
    write_be64(len_be, (int64_t)json_len);
    
    if (demo_write_all(fd, &type, 1) != 0) return -1;
    if (demo_write_all(fd, len_be, sizeof(len_be)) != 0) return -1;
    if (json_len > 0 && json) {
        if (demo_write_all(fd, json, json_len) != 0) return -1;
    }
    return 0;
}

static int read_message(int fd, uint8_t* type_out, char** json_out, size_t* json_len_out) {
    uint8_t type = 0;
    uint8_t len_be[8];
    
    if (demo_read_exact(fd, &type, 1) != 0) {
        return -1;
    }
    if (demo_read_exact(fd, len_be, sizeof(len_be)) != 0) {
        return -1;
    }

    int64_t msg_len = 0;
    for (int i = 0; i < 8; i++) {
        msg_len = (msg_len << 8) | (int64_t)len_be[i];
    }
    if (msg_len < 0 || msg_len > 1024 * 1024) {
        return -1;
    }

    char* payload = NULL;
    if (msg_len > 0) {
        payload = (char*)malloc((size_t)msg_len + 1);
        if (!payload) {
            return -1;
        }
        if (demo_read_exact(fd, payload, (size_t)msg_len) != 0) {
            free(payload);
            return -1;
        }
        payload[msg_len] = '\0';
    }

    *type_out = type;
    *json_out = payload;
    *json_len_out = (size_t)msg_len;
    return 0;
}

static void handle_connection(int conn_fd, const char* run_id) {
    // Read and handle messages in a loop
    while (1) {
        uint8_t type = 0;
        char* json = NULL;
        size_t json_len = 0;
        
        if (read_message(conn_fd, &type, &json, &json_len) != 0) {
            // Connection closed or error
            break;
        }
        
        char resp[512];
        int n = 0;
        
        switch (type) {
            case 'o': // Login
                n = snprintf(resp, sizeof(resp),
                             "{\"version\":\"0.62.1\",\"run_id\":\"%s\",\"error\":\"\"}",
                             run_id ? run_id : "demo_run");
                if (n > 0 && (size_t)n < sizeof(resp)) {
                    send_message(conn_fd, '1', resp, (size_t)n); // LoginResp
                }
                fprintf(stdout, "mock_frps: handled Login\n");
                fflush(stdout);
                break;
                
            case 'p': // NewProxy
                // Reply with success NewProxyResp (type '2')
                n = snprintf(resp, sizeof(resp),
                             "{\"error\":\"\"}");
                if (n > 0 && (size_t)n < sizeof(resp)) {
                    send_message(conn_fd, '2', resp, (size_t)n); // NewProxyResp
                }
                fprintf(stdout, "mock_frps: handled NewProxy\n");
                fflush(stdout);
                break;
                
            case 'h': // Ping (heartbeat)
                // Reply with Pong (TypePong = '4', NOT 'i')
                // See third-party/frp/pkg/msg/msg.go: TypePong = '4'
                send_message(conn_fd, '4', "{}", 2); // Pong
                break;
                
            case 'v': // NewVisitorConn
                // Reply with success NewVisitorConnResp (type '3')
                n = snprintf(resp, sizeof(resp),
                             "{\"error\":\"\"}");
                if (n > 0 && (size_t)n < sizeof(resp)) {
                    send_message(conn_fd, '3', resp, (size_t)n); // NewVisitorConnResp
                }
                fprintf(stdout, "mock_frps: handled NewVisitorConn\n");
                fflush(stdout);
                break;
                
            default:
                fprintf(stderr, "mock_frps: unknown message type '%c' (0x%02x)\n", type, type);
                break;
        }
        
        if (json) {
            free(json);
        }
    }
}

static void sigchld_handler(int sig) {
    (void)sig;
    // Reap zombie processes
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

int main(int argc, char** argv) {
    const char* listen_addr = "127.0.0.1";
    const char* listen_port = "7001";
    const char* run_id = "demo_run";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen-addr") == 0 && i + 1 < argc) {
            listen_addr = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = argv[++i];
        } else if (strcmp(argv[i], "--run-id") == 0 && i + 1 < argc) {
            run_id = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    // Setup SIGCHLD handler to reap zombie processes
    signal(SIGCHLD, sigchld_handler);

    int listen_fd = demo_net_listen_tcp(listen_addr, listen_port, 16);
    if (listen_fd < 0) {
        fprintf(stderr, "mock_frps: failed to listen on %s:%s (errno=%d)\n",
                listen_addr, listen_port, errno);
        return 1;
    }

    fprintf(stdout, "mock_frps: listening on %s:%s, run_id=%s\n",
            listen_addr, listen_port, run_id);
    fflush(stdout);

    while (1) {
        int conn = wrapped_accept(listen_fd, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "mock_frps: accept failed (errno=%d)\n", errno);
            break;
        }

        // Fork to handle connection concurrently
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "mock_frps: fork failed (errno=%d)\n", errno);
            (void)wrapped_close(conn);
            continue;
        }
        
        if (pid == 0) {
            // Child process: handle connection
            (void)wrapped_close(listen_fd);
            handle_connection(conn, run_id);
            (void)wrapped_close(conn);
            _exit(0);
        }
        
        // Parent process: close connection fd and continue accepting
        (void)wrapped_close(conn);
    }

    (void)wrapped_close(listen_fd);
    return 0;
}
