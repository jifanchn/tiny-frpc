#include "common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wrapper.h"

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [--listen-addr ADDR] [--listen-port PORT] [--run-id RUN_ID]\n"
            "\n"
            "This is a tiny FRPS mock for demo purposes.\n"
            "It only handles FRP Login (type 'o') and replies with LoginResp (type '1').\n",
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

static int handle_one_conn(int conn_fd, const char* run_id) {
    uint8_t type = 0;
    uint8_t len_be[8];
    if (demo_read_exact(conn_fd, &type, 1) != 0) {
        return -1;
    }
    if (demo_read_exact(conn_fd, len_be, sizeof(len_be)) != 0) {
        return -1;
    }

    int64_t msg_len = 0;
    for (int i = 0; i < 8; i++) {
        msg_len = (msg_len << 8) | (int64_t)len_be[i];
    }
    if (msg_len < 0 || msg_len > 1024 * 1024) {
        return -1;
    }

    if (msg_len > 0) {
        char* payload = (char*)malloc((size_t)msg_len);
        if (!payload) {
            return -1;
        }
        (void)demo_read_exact(conn_fd, payload, (size_t)msg_len);
        free(payload);
    }

    // Reply LoginResp: must contain run_id, and optional error field.
    char resp[256];
    int n = snprintf(resp, sizeof(resp),
                     "{\"version\":\"0.62.1\",\"run_id\":\"%s\",\"error\":\"\"}",
                     run_id ? run_id : "demo_run");
    if (n <= 0 || (size_t)n >= sizeof(resp)) {
        return -1;
    }

    uint8_t resp_type = (uint8_t)'1';
    uint8_t resp_len_be[8];
    write_be64(resp_len_be, (int64_t)strlen(resp));

    if (demo_write_all(conn_fd, &resp_type, 1) != 0) {
        return -1;
    }
    if (demo_write_all(conn_fd, resp_len_be, sizeof(resp_len_be)) != 0) {
        return -1;
    }
    if (demo_write_all(conn_fd, resp, strlen(resp)) != 0) {
        return -1;
    }

    (void)type; // currently unused
    return 0;
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

        (void)handle_one_conn(conn, run_id);
        (void)wrapped_close(conn);
    }

    (void)wrapped_close(listen_fd);
    return 0;
}


