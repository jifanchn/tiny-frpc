#include "common.h"

#include "frpc.h"
#include "frpc-stcp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wrapper.h"

typedef struct demo_stcp_ctx_s {
    int work_fd;
    frpc_stcp_proxy_t* proxy;
    int verbose;
} demo_stcp_ctx_t;

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  --frps-addr ADDR        FRPS mock address (default: 127.0.0.1)\n"
            "  --frps-port PORT        FRPS mock port (default: 7001)\n"
            "  --token TOKEN           Login token (default: test_token)\n"
            "  --listen-addr ADDR      Data-plane listen address (default: 127.0.0.1)\n"
            "  --listen-port PORT      Data-plane listen port (default: 9001)\n"
            "  --accept-timeout-sec N  Exit if no visitor connects within N seconds (default: 10, 0 = wait forever)\n"
            "  --proxy-name NAME       Proxy name (default: demo_stcp)\n"
            "  --sk SECRET             Secret key (default: demo_secret)\n"
            "  --local-addr ADDR       Local service addr (metadata) (default: 127.0.0.1)\n"
            "  --local-port PORT       Local service port (metadata) (default: 8080)\n"
            "  -v                      Verbose prints\n",
            argv0);
}

static int accept_with_timeout(int listen_fd, int timeout_sec) {
    if (timeout_sec <= 0) {
        return wrapped_accept(listen_fd, NULL, NULL);
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int sel = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        return -1;
    }
    if (sel == 0) {
    wrapped_set_errno(WRAPPED_ETIMEDOUT);
        return -1;
    }
    return wrapped_accept(listen_fd, NULL, NULL);
}

static int on_write_cb(void* user_ctx, uint8_t* data, size_t len) {
    demo_stcp_ctx_t* ctx = (demo_stcp_ctx_t*)user_ctx;
    if (!ctx || ctx->work_fd < 0) {
        return -1;
    }
    if (demo_write_all(ctx->work_fd, data, len) != 0) {
        return -1;
    }
    return (int)len;
}

static int on_data_cb(void* user_ctx, uint8_t* data, size_t len) {
    demo_stcp_ctx_t* ctx = (demo_stcp_ctx_t*)user_ctx;
    if (!ctx || !ctx->proxy) {
        return -1;
    }

    if (ctx->verbose) {
        fprintf(stdout, "server: received %zu bytes, echoing back\n", len);
        fflush(stdout);
    }

    int ret = frpc_stcp_send(ctx->proxy, data, len);
    if (ret < 0) {
        if (ctx->verbose) {
            fprintf(stderr, "server: frpc_stcp_send failed: %d\n", ret);
        }
        return ret;
    }
    return (int)len;
}

static void on_conn_cb(void* user_ctx, int connected, int error_code) {
    demo_stcp_ctx_t* ctx = (demo_stcp_ctx_t*)user_ctx;
    (void)ctx;
    if (connected) {
        fprintf(stdout, "server: stcp connected\n");
    } else {
        fprintf(stdout, "server: stcp disconnected (err=%d)\n", error_code);
    }
    fflush(stdout);
}

static int parse_u16(const char* s, uint16_t* out) {
    if (!s || !out) return -1;
    char* end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0') return -1;
    if (v < 0 || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

int main(int argc, char** argv) {
    const char* frps_addr = "127.0.0.1";
    const char* frps_port_s = "7001";
    const char* token = "test_token";

    const char* listen_addr = "127.0.0.1";
    const char* listen_port_s = "9001";

    const char* proxy_name = "demo_stcp";
    const char* sk = "demo_secret";
    const char* local_addr = "127.0.0.1";
    const char* local_port_s = "8080";

    int verbose = 0;
    int accept_timeout_sec = 10;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--frps-addr") == 0 && i + 1 < argc) {
            frps_addr = argv[++i];
        } else if (strcmp(argv[i], "--frps-port") == 0 && i + 1 < argc) {
            frps_port_s = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--listen-addr") == 0 && i + 1 < argc) {
            listen_addr = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port_s = argv[++i];
        } else if (strcmp(argv[i], "--accept-timeout-sec") == 0 && i + 1 < argc) {
            accept_timeout_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--proxy-name") == 0 && i + 1 < argc) {
            proxy_name = argv[++i];
        } else if (strcmp(argv[i], "--sk") == 0 && i + 1 < argc) {
            sk = argv[++i];
        } else if (strcmp(argv[i], "--local-addr") == 0 && i + 1 < argc) {
            local_addr = argv[++i];
        } else if (strcmp(argv[i], "--local-port") == 0 && i + 1 < argc) {
            local_port_s = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    uint16_t frps_port = 0;
    uint16_t local_port = 0;
    if (parse_u16(frps_port_s, &frps_port) != 0 || parse_u16(local_port_s, &local_port) != 0) {
        fprintf(stderr, "server: invalid port\n");
        return 2;
    }

    int listen_fd = demo_net_listen_tcp(listen_addr, listen_port_s, 16);
    if (listen_fd < 0) {
        fprintf(stderr, "server: failed to listen on %s:%s (errno=%d)\n", listen_addr, listen_port_s, wrapped_get_errno());
        return 1;
    }
    fprintf(stdout, "server: listening data-plane on %s:%s, waiting for visitor...\n", listen_addr, listen_port_s);
    fflush(stdout);

    int work_fd = accept_with_timeout(listen_fd, accept_timeout_sec);
    if (work_fd < 0) {
        fprintf(stderr, "server: accept failed (errno=%d)\n", wrapped_get_errno());
        (void)wrapped_close(listen_fd);
        return 1;
    }
    (void)wrapped_close(listen_fd);

    demo_stcp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.work_fd = work_fd;
    ctx.proxy = NULL;
    ctx.verbose = verbose;

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = frps_addr;
    cfg.server_port = frps_port;
    cfg.token = token;
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    if (!client) {
        fprintf(stderr, "server: frpc_client_new failed\n");
        (void)wrapped_close(work_fd);
        return 1;
    }

    frpc_stcp_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = FRPC_STCP_ROLE_SERVER;
    scfg.proxy_name = proxy_name;
    scfg.sk = sk;
    scfg.local_addr = local_addr;
    scfg.local_port = local_port;
    scfg.on_data = on_data_cb;
    scfg.on_write = on_write_cb;
    scfg.on_connection = on_conn_cb;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &scfg, &ctx);
    if (!proxy) {
        fprintf(stderr, "server: frpc_stcp_proxy_new failed\n");
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }
    ctx.proxy = proxy;

    if (frpc_stcp_proxy_start(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "server: frpc_stcp_proxy_start failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }
    if (frpc_stcp_server_register(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "server: frpc_stcp_server_register failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }

    // Data-plane receive loop: read bytes -> frpc_stcp_receive -> yamux_session_receive.
    uint8_t buf[65536];
    size_t buf_len = 0;

    fprintf(stdout, "server: data-plane connected, entering receive loop\n");
    fflush(stdout);

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(work_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000; // 200ms

        int sel = select(work_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) {
                continue;
            }
            fprintf(stderr, "server: select failed (errno=%d)\n", wrapped_get_errno());
            break;
        }

        if (sel > 0 && FD_ISSET(work_fd, &rfds)) {
            if (buf_len >= sizeof(buf)) {
                fprintf(stderr, "server: receive buffer overflow\n");
                break;
            }
            ssize_t n = wrapped_read(work_fd, buf + buf_len, sizeof(buf) - buf_len);
            if (n < 0) {
                if (wrapped_get_errno() == WRAPPED_EINTR) {
                    continue;
                }
                fprintf(stderr, "server: read failed (errno=%d)\n", wrapped_get_errno());
                break;
            }
            if (n == 0) {
                fprintf(stdout, "server: peer closed\n");
                fflush(stdout);
                break;
            }
            buf_len += (size_t)n;

            while (buf_len > 0) {
                int consumed = frpc_stcp_receive(proxy, buf, buf_len);
                if (consumed < 0) {
                    fprintf(stderr, "server: frpc_stcp_receive error: %d\n", consumed);
                    buf_len = 0;
                    break;
                }
                if (consumed == 0) {
                    break; // need more bytes
                }
                if ((size_t)consumed > buf_len) {
                    fprintf(stderr, "server: invalid consumed=%d > buf_len=%zu\n", consumed, buf_len);
                    buf_len = 0;
                    break;
                }
                memmove(buf, buf + consumed, buf_len - (size_t)consumed);
                buf_len -= (size_t)consumed;
            }
        }

        (void)frpc_stcp_tick(proxy);
    }

    (void)wrapped_close(work_fd);
    frpc_stcp_proxy_free(proxy);
    frpc_client_free(client);
    return 0;
}


