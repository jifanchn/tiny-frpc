#include "common.h"

#include "frpc.h"
#include "frpc-stcp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wrapper.h"

typedef enum {
    VIS_MODE_ONCE = 0,
    VIS_MODE_INTERACTIVE = 1,
    VIS_MODE_LOCAL_FORWARD = 2,
} vis_mode_t;

typedef struct demo_stcp_ctx_s {
    int work_fd;
    frpc_stcp_proxy_t* proxy;
    int verbose;

    // once mode response
    int got_response;
    uint8_t resp_buf[4096];
    size_t resp_len;

    // local-forward mode
    int local_listen_fd;
    int local_client_fd;
} demo_stcp_ctx_t;

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  --frps-addr ADDR        FRPS mock address (default: 127.0.0.1)\n"
            "  --frps-port PORT        FRPS mock port (default: 7001)\n"
            "  --token TOKEN           Login token (default: test_token)\n"
            "  --connect-addr ADDR     Data-plane server address (default: 127.0.0.1)\n"
            "  --connect-port PORT     Data-plane server port (default: 9001)\n"
            "  --proxy-name NAME       Visitor proxy name (default: demo_stcp_visitor)\n"
            "  --server-name NAME      Remote server name (default: demo_stcp)\n"
            "  --sk SECRET             Secret key (default: demo_secret)\n"
            "  --mode once|interactive|local-forward  (default: once)\n"
            "  --message MSG           Message for once mode (default: hello)\n"
            "  --bind-addr ADDR        Local-forward bind addr (default: 127.0.0.1)\n"
            "  --bind-port PORT        Local-forward bind port (default: 6000)\n"
            "  -v                      Verbose prints\n",
            argv0);
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

static vis_mode_t parse_mode(const char* s) {
    if (!s) return VIS_MODE_ONCE;
    if (strcmp(s, "once") == 0) return VIS_MODE_ONCE;
    if (strcmp(s, "interactive") == 0) return VIS_MODE_INTERACTIVE;
    if (strcmp(s, "local-forward") == 0) return VIS_MODE_LOCAL_FORWARD;
    return VIS_MODE_ONCE;
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
    if (!ctx) return -1;

    if (ctx->local_client_fd >= 0) {
        (void)demo_write_all(ctx->local_client_fd, data, len);
        return (int)len;
    }

    if (!ctx->got_response) {
        size_t n = len;
        if (n > sizeof(ctx->resp_buf)) {
            n = sizeof(ctx->resp_buf);
        }
        memcpy(ctx->resp_buf, data, n);
        ctx->resp_len = n;
        ctx->got_response = 1;
    }

    fwrite(data, 1, len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    return (int)len;
}

static void on_conn_cb(void* user_ctx, int connected, int error_code) {
    demo_stcp_ctx_t* ctx = (demo_stcp_ctx_t*)user_ctx;
    (void)ctx;
    if (connected) {
        fprintf(stdout, "visitor: stcp connected\n");
    } else {
        fprintf(stdout, "visitor: stcp disconnected (err=%d)\n", error_code);
    }
    fflush(stdout);
}

// Return values:
//   1: got response (ctx->got_response == 1)
//   0: timeout or peer closed
//  -1: fatal error
static int pump_network(demo_stcp_ctx_t* ctx, int max_wait_sec) {
    if (!ctx || ctx->work_fd < 0 || !ctx->proxy) return -1;

    uint8_t buf[65536];
    size_t buf_len = 0;

    time_t start = time(NULL);

    while (1) {
        if (ctx->got_response) {
            return 1;
        }
        if (max_wait_sec > 0) {
            time_t now = time(NULL);
            if (now != (time_t)-1 && (now - start) >= max_wait_sec) {
                return 0;
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->work_fd, &rfds);

        int maxfd = ctx->work_fd;

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;

        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) continue;
            return -1;
        }
        if (sel == 0) {
            (void)frpc_stcp_tick(ctx->proxy);
            continue;
        }

        if (FD_ISSET(ctx->work_fd, &rfds)) {
            if (buf_len >= sizeof(buf)) return -1;
            ssize_t n = wrapped_read(ctx->work_fd, buf + buf_len, sizeof(buf) - buf_len);
            if (n < 0) {
                if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                return -1;
            }
            if (n == 0) {
                return 0; // peer closed
            }
            buf_len += (size_t)n;

            while (buf_len > 0) {
                int consumed = frpc_stcp_receive(ctx->proxy, buf, buf_len);
                if (consumed < 0) {
                    return -1;
                }
                if (consumed == 0) {
                    break;
                }
                if ((size_t)consumed > buf_len) {
                    return -1;
                }
                memmove(buf, buf + consumed, buf_len - (size_t)consumed);
                buf_len -= (size_t)consumed;
            }
        }

        (void)frpc_stcp_tick(ctx->proxy);
    }
}

int main(int argc, char** argv) {
    const char* frps_addr = "127.0.0.1";
    const char* frps_port_s = "7001";
    const char* token = "test_token";

    const char* connect_addr = "127.0.0.1";
    const char* connect_port_s = "9001";

    const char* proxy_name = "demo_stcp_visitor";
    const char* server_name = "demo_stcp";
    const char* sk = "demo_secret";

    const char* mode_s = "once";
    const char* message = "hello";

    const char* bind_addr = "127.0.0.1";
    const char* bind_port_s = "6000";

    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--frps-addr") == 0 && i + 1 < argc) {
            frps_addr = argv[++i];
        } else if (strcmp(argv[i], "--frps-port") == 0 && i + 1 < argc) {
            frps_port_s = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--connect-addr") == 0 && i + 1 < argc) {
            connect_addr = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            connect_port_s = argv[++i];
        } else if (strcmp(argv[i], "--proxy-name") == 0 && i + 1 < argc) {
            proxy_name = argv[++i];
        } else if (strcmp(argv[i], "--server-name") == 0 && i + 1 < argc) {
            server_name = argv[++i];
        } else if (strcmp(argv[i], "--sk") == 0 && i + 1 < argc) {
            sk = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_s = argv[++i];
        } else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
            message = argv[++i];
        } else if (strcmp(argv[i], "--bind-addr") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (strcmp(argv[i], "--bind-port") == 0 && i + 1 < argc) {
            bind_port_s = argv[++i];
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
    uint16_t bind_port = 0;
    if (parse_u16(frps_port_s, &frps_port) != 0 || parse_u16(bind_port_s, &bind_port) != 0) {
        fprintf(stderr, "visitor: invalid port\n");
        return 2;
    }

    vis_mode_t mode = parse_mode(mode_s);

    int work_fd = demo_net_connect_tcp(connect_addr, connect_port_s);
    if (work_fd < 0) {
        fprintf(stderr, "visitor: failed to connect to %s:%s (errno=%d)\n", connect_addr, connect_port_s, wrapped_get_errno());
        return 1;
    }

    demo_stcp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.work_fd = work_fd;
    ctx.proxy = NULL;
    ctx.verbose = verbose;
    ctx.got_response = 0;
    ctx.resp_len = 0;
    ctx.local_listen_fd = -1;
    ctx.local_client_fd = -1;

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = frps_addr;
    cfg.server_port = frps_port;
    cfg.token = token;
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    if (!client) {
        fprintf(stderr, "visitor: frpc_client_new failed\n");
        (void)wrapped_close(work_fd);
        return 1;
    }

    frpc_stcp_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.role = FRPC_STCP_ROLE_VISITOR;
    vcfg.proxy_name = proxy_name;
    vcfg.sk = sk;
    vcfg.server_name = server_name;
    vcfg.bind_addr = bind_addr;
    vcfg.bind_port = bind_port;
    vcfg.on_data = on_data_cb;
    vcfg.on_write = on_write_cb;
    vcfg.on_connection = on_conn_cb;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &vcfg, &ctx);
    if (!proxy) {
        fprintf(stderr, "visitor: frpc_stcp_proxy_new failed\n");
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }
    ctx.proxy = proxy;

    if (frpc_stcp_proxy_start(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "visitor: frpc_stcp_proxy_start failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }
    if (frpc_stcp_visitor_connect(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "visitor: frpc_stcp_visitor_connect failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        (void)wrapped_close(work_fd);
        return 1;
    }

    if (mode == VIS_MODE_ONCE) {
        int sret = frpc_stcp_send(proxy, (const uint8_t*)message, strlen(message));
        if (sret < 0) {
            fprintf(stderr, "visitor: frpc_stcp_send failed: %d\n", sret);
            (void)wrapped_close(work_fd);
            frpc_stcp_proxy_free(proxy);
            frpc_client_free(client);
            return 1;
        }

        int r = pump_network(&ctx, 5);
        if (r != 1) {
            fprintf(stderr, "visitor: timeout or error waiting for response\n");
            (void)wrapped_close(work_fd);
            frpc_stcp_proxy_free(proxy);
            frpc_client_free(client);
            return 1;
        }
    } else if (mode == VIS_MODE_INTERACTIVE) {
        fprintf(stdout, "visitor: interactive mode; type lines and press Enter\n");
        fflush(stdout);

        uint8_t net_buf[65536];
        size_t net_len = 0;

        char line[4096];
        while (1) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(work_fd, &rfds);
            FD_SET(STDIN_FILENO, &rfds);

            int maxfd = work_fd > STDIN_FILENO ? work_fd : STDIN_FILENO;

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200 * 1000;

            int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0) {
                if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                break;
            }

            if (sel > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
                if (!fgets(line, sizeof(line), stdin)) {
                    break;
                }
                size_t l = strlen(line);
                while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) {
                    line[l - 1] = '\0';
                    l--;
                }
                if (l > 0) {
                    (void)frpc_stcp_send(proxy, (const uint8_t*)line, l);
                }
            }

            if (sel > 0 && FD_ISSET(work_fd, &rfds)) {
                if (net_len >= sizeof(net_buf)) break;
                ssize_t n = wrapped_read(work_fd, net_buf + net_len, sizeof(net_buf) - net_len);
                if (n < 0) {
                    if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                    break;
                }
                if (n == 0) {
                    break;
                }
                net_len += (size_t)n;

                while (net_len > 0) {
                    int consumed = frpc_stcp_receive(proxy, net_buf, net_len);
                    if (consumed < 0) {
                        net_len = 0;
                        break;
                    }
                    if (consumed == 0) break;
                    if ((size_t)consumed > net_len) {
                        net_len = 0;
                        break;
                    }
                    memmove(net_buf, net_buf + consumed, net_len - (size_t)consumed);
                    net_len -= (size_t)consumed;
                }
            }

            (void)frpc_stcp_tick(proxy);
        }
    } else if (mode == VIS_MODE_LOCAL_FORWARD) {
        ctx.local_listen_fd = demo_net_listen_tcp(bind_addr, bind_port_s, 16);
        if (ctx.local_listen_fd < 0) {
            fprintf(stderr, "visitor: failed to listen on %s:%s (errno=%d)\n", bind_addr, bind_port_s, wrapped_get_errno());
        } else {
            fprintf(stdout, "visitor: local-forward listening on %s:%s\n", bind_addr, bind_port_s);
            fflush(stdout);
        }

        // Accept one local client.
        if (ctx.local_listen_fd >= 0) {
            ctx.local_client_fd = wrapped_accept(ctx.local_listen_fd, NULL, NULL);
            if (ctx.local_client_fd < 0) {
                fprintf(stderr, "visitor: accept local client failed (errno=%d)\n", wrapped_get_errno());
            } else {
                fprintf(stdout, "visitor: local client connected\n");
                fflush(stdout);
            }
            (void)wrapped_close(ctx.local_listen_fd);
            ctx.local_listen_fd = -1;
        }

        uint8_t net_buf[65536];
        size_t net_len = 0;
        uint8_t local_buf[4096];

        while (ctx.local_client_fd >= 0) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(work_fd, &rfds);
            FD_SET(ctx.local_client_fd, &rfds);

            int maxfd = work_fd > ctx.local_client_fd ? work_fd : ctx.local_client_fd;

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200 * 1000;

            int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0) {
                if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                break;
            }

            if (sel > 0 && FD_ISSET(ctx.local_client_fd, &rfds)) {
                ssize_t n = wrapped_read(ctx.local_client_fd, local_buf, sizeof(local_buf));
                if (n < 0) {
                    if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                    break;
                }
                if (n == 0) {
                    break;
                }
                (void)frpc_stcp_send(proxy, local_buf, (size_t)n);
            }

            if (sel > 0 && FD_ISSET(work_fd, &rfds)) {
                if (net_len >= sizeof(net_buf)) break;
                ssize_t n = wrapped_read(work_fd, net_buf + net_len, sizeof(net_buf) - net_len);
                if (n < 0) {
                    if (wrapped_get_errno() == WRAPPED_EINTR) continue;
                    break;
                }
                if (n == 0) {
                    break;
                }
                net_len += (size_t)n;

                while (net_len > 0) {
                    int consumed = frpc_stcp_receive(proxy, net_buf, net_len);
                    if (consumed < 0) {
                        net_len = 0;
                        break;
                    }
                    if (consumed == 0) break;
                    if ((size_t)consumed > net_len) {
                        net_len = 0;
                        break;
                    }
                    memmove(net_buf, net_buf + consumed, net_len - (size_t)consumed);
                    net_len -= (size_t)consumed;
                }
            }

            (void)frpc_stcp_tick(proxy);
        }
    }

    if (ctx.local_client_fd >= 0) {
        (void)wrapped_close(ctx.local_client_fd);
        ctx.local_client_fd = -1;
    }

    (void)wrapped_close(work_fd);
    frpc_stcp_proxy_free(proxy);
    frpc_client_free(client);
    return 0;
}


