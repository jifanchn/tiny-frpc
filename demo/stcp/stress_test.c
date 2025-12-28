/**
 * STCP Stress Test
 *
 * This program performs stress testing of the STCP protocol by:
 * 1. Running multiple rounds of visitor-server communication
 * 2. Sending variable-sized payloads
 * 3. Logging detailed packet information (FRP messages, raw data)
 * 4. Measuring throughput and latency
 *
 * Can work with both mock_frps and real frps.
 */

#include "common.h"

#include "frpc.h"
#include "frpc-stcp.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wrapper.h"

/* ---------- Configuration ---------- */
typedef struct stress_config_s {
    const char* frps_addr;
    uint16_t    frps_port;
    const char* token;
    const char* data_addr;
    uint16_t    data_port;
    const char* proxy_name;
    const char* sk;

    int         duration_sec;    // Total test duration (seconds)
    int         msg_interval_ms; // Interval between messages (ms)
    size_t      min_payload;     // Minimum payload size
    size_t      max_payload;     // Maximum payload size

    int         verbose;         // 0=quiet, 1=normal, 2=debug, 3=trace (show packets)
    int         json_output;     // Output final stats as JSON (for automation)
    
    // Fault injection
    int         drop_rate;       // Percentage of messages to drop (0-100)
    int         corrupt_rate;    // Percentage of messages to corrupt (0-100)
    int         delay_min_ms;    // Minimum artificial delay (0 = disabled)
    int         delay_max_ms;    // Maximum artificial delay
    
    // Memory monitoring
    int         mem_monitor;     // Enable memory usage monitoring
} stress_config_t;

/* ---------- Memory monitoring (platform-specific) ---------- */
#ifdef __APPLE__
#include <mach/mach.h>
static size_t get_memory_usage(void) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t size = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &size) == KERN_SUCCESS) {
        return info.resident_size;
    }
    return 0;
}
#elif defined(__linux__)
static size_t get_memory_usage(void) {
    FILE* f = fopen("/proc/self/statm", "r");
    if (!f) return 0;
    size_t pages = 0;
    if (fscanf(f, "%*d %zu", &pages) != 1) pages = 0;
    fclose(f);
    return pages * 4096; // Assume 4KB pages
}
#else
static size_t get_memory_usage(void) { return 0; }
#endif

/* ---------- Statistics ---------- */
#define LATENCY_BUCKETS 10
static const int latency_bucket_ms[] = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1000};

typedef struct stress_stats_s {
    uint64_t    messages_sent;
    uint64_t    messages_recv;
    uint64_t    bytes_sent;
    uint64_t    bytes_recv;
    uint64_t    frp_messages_in;
    uint64_t    frp_messages_out;
    uint64_t    latency_sum_us;
    uint64_t    latency_count;
    uint64_t    latency_min_us;
    uint64_t    latency_max_us;
    uint64_t    latency_histogram[LATENCY_BUCKETS + 1]; // last bucket is for > max
    uint64_t    errors;
    struct timeval start_time;
    
    // Fault injection counters
    uint64_t    dropped_messages;
    uint64_t    corrupted_messages;
    uint64_t    delayed_messages;
    
    // Memory stats
    size_t      mem_start;
    size_t      mem_current;
    size_t      mem_peak;
} stress_stats_t;

/* ---------- Context ---------- */
typedef struct stress_ctx_s {
    int                 work_fd;
    frpc_stcp_proxy_t*  proxy;
    stress_config_t     config;
    stress_stats_t      stats;
    int                 is_server;  // 1 = server, 0 = visitor
    volatile int        running;

    // Message tracking for latency
    uint64_t            last_send_seq;
    struct timeval      last_send_time;

    // Network receive buffer (to handle partial frames)
    uint8_t             recv_buf[65536];
    size_t              recv_buf_len;
} stress_ctx_t;

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

static int64_t tv_diff_us(struct timeval* start, struct timeval* end) {
    return (int64_t)(end->tv_sec - start->tv_sec) * 1000000LL +
           (int64_t)(end->tv_usec - start->tv_usec);
}

static void print_hex_dump(const char* prefix, const uint8_t* data, size_t len, size_t max_show) {
    fprintf(stdout, "%s (%zu bytes): ", prefix, len);
    size_t show = len < max_show ? len : max_show;
    for (size_t i = 0; i < show; i++) {
        fprintf(stdout, "%02x ", data[i]);
    }
    if (len > max_show) {
        fprintf(stdout, "... (%zu more)", len - max_show);
    }
    fprintf(stdout, "\n");
}

/* ---------- Raw packet logger (for debugging) ---------- */
static void log_raw_packet(stress_ctx_t* ctx, const char* direction, const uint8_t* data, size_t len) {
    if (ctx->config.verbose < 3) return;
    print_hex_dump(direction, data, len, 32);
}

/* ---------- FRP message decoder (for logging) ---------- */
static const char* frp_type_str(uint8_t type) {
    switch (type) {
        case 'o': return "Login";
        case '1': return "LoginResp";
        case 'p': return "NewProxy";
        case '2': return "NewProxyResp";
        case 'h': return "Ping";
        case '4': return "Pong";
        case 'v': return "NewVisitorConn";
        case '3': return "NewVisitorConnResp";
        case 'r': return "ReqWorkConn";
        case 'n': return "NewWorkConn";
        case 's': return "StartWorkConn";
        default: return "Unknown";
    }
}

__attribute__((unused))
static void log_frp_message(stress_ctx_t* ctx, const char* direction, uint8_t type, const char* json, size_t json_len) {
    if (ctx->config.verbose < 3) return;

    fprintf(stdout, "[FRP %s] type='%c'(%s) len=%zu\n",
            direction, type, frp_type_str(type), json_len);
    if (json && json_len > 0 && json_len < 256) {
        fprintf(stdout, "  json: %.*s\n", (int)json_len, json);
    } else if (json_len >= 256) {
        fprintf(stdout, "  json: %.256s... (truncated)\n", json);
    }
}

/* ---------- Callbacks ---------- */
static int on_write_cb(void* user_ctx, uint8_t* data, size_t len) {
    stress_ctx_t* ctx = (stress_ctx_t*)user_ctx;
    if (!ctx || ctx->work_fd < 0) return -1;

    if (ctx->config.verbose >= 3) {
        log_raw_packet(ctx, "[OUT]", data, len);
    }

    if (demo_write_all(ctx->work_fd, data, len) != 0) {
        ctx->stats.errors++;
        return -1;
    }
    ctx->stats.bytes_sent += len;
    return (int)len;
}

static int on_data_cb(void* user_ctx, uint8_t* data, size_t len) {
    stress_ctx_t* ctx = (stress_ctx_t*)user_ctx;
    if (!ctx || !ctx->proxy) return -1;

    ctx->stats.messages_recv++;
    ctx->stats.bytes_recv += len;

    if (ctx->config.verbose >= 2) {
        fprintf(stdout, "[DATA] %s received %zu bytes\n",
                ctx->is_server ? "server" : "visitor", len);
    }
    if (ctx->config.verbose >= 3) {
        print_hex_dump("  data", data, len, 32);
    }

    // Server echoes back
    if (ctx->is_server) {
        int ret = frpc_stcp_send(ctx->proxy, data, len);
        if (ret < 0) {
            ctx->stats.errors++;
            return ret;
        }
        ctx->stats.messages_sent++;
    } else {
        // Visitor: calculate latency if this is a response
        if (len >= 8 && ctx->stats.latency_count < ctx->stats.messages_sent) {
            struct timeval now;
            gettimeofday(&now, NULL);
            int64_t lat_us = tv_diff_us(&ctx->last_send_time, &now);
            if (lat_us > 0) {
                uint64_t lat = (uint64_t)lat_us;
                ctx->stats.latency_sum_us += lat;
                ctx->stats.latency_count++;
                
                // Update min/max
                if (lat < ctx->stats.latency_min_us || ctx->stats.latency_min_us == 0) {
                    ctx->stats.latency_min_us = lat;
                }
                if (lat > ctx->stats.latency_max_us) {
                    ctx->stats.latency_max_us = lat;
                }
                
                // Update histogram
                int64_t lat_ms = lat_us / 1000;
                int bucket = LATENCY_BUCKETS; // default: > max
                for (int b = 0; b < LATENCY_BUCKETS; b++) {
                    if (lat_ms <= latency_bucket_ms[b]) {
                        bucket = b;
                        break;
                    }
                }
                ctx->stats.latency_histogram[bucket]++;
            }
        }
    }

    return (int)len;
}

static void on_conn_cb(void* user_ctx, int connected, int error_code) {
    stress_ctx_t* ctx = (stress_ctx_t*)user_ctx;
    const char* role = ctx->is_server ? "server" : "visitor";

    if (connected) {
        if (ctx->config.verbose >= 1) {
            fprintf(stdout, "[CONN] %s: STCP connected\n", role);
        }
    } else {
        if (ctx->config.verbose >= 1) {
            fprintf(stdout, "[CONN] %s: STCP disconnected (err=%d)\n", role, error_code);
        }
        ctx->running = 0;
    }
    fflush(stdout);
}

/* ---------- Network pump ---------- */
static int pump_once(stress_ctx_t* ctx, int timeout_ms) {
    if (ctx->work_fd < 0) return -1;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ctx->work_fd, &rfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(ctx->work_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    if (sel > 0 && FD_ISSET(ctx->work_fd, &rfds)) {
        // Check if we have room in the receive buffer
        if (ctx->recv_buf_len >= sizeof(ctx->recv_buf)) {
            fprintf(stderr, "[PUMP] Receive buffer overflow\n");
            return -1;
        }

        ssize_t n = wrapped_read(ctx->work_fd, 
                                 ctx->recv_buf + ctx->recv_buf_len, 
                                 sizeof(ctx->recv_buf) - ctx->recv_buf_len);
        if (n < 0) {
            if (errno == EINTR) return 0;
            return -1;
        }
        if (n == 0) {
            return -1; // Peer closed
        }

        ctx->recv_buf_len += (size_t)n;

        if (ctx->config.verbose >= 3) {
            log_raw_packet(ctx, "[IN]", ctx->recv_buf, ctx->recv_buf_len);
        }

        // Feed to stcp - process as much as we can
        while (ctx->recv_buf_len > 0) {
            int consumed = frpc_stcp_receive(ctx->proxy, ctx->recv_buf, ctx->recv_buf_len);
            if (consumed < 0) {
                ctx->stats.errors++;
                return -1;
            }
            if (consumed == 0) break; // Need more data
            
            // Move remaining data to the beginning of the buffer
            if ((size_t)consumed < ctx->recv_buf_len) {
                memmove(ctx->recv_buf, ctx->recv_buf + consumed, ctx->recv_buf_len - (size_t)consumed);
            }
            ctx->recv_buf_len -= (size_t)consumed;
        }
    }

    return 0;
}

/* ---------- Generate random payload ---------- */
static void generate_payload(uint8_t* buf, size_t len, uint64_t seq) {
    // First 8 bytes: sequence number (for tracking)
    for (int i = 0; i < 8 && i < (int)len; i++) {
        buf[i] = (uint8_t)((seq >> (56 - i * 8)) & 0xFF);
    }
    // Rest: pseudo-random pattern
    for (size_t i = 8; i < len; i++) {
        buf[i] = (uint8_t)((i ^ seq) & 0xFF);
    }
}

/* ---------- Print statistics ---------- */
static void print_stats(stress_ctx_t* ctx, int final) {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed_sec = (double)tv_diff_us(&ctx->stats.start_time, &now) / 1000000.0;
    if (elapsed_sec < 0.001) elapsed_sec = 0.001;

    double msg_rate = (double)ctx->stats.messages_sent / elapsed_sec;
    double bytes_rate = (double)ctx->stats.bytes_sent / elapsed_sec;
    double avg_lat_ms = ctx->stats.latency_count > 0
                        ? (double)ctx->stats.latency_sum_us / (double)ctx->stats.latency_count / 1000.0
                        : 0.0;

    fprintf(stdout, "\n%s=== %s Statistics (%s) ===\n",
            final ? "\n" : "",
            ctx->is_server ? "Server" : "Visitor",
            final ? "FINAL" : "INTERIM");
    fprintf(stdout, "  Duration:        %.2f sec\n", elapsed_sec);
    fprintf(stdout, "  Messages sent:   %llu\n", (unsigned long long)ctx->stats.messages_sent);
    fprintf(stdout, "  Messages recv:   %llu\n", (unsigned long long)ctx->stats.messages_recv);
    fprintf(stdout, "  Bytes sent:      %llu (%.2f KB/s)\n",
            (unsigned long long)ctx->stats.bytes_sent, bytes_rate / 1024.0);
    fprintf(stdout, "  Bytes recv:      %llu\n", (unsigned long long)ctx->stats.bytes_recv);
    if (!ctx->is_server && ctx->stats.latency_count > 0) {
        fprintf(stdout, "  Avg latency:     %.2f ms\n", avg_lat_ms);
        fprintf(stdout, "  Min latency:     %.2f ms\n", (double)ctx->stats.latency_min_us / 1000.0);
        fprintf(stdout, "  Max latency:     %.2f ms\n", (double)ctx->stats.latency_max_us / 1000.0);
    }
    fprintf(stdout, "  Msg rate:        %.2f msg/s\n", msg_rate);
    fprintf(stdout, "  Errors:          %llu\n", (unsigned long long)ctx->stats.errors);
    
    // Fault injection stats (visitor only)
    if (!ctx->is_server && (ctx->stats.dropped_messages > 0 || ctx->stats.corrupted_messages > 0 || ctx->stats.delayed_messages > 0)) {
        fprintf(stdout, "  --- Fault Injection ---\n");
        if (ctx->stats.dropped_messages > 0)
            fprintf(stdout, "  Dropped msgs:    %llu\n", (unsigned long long)ctx->stats.dropped_messages);
        if (ctx->stats.corrupted_messages > 0)
            fprintf(stdout, "  Corrupted msgs:  %llu\n", (unsigned long long)ctx->stats.corrupted_messages);
        if (ctx->stats.delayed_messages > 0)
            fprintf(stdout, "  Delayed msgs:    %llu\n", (unsigned long long)ctx->stats.delayed_messages);
    }
    
    // Memory stats
    if (ctx->config.mem_monitor) {
        size_t current_mem = get_memory_usage();
        if (current_mem > ctx->stats.mem_peak) {
            ctx->stats.mem_peak = current_mem;
        }
        ctx->stats.mem_current = current_mem;
        fprintf(stdout, "  --- Memory Usage ---\n");
        fprintf(stdout, "  Start:           %.2f MB\n", (double)ctx->stats.mem_start / 1048576.0);
        fprintf(stdout, "  Current:         %.2f MB\n", (double)ctx->stats.mem_current / 1048576.0);
        fprintf(stdout, "  Peak:            %.2f MB\n", (double)ctx->stats.mem_peak / 1048576.0);
        double mem_delta = (double)ctx->stats.mem_current - (double)ctx->stats.mem_start;
        fprintf(stdout, "  Delta:           %+.2f KB\n", mem_delta / 1024.0);
    }
    
    // Print latency histogram in final stats (visitor only)
    if (final && !ctx->is_server && ctx->stats.latency_count > 0 && !ctx->config.json_output) {
        fprintf(stdout, "\n  Latency histogram:\n");
        for (int b = 0; b < LATENCY_BUCKETS; b++) {
            if (ctx->stats.latency_histogram[b] > 0) {
                double pct = 100.0 * (double)ctx->stats.latency_histogram[b] / (double)ctx->stats.latency_count;
                fprintf(stdout, "    <= %3dms: %6llu (%5.1f%%)\n", 
                        latency_bucket_ms[b], 
                        (unsigned long long)ctx->stats.latency_histogram[b], pct);
            }
        }
        if (ctx->stats.latency_histogram[LATENCY_BUCKETS] > 0) {
            double pct = 100.0 * (double)ctx->stats.latency_histogram[LATENCY_BUCKETS] / (double)ctx->stats.latency_count;
            fprintf(stdout, "    > %4dms: %6llu (%5.1f%%)\n", 
                    latency_bucket_ms[LATENCY_BUCKETS - 1],
                    (unsigned long long)ctx->stats.latency_histogram[LATENCY_BUCKETS], pct);
        }
    }
    
    fprintf(stdout, "========================\n\n");
    
    // JSON output for automation (final stats only)
    if (final && ctx->config.json_output) {
        fprintf(stdout, "{\"role\":\"%s\",\"duration_sec\":%.2f,\"messages_sent\":%llu,\"messages_recv\":%llu,"
                        "\"bytes_sent\":%llu,\"bytes_recv\":%llu,\"msg_rate\":%.2f,\"bytes_rate\":%.2f,"
                        "\"errors\":%llu",
                ctx->is_server ? "server" : "visitor", elapsed_sec,
                (unsigned long long)ctx->stats.messages_sent,
                (unsigned long long)ctx->stats.messages_recv,
                (unsigned long long)ctx->stats.bytes_sent,
                (unsigned long long)ctx->stats.bytes_recv,
                msg_rate, bytes_rate,
                (unsigned long long)ctx->stats.errors);
        if (!ctx->is_server && ctx->stats.latency_count > 0) {
            fprintf(stdout, ",\"latency_avg_ms\":%.2f,\"latency_min_ms\":%.2f,\"latency_max_ms\":%.2f",
                    avg_lat_ms, 
                    (double)ctx->stats.latency_min_us / 1000.0,
                    (double)ctx->stats.latency_max_us / 1000.0);
        }
        // Fault injection stats
        if (!ctx->is_server && (ctx->stats.dropped_messages > 0 || ctx->stats.corrupted_messages > 0 || ctx->stats.delayed_messages > 0)) {
            fprintf(stdout, ",\"dropped\":%llu,\"corrupted\":%llu,\"delayed\":%llu",
                    (unsigned long long)ctx->stats.dropped_messages,
                    (unsigned long long)ctx->stats.corrupted_messages,
                    (unsigned long long)ctx->stats.delayed_messages);
        }
        // Memory stats
        if (ctx->config.mem_monitor) {
            fprintf(stdout, ",\"mem_start_mb\":%.2f,\"mem_current_mb\":%.2f,\"mem_peak_mb\":%.2f",
                    (double)ctx->stats.mem_start / 1048576.0,
                    (double)ctx->stats.mem_current / 1048576.0,
                    (double)ctx->stats.mem_peak / 1048576.0);
        }
        fprintf(stdout, "}\n");
    }
    
    fflush(stdout);
}

/* ---------- Server main loop ---------- */
static int run_server(stress_ctx_t* ctx, int listen_fd) {
    fprintf(stdout, "[SERVER] Waiting for visitor connection...\n");
    fflush(stdout);

    int work_fd = wrapped_accept(listen_fd, NULL, NULL);
    if (work_fd < 0) {
        fprintf(stderr, "[SERVER] Accept failed: errno=%d\n", errno);
        return 1;
    }
    ctx->work_fd = work_fd;

    fprintf(stdout, "[SERVER] Visitor connected, initializing STCP...\n");
    fflush(stdout);

    // Create FRP client
    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = ctx->config.frps_addr;
    cfg.server_port = ctx->config.frps_port;
    cfg.token = ctx->config.token;
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    if (!client) {
        fprintf(stderr, "[SERVER] frpc_client_new failed\n");
        wrapped_close(work_fd);
        return 1;
    }

    frpc_stcp_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = FRPC_STCP_ROLE_SERVER;
    scfg.proxy_name = ctx->config.proxy_name;
    scfg.sk = ctx->config.sk;
    scfg.local_addr = "127.0.0.1";
    scfg.local_port = 8080;
    scfg.on_data = on_data_cb;
    scfg.on_write = on_write_cb;
    scfg.on_connection = on_conn_cb;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &scfg, ctx);
    if (!proxy) {
        fprintf(stderr, "[SERVER] frpc_stcp_proxy_new failed\n");
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }
    ctx->proxy = proxy;

    if (frpc_stcp_proxy_start(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "[SERVER] frpc_stcp_proxy_start failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }
    if (frpc_stcp_server_register(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "[SERVER] frpc_stcp_server_register failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }

    fprintf(stdout, "[SERVER] STCP registered, entering main loop (duration=%ds)...\n",
            ctx->config.duration_sec);
    fflush(stdout);

    gettimeofday(&ctx->stats.start_time, NULL);
    ctx->running = 1;
    
    // Initialize memory monitoring
    if (ctx->config.mem_monitor) {
        ctx->stats.mem_start = get_memory_usage();
        ctx->stats.mem_peak = ctx->stats.mem_start;
        ctx->stats.mem_current = ctx->stats.mem_start;
    }

    time_t last_stats = time(NULL);

    while (ctx->running && !g_stop) {
        if (pump_once(ctx, 100) < 0) {
            fprintf(stderr, "[SERVER] Network error\n");
            break;
        }
        frpc_stcp_tick(proxy);

        time_t now = time(NULL);
        if (now - last_stats >= 5) {
            print_stats(ctx, 0);
            last_stats = now;
        }
    }

    print_stats(ctx, 1);

    wrapped_close(work_fd);
    frpc_stcp_proxy_free(proxy);
    frpc_client_free(client);
    return 0;
}

/* ---------- Visitor main loop ---------- */
static int run_visitor(stress_ctx_t* ctx) {
    fprintf(stdout, "[VISITOR] Connecting to server %s:%d...\n",
            ctx->config.data_addr, ctx->config.data_port);
    fflush(stdout);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", ctx->config.data_port);

    int work_fd = demo_net_connect_tcp(ctx->config.data_addr, port_str);
    if (work_fd < 0) {
        fprintf(stderr, "[VISITOR] Connect failed: errno=%d\n", errno);
        return 1;
    }
    ctx->work_fd = work_fd;

    fprintf(stdout, "[VISITOR] Connected, initializing STCP...\n");
    fflush(stdout);

    // Create FRP client
    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = ctx->config.frps_addr;
    cfg.server_port = ctx->config.frps_port;
    cfg.token = ctx->config.token;
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    if (!client) {
        fprintf(stderr, "[VISITOR] frpc_client_new failed\n");
        wrapped_close(work_fd);
        return 1;
    }

    frpc_stcp_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.role = FRPC_STCP_ROLE_VISITOR;
    vcfg.proxy_name = "stress_visitor";
    vcfg.sk = ctx->config.sk;
    vcfg.server_name = ctx->config.proxy_name;
    vcfg.bind_addr = "127.0.0.1";
    vcfg.bind_port = 6000;
    vcfg.on_data = on_data_cb;
    vcfg.on_write = on_write_cb;
    vcfg.on_connection = on_conn_cb;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &vcfg, ctx);
    if (!proxy) {
        fprintf(stderr, "[VISITOR] frpc_stcp_proxy_new failed\n");
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }
    ctx->proxy = proxy;

    if (frpc_stcp_proxy_start(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "[VISITOR] frpc_stcp_proxy_start failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }
    if (frpc_stcp_visitor_connect(proxy) != FRPC_SUCCESS) {
        fprintf(stderr, "[VISITOR] frpc_stcp_visitor_connect failed\n");
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        wrapped_close(work_fd);
        return 1;
    }

    fprintf(stdout, "[VISITOR] STCP connected, starting stress test (duration=%ds, interval=%dms)...\n",
            ctx->config.duration_sec, ctx->config.msg_interval_ms);
    fflush(stdout);

    gettimeofday(&ctx->stats.start_time, NULL);
    ctx->running = 1;
    
    // Initialize memory monitoring
    if (ctx->config.mem_monitor) {
        ctx->stats.mem_start = get_memory_usage();
        ctx->stats.mem_peak = ctx->stats.mem_start;
        ctx->stats.mem_current = ctx->stats.mem_start;
    }

    struct timeval last_send = {0, 0};
    time_t last_stats = time(NULL);
    uint64_t seq = 0;

    uint8_t* payload = malloc(ctx->config.max_payload);
    if (!payload) {
        fprintf(stderr, "[VISITOR] Failed to allocate payload buffer\n");
        wrapped_close(work_fd);
        frpc_stcp_proxy_free(proxy);
        frpc_client_free(client);
        return 1;
    }

    time_t end_time = time(NULL) + ctx->config.duration_sec;

    while (ctx->running && !g_stop && time(NULL) < end_time) {
        struct timeval now;
        gettimeofday(&now, NULL);

        // Send message at interval
        int64_t elapsed_ms = tv_diff_us(&last_send, &now) / 1000;
        if (elapsed_ms >= ctx->config.msg_interval_ms) {
            // Random payload size
            size_t payload_len = ctx->config.min_payload;
            if (ctx->config.max_payload > ctx->config.min_payload) {
                payload_len += (size_t)(rand() % (int)(ctx->config.max_payload - ctx->config.min_payload));
            }

            generate_payload(payload, payload_len, seq);
            ctx->last_send_seq = seq;
            gettimeofday(&ctx->last_send_time, NULL);

            // Fault injection: drop messages
            if (ctx->config.drop_rate > 0 && (rand() % 100) < ctx->config.drop_rate) {
                ctx->stats.dropped_messages++;
                if (ctx->config.verbose >= 2) {
                    fprintf(stdout, "[FAULT] Dropping msg #%llu\n", (unsigned long long)(seq + 1));
                }
                seq++;
                gettimeofday(&last_send, NULL);
                continue;
            }

            // Fault injection: corrupt data
            if (ctx->config.corrupt_rate > 0 && (rand() % 100) < ctx->config.corrupt_rate) {
                // Flip a random byte
                size_t corrupt_idx = (size_t)(rand() % (int)payload_len);
                payload[corrupt_idx] ^= 0xFF;
                ctx->stats.corrupted_messages++;
                if (ctx->config.verbose >= 2) {
                    fprintf(stdout, "[FAULT] Corrupting msg #%llu at byte %zu\n", 
                            (unsigned long long)(seq + 1), corrupt_idx);
                }
            }

            // Fault injection: artificial delay
            if (ctx->config.delay_max_ms > 0) {
                int delay = ctx->config.delay_min_ms;
                if (ctx->config.delay_max_ms > ctx->config.delay_min_ms) {
                    delay += rand() % (ctx->config.delay_max_ms - ctx->config.delay_min_ms);
                }
                if (delay > 0) {
                    usleep((useconds_t)(delay * 1000));
                    ctx->stats.delayed_messages++;
                }
            }

            int ret = frpc_stcp_send(proxy, payload, payload_len);
            if (ret >= 0) {
                ctx->stats.messages_sent++;
                seq++;
                if (ctx->config.verbose >= 2) {
                    fprintf(stdout, "[VISITOR] Sent msg #%llu (%zu bytes)\n",
                            (unsigned long long)seq, payload_len);
                }
            } else {
                ctx->stats.errors++;
                if (ctx->config.verbose >= 1) {
                    fprintf(stderr, "[VISITOR] Send failed: %d\n", ret);
                }
            }

            gettimeofday(&last_send, NULL);
        }

        // Pump network
        if (pump_once(ctx, 10) < 0) {
            fprintf(stderr, "[VISITOR] Network error\n");
            break;
        }
        frpc_stcp_tick(proxy);

        // Print stats every 5 seconds
        time_t now_t = time(NULL);
        if (now_t - last_stats >= 5) {
            print_stats(ctx, 0);
            last_stats = now_t;
        }
    }

    free(payload);
    print_stats(ctx, 1);

    wrapped_close(work_fd);
    frpc_stcp_proxy_free(proxy);
    frpc_client_free(client);
    return 0;
}

/* ---------- Usage ---------- */
static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s --mode server|visitor [options]\n"
            "\n"
            "STCP Stress Test - Tests STCP protocol with detailed packet logging\n"
            "\n"
            "Mode:\n"
            "  --mode server       Run as STCP server (echo service)\n"
            "  --mode visitor      Run as STCP visitor (stress generator)\n"
            "\n"
            "Connection Options:\n"
            "  --frps-addr ADDR    FRPS address (default: 127.0.0.1)\n"
            "  --frps-port PORT    FRPS port (default: 7001)\n"
            "  --token TOKEN       Login token (default: test_token)\n"
            "  --data-addr ADDR    Data-plane address (default: 127.0.0.1)\n"
            "  --data-port PORT    Data-plane port (default: 9001)\n"
            "  --proxy-name NAME   Proxy name (default: stress_stcp)\n"
            "  --sk SECRET         Secret key (default: stress_secret)\n"
            "\n"
            "Stress Options:\n"
            "  --duration SECS     Test duration in seconds (default: 30)\n"
            "  --interval MS       Message interval in ms (default: 100)\n"
            "  --min-payload N     Minimum payload size (default: 64)\n"
            "  --max-payload N     Maximum payload size (default: 1024)\n"
            "\n"
            "Fault Injection (visitor only):\n"
            "  --drop-rate PCT     Drop PCT%% of messages (0-100, default: 0)\n"
            "  --corrupt-rate PCT  Corrupt PCT%% of messages (0-100, default: 0)\n"
            "  --delay-min MS      Minimum artificial delay (default: 0)\n"
            "  --delay-max MS      Maximum artificial delay (default: 0)\n"
            "\n"
            "Monitoring:\n"
            "  --mem-monitor       Enable periodic memory usage reporting\n"
            "\n"
            "Verbosity:\n"
            "  -v                  Verbose (show connection info)\n"
            "  -vv                 Debug (show message info)\n"
            "  -vvv                Trace (show all packets - raw data, FRP messages)\n"
            "  --json              Output final stats as JSON (for automation)\n"
            "\n"
            "Example (mock frps):\n"
            "  Terminal 1: ./demo_stcp_frps --listen-port 7001\n"
            "  Terminal 2: %s --mode server --frps-port 7001 --data-port 9001 -vvv\n"
            "  Terminal 3: %s --mode visitor --frps-port 7001 --data-port 9001 --duration 60 -vvv\n"
            "\n"
            "Example (with fault injection):\n"
            "  %s --mode visitor --frps-port 7001 --drop-rate 5 --corrupt-rate 2 --mem-monitor\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char** argv) {
    stress_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.work_fd = -1;

    // Defaults
    ctx.config.frps_addr = "127.0.0.1";
    ctx.config.frps_port = 7001;
    ctx.config.token = "test_token";
    ctx.config.data_addr = "127.0.0.1";
    ctx.config.data_port = 9001;
    ctx.config.proxy_name = "stress_stcp";
    ctx.config.sk = "stress_secret";
    ctx.config.duration_sec = 30;
    ctx.config.msg_interval_ms = 100;
    ctx.config.min_payload = 64;
    ctx.config.max_payload = 1024;
    ctx.config.verbose = 0;

    const char* mode_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
        } else if (strcmp(argv[i], "--frps-addr") == 0 && i + 1 < argc) {
            ctx.config.frps_addr = argv[++i];
        } else if (strcmp(argv[i], "--frps-port") == 0 && i + 1 < argc) {
            ctx.config.frps_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            ctx.config.token = argv[++i];
        } else if (strcmp(argv[i], "--data-addr") == 0 && i + 1 < argc) {
            ctx.config.data_addr = argv[++i];
        } else if (strcmp(argv[i], "--data-port") == 0 && i + 1 < argc) {
            ctx.config.data_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--proxy-name") == 0 && i + 1 < argc) {
            ctx.config.proxy_name = argv[++i];
        } else if (strcmp(argv[i], "--sk") == 0 && i + 1 < argc) {
            ctx.config.sk = argv[++i];
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            ctx.config.duration_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            ctx.config.msg_interval_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--min-payload") == 0 && i + 1 < argc) {
            ctx.config.min_payload = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-payload") == 0 && i + 1 < argc) {
            ctx.config.max_payload = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            ctx.config.verbose = 1;
        } else if (strcmp(argv[i], "-vv") == 0) {
            ctx.config.verbose = 2;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            ctx.config.verbose = 3;
        } else if (strcmp(argv[i], "--json") == 0) {
            ctx.config.json_output = 1;
        } else if (strcmp(argv[i], "--drop-rate") == 0 && i + 1 < argc) {
            ctx.config.drop_rate = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--corrupt-rate") == 0 && i + 1 < argc) {
            ctx.config.corrupt_rate = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--delay-min") == 0 && i + 1 < argc) {
            ctx.config.delay_min_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--delay-max") == 0 && i + 1 < argc) {
            ctx.config.delay_max_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mem-monitor") == 0) {
            ctx.config.mem_monitor = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!mode_str) {
        fprintf(stderr, "Error: --mode is required\n\n");
        usage(argv[0]);
        return 2;
    }

    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    srand((unsigned)time(NULL));

    int ret = 0;

    if (strcmp(mode_str, "server") == 0) {
        ctx.is_server = 1;

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", ctx.config.data_port);

        int listen_fd = demo_net_listen_tcp(ctx.config.data_addr, port_str, 16);
        if (listen_fd < 0) {
            fprintf(stderr, "[SERVER] Failed to listen on %s:%d (errno=%d)\n",
                    ctx.config.data_addr, ctx.config.data_port, errno);
            return 1;
        }

        fprintf(stdout, "[SERVER] Listening on %s:%d\n", ctx.config.data_addr, ctx.config.data_port);
        fflush(stdout);

        ret = run_server(&ctx, listen_fd);
        wrapped_close(listen_fd);
    } else if (strcmp(mode_str, "visitor") == 0) {
        ctx.is_server = 0;
        ret = run_visitor(&ctx);
    } else {
        fprintf(stderr, "Error: --mode must be 'server' or 'visitor'\n");
        return 2;
    }

    return ret;
}

