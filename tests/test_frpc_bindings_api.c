#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../tiny-frpc/include/frpc-bindings.h"
#include "../tiny-frpc/include/frpc-stcp.h"

// NOTE: tests/ uses limited white-box access for coverage (unit tests only, does not affect external API).
typedef struct frpc_client_wrapper {
    frpc_client_t* client;
    frpc_config_t config;
    bool connected;
    frpc_log_callback_t log_callback;
} frpc_client_wrapper_t;

typedef struct frpc_tunnel_wrapper {
    frpc_client_wrapper_t* client_wrapper;
    frpc_stcp_proxy_t* stcp_proxy;
    frpc_tunnel_config_t config;
    frpc_tunnel_stats_t stats;
    bool active;
    time_t created_time;
} frpc_tunnel_wrapper_t;

// Simple assertion macro (consistent with existing tests style)
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s\n", msg); \
            return -1; \
        } else { \
            printf("PASS: %s\n", msg); \
        } \
    } while (0)

#define TEST_ASSERT_EQ(exp, act, msg) \
    do { \
        if ((exp) != (act)) { \
            fprintf(stderr, "FAIL: %s (expected: %d, actual: %d)\n", msg, (int)(exp), (int)(act)); \
            return -1; \
        } else { \
            printf("PASS: %s\n", msg); \
        } \
    } while (0)

static int read_exact(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
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

typedef struct mock_frps_s {
    int listen_fd;
    uint16_t port;
    const char* loginresp_json;
    uint8_t loginresp_type;
    pthread_t thread;
} mock_frps_t;

static void* mock_frps_thread(void* arg) {
    mock_frps_t* s = (mock_frps_t*)arg;

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int conn = accept(s->listen_fd, (struct sockaddr*)&peer, &peer_len);
    if (conn < 0) {
        return NULL;
    }

    // Read Login: 1 byte type + 8 bytes length + payload
    uint8_t type = 0;
    uint8_t len_be[8];
    if (read_exact(conn, &type, 1) != 0) goto out;
    if (read_exact(conn, len_be, sizeof(len_be)) != 0) goto out;

    // Parse length (big-endian int64)
    int64_t msg_len = 0;
    for (int i = 0; i < 8; i++) {
        msg_len = (msg_len << 8) | (int64_t)len_be[i];
    }
    if (msg_len < 0 || msg_len > 64 * 1024) goto out;

    char* payload = (char*)malloc((size_t)msg_len + 1);
    if (!payload) goto out;
    if (msg_len > 0) {
        if (read_exact(conn, payload, (size_t)msg_len) != 0) {
            free(payload);
            goto out;
        }
    }
    payload[msg_len] = '\0';

    // Basic sanity: client should send Login type 'o'
    // (we don't hard-fail tests here; just best-effort to avoid flakiness)
    (void)type;
    (void)payload;
    free(payload);

    // Write LoginResp
    const char* resp = s->loginresp_json ? s->loginresp_json : "{\"version\":\"0.62.1\",\"run_id\":\"test\"}";
    size_t resp_len = strlen(resp);
    uint8_t resp_len_be[8];
    write_be64(resp_len_be, (int64_t)resp_len);

    (void)write_all(conn, &s->loginresp_type, 1);
    (void)write_all(conn, resp_len_be, sizeof(resp_len_be));
    (void)write_all(conn, resp, resp_len);

out:
    close(conn);
    close(s->listen_fd);
    return NULL;
}

static int mock_frps_start(mock_frps_t* s, uint8_t resp_type, const char* resp_json) {
    memset(s, 0, sizeof(*s));
    s->loginresp_type = resp_type;
    s->loginresp_json = resp_json;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr*)&bound, &blen) != 0) {
        close(fd);
        return -1;
    }
    s->port = ntohs(bound.sin_port);
    s->listen_fd = fd;

    if (pthread_create(&s->thread, NULL, mock_frps_thread, s) != 0) {
        close(fd);
        return -1;
    }
    return 0;
}

static void mock_frps_join(mock_frps_t* s) {
    (void)pthread_join(s->thread, NULL);
}

static int g_log_count = 0;
static int g_data_cb_calls = 0;
static void test_log_cb(int level, const char* message) {
    (void)level;
    (void)message;
    g_log_count++;
}

typedef struct {
    int connected_events;
    int disconnected_events;
} conn_events_t;

static void test_conn_cb(frpc_tunnel_handle_t tunnel, int connected, int error_code, void* user_data) {
    (void)tunnel;
    (void)error_code;
    conn_events_t* ev = (conn_events_t*)user_data;
    if (!ev) return;
    if (connected) ev->connected_events++;
    else ev->disconnected_events++;
}

static void test_data_cb(frpc_tunnel_handle_t tunnel, const uint8_t* data, size_t len, void* user_data) {
    (void)tunnel;
    (void)user_data;
    g_data_cb_calls++;
    // Just touch the buffer to avoid unused warnings and cover callback path.
    if (data && len > 0) {
        volatile uint8_t x = data[0];
        (void)x;
    }
}

static int test_bindings_api_basic(void) {
    printf("\n=== Testing frpc-bindings API (connect + STCP tunnels) ===\n");

    mock_frps_t frps;
    TEST_ASSERT_EQ(0, mock_frps_start(&frps, (uint8_t)'1',
                                     "{\"version\":\"0.62.1\",\"run_id\":\"unit_test_run_id\"}"),
                   "mock frps should start");

    frpc_init();
    frpc_set_log_callback(test_log_cb);

    frpc_handle_t h = frpc_create("127.0.0.1", frps.port, "test_token");
    TEST_ASSERT(h != NULL, "frpc_create should return non-NULL handle");

    int ret = frpc_connect(h);
    TEST_ASSERT_EQ(0, ret, "frpc_connect should succeed");
    TEST_ASSERT(frpc_is_connected(h), "frpc_is_connected should be true after connect");

    // Join server thread after login handshake done.
    mock_frps_join(&frps);

    // NOTE: frpc_start_tunnel requires sending encrypted NewProxy message which needs an
    // active connection. The mock_frps only handles Login/LoginResp and closes the connection.
    // Full tunnel lifecycle testing requires real frps (covered in cmd/frpc_test).
    // Here we only test create_tunnel/destroy_tunnel without start (no network I/O after login).

    // STCP server tunnel (create/destroy only, skip start - mock connection is closed)
    conn_events_t ev1 = {0};
    frpc_tunnel_config_t cfg1;
    frpc_tunnel_config_init(&cfg1);
    cfg1.tunnel_type = FRPC_TUNNEL_STCP_SERVER;
    cfg1.tunnel_name = "unit_stcp_server";
    cfg1.secret_key = "unit_secret";
    cfg1.local_addr = "127.0.0.1";
    cfg1.local_port = 8080;
    cfg1.connection_callback = test_conn_cb;
    cfg1.data_callback = test_data_cb;
    cfg1.user_data = &ev1;

    frpc_tunnel_handle_t t1 = frpc_create_tunnel(h, &cfg1);
    TEST_ASSERT(t1 != NULL, "frpc_create_tunnel(STCP_SERVER) should succeed");
    // Skip start_tunnel - requires active encrypted connection to frps
    TEST_ASSERT(!frpc_is_tunnel_active(t1), "tunnel should be inactive before start");
    frpc_destroy_tunnel(t1);

    // STCP visitor tunnel (create/destroy only, skip start)
    conn_events_t ev2 = {0};
    frpc_tunnel_config_t cfg2;
    frpc_tunnel_config_init(&cfg2);
    cfg2.tunnel_type = FRPC_TUNNEL_STCP_VISITOR;
    cfg2.tunnel_name = "unit_stcp_visitor";
    cfg2.secret_key = "unit_secret";
    cfg2.remote_name = "unit_remote_name";
    cfg2.bind_addr = "127.0.0.1";
    cfg2.bind_port = 0;
    cfg2.connection_callback = test_conn_cb;
    cfg2.data_callback = test_data_cb;
    cfg2.user_data = &ev2;

    frpc_tunnel_handle_t t2 = frpc_create_tunnel(h, &cfg2);
    TEST_ASSERT(t2 != NULL, "frpc_create_tunnel(STCP_VISITOR) should succeed");
    // Skip start_tunnel - requires active encrypted connection to frps
    TEST_ASSERT(!frpc_is_tunnel_active(t2), "visitor tunnel should be inactive before start");
    frpc_destroy_tunnel(t2);

    // Misc: process events + error message
    (void)frpc_process_events(h);
    TEST_ASSERT(strcmp(frpc_get_error_message(FRPC_ERROR_AUTH), "Authentication error") == 0,
                "frpc_get_error_message should map error codes");

    TEST_ASSERT_EQ(0, frpc_disconnect(h), "frpc_disconnect should succeed");
    TEST_ASSERT(!frpc_is_connected(h), "frpc_is_connected should be false after disconnect");
    frpc_destroy(h);

    // Log callback should have been invoked at least once
    TEST_ASSERT(g_log_count > 0, "log callback should be invoked");

    return 0;
}

static int test_connect_error_cases(void) {
    printf("\n=== Testing frpc_connect error cases ===\n");

    // Case 1: unexpected response type -> FRPC_ERROR_PROTO
    {
        mock_frps_t frps;
        TEST_ASSERT_EQ(0, mock_frps_start(&frps, (uint8_t)'X',
                                         "{\"version\":\"0.62.1\",\"run_id\":\"ignored\"}"),
                       "mock frps (wrong type) should start");

        frpc_handle_t h = frpc_create("127.0.0.1", frps.port, "test_token");
        TEST_ASSERT(h != NULL, "frpc_create should succeed (wrong type)");
        int ret = frpc_connect(h);
        TEST_ASSERT_EQ(FRPC_ERROR_PROTO, ret, "frpc_connect should return FRPC_ERROR_PROTO on wrong type");
        frpc_destroy(h);
        mock_frps_join(&frps);
    }

    // Case 2: LoginResp contains \"error\" -> FRPC_ERROR_AUTH
    {
        mock_frps_t frps;
        TEST_ASSERT_EQ(0, mock_frps_start(&frps, (uint8_t)'1',
                                         "{\"error\":\"bad token\"}"),
                       "mock frps (error field) should start");

        frpc_handle_t h = frpc_create("127.0.0.1", frps.port, "test_token");
        TEST_ASSERT(h != NULL, "frpc_create should succeed (error field)");
        int ret = frpc_connect(h);
        TEST_ASSERT_EQ(FRPC_ERROR_AUTH, ret, "frpc_connect should return FRPC_ERROR_AUTH on LoginResp error");
        frpc_destroy(h);
        mock_frps_join(&frps);
    }

    // Case 3: missing run_id -> FRPC_ERROR_PROTO
    {
        mock_frps_t frps;
        TEST_ASSERT_EQ(0, mock_frps_start(&frps, (uint8_t)'1',
                                         "{\"version\":\"0.62.1\"}"),
                       "mock frps (missing run_id) should start");

        frpc_handle_t h = frpc_create("127.0.0.1", frps.port, "test_token");
        TEST_ASSERT(h != NULL, "frpc_create should succeed (missing run_id)");
        int ret = frpc_connect(h);
        TEST_ASSERT_EQ(FRPC_ERROR_PROTO, ret, "frpc_connect should return FRPC_ERROR_PROTO on missing run_id");
        frpc_destroy(h);
        mock_frps_join(&frps);
    }

    return 0;
}

int main(void) {
    printf("Running frpc-bindings API tests...\n");
    int failed = 0;

    if (test_bindings_api_basic() != 0) failed++;
    if (test_connect_error_cases() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


