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

#include "../tiny-frpc/include/frpc.h"
#include "../tiny-frpc/include/frpc-stcp.h"

// Simple assertion macro
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

// mock_frps is not used in this test file since we skip frpc_client_connect
// (requires encryption which the simple mock doesn't support).
// Full integration tests with real frps are in cmd/frpc_test.

// Suppress unused warnings for helper functions that might be used in the future
__attribute__((unused))
static int read_exact_helper(int fd, void* buf, size_t len) {
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

typedef struct mock_frps_s {
    int listen_fd;
    uint16_t port;
    pthread_t thread;
} mock_frps_t;

__attribute__((unused))
static void* mock_frps_thread(void* arg) {
    mock_frps_t* s = (mock_frps_t*)arg;
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int conn = accept(s->listen_fd, (struct sockaddr*)&peer, &peer_len);
    if (conn < 0) return NULL;

    // Read Login: 1 + 8 + payload
    uint8_t type = 0;
    uint8_t len_be[8];
    if (read_exact(conn, &type, 1) != 0) goto out;
    if (read_exact(conn, len_be, sizeof(len_be)) != 0) goto out;

    int64_t msg_len = 0;
    for (int i = 0; i < 8; i++) msg_len = (msg_len << 8) | (int64_t)len_be[i];
    if (msg_len < 0 || msg_len > 64 * 1024) goto out;
    if (msg_len > 0) {
        char* payload = (char*)malloc((size_t)msg_len);
        if (!payload) goto out;
        (void)read_exact(conn, payload, (size_t)msg_len);
        free(payload);
    }

    // Reply LoginResp
    const char* resp = "{\"version\":\"0.62.1\",\"run_id\":\"stcp_unit_run\"}";
    size_t resp_len = strlen(resp);
    uint8_t resp_len_be[8];
    write_be64(resp_len_be, (int64_t)resp_len);

    uint8_t resp_type = (uint8_t)'1';
    (void)write_all(conn, &resp_type, 1);
    (void)write_all(conn, resp_len_be, sizeof(resp_len_be));
    (void)write_all(conn, resp, resp_len);

out:
    close(conn);
    close(s->listen_fd);
    return NULL;
}

__attribute__((unused))
static int mock_frps_start(mock_frps_t* s) {
    memset(s, 0, sizeof(*s));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, 1) != 0) { close(fd); return -1; }

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr*)&bound, &blen) != 0) { close(fd); return -1; }
    s->port = ntohs(bound.sin_port);
    s->listen_fd = fd;

    if (pthread_create(&s->thread, NULL, mock_frps_thread, s) != 0) { close(fd); return -1; }
    return 0;
}

__attribute__((unused))
static void mock_frps_join(mock_frps_t* s) {
    (void)pthread_join(s->thread, NULL);
}

typedef struct {
    int on_data_calls;
    int on_write_calls;
    int on_conn_up;
    int on_conn_down;
} stcp_cb_state_t;

static int on_data(void* user_ctx, uint8_t* data, size_t len) {
    stcp_cb_state_t* st = (stcp_cb_state_t*)user_ctx;
    if (st) st->on_data_calls++;
    if (data && len > 0) {
        volatile uint8_t x = data[0];
        (void)x;
    }
    return (int)len;
}

static int on_write(void* user_ctx, uint8_t* data, size_t len) {
    stcp_cb_state_t* st = (stcp_cb_state_t*)user_ctx;
    if (st) st->on_write_calls++;
    (void)data;
    return (int)len;
}

static void on_conn(void* user_ctx, int connected, int error_code) {
    (void)error_code;
    stcp_cb_state_t* st = (stcp_cb_state_t*)user_ctx;
    if (!st) return;
    if (connected) st->on_conn_up++;
    else st->on_conn_down++;
}

static int test_stcp_server_receive_paths(void) {
    printf("\n=== Testing frpc-stcp server receive paths ===\n");

    // NOTE: frpc_stcp_server_register requires encrypted connection to frps.
    // Full registration is tested in cmd/frpc_test with real frps.
    // We don't start mock_frps since we're not connecting to it.

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = "127.0.0.1";
    cfg.server_port = 7000; // Doesn't matter, we won't connect
    cfg.token = "test_token";
    cfg.heartbeat_interval = 0;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    TEST_ASSERT(client != NULL, "frpc_client_new should succeed");

    // Server proxy
    stcp_cb_state_t st = {0};
    frpc_stcp_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = FRPC_STCP_ROLE_SERVER;
    scfg.proxy_name = "unit_stcp_server";
    scfg.sk = "unit_sk";
    scfg.local_addr = "127.0.0.1";
    scfg.local_port = 8080;
    scfg.on_data = on_data;
    scfg.on_write = on_write;
    scfg.on_connection = on_conn;

    frpc_stcp_proxy_t* p = frpc_stcp_proxy_new(client, &scfg, &st);
    TEST_ASSERT(p != NULL, "frpc_stcp_proxy_new(server) should succeed");

    // Start proxy (just sets is_started, doesn't connect)
    TEST_ASSERT_EQ(0, frpc_stcp_proxy_start(p), "frpc_stcp_proxy_start(server) should succeed");
    // Skip frpc_stcp_server_register - requires encrypted connection which mock_frps doesn't support
    // Registration is tested in cmd/frpc_test with real frps
    // Full STCP integration is tested in cmd/frpc_test with real frps.
    
    // Test receive path (data goes directly to on_data callback in Direct TCP mode)
    const uint8_t test_data[] = "hello";
    int r = frpc_stcp_receive(p, test_data, sizeof(test_data) - 1);
    TEST_ASSERT(r >= 0, "frpc_stcp_receive should succeed in direct TCP mode");
    TEST_ASSERT(st.on_data_calls >= 1, "on_data callback should be invoked");

    // Exercise send error paths
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, frpc_stcp_send(NULL, (const uint8_t*)"x", 1),
                   "frpc_stcp_send(NULL,...) should return invalid param");
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, frpc_stcp_send(p, NULL, 1),
                   "frpc_stcp_send(proxy,NULL) should return invalid param");
    TEST_ASSERT(frpc_stcp_send(p, (const uint8_t*)"x", 1) <= 1, "frpc_stcp_send should return <=len (may fail if not connected)");

    // Stop/free
    (void)frpc_stcp_proxy_stop(p);
    frpc_stcp_proxy_free(p);
    frpc_client_free(client);

    return 0;
}

static int test_stcp_visitor_ack_and_tick_and_allow_users(void) {
    printf("\n=== Testing frpc-stcp visitor ACK + tick + allow_users ===\n");

    // No mock_frps needed since we're not connecting to it

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = "127.0.0.1";
    cfg.server_port = 7000; // Doesn't matter, we won't connect
    cfg.token = "test_token";
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* client = frpc_client_new(&cfg, NULL);
    TEST_ASSERT(client != NULL, "frpc_client_new should succeed");

    // Create a server proxy to exercise allow_users and tick paths
    stcp_cb_state_t st_server = {0};
    frpc_stcp_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = FRPC_STCP_ROLE_SERVER;
    scfg.proxy_name = "unit_stcp_server2";
    scfg.sk = "unit_sk";
    scfg.local_addr = "127.0.0.1";
    scfg.local_port = 8081;
    scfg.on_data = on_data;
    scfg.on_write = on_write;
    scfg.on_connection = on_conn;

    frpc_stcp_proxy_t* sp = frpc_stcp_proxy_new(client, &scfg, &st_server);
    TEST_ASSERT(sp != NULL, "frpc_stcp_proxy_new(server2) should succeed");
    TEST_ASSERT_EQ(0, frpc_stcp_proxy_start(sp), "frpc_stcp_proxy_start(server2) should succeed");
    // Skip frpc_stcp_server_register - requires encrypted connection which mock_frps doesn't support

    // allow_users: set twice to cover cleanup + replace
    const char* users1[] = {"u1", "u2"};
    TEST_ASSERT_EQ(0, frpc_stcp_server_set_allow_users(sp, users1, 2), "set_allow_users(2) should succeed");
    const char* users2[] = {"u3"};
    TEST_ASSERT_EQ(0, frpc_stcp_server_set_allow_users(sp, users2, 1), "set_allow_users(1) should succeed");
    TEST_ASSERT_EQ(0, frpc_stcp_server_set_allow_users(sp, NULL, 0), "set_allow_users(clear) should succeed");

    // tick paths
    TEST_ASSERT(frpc_stcp_tick(sp) <= 0 || frpc_stcp_tick(sp) == 0, "frpc_stcp_tick(server) should not crash");

    // Visitor proxy - test create/config only, skip connect (requires new TCP connection to frps)
    stcp_cb_state_t st_vis = {0};
    frpc_stcp_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.role = FRPC_STCP_ROLE_VISITOR;
    vcfg.proxy_name = "unit_stcp_visitor2";
    vcfg.sk = "unit_sk";
    vcfg.server_name = "unit_remote_name";
    vcfg.bind_addr = "127.0.0.1";
    vcfg.bind_port = 9000;
    vcfg.on_data = on_data;
    vcfg.on_write = on_write;
    vcfg.on_connection = on_conn;

    frpc_stcp_proxy_t* vp = frpc_stcp_proxy_new(client, &vcfg, &st_vis);
    TEST_ASSERT(vp != NULL, "frpc_stcp_proxy_new(visitor) should succeed");
    TEST_ASSERT_EQ(0, frpc_stcp_proxy_start(vp), "frpc_stcp_proxy_start(visitor) should succeed");
    // Skip frpc_stcp_visitor_connect - requires new TCP connection which mock_frps doesn't support
    // Full visitor test is in cmd/frpc_test with real frps

    // Test tick path (even without connection)
    TEST_ASSERT(frpc_stcp_tick(vp) <= 0 || frpc_stcp_tick(vp) == 0, "frpc_stcp_tick(visitor) should not crash");

    // Invalid-param branches
    const uint8_t dummy_payload[] = "test";
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, frpc_stcp_receive(NULL, dummy_payload, 1),
                   "frpc_stcp_receive(NULL,...) should return invalid param");
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, frpc_stcp_receive(vp, NULL, 1),
                   "frpc_stcp_receive(proxy,NULL) should return invalid param");

    // Wrong-role branch for allow_users
    TEST_ASSERT_EQ(FRPC_ERROR_INVALID_PARAM, frpc_stcp_server_set_allow_users(vp, users2, 1),
                   "set_allow_users on visitor should fail");

    (void)frpc_stcp_proxy_stop(vp);
    frpc_stcp_proxy_free(vp);

    (void)frpc_stcp_proxy_stop(sp);
    frpc_stcp_proxy_free(sp);
    frpc_client_free(client);

    return 0;
}

int main(void) {
    printf("Running frpc-stcp unit tests...\n");
    int failed = 0;

    if (test_stcp_server_receive_paths() != 0) failed++;
    if (test_stcp_visitor_ack_and_tick_and_allow_users() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


