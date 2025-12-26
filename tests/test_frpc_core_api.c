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

typedef struct mock_frps_s {
    int listen_fd;
    uint16_t port;
    pthread_t thread;
} mock_frps_t;

static void* mock_frps_thread(void* arg) {
    mock_frps_t* s = (mock_frps_t*)arg;
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int conn = accept(s->listen_fd, (struct sockaddr*)&peer, &peer_len);
    if (conn < 0) return NULL;

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
    const char* resp = "{\"version\":\"0.62.1\",\"run_id\":\"frpc_core_run\"}";
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

static void mock_frps_join(mock_frps_t* s) {
    (void)pthread_join(s->thread, NULL);
}

typedef struct {
    int connect_events;
    int disconnect_events;
} ev_state_t;

static void on_event(void* user_ctx, int event_type, void* event_data) {
    (void)event_data;
    ev_state_t* st = (ev_state_t*)user_ctx;
    if (!st) return;
    if (event_type == 1) st->connect_events++;
    else if (event_type == 0) st->disconnect_events++;
}

static int test_frpc_core_api(void) {
    printf("\n=== Testing frpc core API ===\n");

    // Invalid configs (cover frpc_client_new validation)
    TEST_ASSERT(frpc_client_new(NULL, NULL) == NULL, "frpc_client_new(NULL) should return NULL");
    frpc_config_t bad;
    memset(&bad, 0, sizeof(bad));
    bad.server_port = 7000;
    TEST_ASSERT(frpc_client_new(&bad, NULL) == NULL, "frpc_client_new(missing server_addr) should return NULL");

    mock_frps_t frps;
    TEST_ASSERT_EQ(0, mock_frps_start(&frps), "mock frps should start");

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = "127.0.0.1";
    cfg.server_port = frps.port;
    cfg.token = "test_token";
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    ev_state_t ev = {0};
    frpc_client_t* c = frpc_client_new(&cfg, &ev);
    TEST_ASSERT(c != NULL, "frpc_client_new should succeed");
    frpc_client_set_event_callback(c, on_event);

    int ret = frpc_client_connect(c);
    TEST_ASSERT_EQ(0, ret, "frpc_client_connect should succeed");
    mock_frps_join(&frps);
    TEST_ASSERT(ev.connect_events >= 1, "event callback should receive connect event");

    // frpc_client_receive (connected path)
    const uint8_t dummy_rx[] = {0x01, 0x02, 0x03};
    TEST_ASSERT_EQ(0, frpc_client_receive(c, dummy_rx, sizeof(dummy_rx)), "frpc_client_receive should succeed when connected");

    // frpc_client_send_yamux_frame_bytes
    const uint8_t yb[] = {0x00, 0x01};
    TEST_ASSERT(frpc_client_send_yamux_frame_bytes(NULL, yb, sizeof(yb)) < 0, "send_yamux_frame_bytes(NULL) should fail");
    TEST_ASSERT(frpc_client_send_yamux_frame_bytes(c, NULL, 1) < 0, "send_yamux_frame_bytes(NULL data) should fail");
    TEST_ASSERT(frpc_client_send_yamux_frame_bytes(c, yb, 0) < 0, "send_yamux_frame_bytes(len=0) should fail");
    TEST_ASSERT_EQ((int)sizeof(yb), frpc_client_send_yamux_frame_bytes(c, yb, sizeof(yb)), "send_yamux_frame_bytes should return len on success");

    // Heartbeat tick path (sleep > 1s)
    usleep(1100 * 1000);
    TEST_ASSERT_EQ(0, frpc_client_tick(c), "frpc_client_tick should succeed");

    // Disconnect + receive when disconnected
    TEST_ASSERT_EQ(0, frpc_client_disconnect(c), "frpc_client_disconnect should succeed");
    TEST_ASSERT(ev.disconnect_events >= 1, "event callback should receive disconnect event");
    TEST_ASSERT(frpc_client_receive(c, dummy_rx, sizeof(dummy_rx)) < 0, "frpc_client_receive should fail when disconnected");

    frpc_client_free(c);
    return 0;
}

static int test_frpc_dial_server_errors(void) {
    printf("\n=== Testing frpc_dial_server error paths ===\n");

    // NULL client
    int fd = frpc_dial_server(NULL);
    TEST_ASSERT(fd < 0, "frpc_dial_server(NULL) should fail");

    // Client not connected
    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = "127.0.0.1";
    cfg.server_port = 65534; // unlikely to be listening
    cfg.token = "test";
    cfg.heartbeat_interval = 0;
    cfg.tls_enable = false;

    frpc_client_t* c = frpc_client_new(&cfg, NULL);
    TEST_ASSERT(c != NULL, "frpc_client_new should succeed");

    // dial without connect - should still attempt dial (may fail but not crash)
    fd = frpc_dial_server(c);
    // Result depends on whether port is reachable; just verify no crash
    printf("PASS: frpc_dial_server on non-connected client returns %d (no crash)\n", fd);
    if (fd >= 0) close(fd);

    frpc_client_free(c);
    return 0;
}

static int test_frpc_send_msg_on_fd_errors(void) {
    printf("\n=== Testing frpc_send_msg_on_fd error paths ===\n");

    // Invalid fd
    int ret = frpc_send_msg_on_fd(-1, 'p', "{}", 2);
    TEST_ASSERT(ret < 0, "frpc_send_msg_on_fd(-1) should fail");

    // NULL json
    ret = frpc_send_msg_on_fd(1, 'p', NULL, 0);
    TEST_ASSERT(ret < 0, "frpc_send_msg_on_fd(NULL json) should fail");

    return 0;
}

static int test_frpc_read_msg_from_fd_errors(void) {
    printf("\n=== Testing frpc_read_msg_from_fd error paths ===\n");

    uint8_t type_out;
    char* json_out = NULL;
    size_t json_len_out;

    // Invalid fd
    int ret = frpc_read_msg_from_fd(-1, &type_out, &json_out, &json_len_out, 100);
    TEST_ASSERT(ret < 0, "frpc_read_msg_from_fd(-1) should fail");

    // NULL pointers
    ret = frpc_read_msg_from_fd(1, NULL, &json_out, &json_len_out, 100);
    TEST_ASSERT(ret < 0, "frpc_read_msg_from_fd(NULL type) should fail");

    ret = frpc_read_msg_from_fd(1, &type_out, NULL, &json_len_out, 100);
    TEST_ASSERT(ret < 0, "frpc_read_msg_from_fd(NULL json) should fail");

    return 0;
}

static int test_frpc_client_accessors(void) {
    printf("\n=== Testing frpc_client accessor functions ===\n");

    mock_frps_t frps;
    TEST_ASSERT_EQ(0, mock_frps_start(&frps), "mock frps should start");

    frpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_addr = "127.0.0.1";
    cfg.server_port = frps.port;
    cfg.token = "test_token";
    cfg.heartbeat_interval = 1;
    cfg.tls_enable = false;

    frpc_client_t* c = frpc_client_new(&cfg, NULL);
    TEST_ASSERT(c != NULL, "frpc_client_new should succeed");

    // Test accessors before connect
    const char* addr = frpc_client_get_server_addr(c);
    TEST_ASSERT(addr != NULL && strcmp(addr, "127.0.0.1") == 0, "get_server_addr should return correct address");

    uint16_t port = frpc_client_get_server_port(c);
    TEST_ASSERT_EQ(frps.port, port, "get_server_port should return correct port");

    // run_id should be NULL before connect
    const char* run_id = frpc_client_get_run_id(c);
    TEST_ASSERT(run_id == NULL || strlen(run_id) == 0, "run_id should be empty before connect");

    // Connect
    TEST_ASSERT_EQ(0, frpc_client_connect(c), "frpc_client_connect should succeed");
    mock_frps_join(&frps);

    // run_id should be set after connect
    run_id = frpc_client_get_run_id(c);
    TEST_ASSERT(run_id != NULL && strlen(run_id) > 0, "run_id should be set after connect");
    printf("PASS: run_id after connect: %s\n", run_id);

    frpc_client_disconnect(c);
    frpc_client_free(c);
    return 0;
}

int main(void) {
    printf("Running frpc core API tests...\n");
    int failed = 0;

    if (test_frpc_core_api() != 0) failed++;
    if (test_frpc_dial_server_errors() != 0) failed++;
    if (test_frpc_send_msg_on_fd_errors() != 0) failed++;
    if (test_frpc_read_msg_from_fd_errors() != 0) failed++;
    if (test_frpc_client_accessors() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


