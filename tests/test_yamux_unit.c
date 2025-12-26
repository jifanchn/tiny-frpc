#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "../tiny-frpc/include/yamux.h"

// We use yamux_serialize_frame_header from yamux.c (not declared in yamux.h)
void yamux_serialize_frame_header(const yamux_frame_header_t* local_header, uint8_t* buffer);

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

typedef struct {
    uint8_t* data;
    size_t len;
    size_t cap;
} wire_buf_t;

static int wire_append(wire_buf_t* w, const uint8_t* data, size_t len) {
    if (!w || (!data && len > 0)) return -1;
    if (len == 0) return 0;
    if (w->len + len > w->cap) {
        size_t new_cap = w->cap ? w->cap : 4096;
        while (new_cap < w->len + len) new_cap *= 2;
        uint8_t* p = (uint8_t*)realloc(w->data, new_cap);
        if (!p) return -1;
        w->data = p;
        w->cap = new_cap;
    }
    memcpy(w->data + w->len, data, len);
    w->len += len;
    return 0;
}

static void wire_reset(wire_buf_t* w) {
    if (!w) return;
    w->len = 0;
}

typedef struct {
    wire_buf_t c2s;
    wire_buf_t s2c;

    uint32_t stream_id;

    int server_new_stream_calls;
    int client_established_calls;
    int server_data_calls;
    size_t server_bytes;
    int client_window_updated_calls;
    uint32_t last_client_window;
    int server_stream_close_calls;
    int client_session_close_calls;
} yamux_test_ctx_t;

static int write_fn(void* user_conn_ctx, const uint8_t* data, size_t len) {
    wire_buf_t* w = (wire_buf_t*)user_conn_ctx;
    if (!w) return -1;
    if (wire_append(w, data, len) != 0) return -1;
    return (int)len;
}

static int server_on_new_stream(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    (void)p_stream;
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)session_user_data;
    if (t) t->server_new_stream_calls++;
    if (p_stream_user_data_out) *p_stream_user_data_out = session_user_data;
    return 1; // accept
}

static int server_on_stream_data(void* stream_user_data, const uint8_t* data, size_t len) {
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)stream_user_data;
    if (t) {
        t->server_data_calls++;
        t->server_bytes += len;
    }
    // Touch data to cover path
    if (data && len > 0) {
        volatile uint8_t x = data[0];
        (void)x;
    }
    return (int)len;
}

static void server_on_stream_close(void* stream_user_data, bool by_remote, uint32_t error_code) {
    (void)by_remote;
    (void)error_code;
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)stream_user_data;
    if (t) t->server_stream_close_calls++;
}

static void client_on_stream_established(void* stream_user_data) {
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)stream_user_data;
    if (t) t->client_established_calls++;
}

static void client_on_stream_write_window_updated(void* stream_user_data, uint32_t new_window_size) {
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)stream_user_data;
    if (t) {
        t->client_window_updated_calls++;
        t->last_client_window = new_window_size;
    }
}

static void client_on_session_close(void* session_user_data, bool by_remote, uint32_t error_code) {
    (void)by_remote;
    (void)error_code;
    yamux_test_ctx_t* t = (yamux_test_ctx_t*)session_user_data;
    if (t) t->client_session_close_calls++;
}

static int flush_to_peer(yamux_session_t* peer, wire_buf_t* w) {
    if (!peer || !w) return -1;
    if (w->len == 0) return 0;
    int ret = yamux_session_receive(peer, w->data, w->len);
    wire_reset(w);
    return ret;
}

static int test_yamux_inmemory_basic(void) {
    printf("\n=== Testing yamux in-memory client<->server ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = true;
    client_cfg.keepalive_interval_ms = 10;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 64;
    client_cfg.max_streams = 8;
    client_cfg.on_stream_established = client_on_stream_established;
    client_cfg.on_stream_write_window_updated = client_on_stream_write_window_updated;
    client_cfg.on_session_close = client_on_session_close;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = true;
    server_cfg.keepalive_interval_ms = 10;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 64;
    server_cfg.max_streams = 8;
    server_cfg.on_new_stream = server_on_new_stream;
    server_cfg.on_stream_data = server_on_stream_data;
    server_cfg.on_stream_close = server_on_stream_close;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    // Open stream from client -> should emit SYN to c2s
    void* stream_ud = &t;
    uint32_t sid = yamux_session_open_stream(cs, &stream_ud);
    TEST_ASSERT(sid != 0, "yamux_session_open_stream should return non-zero stream id");
    t.stream_id = sid;

    // Deliver SYN to server; server should accept and send ACK back
    TEST_ASSERT(flush_to_peer(ss, &t.c2s) >= 0, "server should receive client's SYN");
    TEST_ASSERT_EQ(1, t.server_new_stream_calls, "server on_new_stream should be called once");

    // Deliver ACK back to client; client should mark established
    TEST_ASSERT(flush_to_peer(cs, &t.s2c) >= 0, "client should receive server ACK");
    TEST_ASSERT(t.client_established_calls >= 1, "client on_stream_established should be called");

    // Send DATA from client -> server
    const uint8_t msg[] = "hello";
    int n = yamux_stream_write(cs, sid, msg, sizeof(msg) - 1);
    TEST_ASSERT(n > 0, "yamux_stream_write should return >0");
    TEST_ASSERT(flush_to_peer(ss, &t.c2s) >= 0, "server should receive DATA");
    TEST_ASSERT(t.server_data_calls >= 1, "server on_stream_data should be called");
    TEST_ASSERT(t.server_bytes >= (sizeof(msg) - 1), "server should receive all bytes");

    // Receiver processed bytes -> send WINDOW_UPDATE back
    TEST_ASSERT_EQ(0, yamux_stream_window_update(ss, sid, (uint32_t)(sizeof(msg) - 1)),
                   "yamux_stream_window_update(server) should succeed");
    TEST_ASSERT(flush_to_peer(cs, &t.s2c) >= 0, "client should receive WINDOW_UPDATE");
    TEST_ASSERT(t.client_window_updated_calls >= 1, "client write window updated callback should be called");
    TEST_ASSERT(t.last_client_window >= 64, "client window size should be >= initial");

    // Keepalive tick -> try to trigger ping/pong path
    usleep(20000); // 20ms > keepalive_interval_ms
    yamux_session_tick(cs);
    (void)flush_to_peer(ss, &t.c2s);
    (void)flush_to_peer(cs, &t.s2c);

    // Close stream (FIN) and close session (GoAway)
    TEST_ASSERT_EQ(0, yamux_stream_close(cs, sid, 0), "yamux_stream_close(FIN) should succeed");
    (void)flush_to_peer(ss, &t.c2s);

    TEST_ASSERT_EQ(0, yamux_session_close(cs), "yamux_session_close should succeed");
    (void)flush_to_peer(ss, &t.c2s);
    // server may send GoAway back; deliver if any
    (void)flush_to_peer(cs, &t.s2c);

    // Free sessions (should close remaining streams)
    yamux_session_free(cs);
    yamux_session_free(ss);

    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_rst_and_free(void) {
    printf("\n=== Testing yamux RST + remove_and_free_stream ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = false;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 64;
    client_cfg.max_streams = 8;
    client_cfg.on_stream_established = client_on_stream_established;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = false;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 64;
    server_cfg.max_streams = 8;
    server_cfg.on_new_stream = server_on_new_stream;
    server_cfg.on_stream_close = server_on_stream_close;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    void* stream_ud = &t;
    uint32_t sid = yamux_session_open_stream(cs, &stream_ud);
    TEST_ASSERT(sid != 0, "open_stream should succeed");

    (void)flush_to_peer(ss, &t.c2s);
    (void)flush_to_peer(cs, &t.s2c);

    // Close with RST (error_code_if_rst != 0) -> should remove stream immediately on client side.
    TEST_ASSERT_EQ(0, yamux_stream_close(cs, sid, 1), "yamux_stream_close(RST) should succeed");
    (void)flush_to_peer(ss, &t.c2s);
    (void)flush_to_peer(cs, &t.s2c);

    // After RST, writing should fail.
    int n = yamux_stream_write(cs, sid, (const uint8_t*)"x", 1);
    TEST_ASSERT(n < 0, "yamux_stream_write on closed stream should fail");

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_window_violation_and_unknown_frames(void) {
    printf("\n=== Testing yamux window violation + unknown frames ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = false;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 8;
    client_cfg.max_streams = 8;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = false;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 8;
    server_cfg.max_streams = 8;
    server_cfg.on_new_stream = server_on_new_stream;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    // Handshake one stream
    void* stream_ud = &t;
    uint32_t sid = yamux_session_open_stream(cs, &stream_ud);
    TEST_ASSERT(sid != 0, "open_stream should succeed");
    (void)flush_to_peer(ss, &t.c2s);
    (void)flush_to_peer(cs, &t.s2c);

    // 1) Unknown frame type on StreamID 0 should be ignored
    uint8_t unk[YAMUX_FRAME_HEADER_SIZE];
    yamux_frame_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = YAMUX_VERSION;
    h.type = 0x99;
    h.flags = 0;
    h.stream_id = 0;
    h.length = 0;
    yamux_serialize_frame_header(&h, unk);
    TEST_ASSERT(yamux_session_receive(ss, unk, sizeof(unk)) >= 0, "unknown type on stream 0 should not hard-fail");

    // 2) DATA larger than local window -> should trigger protocol error / RST path
    const size_t big_len = 32;
    uint8_t* big = (uint8_t*)malloc(YAMUX_FRAME_HEADER_SIZE + big_len);
    TEST_ASSERT(big != NULL, "malloc big frame should succeed");
    memset(&h, 0, sizeof(h));
    h.version = YAMUX_VERSION;
    h.type = YAMUX_TYPE_DATA;
    h.flags = 0;
    h.stream_id = sid;
    h.length = (uint32_t)big_len; // > initial_stream_window_size(8)
    yamux_serialize_frame_header(&h, big);
    memset(big + YAMUX_FRAME_HEADER_SIZE, 'A', big_len);
    int ret = yamux_session_receive(ss, big, YAMUX_FRAME_HEADER_SIZE + big_len);
    // Either protocol error or non-negative depending on implementation details, but must not crash.
    TEST_ASSERT(ret <= 0, "oversized DATA should not be treated as successful consumption");
    free(big);

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_multiple_streams(void) {
    printf("\n=== Testing yamux multiple streams ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = false;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 1024;
    client_cfg.max_streams = 16;
    client_cfg.on_stream_established = client_on_stream_established;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = false;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 1024;
    server_cfg.max_streams = 16;
    server_cfg.on_new_stream = server_on_new_stream;
    server_cfg.on_stream_data = server_on_stream_data;
    server_cfg.on_stream_close = server_on_stream_close;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    // Open multiple streams
    uint32_t stream_ids[4];
    for (int i = 0; i < 4; i++) {
        void* stream_ud = &t;
        stream_ids[i] = yamux_session_open_stream(cs, &stream_ud);
        TEST_ASSERT(stream_ids[i] != 0, "open_stream should succeed");
    }

    // Deliver all SYN frames
    TEST_ASSERT(flush_to_peer(ss, &t.c2s) >= 0, "server should receive SYNs");
    TEST_ASSERT_EQ(4, t.server_new_stream_calls, "server should receive 4 new streams");

    // Deliver ACKs
    TEST_ASSERT(flush_to_peer(cs, &t.s2c) >= 0, "client should receive ACKs");
    TEST_ASSERT(t.client_established_calls >= 4, "all streams should be established");

    // Send data on each stream
    for (int i = 0; i < 4; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "stream%d_data", i);
        int n = yamux_stream_write(cs, stream_ids[i], (const uint8_t*)msg, strlen(msg));
        TEST_ASSERT(n > 0, "yamux_stream_write should succeed");
    }

    // Deliver data
    TEST_ASSERT(flush_to_peer(ss, &t.c2s) >= 0, "server should receive data");
    TEST_ASSERT(t.server_data_calls >= 4, "server should receive data on all streams");

    // Close all streams
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(0, yamux_stream_close(cs, stream_ids[i], 0), "stream close should succeed");
    }
    (void)flush_to_peer(ss, &t.c2s);

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_ping_pong(void) {
    printf("\n=== Testing yamux ping/pong ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = true;
    client_cfg.keepalive_interval_ms = 5;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 64;
    client_cfg.max_streams = 8;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = true;
    server_cfg.keepalive_interval_ms = 5;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 64;
    server_cfg.max_streams = 8;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    // Trigger keepalive tick multiple times
    for (int i = 0; i < 3; i++) {
        usleep(10000); // 10ms
        yamux_session_tick(cs);
        (void)flush_to_peer(ss, &t.c2s);
        yamux_session_tick(ss);
        (void)flush_to_peer(cs, &t.s2c);
    }

    // Sessions should still be valid
    TEST_ASSERT(yamux_session_is_closed(cs) == false, "client session should not be closed");
    TEST_ASSERT(yamux_session_is_closed(ss) == false, "server session should not be closed");

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_goaway(void) {
    printf("\n=== Testing yamux GO_AWAY handling ===\n");

    yamux_test_ctx_t t;
    memset(&t, 0, sizeof(t));

    yamux_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.enable_keepalive = false;
    client_cfg.max_stream_window_size = 256 * 1024;
    client_cfg.initial_stream_window_size = 64;
    client_cfg.max_streams = 8;
    client_cfg.on_session_close = client_on_session_close;
    client_cfg.write_fn = write_fn;
    client_cfg.user_conn_ctx = &t.c2s;

    yamux_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.enable_keepalive = false;
    server_cfg.max_stream_window_size = 256 * 1024;
    server_cfg.initial_stream_window_size = 64;
    server_cfg.max_streams = 8;
    server_cfg.write_fn = write_fn;
    server_cfg.user_conn_ctx = &t.s2c;

    yamux_session_t* cs = yamux_session_new(&client_cfg, true, &t);
    TEST_ASSERT(cs != NULL, "yamux_session_new(client) should succeed");
    yamux_session_t* ss = yamux_session_new(&server_cfg, false, &t);
    TEST_ASSERT(ss != NULL, "yamux_session_new(server) should succeed");

    // Server sends GO_AWAY
    TEST_ASSERT_EQ(0, yamux_session_close(ss), "server session close should succeed");
    (void)flush_to_peer(cs, &t.s2c);

    // Client should receive GO_AWAY and mark session as closed
    TEST_ASSERT(t.client_session_close_calls >= 1, "client should receive session close callback");

    // Trying to open new stream should fail
    void* stream_ud = &t;
    uint32_t sid = yamux_session_open_stream(cs, &stream_ud);
    TEST_ASSERT(sid == 0, "open_stream on closed session should fail");

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(t.c2s.data);
    free(t.s2c.data);
    return 0;
}

static int test_yamux_null_callbacks(void) {
    printf("\n=== Testing yamux with NULL callbacks ===\n");

    wire_buf_t c2s = {0};
    wire_buf_t s2c = {0};

    yamux_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_keepalive = false;
    cfg.max_stream_window_size = 256 * 1024;
    cfg.initial_stream_window_size = 64;
    cfg.max_streams = 8;
    // All callbacks NULL
    cfg.write_fn = write_fn;
    cfg.user_conn_ctx = &c2s;

    yamux_session_t* cs = yamux_session_new(&cfg, true, NULL);
    TEST_ASSERT(cs != NULL, "yamux_session_new with NULL callbacks should succeed");

    cfg.user_conn_ctx = &s2c;
    yamux_session_t* ss = yamux_session_new(&cfg, false, NULL);
    TEST_ASSERT(ss != NULL, "server session with NULL callbacks should succeed");

    // Open stream should work even without callbacks
    void* stream_ud = NULL;
    uint32_t sid = yamux_session_open_stream(cs, &stream_ud);
    TEST_ASSERT(sid != 0, "open_stream should succeed with NULL callbacks");

    (void)flush_to_peer(ss, &c2s);
    (void)flush_to_peer(cs, &s2c);

    yamux_session_free(cs);
    yamux_session_free(ss);
    free(c2s.data);
    free(s2c.data);
    return 0;
}

int main(void) {
    printf("Running yamux unit tests...\n");
    int failed = 0;

    if (test_yamux_inmemory_basic() != 0) failed++;
    if (test_yamux_rst_and_free() != 0) failed++;
    if (test_yamux_window_violation_and_unknown_frames() != 0) failed++;
    if (test_yamux_multiple_streams() != 0) failed++;
    if (test_yamux_ping_pong() != 0) failed++;
    if (test_yamux_goaway() != 0) failed++;
    if (test_yamux_null_callbacks() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


