#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

#include "../wrapper/linux/wrapper.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

static int test_getaddrinfo_basic(void) {
    printf("\n=== Testing wrapped_getaddrinfo ===\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo* res = NULL;
    int ret = wrapped_getaddrinfo("127.0.0.1", "80", &hints, &res);
    TEST_ASSERT(ret == 0, "wrapped_getaddrinfo should succeed for 127.0.0.1:80");
    TEST_ASSERT(res != NULL, "wrapped_getaddrinfo should return a non-null result");

    wrapped_freeaddrinfo(res);
    return 0;
}

static int test_tcp_roundtrip(void) {
    printf("\n=== Testing TCP roundtrip via wrapper ===\n");

    int listen_fd = wrapped_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listen_fd >= 0, "wrapped_socket should create listen socket");

    int one = 1;
    (void)wrapped_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(0); // ephemeral

    TEST_ASSERT(wrapped_bind(listen_fd, (const struct sockaddr*)&addr, sizeof(addr)) == 0,
                "wrapped_bind should succeed");
    TEST_ASSERT(wrapped_listen(listen_fd, 1) == 0, "wrapped_listen should succeed");

    // Get actual port (using getsockname syscall directly, wrapper only wraps core syscalls)
    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    TEST_ASSERT(getsockname(listen_fd, (struct sockaddr*)&bound, &bound_len) == 0,
                "getsockname should succeed");
    uint16_t port = ntohs(bound.sin_port);
    TEST_ASSERT(port != 0, "server should have a non-zero port");

    int client_fd = wrapped_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_fd >= 0, "wrapped_socket should create client socket");

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr("127.0.0.1");
    srv.sin_port = htons(port);

    TEST_ASSERT(wrapped_connect(client_fd, (const struct sockaddr*)&srv, sizeof(srv)) == 0,
                "wrapped_connect should succeed");

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int server_fd = wrapped_accept(listen_fd, (struct sockaddr*)&peer, &peer_len);
    TEST_ASSERT(server_fd >= 0, "wrapped_accept should succeed");

    const char* ping = "ping";
    const char* pong = "pong";
    char buf[16];
    memset(buf, 0, sizeof(buf));

    TEST_ASSERT(wrapped_write(client_fd, ping, strlen(ping)) == (ssize_t)strlen(ping),
                "wrapped_write(client->server) should write all bytes");

    ssize_t n = wrapped_read(server_fd, buf, sizeof(buf) - 1);
    TEST_ASSERT(n == (ssize_t)strlen(ping), "wrapped_read(server) should read ping length");
    TEST_ASSERT(strncmp(buf, ping, strlen(ping)) == 0, "server should receive 'ping'");

    memset(buf, 0, sizeof(buf));
    TEST_ASSERT(wrapped_write(server_fd, pong, strlen(pong)) == (ssize_t)strlen(pong),
                "wrapped_write(server->client) should write all bytes");

    n = wrapped_read(client_fd, buf, sizeof(buf) - 1);
    TEST_ASSERT(n == (ssize_t)strlen(pong), "wrapped_read(client) should read pong length");
    TEST_ASSERT(strncmp(buf, pong, strlen(pong)) == 0, "client should receive 'pong'");

    wrapped_close(server_fd);
    wrapped_close(client_fd);
    wrapped_close(listen_fd);
    return 0;
}

static int test_fcntl_nonblock(void) {
    printf("\n=== Testing wrapped_fcntl (O_NONBLOCK) ===\n");

    int fd = wrapped_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(fd >= 0, "wrapped_socket should create socket");

    int flags = wrapped_fcntl(fd, F_GETFL);
    TEST_ASSERT(flags >= 0, "wrapped_fcntl(F_GETFL) should succeed");

    int ret = wrapped_fcntl(fd, F_SETFL, (long)(flags | O_NONBLOCK));
    TEST_ASSERT(ret == 0, "wrapped_fcntl(F_SETFL, O_NONBLOCK) should succeed");

    int flags2 = wrapped_fcntl(fd, F_GETFL);
    TEST_ASSERT(flags2 >= 0, "wrapped_fcntl(F_GETFL) should succeed after set");
    TEST_ASSERT((flags2 & O_NONBLOCK) != 0, "O_NONBLOCK should be set");

    wrapped_close(fd);
    return 0;
}

static int test_error_paths(void) {
    printf("\n=== Testing wrapper error paths ===\n");

    // Invalid fd should fail
    TEST_ASSERT(wrapped_close(-1) < 0, "wrapped_close(-1) should fail");
    TEST_ASSERT(wrapped_fcntl(-1, F_GETFL) < 0, "wrapped_fcntl(-1, F_GETFL) should fail");

    // wrapped_socket error branch
    TEST_ASSERT(wrapped_socket(-1, -1, -1) < 0, "wrapped_socket(invalid) should fail");

    int one = 1;
    TEST_ASSERT(wrapped_setsockopt(-1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0,
                "wrapped_setsockopt(-1, ...) should fail");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(1);

    TEST_ASSERT(wrapped_connect(-1, (const struct sockaddr*)&addr, sizeof(addr)) < 0,
                "wrapped_connect(-1, ...) should fail");
    TEST_ASSERT(wrapped_bind(-1, (const struct sockaddr*)&addr, sizeof(addr)) < 0,
                "wrapped_bind(-1, ...) should fail");
    TEST_ASSERT(wrapped_listen(-1, 1) < 0, "wrapped_listen(-1, ...) should fail");

    // wrapped_accept error branch
    struct sockaddr_in dummy;
    socklen_t dummy_len = sizeof(dummy);
    memset(&dummy, 0, sizeof(dummy));
    TEST_ASSERT(wrapped_accept(-1, (struct sockaddr*)&dummy, &dummy_len) < 0,
                "wrapped_accept(-1, ...) should fail");

    // wrapped_write error branch
    TEST_ASSERT(wrapped_write(-1, "x", 1) < 0, "wrapped_write(-1, ...) should fail");

    // wrapped_fcntl branch for F_GETLK/F_SETLK/F_SETLKW
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    TEST_ASSERT(wrapped_fcntl(-1, F_GETLK, &fl) < 0, "wrapped_fcntl(-1, F_GETLK, ...) should fail");

    // wrapped_getaddrinfo error branch
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo* res = NULL;
    TEST_ASSERT(wrapped_getaddrinfo("127.0.0.1", "notaport", &hints, &res) != 0,
                "wrapped_getaddrinfo(invalid service) should fail");
    if (res) {
        wrapped_freeaddrinfo(res);
    }

    return 0;
}

int main(void) {
    printf("Running wrapper tests...\n");
    int failed = 0;

    if (test_getaddrinfo_basic() != 0) failed++;
    if (test_tcp_roundtrip() != 0) failed++;
    if (test_fcntl_nonblock() != 0) failed++;
    if (test_error_paths() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


