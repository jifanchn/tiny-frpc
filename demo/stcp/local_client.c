#include "common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "wrapper.h"

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [--connect-addr ADDR] [--connect-port PORT] [--message MSG]\n"
            "\n"
            "A tiny TCP client for demo/stcp visitor local-forward mode.\n",
            argv0);
}

int main(int argc, char** argv) {
    const char* connect_addr = "127.0.0.1";
    const char* connect_port = "6000";
    const char* message = "hello\n";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--connect-addr") == 0 && i + 1 < argc) {
            connect_addr = argv[++i];
        } else if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            connect_port = argv[++i];
        } else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
            message = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    int fd = demo_net_connect_tcp(connect_addr, connect_port);
    if (fd < 0) {
        fprintf(stderr, "local_client: connect %s:%s failed (errno=%d)\n", connect_addr, connect_port, errno);
        return 1;
    }

    if (demo_write_all(fd, message, strlen(message)) != 0) {
        fprintf(stderr, "local_client: write failed (errno=%d)\n", errno);
        (void)wrapped_close(fd);
        return 1;
    }

    // Read one reply (best-effort).
    uint8_t buf[4096];
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (sel > 0 && FD_ISSET(fd, &rfds)) {
        ssize_t n = wrapped_read(fd, buf, sizeof(buf));
        if (n > 0) {
            fwrite(buf, 1, (size_t)n, stdout);
            fflush(stdout);
        }
    }

    (void)wrapped_close(fd);
    return 0;
}


