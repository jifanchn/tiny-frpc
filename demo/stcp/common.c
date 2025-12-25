#include "common.h"

#include "wrapper.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int demo_write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = wrapped_write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int demo_read_exact(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = wrapped_read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int demo_net_set_reuseaddr(int fd) {
    int one = 1;
    return wrapped_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
}

int demo_net_listen_tcp(const char* bind_addr, const char* bind_port, int backlog) {
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* rp = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (wrapped_getaddrinfo(bind_addr, bind_port, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = wrapped_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)demo_net_set_reuseaddr(fd);

        if (wrapped_bind(fd, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
            if (wrapped_listen(fd, backlog) == 0) {
                break;
            }
        }

        (void)wrapped_close(fd);
        fd = -1;
    }

    wrapped_freeaddrinfo(res);
    return fd;
}

int demo_net_connect_tcp(const char* server_addr, const char* server_port) {
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* rp = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    if (wrapped_getaddrinfo(server_addr, server_port, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = wrapped_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        if (wrapped_connect(fd, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
            break;
        }

        (void)wrapped_close(fd);
        fd = -1;
    }

    wrapped_freeaddrinfo(res);
    return fd;
}

int demo_set_nonblock(int fd, int nonblock) {
    int flags = wrapped_fcntl(fd, F_GETFL);
    if (flags < 0) {
        return -1;
    }
    if (nonblock) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    if (wrapped_fcntl(fd, F_SETFL, (long)flags) < 0) {
        return -1;
    }
    return 0;
}


