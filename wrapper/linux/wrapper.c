#define _GNU_SOURCE // Enable GNU extensions for broader POSIX feature availability
#include "wrapper.h"
#include <stdarg.h> // For va_list, va_start, va_end in wrapped_fcntl
#include <stdio.h>  // For perror, printf (temporary for debugging)
#include <stdlib.h> // For getenv
#include <ctype.h>  // For isspace

// Thin wrapper functions around POSIX syscalls.
// In the future, these may grow more robust error handling or logging.
//
// Quiet by default; set TINY_FRPC_VERBOSE=1 to print perror/getaddrinfo details.
static int wrapper_verbose_enabled(void) {
    static int inited = 0;
    static int enabled = 0;
    if (!inited) {
        const char* v = getenv("TINY_FRPC_VERBOSE");
        enabled = (v && v[0] != '\0' && v[0] != '0');
        inited = 1;
    }
    return enabled;
}

int wrapped_socket(int domain, int type, int protocol) {
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        if (wrapper_verbose_enabled()) {
            perror("socket");
        }
    }
    return fd;
}

int wrapped_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = connect(sockfd, addr, addrlen);
    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("connect");
        }
    }
    return ret;
}

int wrapped_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = bind(sockfd, addr, addrlen);
    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("bind");
        }
    }
    return ret;
}

int wrapped_listen(int sockfd, int backlog) {
    int ret = listen(sockfd, backlog);
    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("listen");
        }
    }
    return ret;
}

int wrapped_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int fd = accept(sockfd, addr, addrlen);
    if (fd < 0) {
        if (wrapper_verbose_enabled()) {
            perror("accept");
        }
    }
    return fd;
}

ssize_t wrapped_read(int fd, void *buf, size_t count) {
    ssize_t n = read(fd, buf, count);
    // For read(), we don't call perror(): 0 or -1 (EAGAIN/EWOULDBLOCK) can be normal.
    return n;
}

ssize_t wrapped_write(int fd, const void *buf, size_t count) {
    ssize_t n = write(fd, buf, count);
    if (n < 0) {
        if (wrapper_verbose_enabled()) {
            perror("write");
        }
    }
    return n;
}

int wrapped_close(int fd) {
    int ret = close(fd);
    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("close");
        }
    }
    return ret;
}

int wrapped_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    int ret = setsockopt(sockfd, level, optname, optval, optlen);
    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("setsockopt");
        }
    }
    return ret;
}

int wrapped_fcntl(int fd, int cmd, ...) {
    va_list args;
    long argl; // The 3rd argument of fcntl is usually a long or a pointer
    int ret;

    va_start(args, cmd);

    // Some commands take a 3rd argument, some don't.
    // - F_DUPFD/F_SETFD/F_SETFL/F_SETOWN take an integer/long argument.
    // - F_GETLK/F_SETLK/F_SETLKW take a `struct flock *`.
    // For simplicity, we branch on `cmd` here.
    if (cmd == F_DUPFD || cmd == F_SETFD || cmd == F_SETFL || cmd == F_SETOWN) {
        argl = va_arg(args, long); // could be int; long is safer for promotions
        ret = fcntl(fd, cmd, argl);
    } else if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
        // Simplified: actual type is `struct flock *`.
        // We primarily care about F_SETFL (e.g. O_NONBLOCK) for this project.
        void* argp = va_arg(args, void*);
        ret = fcntl(fd, cmd, argp);
    } else {
        ret = fcntl(fd, cmd); // e.g. F_GETFD, F_GETFL
    }
    
    va_end(args);

    if (ret < 0) {
        if (wrapper_verbose_enabled()) {
            perror("fcntl");
        }
    }
    return ret;
}

int wrapped_select(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, struct timeval *timeout) {
    int ret = select(nfds, readfds, writefds, exceptfds, timeout);
    // Don't call perror on error; EINTR is expected and caller handles it.
    return ret;
}

time_t wrapped_time(time_t *tloc) {
    return time(tloc);
}

int wrapped_isspace(int c) {
    return isspace(c);
}

int wrapped_get_errno(void) {
    return errno;
}

void wrapped_set_errno(int err) {
    errno = err;
}

int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res) {
    int ret = getaddrinfo(node, service, hints, res);
    if (ret != 0) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        }
    }
    return ret;
}

void wrapped_freeaddrinfo(struct addrinfo *res) {
    freeaddrinfo(res);
} 