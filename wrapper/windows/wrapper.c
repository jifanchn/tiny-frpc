/*
 * Windows wrapper implementation for tiny-frpc
 * Provides platform abstraction using Winsock2 and Windows CRT
 */

#include "wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

/* Static flag to track Winsock initialization */
static int g_winsock_initialized = 0;

/* Verbose logging (quiet by default; set TINY_FRPC_VERBOSE=1 to enable) */
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

/* Initialize Winsock - must be called before any socket operations */
int wrapped_winsock_init(void) {
    if (g_winsock_initialized) {
        return 0;
    }
    
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "WSAStartup failed: %d\n", result);
        }
        return -1;
    }
    g_winsock_initialized = 1;
    return 0;
}

void wrapped_winsock_cleanup(void) {
    if (g_winsock_initialized) {
        WSACleanup();
        g_winsock_initialized = 0;
    }
}

int wrapped_socket(int domain, int type, int protocol) {
    /* Auto-initialize Winsock on first socket call */
    if (!g_winsock_initialized) {
        if (wrapped_winsock_init() != 0) {
            return -1;
        }
    }
    
    SOCKET s = socket(domain, type, protocol);
    if (s == INVALID_SOCKET) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    /* Cast SOCKET to int for API compatibility (works for small socket values) */
    return (int)s;
}

int wrapped_connect(SOCKET sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = connect(sockfd, addr, addrlen);
    if (ret == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "connect failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return 0;
}

int wrapped_bind(SOCKET sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = bind(sockfd, addr, addrlen);
    if (ret == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return 0;
}

int wrapped_listen(SOCKET sockfd, int backlog) {
    int ret = listen(sockfd, backlog);
    if (ret == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return 0;
}

SOCKET wrapped_accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    SOCKET s = accept(sockfd, addr, addrlen);
    if (s == INVALID_SOCKET) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        }
    }
    return s;
}

ssize_t wrapped_read(SOCKET fd, void *buf, size_t count) {
    int n = recv(fd, (char*)buf, (int)count, 0);
    if (n == SOCKET_ERROR) {
        /* Don't print error for WSAEWOULDBLOCK - that's normal for non-blocking */
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && wrapper_verbose_enabled()) {
            fprintf(stderr, "recv failed: %d\n", err);
        }
        return -1;
    }
    return n;
}

ssize_t wrapped_write(SOCKET fd, const void *buf, size_t count) {
    int n = send(fd, (const char*)buf, (int)count, 0);
    if (n == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "send failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return n;
}

int wrapped_close(SOCKET fd) {
    int ret = closesocket(fd);
    if (ret == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "closesocket failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return 0;
}

int wrapped_setsockopt(SOCKET sockfd, int level, int optname, const char *optval, socklen_t optlen) {
    int ret = setsockopt(sockfd, level, optname, optval, optlen);
    if (ret == SOCKET_ERROR) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
        }
        return -1;
    }
    return 0;
}

int wrapped_fcntl(SOCKET fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    
    int ret = 0;
    
    if (cmd == F_GETFL) {
        /* Windows doesn't have fcntl flags; return 0 */
        ret = 0;
    } else if (cmd == F_SETFL) {
        long flags = va_arg(args, long);
        if (flags & O_NONBLOCK) {
            /* Set socket to non-blocking mode */
            u_long mode = 1;
            if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) {
                if (wrapper_verbose_enabled()) {
                    fprintf(stderr, "ioctlsocket(FIONBIO) failed: %d\n", WSAGetLastError());
                }
                ret = -1;
            }
        } else {
            /* Set socket to blocking mode */
            u_long mode = 0;
            if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) {
                if (wrapper_verbose_enabled()) {
                    fprintf(stderr, "ioctlsocket(FIONBIO) failed: %d\n", WSAGetLastError());
                }
                ret = -1;
            }
        }
    } else {
        /* Unsupported command */
        ret = -1;
    }
    
    va_end(args);
    return ret;
}

int wrapped_select(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, struct timeval *timeout) {
    /* nfds is ignored on Windows; Winsock select uses fd_set count internally */
    (void)nfds;
    int ret = select(0, readfds, writefds, exceptfds, timeout);
    if (ret == SOCKET_ERROR) {
        /* Don't log for WSAEINTR - caller handles it */
        return -1;
    }
    return ret;
}

time_t wrapped_time(time_t *tloc) {
    return time(tloc);
}

uint64_t wrapped_get_time_ms(void) {
    return GetTickCount64();
}

int wrapped_isspace(int c) {
    return isspace(c);
}

int wrapped_get_errno(void) {
    return WSAGetLastError();
}

void wrapped_set_errno(int err) {
    WSASetLastError(err);
}

int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res) {
    /* Auto-initialize Winsock */
    if (!g_winsock_initialized) {
        if (wrapped_winsock_init() != 0) {
            return -1;
        }
    }
    
    int ret = getaddrinfo(node, service, hints, res);
    if (ret != 0) {
        if (wrapper_verbose_enabled()) {
            fprintf(stderr, "getaddrinfo failed: %d\n", ret);
        }
    }
    return ret;
}

void wrapped_freeaddrinfo(struct addrinfo *res) {
    freeaddrinfo(res);
}
