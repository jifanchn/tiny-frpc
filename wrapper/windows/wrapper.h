#ifndef TINY_FRPC_WRAPPER_H
#define TINY_FRPC_WRAPPER_H

/*
 * Windows wrapper for tiny-frpc
 * Provides platform abstraction using Winsock2 and Windows CRT
 */

/* Ensure Windows Vista+ APIs are available (for getaddrinfo) */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

/* Note: Link with ws2_32.lib (-lws2_32 for mingw) */

/* Errno-related wrapper constants (mapped to Winsock errors) */
#define WRAPPED_EINTR      WSAEINTR
#define WRAPPED_ETIMEDOUT  WSAETIMEDOUT
#define WRAPPED_ECONNRESET WSAECONNRESET

/* Type definitions for compatibility */
typedef int socklen_t;
#ifndef ssize_t
typedef SSIZE_T ssize_t;
#endif

/* Socket operations */
int wrapped_socket(int domain, int type, int protocol);
int wrapped_connect(SOCKET sockfd, const struct sockaddr *addr, socklen_t addrlen);
int wrapped_bind(SOCKET sockfd, const struct sockaddr *addr, socklen_t addrlen);
int wrapped_listen(SOCKET sockfd, int backlog);
SOCKET wrapped_accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t wrapped_read(SOCKET fd, void *buf, size_t count);
ssize_t wrapped_write(SOCKET fd, const void *buf, size_t count);
int wrapped_close(SOCKET fd);
int wrapped_setsockopt(SOCKET sockfd, int level, int optname, const char *optval, socklen_t optlen);
int wrapped_fcntl(SOCKET fd, int cmd, ...);

/* fcntl commands (not native to Windows, emulated) */
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x0004

/* I/O multiplexing */
int wrapped_select(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, struct timeval *timeout);

/* Time operations */
time_t wrapped_time(time_t *tloc);
uint64_t wrapped_get_time_ms(void);

/* Character classification */
int wrapped_isspace(int c);

/* Get last error code (wrapper for WSAGetLastError) */
int wrapped_get_errno(void);

/* Set last error code (wrapper for WSASetLastError) */
void wrapped_set_errno(int err);

/* Address resolution */
int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res);
void wrapped_freeaddrinfo(struct addrinfo *res);

/* Winsock initialization (must be called before any socket operations) */
int wrapped_winsock_init(void);
void wrapped_winsock_cleanup(void);

#endif /* TINY_FRPC_WRAPPER_H */
