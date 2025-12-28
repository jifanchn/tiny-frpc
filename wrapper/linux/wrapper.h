#ifndef TINY_FRPC_WRAPPER_H
#define TINY_FRPC_WRAPPER_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h> // For getaddrinfo
#include <fcntl.h> // For fcntl
#include <sys/select.h> // For select
#include <time.h>  // For time_t
#include <errno.h> // For errno constants

// Errno-related wrapper constants (for embedded portability)
#define WRAPPED_EINTR      EINTR
#define WRAPPED_ETIMEDOUT  ETIMEDOUT
#define WRAPPED_ECONNRESET ECONNRESET
#define WRAPPED_EAGAIN     EAGAIN
#define WRAPPED_EWOULDBLOCK EWOULDBLOCK

// Socket operations
int wrapped_socket(int domain, int type, int protocol);
int wrapped_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int wrapped_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int wrapped_listen(int sockfd, int backlog);
int wrapped_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t wrapped_read(int fd, void *buf, size_t count);
ssize_t wrapped_write(int fd, const void *buf, size_t count);
int wrapped_close(int fd);
int wrapped_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int wrapped_fcntl(int fd, int cmd, ... /* arg */ );

// I/O multiplexing
// Portable timeval type - platform implementations define the actual type
typedef struct timeval wrapped_timeval_t;
typedef time_t wrapped_time_t;

int wrapped_select(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, wrapped_timeval_t *timeout);

// Time operations
wrapped_time_t wrapped_time(wrapped_time_t *tloc);
void wrapped_usleep(unsigned int usec);
uint64_t wrapped_get_time_ms(void);

// Character classification
int wrapped_isspace(int c);

// Get last error code (wrapper for errno)
int wrapped_get_errno(void);

// Set last error code (wrapper for errno)
void wrapped_set_errno(int err);

// Address resolution
int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res);
void wrapped_freeaddrinfo(struct addrinfo *res);

#endif //TINY_FRPC_WRAPPER_H 