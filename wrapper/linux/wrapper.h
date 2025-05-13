#ifndef TINY_FRPC_WRAPPER_H
#define TINY_FRPC_WRAPPER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h> // For getaddrinfo
#include <fcntl.h> // For fcntl

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

// Address resolution
int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res);
void wrapped_freeaddrinfo(struct addrinfo *res);

#endif //TINY_FRPC_WRAPPER_H 