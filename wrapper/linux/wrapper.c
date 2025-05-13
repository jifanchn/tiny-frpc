#define _GNU_SOURCE // 为了获取更多的POSIX扩展功能
#include "wrapper.h"
#include <stdarg.h> // For va_list, va_start, va_end in wrapped_fcntl
#include <stdio.h>  // For perror, printf (temporary for debugging)

// 简单的包装函数，只是调用原始函数并可以打印错误信息
// 将来，这些可能会有更复杂的错误处理或日志记录

int wrapped_socket(int domain, int type, int protocol) {
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        perror("socket");
    }
    return fd;
}

int wrapped_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = connect(sockfd, addr, addrlen);
    if (ret < 0) {
        perror("connect");
    }
    return ret;
}

int wrapped_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = bind(sockfd, addr, addrlen);
    if (ret < 0) {
        perror("bind");
    }
    return ret;
}

int wrapped_listen(int sockfd, int backlog) {
    int ret = listen(sockfd, backlog);
    if (ret < 0) {
        perror("listen");
    }
    return ret;
}

int wrapped_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int fd = accept(sockfd, addr, addrlen);
    if (fd < 0) {
        perror("accept");
    }
    return fd;
}

ssize_t wrapped_read(int fd, void *buf, size_t count) {
    ssize_t n = read(fd, buf, count);
    // 对于read，我们不使用perror，因为返回0或-1（当EAGAIN/EWOULDBLOCK时）可能是正常的
    return n;
}

ssize_t wrapped_write(int fd, const void *buf, size_t count) {
    ssize_t n = write(fd, buf, count);
    if (n < 0) {
        perror("write");
    }
    return n;
}

int wrapped_close(int fd) {
    int ret = close(fd);
    if (ret < 0) {
        perror("close");
    }
    return ret;
}

int wrapped_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    int ret = setsockopt(sockfd, level, optname, optval, optlen);
    if (ret < 0) {
        perror("setsockopt");
    }
    return ret;
}

int wrapped_fcntl(int fd, int cmd, ...) {
    va_list args;
    long argl; // POSIX fcntl的第三个参数通常是long或指针
    int ret;

    va_start(args, cmd);

    // F_DUPFD, F_GETFD, F_GETFL, F_GETOWN不需要第三个参数（或者F_DUPFD用int）
    // F_SETFD, F_SETFL, F_SETOWN需要int/long参数
    // F_GETLK, F_SETLK, F_SETLKW需要struct flock*
    // 为简单起见，我们假设arg是long类型的，适用于需要它的命令
    // 更健壮的包装器会检查'cmd'的具体值
    if (cmd == F_DUPFD || cmd == F_SETFD || cmd == F_SETFL || cmd == F_SETOWN) {
        argl = va_arg(args, long); // 或int，但long对提升更安全
        ret = fcntl(fd, cmd, argl);
    } else if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
        // 这是一个简化。实际类型是struct flock*
        // 目前，如果用户想使用这些，他们应该直接调用fcntl
        // 或者这个包装器需要更复杂
        // 我们主要关注F_SETFL用于O_NONBLOCK
        void* argp = va_arg(args, void*);
        ret = fcntl(fd, cmd, argp);
    } else {
        ret = fcntl(fd, cmd); // 像F_GETFD, F_GETFL这样的命令
    }
    
    va_end(args);

    if (ret < 0) {
        perror("fcntl");
    }
    return ret;
}

int wrapped_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                        struct addrinfo **res) {
    int ret = getaddrinfo(node, service, hints, res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
    }
    return ret;
}

void wrapped_freeaddrinfo(struct addrinfo *res) {
    freeaddrinfo(res);
} 