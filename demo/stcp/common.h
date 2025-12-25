#ifndef DEMO_STCP_COMMON_H
#define DEMO_STCP_COMMON_H

#include <stddef.h>

int demo_write_all(int fd, const void* buf, size_t len);
int demo_read_exact(int fd, void* buf, size_t len);

int demo_net_listen_tcp(const char* bind_addr, const char* bind_port, int backlog);
int demo_net_connect_tcp(const char* server_addr, const char* server_port);

int demo_set_nonblock(int fd, int nonblock);

#endif // DEMO_STCP_COMMON_H


