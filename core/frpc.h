//
// Created by JiFan on 2020/12/6.
//

#ifndef TINY_FRPC_FRPC_H
#define TINY_FRPC_FRPC_H

#include "yamux.h"

#define FRPC_TCP_READ_BUF_LEN (1024)
#define FRPC_TCP_WRITE_BUF_LEN (1024)
#define FRPC_DOMAIN_NAME_LEN (32)
#define FRPC_TCP_READ_TIMEOUT (1000)
#define FRPC_IDLE_TIMEOUT (120000)
#define FRPC_PING_TIMEOUT (30000)

typedef struct s_frpc_tcp_handle {
    char read_buf[FRPC_TCP_READ_BUF_LEN];
    char write_buf[FRPC_TCP_WRITE_BUF_LEN];

    yamux mux;
    char frps_ip[32];
    int frps_port;
    char mux_domain_name[FRPC_DOMAIN_NAME_LEN];

    int admin_stream;
    int timeout;
    int ping_timeout;
    unsigned short start_time;
    unsigned short end_time;
    unsigned short time_delta;

}frpc_tcp_handle;

void frpc_loop(frpc_tcp_handle*);

#endif //TINY_FRPC_FRPC_H
