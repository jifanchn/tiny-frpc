//
// Created by JiFan on 2020/12/6.
//
#include "conn_wrapper.h"
#include "yamux.h"
#include "frpc_common.h"

void frpc_init(frpc_tcp_handle* h){
    yamux_init(&h->mux);
}

int frpc_login(frpc_tcp_handle* h){
    return 0;
}

int frpc_send_config(frpc_tcp_handle *h){
    if (h->admin_session < 0){

    }
    return 0;
}

int frpc_ping(frpc_tcp_handle* h){
   return 0;
}

void frpc_loop(frpc_tcp_handle* h){
    unsigned char tcp_read_buf[FRPC_TCP_READ_BUF_LEN];
    unsigned char tcp_write_buf[FRPC_TCP_WRITE_BUF_LEN];
    int result;

    frpc_init(h);

    result = yamux_create_tcp(&h->mux, h->frps_ip, h->frps_port);
    if (result < 0){
        frpc_log(FRPC_LOG_LEVEL_ERROR, "yamux create tcp failed.");
        return;
    }

    h->admin_session = yamux_create_session(&h->mux);
    if (h->admin_session < 0){
        frpc_log(FRPC_LOG_LEVEL_ERROR, "yamux create admin session failed.");
        return;
    }

    result = frpc_login(h);
    if (result < 0){
        frpc_log(FRPC_LOG_LEVEL_ERROR, "frpc login failed.");
        return;
    }

    h->timeout = FRPC_IDLE_TIMEOUT;
    h->ping_timeout = FRPC_PING_TIMEOUT;
    h->start_time = frpc_hal_get_tick();
    h->end_time = h->start_time;
    h->time_delta = 0;
    while (h->timeout > 0) {
        h->time_delta = h->end_time - h->start_time;
        h->timeout -= h->time_delta;
        h->ping_timeout -= h->time_delta;
        h->start_time = h->end_time;
        if (h->timeout < 0) {
            frpc_log(FRPC_LOG_LEVEL_ERROR, "frpc timed out.");
            yamux_destory_tcp(&h->mux);
            return;
        }
        if (h->ping_timeout < 0) {
            frpc_log(FRPC_LOG_LEVEL_DEBUG, "frpc send ping message.");
            frpc_ping(h);
            h->end_time = frpc_hal_get_tick();
            continue;
        }

        result = yamux_tick(&h->mux, h->read_buf, FRPC_TCP_READ_BUF_LEN, FRPC_TCP_READ_TIMEOUT);
        if (result < 0){
            h->end_time = frpc_hal_get_tick();
            continue;
        }
        h->timeout = FRPC_IDLE_TIMEOUT;
    }
}