//
// Created by JiFan on 2020/12/6.
//
#include <string.h>
#include "conn_wrapper.h"
#include "yamux.h"

void yamux_header_pack(char* s, yamux_header* h){
    // we can use union here, but some little endia cpu can not work
    s[0] = h->version;
    s[1] = h->type;
    s[2] = (h->flags >> 8) & 0xFF;
    s[3] = h->flags & 0xFF;
    s[4] = (h->stream_id >> 24) & 0xFF;
    s[5] = (h->stream_id >> 16) & 0xFF;
    s[6] = (h->stream_id >> 8) & 0xFF;
    s[7] = h->stream_id & 0xFF;
    s[8] = (h->data_len >> 24) & 0xFF;
    s[9] = (h->data_len >> 16) & 0xFF;
    s[10] = (h->data_len >> 8) & 0xFF;
    s[11] = h->data_len & 0xFF;
}

void yamux_header_unpack(yamux_header* h, char* s){
    h->version = s[0];
    h->type = s[1];
    h->flags = ((unsigned short)s[2] << 8) | (unsigned short)s[3];
    h->stream_id = ((unsigned int)s[4] << 24) | ((unsigned int)s[5] << 16) |
            ((unsigned int)s[6] << 8) | ((unsigned int)s[7] << 9);
    h->data_len = ((unsigned int)s[8] << 24) | ((unsigned int)s[9] << 16) |
                   ((unsigned int)s[10] << 8) | ((unsigned int)s[11] << 9);
}

void yamux_init(yamux* h){
    memset(h, 0, sizeof(yamux));
    h->next_stream = 1;
}

int yamux_create_tcp(yamux* h, char* ip, int port){
    h->conn = frpc_hal_create_tcp(ip, port);
    return h->conn;
}

int yamux_create_stream(yamux* h){

}

int yamux_destory_stream(yamux* h, int s){

}

int yamux_destory_tcp(yamux* h){

}

int yamux_tick(yamux* h, char* buf, int buf_size, int timeout){

}

int yamux_stream_send(yamux* h, int session, char* buf, int len){

}