//
// Created by JiFan on 2020/12/6.
//
#include <string.h>
#include "wrapper.h"
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
    h->next_stream = 0;
    h->start_time = frpc_hal_get_tick();
    h->ping_timeout = YAMUX_PING_TIMEOUT;
    for (int i=0; i<YAMUX_MAX_STREAMS; i++)
        h->stream_list[i] = -1;
    frpc_log(FRPC_LOG_LEVEL_INFO, "init yamux.");
}

int yamux_create_tcp(yamux* h, char* ip, int port){
    h->conn = frpc_hal_create_tcp(ip, port);
    frpc_log_with_int(FRPC_LOG_LEVEL_INFO, "init yamux tcp connection.", h->conn);
    return h->conn;
}

int yamux_session_control_message(yamux* h, unsigned stream_id, char type, unsigned short flags, char* buf){
    h->send_header.stream_id = stream_id;
    h->send_header.type = type;
    h->send_header.flags = flags;
    h->send_header.data_len = 0;
    h->send_header.version = 0;
    yamux_header_pack(buf, &h->send_header);
    frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "send yamux message.", ((int)type)*100 + flags);
    return frpc_hal_tcp_write(h->conn, buf, 12, 100);
}

int yamux_create_stream(yamux* h, char* buf){
    int found = -1;
    for (int i=0; i < YAMUX_MAX_STREAMS; i++){
        if (h->stream_list[i] == -1){
            h->stream_list[i] = h->next_stream;
            h->stream_alive[i] = YAMUX_PING_ALIVE_TIMEOUT;
            found = h->next_stream;
            break;
        }
    }
    if (found < 0) {
        frpc_log(FRPC_LOG_LEVEL_ERROR, "yamux create stream error, streams full.");
        return -1;
    }

    yamux_session_control_message(h, h->next_stream, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_SYN, buf);
    h->next_stream += 2;
    frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux create stream.", h->next_stream);
    return found;
}

int yamux_destory_stream(yamux* h, int s, char* buf){
    yamux_session_control_message(h, s, YAMUX_TYPE_GOAWAY, YAMUX_FLAG_FIN, buf);

    for (int i=0; i < YAMUX_MAX_STREAMS; i++){
        if (h->stream_list[i] == s){
            h->stream_list[i] = -1;
            break;
        }
    }
    frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux destory stream.", s);
    return s;
}

int yamux_destory_tcp(yamux* h){
    frpc_hal_tcp_close(h->conn);
    frpc_log_with_int(FRPC_LOG_LEVEL_INFO, "yamux tcp destory.", h->conn);
    h->conn = 0;
    return 0;
}

int yamux_tick(yamux* h, char* buf, int buf_size, int timeout){
    int found = -1;

    h->end_time = frpc_hal_get_tick();
    h->time_delta = h->end_time - h->start_time;
    h->start_time = h->end_time;
    h->ping_timeout -= h->time_delta;
    if (h->ping_timeout < 0){
        frpc_log(FRPC_LOG_LEVEL_INFO, "yamux sending ping.");
        for (int i=0; i < YAMUX_MAX_STREAMS; i++){
            if (h->stream_list[i] == -1) continue;
            yamux_session_control_message(h, h->stream_list[i], YAMUX_TYPE_PING, YAMUX_FLAG_SYN, buf);
        }
    }
    for (int i=0; i < YAMUX_MAX_STREAMS; i++){
        if (h->stream_list[i] == -1) continue;
        h->stream_alive[i] -= h->time_delta;
        if (h->stream_alive[i] < 0){
            yamux_destory_stream(h, h->stream_list[i], buf);
        }
    }

    int size = frpc_hal_tcp_read(h->conn, buf, buf_size, timeout);
    if (size > 0) {
        if (size < YAMUX_HEADER_SIZE) return -1;
        yamux_header_unpack(&h->receive_header, buf);
        if (h->receive_header.version != 0) return -2;
        if (h->receive_header.flags > YAMUX_FLAG_SYN + YAMUX_FLAG_FIN + YAMUX_FLAG_ACK + YAMUX_FLAG_RST) return -3;
        if (h->receive_header.type > YAMUX_TYPE_GOAWAY) return -4;
        switch (h->receive_header.type){
            case YAMUX_TYPE_DATA:
                if ((h->receive_header.flags & YAMUX_FLAG_ACK) > 0) return 0;
                frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux receive data stream.", h->receive_header.stream_id);
                frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux receive data len.", h->receive_header.data_len);
                return (int)h->receive_header.data_len;
            case YAMUX_TYPE_WINDOW_UPDATE:
                if ((h->receive_header.flags & YAMUX_FLAG_ACK) > 0) return 0;
                yamux_session_control_message(h, h->receive_header.stream_id, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_ACK, buf);
                frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux window update.", h->receive_header.stream_id);
                return 0;
            case YAMUX_TYPE_PING:
                found = -1;
                for (int i=0; i < YAMUX_MAX_STREAMS; i++){
                    if (h->stream_list[i] == h->receive_header.stream_id){
                        found = i;
                    }
                }
                if (found < 0){
                    return 0;
                }
                frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux receive ping.", h->receive_header.stream_id);
                h->stream_alive[found] = YAMUX_PING_ALIVE_TIMEOUT;
                yamux_session_control_message(h, h->receive_header.stream_id, YAMUX_TYPE_PING, YAMUX_FLAG_ACK, buf);
                return 0;
            case YAMUX_TYPE_GOAWAY:
                frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux receive goaway.", h->receive_header.stream_id);
                if ((h->receive_header.flags & YAMUX_FLAG_ACK) > 0) return 0;
                for (int i=0; i < YAMUX_MAX_STREAMS; i++){
                    if (h->stream_list[i] == h->receive_header.stream_id){
                        h->stream_list[i] = -1;
                        break;
                    }
                }
                break;
            default:
                return -5;
        }
    }
    return 0;
}

int yamux_stream_send(yamux* h, int stream, char* buf, int len){
    int found = -1;
    for (int i=0; i < YAMUX_MAX_STREAMS; i++){
        if (h->stream_list[i] == stream){
            found = i;
        }
    }
    if (found < 0) return -1;

    h->send_header.version = 0;
    h->send_header.stream_id = stream;
    h->send_header.data_len = len;
    h->send_header.flags = YAMUX_FLAG_SYN;
    h->send_header.type = YAMUX_TYPE_DATA;
    yamux_header_pack(buf, &h->send_header);

    frpc_log_with_int(FRPC_LOG_LEVEL_DEBUG, "yamux send.", h->receive_header.stream_id);

    return frpc_hal_tcp_write(h->conn, buf, len + YAMUX_HEADER_SIZE, 100);
}