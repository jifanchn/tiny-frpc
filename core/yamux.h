//
// Created by JiFan on 2020/12/6.
//

#ifndef TINY_FRPC_YAMUX_H
#define TINY_FRPC_YAMUX_H

#define YAMUX_MAX_STREAMS 5
#define YAMUX_PING_TIMEOUT 1000
#define YAMUX_PING_ALIVE_TIMEOUT 30000000

#define YAMUX_HEADER_SIZE (12)
#define YAMUX_VERSION (0)
// type of data
#define YAMUX_TYPE_DATA (0)
#define YAMUX_TYPE_WINDOW_UPDATE (1)
#define YAMUX_TYPE_PING (2)
#define YAMUX_TYPE_GOAWAY (3)
// type of flag
#define YAMUX_FLAG_SYN (1)
#define YAMUX_FLAG_ACK (2)
#define YAMUX_FLAG_FIN (4)
#define YAMUX_FLAG_RST (8)
// window
#define YAMUX_INITIAL_WINDOW_SIZE (256*1024)
// goaway
#define YAMUX_GOAWAY_NORMAL (0)
#define YAMUX_GOAWAY_PROTO_ERROR (1)
#define YAMUX_GOAWAY_INTERNAL_ERROR (2)

typedef struct s_yamux_header {
    char version;                       // byte 0
    char type;                          // byte 1
    unsigned short flags;               // byte 2,3
    unsigned int stream_id;             // byte 4,5,6,7
    unsigned int data_len;              // byte 8,9,10,11
} yamux_header;

typedef struct s_yamux {
    int conn;

    int next_stream;
    int streams;
    yamux_header receive_header, send_header;

    int ping_timeout;
    int next_ping;
    unsigned short start_time;
    unsigned short end_time;
    unsigned short time_delta;

    int stream_list[YAMUX_MAX_STREAMS];
    int session_alive;

    int receive_start, receive_size;
} yamux;

void yamux_header_pack(char*, yamux_header*);
void yamux_header_unpack(yamux_header*, char*);

void yamux_init(yamux* h);
int yamux_create_tcp(yamux* h, char* ip, int port);
int yamux_create_stream(yamux* h, char* buf);
int yamux_destory_stream(yamux* h, int s, char* buf);
int yamux_destory_tcp(yamux* h);

int yamux_tick(yamux* h, char* buf, int buf_size, int* data_start, char* send_buf, int send_buf_size, int timeout);
int yamux_stream_send(yamux* h, int session, char* buf, int len);

#endif //TINY_FRPC_YAMUX_H
