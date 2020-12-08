#ifndef TINY_FRPC_CONN_WRAPPER_H
#define TINY_FRPC_CONN_WRAPPER_H

int frpc_hal_get_tick();
int frpc_hal_create_tcp(char* ip, int port);
int frpc_hal_tcp_write(int handle, char *buf, int size);
int frpc_hal_tcp_read(int handle, char *buf, int size, int timeout_ms);
void frpc_hal_tcp_close(int handle);


#define FRPC_LOG_LEVEL_ERROR 0
#define FRPC_LOG_LEVEL_WARNING 1
#define FRPC_LOG_LEVEL_INFO 2
#define FRPC_LOG_LEVEL_DEBUG 3
void frpc_log(unsigned char, char*);

#endif //TINY_FRPC_CONN_WRAPPER_H