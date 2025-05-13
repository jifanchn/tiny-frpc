#ifndef FRPC_H
#define FRPC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// FRP客户端配置结构体
typedef struct frpc_config_s {
    const char* server_addr;       // FRP服务器地址
    uint16_t server_port;          // FRP服务器端口
    const char* token;             // 认证令牌（如果需要）
    uint32_t heartbeat_interval;   // 心跳间隔（秒）
    bool tls_enable;               // 是否启用TLS
} frpc_config_t;

// FRP客户端实例（不透明指针）
typedef struct frpc_client frpc_client_t;

// 错误码
enum frpc_error_code {
    FRPC_SUCCESS = 0,
    FRPC_ERROR_INVALID_PARAM = -1,
    FRPC_ERROR_MEMORY = -2,
    FRPC_ERROR_NETWORK = -3,
    FRPC_ERROR_AUTH = -4,
    FRPC_ERROR_TIMEOUT = -5,
    FRPC_ERROR_PROTO = -6,
    FRPC_ERROR_INTERNAL = -7
};

// 回调函数类型
// 当网络事件（连接、断开等）发生时调用
typedef void (*frpc_event_callback)(void* user_ctx, int event_type, void* event_data);

// 创建FRP客户端实例
frpc_client_t* frpc_client_new(const frpc_config_t* config, void* user_ctx);

// 释放FRP客户端实例
void frpc_client_free(frpc_client_t* client);

// 连接到FRP服务器
int frpc_client_connect(frpc_client_t* client);

// 断开与FRP服务器的连接
int frpc_client_disconnect(frpc_client_t* client);

// 处理接收到的数据
int frpc_client_receive(frpc_client_t* client, const uint8_t* data, size_t len);

// 定期调用以处理心跳等定时任务
int frpc_client_tick(frpc_client_t* client);

// 设置事件回调
void frpc_client_set_event_callback(frpc_client_t* client, frpc_event_callback callback);

#endif // FRPC_H 