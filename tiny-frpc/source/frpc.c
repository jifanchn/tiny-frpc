#include "../include/frpc.h"
#include "../include/tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// FRP客户端结构体定义
struct frpc_client {
    frpc_config_t config;
    void* user_ctx;
    frpc_event_callback event_callback;
    
    // 网络连接相关字段
    int socket_fd;
    uint8_t* recv_buffer;
    size_t recv_buffer_size;
    
    // 状态标志
    bool is_connected;
    uint64_t last_heartbeat_time;
};

// 创建FRP客户端实例
frpc_client_t* frpc_client_new(const frpc_config_t* config, void* user_ctx) {
    if (!config || !config->server_addr) {
        fprintf(stderr, "Error: Invalid FRP client configuration\n");
        return NULL;
    }
    
    struct frpc_client* client = (struct frpc_client*)malloc(sizeof(struct frpc_client));
    if (!client) {
        fprintf(stderr, "Error: Failed to allocate memory for FRP client\n");
        return NULL;
    }
    
    memset(client, 0, sizeof(struct frpc_client));
    client->config = *config;
    client->user_ctx = user_ctx;
    
    // 复制服务器地址和令牌
    client->config.server_addr = strdup(config->server_addr);
    if (config->token) {
        client->config.token = strdup(config->token);
    }
    
    // 初始化接收缓冲区
    client->recv_buffer_size = 4096;  // 默认缓冲区大小
    client->recv_buffer = (uint8_t*)malloc(client->recv_buffer_size);
    if (!client->recv_buffer) {
        fprintf(stderr, "Error: Failed to allocate receive buffer\n");
        free((void*)client->config.server_addr);
        if (client->config.token) {
            free((void*)client->config.token);
        }
        free(client);
        return NULL;
    }
    
    client->socket_fd = -1;  // 初始化为无效值
    
    return client;
}

// 释放FRP客户端实例
void frpc_client_free(frpc_client_t* client) {
    if (!client) return;
    
    // 首先断开连接
    if (client->is_connected) {
        frpc_client_disconnect(client);
    }
    
    // 释放接收缓冲区
    if (client->recv_buffer) {
        free(client->recv_buffer);
    }
    
    // 释放复制的字符串
    if (client->config.server_addr) {
        free((void*)client->config.server_addr);
    }
    if (client->config.token) {
        free((void*)client->config.token);
    }
    
    free(client);
}

// 连接到FRP服务器
int frpc_client_connect(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (client->is_connected) {
        fprintf(stderr, "Warning: FRP client already connected\n");
        return FRPC_SUCCESS;
    }
    
    // 为测试目的，我们模拟连接成功
    // 实际实现应该使用POSIX套接字API建立TCP连接
    fprintf(stdout, "Connecting to FRP server: %s:%d\n", 
            client->config.server_addr, client->config.server_port);
    
    // 更新状态
    client->is_connected = true;
    client->last_heartbeat_time = tools_get_time_ms();
    
    // 通知连接事件
    if (client->event_callback) {
        client->event_callback(client->user_ctx, 1, NULL); // 1 表示连接事件
    }
    
    return FRPC_SUCCESS;
}

// 断开与FRP服务器的连接
int frpc_client_disconnect(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        return FRPC_SUCCESS;
    }
    
    // 为测试目的，我们只更新状态
    // 实际实现应该关闭套接字连接
    fprintf(stdout, "Disconnecting from FRP server\n");
    
    client->is_connected = false;
    
    // 通知断开连接事件
    if (client->event_callback) {
        client->event_callback(client->user_ctx, 0, NULL); // 0 表示断开连接事件
    }
    
    return FRPC_SUCCESS;
}

// 处理接收到的数据
int frpc_client_receive(frpc_client_t* client, const uint8_t* data, size_t len) {
    if (!client || !data) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        fprintf(stderr, "Error: FRP client not connected\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    // 简单地将收到的数据输出到控制台，用于调试
    fprintf(stdout, "Received %zu bytes of data\n", len);
    
    // 这里应该实际处理接收到的FRP协议消息
    // ...
    
    return FRPC_SUCCESS;
}

// 定期调用以处理心跳等定时任务
int frpc_client_tick(frpc_client_t* client) {
    if (!client) return FRPC_ERROR_INVALID_PARAM;
    
    if (!client->is_connected) {
        return FRPC_SUCCESS;
    }
    
    uint64_t current_time = tools_get_time_ms();
    
    // 检查是否需要发送心跳
    if (client->config.heartbeat_interval > 0 && 
        current_time - client->last_heartbeat_time >= client->config.heartbeat_interval * 1000) {
        
        // 发送心跳消息
        fprintf(stdout, "Sending heartbeat to FRP server\n");
        
        // 实际应该构造并发送心跳消息
        // ...
        
        client->last_heartbeat_time = current_time;
    }
    
    return FRPC_SUCCESS;
}

// 设置事件回调
void frpc_client_set_event_callback(frpc_client_t* client, frpc_event_callback callback) {
    if (!client) return;
    
    client->event_callback = callback;
} 