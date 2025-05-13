#ifndef FRPC_STCP_H
#define FRPC_STCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "frpc.h"   // 包含基本FRP客户端定义
#include "yamux.h"  // 包含yamux会话和流定义

// STCP代理类型
typedef enum {
    FRPC_STCP_ROLE_SERVER = 0,  // STCP服务端
    FRPC_STCP_ROLE_VISITOR = 1  // STCP访问端
} frpc_stcp_role_t;

// STCP代理配置
typedef struct frpc_stcp_config_s {
    frpc_stcp_role_t role;       // 代理角色（服务端或访问端）
    const char* proxy_name;      // 代理名称
    const char* sk;              // 共享密钥
    
    // 服务端特有配置
    const char* local_addr;      // 本地服务地址
    uint16_t local_port;         // 本地服务端口
    
    // 访问端特有配置
    const char* server_name;     // 要连接的服务端名称
    const char* bind_addr;       // 本地绑定地址
    uint16_t bind_port;          // 本地绑定端口
    
    // 回调函数
    int (*on_data)(void* user_ctx, uint8_t* data, size_t len);
    int (*on_write)(void* user_ctx, uint8_t* data, size_t len);
    void (*on_connection)(void* user_ctx, int connected, int error_code);
} frpc_stcp_config_t;

// STCP代理实例（不透明指针）
typedef struct frpc_stcp_proxy frpc_stcp_proxy_t;

// 创建STCP代理
frpc_stcp_proxy_t* frpc_stcp_proxy_new(frpc_client_t* client, 
                                       const frpc_stcp_config_t* config, 
                                       void* user_ctx);

// 释放STCP代理
void frpc_stcp_proxy_free(frpc_stcp_proxy_t* proxy);

// 启动STCP代理
int frpc_stcp_proxy_start(frpc_stcp_proxy_t* proxy);

// 停止STCP代理
int frpc_stcp_proxy_stop(frpc_stcp_proxy_t* proxy);

// 发送数据（针对访问端）
int frpc_stcp_send(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len);

// 接收数据处理
int frpc_stcp_receive(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len);

// 处理定期任务
int frpc_stcp_tick(frpc_stcp_proxy_t* proxy);

// Visitor特有接口
// 建立与服务器的连接
int frpc_stcp_visitor_connect(frpc_stcp_proxy_t* proxy);

// 关闭与服务器的连接
int frpc_stcp_visitor_disconnect(frpc_stcp_proxy_t* proxy);

// Server特有接口
// 注册本地服务
int frpc_stcp_server_register(frpc_stcp_proxy_t* proxy);

// 设置允许连接的用户列表
int frpc_stcp_server_set_allow_users(frpc_stcp_proxy_t* proxy, const char** users, size_t count);

// 设置数据传输参数
typedef struct frpc_stcp_transport_config_s {
    bool use_encryption;         // 是否使用加密
    bool use_compression;        // 是否使用压缩
} frpc_stcp_transport_config_t;

// 设置传输配置
int frpc_stcp_set_transport_config(frpc_stcp_proxy_t* proxy, const frpc_stcp_transport_config_t* config);

#endif // FRPC_STCP_H 