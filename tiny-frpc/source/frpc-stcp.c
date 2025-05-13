#include "../include/frpc-stcp.h"
#include "../include/tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// STCP代理结构体定义
struct frpc_stcp_proxy {
    frpc_stcp_config_t config;
    frpc_client_t* client;
    void* user_ctx;
    
    // yamux相关字段
    yamux_session_t* yamux_session;
    uint32_t active_stream_id;
    
    // 传输配置
    bool use_encryption;
    bool use_compression;
    
    // 服务端特有字段
    char** allow_users;
    size_t allow_users_count;
    
    // 状态标志
    bool is_started;
    bool is_connected;
    bool is_registered;    // 对于server，表示是否已注册到frps
};

// 创建STCP代理
frpc_stcp_proxy_t* frpc_stcp_proxy_new(frpc_client_t* client, 
                                       const frpc_stcp_config_t* config, 
                                       void* user_ctx) {
    if (!client || !config) {
        fprintf(stderr, "Error: Invalid STCP proxy parameters\n");
        return NULL;
    }
    
    struct frpc_stcp_proxy* proxy = (struct frpc_stcp_proxy*)malloc(sizeof(struct frpc_stcp_proxy));
    if (!proxy) {
        fprintf(stderr, "Error: Failed to allocate memory for STCP proxy\n");
        return NULL;
    }
    
    memset(proxy, 0, sizeof(struct frpc_stcp_proxy));
    proxy->config = *config;
    proxy->client = client;
    proxy->user_ctx = user_ctx;
    
    // 复制字符串字段
    proxy->config.proxy_name = strdup(config->proxy_name);
    proxy->config.sk = strdup(config->sk);
    
    if (config->role == FRPC_STCP_ROLE_SERVER) {
        if (config->local_addr) {
            proxy->config.local_addr = strdup(config->local_addr);
        }
    } else { // VISITOR
        if (config->server_name) {
            proxy->config.server_name = strdup(config->server_name);
        }
        if (config->bind_addr) {
            proxy->config.bind_addr = strdup(config->bind_addr);
        }
    }
    
    return proxy;
}

// 释放STCP代理
void frpc_stcp_proxy_free(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return;
    
    // 先停止代理
    if (proxy->is_started) {
        frpc_stcp_proxy_stop(proxy);
    }
    
    // 释放复制的字符串
    if (proxy->config.proxy_name) free((void*)proxy->config.proxy_name);
    if (proxy->config.sk) free((void*)proxy->config.sk);
    
    if (proxy->config.role == FRPC_STCP_ROLE_SERVER) {
        if (proxy->config.local_addr) free((void*)proxy->config.local_addr);
        
        // 释放允许的用户列表
        if (proxy->allow_users) {
            for (size_t i = 0; i < proxy->allow_users_count; i++) {
                if (proxy->allow_users[i]) {
                    free(proxy->allow_users[i]);
                }
            }
            free(proxy->allow_users);
        }
    } else { // VISITOR
        if (proxy->config.server_name) free((void*)proxy->config.server_name);
        if (proxy->config.bind_addr) free((void*)proxy->config.bind_addr);
    }
    
    free(proxy);
}

// 生成身份验证密钥
// 模拟 util.GetAuthKey(sk, timestamp)
static char* get_auth_key(const char* sk, int64_t timestamp) {
    // 简化版本，实际应该使用加密哈希
    // 对应 Go 代码中的 util.GetAuthKey 函数
    char* buffer = (char*)malloc(128);
    if (!buffer) return NULL;
    
    snprintf(buffer, 128, "%s%lld", sk, timestamp);
    return buffer;
}

// Yamux会话相关回调函数
static int on_stream_data_wrapper(void* user_data, const uint8_t* data, size_t len) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)user_data;
    if (!proxy) return -1;
    
    // 调用用户提供的数据回调
    if (proxy->config.on_data) {
        return proxy->config.on_data(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    return 0;
}

static void on_stream_close_wrapper(void* user_data, bool by_remote, uint32_t error_code) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)user_data;
    if (!proxy) return;
    
    // 如果关闭的是活跃流，则清除活跃流ID
    // 注意：这里我们无法确定具体的流ID，因此在其他地方需要处理活跃流ID的清理
    fprintf(stdout, "Yamux stream closed (by_remote: %d, error_code: %u)\n", by_remote, error_code);
}

static int on_write_wrapper(void* user_ctx, const uint8_t* data, size_t len) {
    frpc_stcp_proxy_t* proxy = (frpc_stcp_proxy_t*)user_ctx;
    if (!proxy) return -1;
    
    // 调用用户提供的写入回调
    if (proxy->config.on_write) {
        return proxy->config.on_write(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    return len; // 默认假设全部写入成功
}

// 初始化yamux会话
static yamux_session_t* init_yamux_session(frpc_stcp_proxy_t* proxy, bool is_client) {
    if (!proxy) return NULL;
    
    // 创建yamux配置
    yamux_config_t config;
    memset(&config, 0, sizeof(config));
    
    // 设置默认配置值
    config.enable_keepalive = true;
    config.keepalive_interval_ms = 30000; // 30秒
    config.max_stream_window_size = 256 * 1024;
    config.initial_stream_window_size = 128 * 1024;
    config.max_streams = 32;
    
    // 设置回调函数
    config.on_stream_data = on_stream_data_wrapper;
    config.on_stream_close = on_stream_close_wrapper;
    config.on_new_stream = NULL; // 我们手动处理新流
    config.on_stream_established = NULL;
    config.write_fn = on_write_wrapper;
    config.user_conn_ctx = proxy; // 设置用户上下文为代理对象
    
    // 创建yamux会话
    yamux_session_t* session = yamux_session_new(&config, is_client, proxy);
    
    return session;
}

// 启动STCP Visitor代理
static int stcp_visitor_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->config.server_name) {
        fprintf(stderr, "Error: STCP visitor missing server_name\n");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // 检查bind_addr和bind_port
    if (!proxy->config.bind_addr || proxy->config.bind_port == 0) {
        fprintf(stderr, "Warning: STCP visitor missing bind_addr or bind_port, using defaults\n");
        if (!proxy->config.bind_addr) {
            // 设置默认绑定地址
            proxy->config.bind_addr = strdup("127.0.0.1");
            if (!proxy->config.bind_addr) {
                return FRPC_ERROR_MEMORY;
            }
        }
        if (proxy->config.bind_port == 0) {
            // 设置默认端口
            proxy->config.bind_port = 10000;
        }
    }
    
    fprintf(stdout, "Starting STCP visitor for server: %s\n", proxy->config.server_name);
    
    proxy->is_started = true;
    return FRPC_SUCCESS;
}

// 启动STCP Server代理
static int stcp_server_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->config.local_addr) {
        fprintf(stderr, "Error: STCP server missing local_addr\n");
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // 目前仅实现基本功能
    fprintf(stdout, "Starting STCP server for local service: %s:%d\n", 
            proxy->config.local_addr, proxy->config.local_port);
    
    proxy->is_started = true;
    return FRPC_SUCCESS;
}

// 启动STCP代理
int frpc_stcp_proxy_start(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (proxy->is_started) {
        fprintf(stderr, "Warning: STCP proxy already started\n");
        return FRPC_SUCCESS;
    }
    
    // 根据角色启动不同的代理
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
        return stcp_visitor_start(proxy);
    } else {
        return stcp_server_start(proxy);
    }
}

// 停止STCP代理
int frpc_stcp_proxy_stop(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        return FRPC_SUCCESS;
    }
    
    // 根据角色执行不同的停止操作
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
        // 断开与服务器的连接
        if (proxy->is_connected) {
            frpc_stcp_visitor_disconnect(proxy);
        }
    } else {
        // 取消注册服务
        if (proxy->is_registered) {
            // 向frps发送注销消息
            // ...
            proxy->is_registered = false;
        }
    }
    
    // 关闭yamux会话（如果存在）
    if (proxy->yamux_session) {
        yamux_session_free(proxy->yamux_session);
        proxy->yamux_session = NULL;
    }
    
    proxy->is_started = false;
    proxy->is_connected = false;
    
    // 关闭当前活动的流，如果有的话
    if (proxy->active_stream_id) {
        yamux_stream_close(proxy->yamux_session, proxy->active_stream_id, 0);  // 0表示正常关闭，不是RST
        proxy->active_stream_id = 0;
    }
    
    return FRPC_SUCCESS;
}

// STCP Visitor建立与服务器的连接
int frpc_stcp_visitor_connect(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_VISITOR) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP visitor not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    if (proxy->is_connected) {
        fprintf(stderr, "Warning: STCP visitor already connected\n");
        return FRPC_SUCCESS;
    }
    
    // 1. 确保FRP客户端已连接
    int ret = frpc_client_connect(proxy->client);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to connect FRP client to server\n");
        return ret;
    }
    
    // 2. 构建NewVisitorConn消息
    // 在实际实现中，应该序列化为JSON并通过FRP客户端发送
    time_t current_time;
    time(&current_time);
    int64_t timestamp = (int64_t)current_time;
    
    char* sign_key = get_auth_key(proxy->config.sk, timestamp);
    if (!sign_key) {
        fprintf(stderr, "Error: Failed to generate sign key\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    fprintf(stdout, "Connecting to server '%s' with sign key: %s, timestamp: %lld\n", 
            proxy->config.server_name, sign_key, timestamp);
    
    // 这里应该构建并发送NewVisitorConn消息
    // {
    //   "run_id": 客户端唯一ID,
    //   "proxy_name": proxy->config.proxy_name,
    //   "sign_key": sign_key,
    //   "timestamp": timestamp,
    //   "use_encryption": proxy->use_encryption,
    //   "use_compression": proxy->use_compression
    // }
    fprintf(stdout, "Sending NewVisitorConn message for proxy: %s\n", proxy->config.proxy_name);
    
    // 3. 验证响应（在实际接收数据时由frpc_stcp_receive处理）
    // 这里模拟接收到成功响应
    
    free(sign_key);
    
    // 4. 初始化yamux客户端会话
    if (!proxy->yamux_session) {
        proxy->yamux_session = init_yamux_session(proxy, true);
        if (!proxy->yamux_session) {
            fprintf(stderr, "Error: Failed to initialize yamux client session\n");
            return FRPC_ERROR_INTERNAL;
        }
    }
    
    // 5. 打开一个流用于数据通信
    void* stream_data = NULL; // 可以设置自定义流数据
    uint32_t stream_id = yamux_session_open_stream(proxy->yamux_session, &stream_data);
    if (stream_id == 0) {
        fprintf(stderr, "Error: Failed to open yamux stream\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    proxy->active_stream_id = stream_id;
    fprintf(stdout, "Opened stream ID %u for data communication\n", stream_id);
    
    // 标记为已连接
    proxy->is_connected = true;
    
    // 回调通知
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);  // 1表示已连接，0表示无错误
    }
    
    return FRPC_SUCCESS;
}

// 关闭与服务器的连接
int frpc_stcp_visitor_disconnect(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_VISITOR) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_connected) {
        return FRPC_SUCCESS;
    }
    
    // 关闭活跃的流
    if (proxy->yamux_session && proxy->active_stream_id) {
        yamux_stream_close(proxy->yamux_session, proxy->active_stream_id, 0);  // 0表示正常关闭，不是RST
        proxy->active_stream_id = 0;
    }
    
    // 关闭yamux会话
    if (proxy->yamux_session) {
        yamux_session_close(proxy->yamux_session);
        yamux_session_free(proxy->yamux_session);
        proxy->yamux_session = NULL;
    }
    
    // 向frps发送断开连接的消息
    // ...
    
    proxy->is_connected = false;
    
    // 回调通知
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_INTERNAL);  // 0表示断开连接，错误码表示原因
    }
    
    return FRPC_SUCCESS;
}

// Server注册本地服务
int frpc_stcp_server_register(frpc_stcp_proxy_t* proxy) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_SERVER) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP server not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    if (proxy->is_registered) {
        fprintf(stderr, "Warning: STCP server already registered\n");
        return FRPC_SUCCESS;
    }
    
    // 1. 确保FRP客户端已连接
    int ret = frpc_client_connect(proxy->client);
    if (ret != FRPC_SUCCESS) {
        fprintf(stderr, "Error: Failed to connect FRP client to server\n");
        return ret;
    }
    
    // 2. 向frps服务器注册STCP服务，构建NewProxy消息
    // 在实际实现中，应该序列化为JSON并通过FRP客户端发送
    // {
    //   "proxy_name": proxy->config.proxy_name,
    //   "proxy_type": "stcp",
    //   "sk": proxy->config.sk,
    //   "local_ip": proxy->config.local_addr,
    //   "local_port": proxy->config.local_port,
    //   "use_encryption": proxy->use_encryption,
    //   "use_compression": proxy->use_compression
    // }
    fprintf(stdout, "Registering STCP server '%s' for local service: %s:%d\n", 
            proxy->config.proxy_name, proxy->config.local_addr, proxy->config.local_port);
    
    // 3. 等待响应（在实际接收数据时由frpc_stcp_receive处理）
    // 这里模拟接收到成功响应
    
    // 4. 初始化yamux服务器会话
    if (!proxy->yamux_session) {
        proxy->yamux_session = init_yamux_session(proxy, false);
        if (!proxy->yamux_session) {
            fprintf(stderr, "Error: Failed to initialize yamux server session\n");
            return FRPC_ERROR_INTERNAL;
        }
    }
    
    fprintf(stdout, "Yamux server session initialized for STCP server\n");
    
    // 标记为已注册
    proxy->is_registered = true;
    
    // 回调通知连接成功
    if (proxy->config.on_connection) {
        proxy->config.on_connection(proxy->user_ctx, 1, 0);
    }
    
    return FRPC_SUCCESS;
}

// 设置允许连接的用户列表
int frpc_stcp_server_set_allow_users(frpc_stcp_proxy_t* proxy, const char** users, size_t count) {
    if (!proxy || proxy->config.role != FRPC_STCP_ROLE_SERVER) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    // 释放旧的用户列表
    if (proxy->allow_users) {
        for (size_t i = 0; i < proxy->allow_users_count; i++) {
            if (proxy->allow_users[i]) {
                free(proxy->allow_users[i]);
            }
        }
        free(proxy->allow_users);
        proxy->allow_users = NULL;
        proxy->allow_users_count = 0;
    }
    
    // 复制新的用户列表
    if (count > 0 && users) {
        proxy->allow_users = (char**)malloc(count * sizeof(char*));
        if (!proxy->allow_users) {
            fprintf(stderr, "Error: Failed to allocate memory for allow users\n");
            return FRPC_ERROR_MEMORY;
        }
        
        for (size_t i = 0; i < count; i++) {
            if (users[i]) {
                proxy->allow_users[i] = strdup(users[i]);
                if (!proxy->allow_users[i]) {
                    // 释放已分配的内存
                    for (size_t j = 0; j < i; j++) {
                        free(proxy->allow_users[j]);
                    }
                    free(proxy->allow_users);
                    proxy->allow_users = NULL;
                    return FRPC_ERROR_MEMORY;
                }
            } else {
                proxy->allow_users[i] = NULL;
            }
        }
        
        proxy->allow_users_count = count;
    }
    
    return FRPC_SUCCESS;
}

// 设置传输配置
int frpc_stcp_set_transport_config(frpc_stcp_proxy_t* proxy, const frpc_stcp_transport_config_t* config) {
    if (!proxy || !config) {
        return FRPC_ERROR_INVALID_PARAM;
    }
    
    proxy->use_encryption = config->use_encryption;
    proxy->use_compression = config->use_compression;
    
    return FRPC_SUCCESS;
}

// 发送数据（针对访问端和服务端）
int frpc_stcp_send(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len) {
    if (!proxy || !data) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP proxy not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    // 对于visitor，检查是否已连接
    if (proxy->config.role == FRPC_STCP_ROLE_VISITOR && !proxy->is_connected) {
        fprintf(stderr, "Error: STCP visitor not connected\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    // 对于server，检查是否已注册
    if (proxy->config.role == FRPC_STCP_ROLE_SERVER && !proxy->is_registered) {
        fprintf(stderr, "Error: STCP server not registered\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    // 通过yamux会话发送数据
    if (proxy->yamux_session && proxy->active_stream_id) {
        fprintf(stdout, "Sending %zu bytes via Yamux stream %u\n", len, proxy->active_stream_id);
        
        int ret = yamux_stream_write(proxy->yamux_session, proxy->active_stream_id, data, len);
        if (ret < 0) {
            fprintf(stderr, "Error: Failed to write to yamux stream, error code: %d\n", ret);
            return FRPC_ERROR_INTERNAL;
        }
        
        if ((size_t)ret < len) {
            fprintf(stderr, "Warning: Only sent %d of %zu bytes (may need flow control)\n", ret, len);
        } else {
            fprintf(stdout, "Successfully sent %d bytes\n", ret);
        }
        
        return ret;
    } else {
        fprintf(stderr, "Error: No active yamux stream for STCP proxy (session: %p, stream: %u)\n", 
                (void*)proxy->yamux_session, proxy->active_stream_id);
        return FRPC_ERROR_INTERNAL;
    }
}

// 接收数据处理
int frpc_stcp_receive(frpc_stcp_proxy_t* proxy, const uint8_t* data, size_t len) {
    if (!proxy || !data) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        fprintf(stderr, "Error: STCP proxy not started\n");
        return FRPC_ERROR_INTERNAL;
    }
    
    fprintf(stdout, "STCP proxy received %zu bytes of data\n", len);
    
    // 处理可能的FRP协议消息
    // 简化版本：假设已经建立了连接，所有数据都是给yamux的
    
    // 如果有yamux会话，则将数据交给yamux处理
    if (proxy->yamux_session) {
        int ret = yamux_session_receive(proxy->yamux_session, data, len);
        if (ret < 0) {
            fprintf(stderr, "Error: Yamux session receive failed with code: %d\n", ret);
            return FRPC_ERROR_INTERNAL;
        }
        fprintf(stdout, "Yamux processed %d bytes of data\n", ret);
        return ret;
    }
    
    // 如果没有yamux会话，则直接调用回调函数
    if (proxy->config.on_data) {
        return proxy->config.on_data(proxy->user_ctx, (uint8_t*)data, len);
    }
    
    return FRPC_SUCCESS;
}

// 处理定期任务
int frpc_stcp_tick(frpc_stcp_proxy_t* proxy) {
    if (!proxy) return FRPC_ERROR_INVALID_PARAM;
    
    if (!proxy->is_started) {
        return FRPC_SUCCESS;
    }
    
    // 处理FRP客户端的定期任务
    if (proxy->client) {
        int ret = frpc_client_tick(proxy->client);
        if (ret != FRPC_SUCCESS) {
            fprintf(stderr, "Warning: FRP client tick failed with code: %d\n", ret);
        }
    }
    
    // 处理yamux会话的定期任务
    if (proxy->yamux_session) {
        yamux_session_tick(proxy->yamux_session);
        
        // 检查会话是否关闭，如果关闭则重置连接状态
        if (yamux_session_is_closed(proxy->yamux_session)) {
            fprintf(stdout, "Yamux session closed, resetting connection state\n");
            
            // 重置状态
            if (proxy->config.role == FRPC_STCP_ROLE_VISITOR) {
                proxy->is_connected = false;
            } else {
                // 对于服务端，仅在某些情况下重置注册状态
                // 通常不应该因为一个会话关闭而取消整个服务的注册
            }
            
            // 通知连接断开
            if (proxy->config.on_connection) {
                proxy->config.on_connection(proxy->user_ctx, 0, FRPC_ERROR_INTERNAL);  // 0表示断开连接，错误码表示原因
            }
            
            // 释放会话
            yamux_session_free(proxy->yamux_session);
            proxy->yamux_session = NULL;
            proxy->active_stream_id = 0;
        }
    }
    
    return FRPC_SUCCESS;
} 