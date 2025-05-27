/**
 * @file frpc_handler.c
 * @brief FRP protocol message handlers implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frpc_handler.h"
#include "frpc_protocol.h"
#include "frpc_internal.h"
#include "frpc_visitor.h"

/* Buffer for message handling */
#define HANDLER_BUFFER_SIZE 4096
static uint8_t handler_buffer[HANDLER_BUFFER_SIZE];

/* Forward declarations for internal functions */
static int handle_login_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len);
static int handle_new_proxy_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len);
static int handle_pong(frpc_ctx_t *ctx, const uint8_t *data, size_t len);
static int handle_new_work_conn(frpc_ctx_t *ctx, const uint8_t *data, size_t len);
static int handle_new_visitor_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len);
static int handle_start_workconn(frpc_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Handle an incoming message from the frps server
 * 
 * @param ctx frpc client context
 * @param type Message type
 * @param seq Message sequence number
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
int frpc_handle_message(frpc_ctx_t *ctx, uint8_t type, uint64_t seq, const uint8_t *data, size_t len) {
    if (!ctx) {
        set_error("Invalid context");
        return -1;
    }
    
    switch (type) {
    case FRPC_MSG_TYPE_LOGIN_RESP:
        return handle_login_resp(ctx, data, len);
        
    case FRPC_MSG_TYPE_NEW_PROXY_RESP:
        return handle_new_proxy_resp(ctx, data, len);
        
    case FRPC_MSG_TYPE_PONG:
        return handle_pong(ctx, data, len);
        
    case FRPC_MSG_TYPE_NEW_WORK_CONN:
        return handle_new_work_conn(ctx, data, len);
        
    case FRPC_MSG_TYPE_NEW_VISITOR_RESP:
        return handle_new_visitor_resp(ctx, data, len);
        
    case FRPC_MSG_TYPE_START_WORKCONN:
        return handle_start_workconn(ctx, data, len);
        
    default:
        set_error("Unknown message type: %d", type);
        return -1;
    }
}

/**
 * @brief Send login message to frps server
 * 
 * @param ctx frpc client context
 * @return 0 on success, -1 on error
 */
int frpc_send_login(frpc_ctx_t *ctx) {
    if (!ctx) {
        set_error("Invalid context");
        return -1;
    }
    
    frpc_msg_header_t header;
    int len = frpc_protocol_create_login(FRPC_VERSION, ctx->config.user, 
                                        ctx->config.token, handler_buffer, 
                                        HANDLER_BUFFER_SIZE, &header);
    
    if (len < 0) {
        set_error("Failed to create login message");
        return -1;
    }
    
    /* Send login message */
    if (yamux_write_all(ctx->control_stream, handler_buffer, len) != len) {
        set_error("Failed to send login message");
        return -1;
    }
    
    /* Save sequence number */
    ctx->seq = header.seq + 1;
    
    return 0;
}

/**
 * @brief Send a ping message to frps server
 * 
 * @param ctx frpc client context
 * @return 0 on success, -1 on error
 */
int frpc_send_ping(frpc_ctx_t *ctx) {
    if (!ctx) {
        set_error("Invalid context");
        return -1;
    }
    
    frpc_msg_header_t header;
    int len = frpc_protocol_create_ping(handler_buffer, HANDLER_BUFFER_SIZE, ctx->seq, &header);
    
    if (len < 0) {
        set_error("Failed to create ping message");
        return -1;
    }
    
    /* Send ping message */
    if (yamux_write_all(ctx->control_stream, handler_buffer, len) != len) {
        set_error("Failed to send ping message");
        return -1;
    }
    
    /* Save sequence number */
    ctx->seq++;
    
    return 0;
}

/**
 * @brief Send a new proxy message to frps server
 * 
 * @param ctx frpc client context
 * @param proxy Proxy configuration
 * @return 0 on success, -1 on error
 */
int frpc_send_new_proxy(frpc_ctx_t *ctx, const frpc_proxy_config_t *proxy) {
    if (!ctx || !proxy) {
        set_error("Invalid context or proxy");
        return -1;
    }
    
    frpc_msg_header_t header;
    int len = frpc_protocol_create_new_proxy(proxy->name, proxy->type, 
                                           proxy->remote_port, handler_buffer, 
                                           HANDLER_BUFFER_SIZE, &header);
    
    if (len < 0) {
        set_error("Failed to create new proxy message");
        return -1;
    }
    
    /* Send new proxy message */
    if (yamux_write_all(ctx->control_stream, handler_buffer, len) != len) {
        set_error("Failed to send new proxy message");
        return -1;
    }
    
    /* Save sequence number */
    ctx->seq = header.seq + 1;
    
    return 0;
}

/**
 * @brief Handle a login response message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_login_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) {
        set_error("Invalid parameters");
        return -1;
    }
    
    int error_code;
    char error_msg[256] = {0};
    
    if (frpc_protocol_parse_login_resp(data, len, &error_code, error_msg, sizeof(error_msg)) < 0) {
        set_error("Failed to parse login response");
        return -1;
    }
    
    if (error_code != 0) {
        set_error("Login failed: %s", error_msg);
        return -1;
    }
    
    /* Login successful, send proxy configuration */
    ctx->login_status = FRPC_LOGIN_STATUS_SUCCESS;
    
    /* Register all proxies */
    proxy_list_t *proxy = ctx->proxies;
    while (proxy) {
        if (frpc_send_new_proxy(ctx, &proxy->config) < 0) {
            set_error("Failed to register proxy: %s", proxy->config.name);
            return -1;
        }
        proxy = proxy->next;
    }
    
    return 0;
}

/**
 * @brief Handle a new proxy response message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_new_proxy_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* TODO: Parse the JSON content properly */
    /* For now, just assume success and log the response */
    
    if (ctx->debug) {
        fprintf(stderr, "Debug: Received new proxy response (%zu bytes)\n", len);
    }
    
    return 0;
}

/**
 * @brief Handle a pong message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_pong(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx) {
        set_error("Invalid context");
        return -1;
    }
    
    /* Update last heartbeat time */
    ctx->last_pong = time(NULL);
    
    if (ctx->debug) {
        fprintf(stderr, "Debug: Received pong\n");
    }
    
    return 0;
}

/**
 * @brief Handle a new work connection message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_new_work_conn(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx) {
        set_error("Invalid context");
        return -1;
    }
    
    /* TODO: Implement work connection handling */
    
    if (ctx->debug) {
        fprintf(stderr, "Debug: Received new work connection request\n");
    }
    
    return 0;
}

/**
 * @brief Handle a new visitor response message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_new_visitor_resp(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* 解析JSON响应数据 */
    /* 响应格式应该类似: {"error": 0, "reason": "", "proxy_name": "stcp-visitor"} */
    
    /* 简单解析,查找error字段 */
    int error_code = 0;
    char error_reason[256] = {0};
    char proxy_name[128] = {0};
    char server_name[128] = {0};
    uint16_t bind_port = 0;
    
    /* 为简化实现，我们这里只做基本的字符串解析 */
    /* 在实际产品中应该使用JSON库进行解析 */
    char buffer[4096] = {0};
    if (len >= sizeof(buffer)) {
        set_error("Response too large");
        return -1;
    }
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    
    /* 查找error字段值 */
    char *error_start = strstr(buffer, "\"error\":");
    if (error_start) {
        error_code = strtol(error_start + 8, NULL, 10);
    }
    
    /* 查找reason字段值 */
    char *reason_start = strstr(buffer, "\"reason\":");
    if (reason_start) {
        reason_start += 9; // 跳过"reason":"部分
        char *reason_end = strchr(reason_start, '"');
        if (reason_end) {
            size_t reason_len = reason_end - reason_start;
            if (reason_len < sizeof(error_reason)) {
                strncpy(error_reason, reason_start, reason_len);
                error_reason[reason_len] = '\0';
            }
        }
    }
    
    /* 查找proxy_name字段值 */
    char *name_start = strstr(buffer, "\"proxy_name\":");
    if (name_start) {
        name_start += 13; // 跳过"proxy_name":"部分
        char *name_end = strchr(name_start, '"');
        if (name_end) {
            size_t name_len = name_end - name_start;
            if (name_len < sizeof(proxy_name)) {
                strncpy(proxy_name, name_start, name_len);
                proxy_name[name_len] = '\0';
            }
        }
    }
    
    if (error_code != 0) {
        set_error("New visitor response error: %d, %s", error_code, error_reason);
        return -1;
    }
    
    /* 打印调试信息 */
    if (ctx->debug) {
        fprintf(stderr, "Debug: New visitor response success for proxy: %s\n", proxy_name);
    }
    
    /* 查找对应代理的配置信息 */
    proxy_list_t *proxy = ctx->proxies;
    while (proxy) {
        if (strcmp(proxy->config.name, proxy_name) == 0) {
            if (proxy->config.is_visitor) {
                /* 获取server_name和bind_port */
                if (proxy->config.server_name) {
                    strncpy(server_name, proxy->config.server_name, sizeof(server_name)-1);
                }
                bind_port = proxy->config.bind_port;
                break;
            }
        }
        proxy = proxy->next;
    }
    
    /* 确保我们找到了代理配置 */
    if (bind_port == 0 || server_name[0] == '\0') {
        set_error("Failed to find visitor proxy configuration for '%s'", proxy_name);
        return -1;
    }
    
    /* 注册访问者信息 */
    if (ctx->debug) {
        fprintf(stderr, "Debug: Registering STCP visitor for %s on port %d\n", 
                proxy_name, bind_port);
    }
    
    /* 将访问者注册到访问者系统 */
    if (frpc_create_stcp_visitor(ctx, proxy_name, server_name, bind_port) < 0) {
        /* set_error已经在frpc_create_stcp_visitor中设置 */
        return -1;
    }
    
    return 0;
}

/**
 * @brief Handle a start work connection message
 * 
 * @param ctx frpc client context
 * @param data Message data
 * @param len Message data length
 * @return 0 on success, -1 on error
 */
static int handle_start_workconn(frpc_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) {
        set_error("Invalid parameters");
        return -1;
    }
    
    /* 解析工作连接请求 */
    /* 请求格式类似: {"proxy_name":"stcp-visitor", "src_addr":"xxx", "dst_addr":"xxx"} */
    
    char buffer[4096] = {0};
    if (len >= sizeof(buffer)) {
        set_error("Request too large");
        return -1;
    }
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    
    char proxy_name[128] = {0};
    
    /* 查找proxy_name字段值 */
    char *name_start = strstr(buffer, "\"proxy_name\":");
    if (name_start) {
        name_start += 13; // 跳过"proxy_name":"部分
        char *name_end = strchr(name_start, '"');
        if (name_end) {
            size_t name_len = name_end - name_start;
            if (name_len < sizeof(proxy_name)) {
                strncpy(proxy_name, name_start, name_len);
                proxy_name[name_len] = '\0';
            }
        }
    }
    
    if (proxy_name[0] == '\0') {
        set_error("Invalid start workconn request: missing proxy_name");
        return -1;
    }
    
    /* 打印调试信息 */
    if (ctx->debug) {
        fprintf(stderr, "Debug: Start work connection for proxy: %s\n", proxy_name);
    }
    
    /* 为STCP创建工作连接 */
    /* 步骤如下:
     * 1. 创建新的yamux流
     * 2. 发送工作连接消息
     * 3. 连接到本地服务
     * 4. 在两者之间转发数据 */
    
    /* 创建一个新的工作连接流 */
    void *work_stream = NULL;
    if (!ctx->yamux_session) {
        set_error("No yamux session available");
        return -1;
    }
    
    /* 使用yamux创建一个新的流 - 实际实现需要调用yamux API */
    /* 这里假设已经有了合适的函数 yamux_open_stream */
    /* work_stream = yamux_open_stream(ctx->yamux_session); */
    
    /* 发送工作连接消息 */
    frpc_msg_header_t header;
    int msg_len = frpc_protocol_create_work_conn(handler_buffer, 
                                             HANDLER_BUFFER_SIZE, 
                                             ctx->seq, 
                                             &header);
    if (msg_len < 0) {
        set_error("Failed to create work connection message");
        return -1;
    }
    
    /* 发送工作连接消息 */
    /* 注意：这里我们应该使用新创建的work_stream，但由于当前缺少完整的yamux支持，
     * 我们临时使用控制流。在实际实现中这是错误的! */
    if (yamux_write_all(ctx->control_stream, handler_buffer, msg_len) != msg_len) {
        set_error("Failed to send work connection message");
        return -1;
    }
    
    /* 更新序列号 */
    ctx->seq = header.seq + 1;
    
    /* 在实际实现中，这里应该启动一个线程/协程来管理这个连接 */
    /* 目前为了示例目的，我们简单返回成功 */
    
    return 0;
}
