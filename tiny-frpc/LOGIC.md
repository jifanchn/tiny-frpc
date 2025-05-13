# TINY-FRPC 实现逻辑

## 项目概述

TINY-FRPC 是一个用 C 语言实现的、基于 FRP 协议的轻量级客户端库，专注于提供 STCP（Secret TCP）功能。该项目的主要目标是为嵌入式设备提供一种安全可靠的内网穿透解决方案。

## 架构设计

### 核心组件

1. **协议层**
   - 实现 FRP 协议中的 STCP 相关消息格式和处理逻辑
   - 处理认证与授权

2. **传输层**
   - 基于 Yamux 多路复用协议实现连接复用
   - 支持数据加密和压缩

3. **接口层**
   - 提供简洁易用的 C 语言 API
   - 支持回调函数机制进行事件通知

4. **平台抽象层**
   - 通过统一的 POSIX API 封装实现跨平台兼容

### 数据流

```
+-------------+      +-------------+      +-------------+
|  应用程序   |<---->|  TINY-FRPC  |<---->|  FRP 服务器 |
+-------------+      +-------------+      +-------------+
                           |
                    +-------------+
                    | POSIX 封装  |
                    +-------------+
                           |
                    +-------------+
                    | 系统调用    |
                    +-------------+
```

## 实现细节

### STCP Visitor

STCP Visitor 是用于访问内网服务的客户端组件，其工作流程如下：

1. 连接到 frps 服务器
2. 发送 NewVisitorConn 消息，包含鉴权信息
3. 接收 NewVisitorConnResp 响应
4. 建立与 STCP Server 的通信通道
5. 通过 Yamux 多路复用处理数据传输

主要接口：
- `frpc_stcp_proxy_new`: 创建 STCP Visitor 实例
- `frpc_stcp_proxy_start`: 启动 Visitor
- `frpc_stcp_visitor_connect`: 连接到服务器
- `frpc_stcp_send`: 发送数据

### STCP Server

STCP Server 是运行在内网的服务端组件，其工作流程如下：

1. 连接到 frps 服务器
2. 注册 STCP 服务（发送 NewProxy 消息）
3. 等待来自 Visitor 的连接请求
4. 与本地服务建立连接，并将流量转发到 Visitor

主要接口：
- `frpc_stcp_proxy_new`: 创建 STCP Server 实例
- `frpc_stcp_proxy_start`: 启动 Server
- `frpc_stcp_server_register`: 注册服务到 frps
- `frpc_stcp_server_set_allow_users`: 设置允许连接的用户列表

### Yamux 集成

Yamux 是一个多路复用协议，它允许在单个 TCP 连接上创建多个逻辑流。在 TINY-FRPC 中，我们通过以下方式集成 Yamux：

1. 初始化 Yamux 会话（根据角色创建客户端或服务器会话）
2. 通过会话创建新流或接受流
3. 使用流进行数据传输
4. 定期调用 `yamux_session_tick` 处理心跳等任务

### 内存管理

由于针对嵌入式环境，TINY-FRPC 特别注重内存使用效率：

1. 最小化动态内存分配
2. 避免大型缓冲区
3. 及时释放不再使用的资源
4. 提供清晰的内存所有权模型

## 使用模式

### 作为 Visitor 使用

```c
// 创建 STCP Visitor 配置
frpc_stcp_config_t config;
memset(&config, 0, sizeof(config));
config.role = FRPC_STCP_ROLE_VISITOR;
config.proxy_name = "my_visitor";
config.sk = "shared_secret_key";
config.server_name = "remote_service";
config.bind_addr = "127.0.0.1";
config.bind_port = 8080;

// 设置回调函数
config.on_data = my_data_callback;
config.on_connection = my_connection_callback;

// 创建代理
frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
frpc_stcp_proxy_start(proxy);
frpc_stcp_visitor_connect(proxy);

// 使用完后释放资源
frpc_stcp_proxy_free(proxy);
```

### 作为 Server 使用

```c
// 创建 STCP Server 配置
frpc_stcp_config_t config;
memset(&config, 0, sizeof(config));
config.role = FRPC_STCP_ROLE_SERVER;
config.proxy_name = "my_service";
config.sk = "shared_secret_key";
config.local_addr = "127.0.0.1";
config.local_port = 8000;

// 设置回调函数
config.on_data = my_data_callback;
config.on_connection = my_connection_callback;

// 创建代理
frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
frpc_stcp_proxy_start(proxy);
frpc_stcp_server_register(proxy);

// 使用完后释放资源
frpc_stcp_proxy_free(proxy);
```

## 限制与约束

1. 目前仅支持 STCP 模式，不支持其他 FRP 代理类型
2. 受嵌入式环境限制，部分高级功能未实现
3. 依赖 POSIX 兼容的环境
4. 不支持热重载配置

## 未来计划

1. 实现更多 FRP 代理类型支持
2. 优化内存和 CPU 使用
3. 增强错误处理和恢复机制
4. 提供更完善的日志和调试功能 