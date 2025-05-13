# FRP STCP 协议概述

## 什么是STCP (Secret TCP)

STCP是FRP中的一种代理类型，它允许将TCP流量转发到内网服务器，同时提供了一种通过密钥进行连接验证的安全机制。STCP由两个关键组件组成：Visitor和Server。

## STCP工作原理

1. **Server组件**：
   - 在内网中运行，连接到FRP服务器(frps)
   - 注册一个STCP代理，并提供一个密钥(key)
   - 等待来自Visitor的连接

2. **Visitor组件**：
   - 可以在任何能够访问frps的地方运行
   - 连接到FRP服务器(frps)
   - 使用相同的密钥请求连接到特定的STCP服务
   - 通过frps中转与内网Server建立连接

3. **通信流程**：
   - Visitor → frps：请求连接到特定的STCP服务并提供密钥
   - frps验证密钥并找到对应的Server
   - frps在Visitor和Server之间建立连接通道
   - Visitor和Server开始直接通信（通过frps中转）

4. **详细通信过程**：
   - **Server端初始化**：
     - 连接到frps (TCP连接)
     - 发送Login消息进行身份认证
     - 接收LoginResp响应
     - 发送NewProxy消息注册STCP服务
     - 接收NewProxyResp响应
     - 等待frps的连接请求

   - **Visitor端请求连接**：
     - 连接到frps (TCP连接)
     - 创建新的visitor连接
     - 发送NewVisitorConn消息，包含:
       - RunID (客户端唯一标识)
       - ProxyName (目标服务名称)
       - SignKey (使用密钥生成的签名)
       - Timestamp (时间戳，用于防重放)
       - UseEncryption (是否加密)
       - UseCompression (是否压缩)
     - 接收NewVisitorConnResp响应
     - 如果成功，建立与Server的数据通道

   - **frps服务器处理**：
     - 接收Visitor的连接请求
     - 验证SignKey (使用密钥和时间戳)
     - 查找对应的Server代理
     - 与Server建立工作连接
     - 将Visitor连接与Server工作连接关联
     - 返回成功响应给Visitor

   - **数据传输**：
     - 建立连接后，数据通过frps在Visitor和Server之间透明传输
     - 如果启用加密，数据将在传输前加密
     - 如果启用压缩，数据将在传输前压缩

## Yamux在STCP中的作用

FRP使用Yamux协议来多路复用底层TCP连接，使得多个应用流量能共享同一个TCP连接，从而提高效率和性能。

1. **连接复用**：
   - 使用Yamux建立多路复用会话
   - 在单个TCP连接上创建多个逻辑流
   - 每个应用连接映射到一个Yamux流

2. **Yamux会话建立**：
   - 服务端和客户端建立TCP连接
   - 使用fmux.Server或fmux.Client初始化Yamux会话
   - 会话配置包括：
     - KeepAliveInterval (保活间隔)
     - MaxStreamWindowSize (流窗口大小)
     - 等其他参数

3. **流操作**：
   - 服务端通过session.AcceptStream()接受新流
   - 客户端通过session.OpenStream()创建新流
   - 每个流作为独立的连接处理

## 需要实现的组件

1. **STCP Visitor**：
   - 连接到frps
   - 认证和协商
   - 建立数据通道
   - 处理数据传输
   - 管理连接生命周期

2. **STCP Server**：
   - 连接到frps
   - 注册STCP服务
   - 接受来自Visitor的连接请求
   - 处理数据传输
   - 管理连接生命周期

## 实现注意事项

1. **认证安全**：
   - 正确实现密钥验证机制
   - 使用util.GetAuthKey()生成签名
   - 验证时间戳防止重放攻击

2. **连接管理**：
   - 妥善处理连接的建立和关闭
   - 实现心跳机制保持连接活跃
   - 处理异常情况和错误恢复

3. **数据处理**：
   - 高效的数据传输和缓冲
   - 正确处理加密和压缩
   - 处理分包和粘包问题

4. **资源管理**：
   - 避免内存泄漏
   - 及时关闭不再使用的连接
   - 限制最大连接数和资源使用

## 消息格式

1. **NewVisitorConn** (Visitor->frps):
   ```
   {
     "run_id": "visitor客户端ID",
     "proxy_name": "目标服务名称",
     "sign_key": "基于密钥和时间戳的签名",
     "timestamp": 当前时间戳,
     "use_encryption": true/false,
     "use_compression": true/false
   }
   ```

2. **NewVisitorConnResp** (frps->Visitor):
   ```
   {
     "proxy_name": "目标服务名称",
     "error": "错误信息(如果有)"
   }
   ```

## 相关代码分析

在实现过程中，需要参考FRP源代码中以下关键文件：

1. `client/visitor/visitor.go` - 访问者基础实现
2. `client/visitor/stcp.go` - STCP访问者具体实现
3. `server/proxy/stcp.go` - 服务器端STCP代理实现
4. `server/visitor/visitor.go` - 服务器端访问者管理
5. `pkg/msg/msg.go` - 消息定义
6. `pkg/util/util.go` - 工具函数，包括认证等 