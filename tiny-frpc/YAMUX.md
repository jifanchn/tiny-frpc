# YAMUX 协议核心概念

Yamux 是一个多路复用协议，允许在单个底层连接（如 TCP）上承载多个独立的双向流。

## 1. 帧 (Frame)

帧是 Yamux 协议中数据传输的基本单元。每个帧都有一个标准的头部。

### 1.1. 帧头部 (Frame Header)

| 字段       | 长度 (bytes) | 描述                                     |
| ---------- | ------------ | ---------------------------------------- |
| Version    | 1            | 协议版本 (当前为 0)                      |
| Type       | 1            | 帧类型                                   |
| Flags      | 2            | 标志位                                   |
| StreamID   | 4            | 流 ID                                    |
| Length     | 4            | 帧负载的长度 (Payload Length)             |

**总头部长度: 12 bytes**

### 1.2. 帧类型 (Frame Type)

- `0x0 (Data)`: 数据帧，用于传输应用数据。
- `0x1 (WindowUpdate)`: 窗口更新帧，用于流量控制。
- `0x2 (Ping)`: Ping 帧，用于保持连接活跃和测量延迟。
- `0x3 (GoAway)`: GoAway 帧，用于优雅关闭会话。

### 1.3. 标志位 (Flags)

- `0x1 (SYN)`: Stream Open。由发起方设置，用于请求建立新流。
- `0x2 (ACK)`: Stream Acknowledge。由接收方设置，用于确认新流已建立。
- `0x4 (FIN)`: Stream Finish。表示发送方已完成该方向的数据发送。
- `0x8 (RST)`: Stream Reset。表示流被异常终止。

## 2. 会话 (Session)

会话代表一个底层的网络连接（例如 TCP 连接），它管理着所有通过该连接复用的流。

- **职责**:
    - 建立和维护底层连接。
    - 管理流的生命周期（创建、接受、关闭）。
    - 分配和管理 StreamID。客户端发起的流使用奇数 ID，服务端发起的流使用偶数 ID。StreamID 0 保留，不用于流。
    - 处理 Ping 帧和 GoAway 帧。
    - 管理会话级别的配置，如 keep-alive 间隔。
    - 从底层连接读取数据，解析成帧，并分发给对应的流。
    - 将流发送的数据封装成帧，并通过底层连接发送出去。

## 3. 流 (Stream)

流是在一个 Yamux 会话内部建立的双向、可靠的字节流通道。每个流都有一个唯一的 StreamID。

- **职责**:
    - 通过发送 SYN 帧来请求打开一个新流。
    - 接收 SYN 帧并响应 ACK 帧来接受一个新流。
    - 发送和接收数据帧。
    - 通过发送 FIN 帧来关闭流的一个方向。当双方都发送并接收到 FIN 后，流被完全关闭。
    - 通过发送 RST 帧来强制关闭流。
    - 实现流量控制：
        - 每个流都有一个接收窗口 (receive window)。
        - 流的发送方不能发送超过接收方窗口大小的数据。
        - 接收方在处理完数据后，通过发送 WindowUpdate 帧来扩大窗口，允许发送方继续发送数据。

## 4. 流量控制 (Flow Control)

Yamux 使用基于窗口的流量控制机制，确保发送方不会淹没接收方。

- 每个流都有一个独立的接收窗口。
- 会话初始化时，会为每个新流设置一个初始窗口大小。
- 当流接收到数据并将其传递给应用层后，它会发送一个 WindowUpdate 帧给对方，告知对方可以发送更多的数据。WindowUpdate 帧中的 `Length` 字段表示窗口增加的大小。

## 5. Ping 和 Keep-Alive

- Ping 帧用于检测连接是否仍然活跃，并可以用来估算 RTT (Round-Trip Time)。
- 会话可以配置一个 keep-alive 间隔。如果在此间隔内没有数据传输，会话会自动发送 Ping 帧。
- Ping 帧的类型为 `0x2 (Ping)`。
    - 请求 Ping：`Flags` 字段为 `0x0`，`StreamID` 字段为 `0`。`Length` 字段包含一个 `uint32` 的 Opaque ID。
    - 响应 Ping：`Flags` 字段为 `0x1 (ACK)`，`StreamID` 字段为 `0`。`Length` 字段包含与请求中相同的 Opaque ID。

## 6. 关闭 (Shutdown)

### 6.1. 流关闭 (Stream Shutdown)

- **优雅关闭**:
    1. 一方发送带有 `FIN` 标志的帧，表示该方向数据发送完毕。
    2. 另一方收到 `FIN` 后，也发送带有 `FIN` 标志的帧。
    3. 当双方都发送并接收到 `FIN` 后，流被视为关闭。
- **强制关闭 (Reset)**:
    - 任何一方都可以发送带有 `RST` 标志的帧来立即终止流。这通常在发生错误时使用。

### 6.2. 会话关闭 (Session Shutdown)

- **GoAway 帧**:
    - 用于通知对方会话即将关闭。
    - `GoAway` 帧的类型为 `0x3 (GoAway)`。
    - `StreamID` 字段指示最后一个被处理或接受的流 ID。在此 ID 之后的流应该被认为是无效的。
    - `Length` 字段包含一个错误码，指示关闭的原因。
        - `0x0`: 正常关闭
        - `0x1`: 协议错误
        - `0x2`: 内部错误
- 当收到 `GoAway` 帧后，不应再创建新的流。现有流可以继续处理，直到完成或被 `GoAway` 中指定的 `StreamID` 中断。
- 当所有流都关闭且 `GoAway` 已处理后，底层连接可以被关闭。

## 7. C实现用法

本节描述如何在C代码中使用Yamux库，特别是在嵌入式环境中的应用。

### 7.1. 基本依赖

Yamux的C实现设计为只依赖标准C库和POSIX接口的包装，使其能够在资源受限的嵌入式环境中运行：

```c
#include <stdio.h>   // 用于错误输出，可选
#include <stdlib.h>  // 用于内存分配
#include <string.h>  // 用于内存操作
#include <stdint.h>  // 用于固定大小整数类型
#include <stdbool.h> // 用于布尔类型
```

POSIX功能通过wrapper模块间接调用，使代码更容易移植到不同平台：

```c
// 不直接包含系统头文件
// #include <sys/socket.h>
// #include <netinet/in.h>

// 而是使用包装器
#include "wrapper.h"
```

### 7.2. 初始化会话

首先，需要创建和配置一个Yamux会话：

```c
#include "yamux.h"

// 写回调函数，用于将数据发送到底层连接
int my_write_function(void* user_conn_ctx, const uint8_t* data, size_t len) {
    // 使用wrapper进行套接字写入
    return wrapped_write((int)(intptr_t)user_conn_ctx, data, len);
}

// 流数据回调函数，处理接收到的数据
int my_stream_data_callback(void* stream_user_data, const uint8_t* data, size_t len) {
    printf("收到数据: %zu 字节\n", len);
    // 处理数据...
    return len; // 返回成功处理的字节数
}

// 新流回调函数，当对方请求新流时调用
bool my_new_stream_callback(void* session_ctx, uint32_t stream_id, void** stream_user_data) {
    printf("收到新流请求，流ID: %u\n", stream_id);
    // 创建流的用户数据
    *stream_user_data = malloc(sizeof(MyStreamContext));
    return true; // 返回true表示接受流
}

// 流关闭回调函数
void my_stream_close_callback(void* stream_user_data, bool by_remote, uint32_t error_code) {
    printf("流关闭: 由%s关闭，错误码:%u\n", by_remote ? "远端" : "本地", error_code);
    free(stream_user_data);
}

// 创建会话
yamux_session_t* create_yamux_session(int socket_fd, bool is_client) {
    // 配置yamux
    yamux_config_t config;
    memset(&config, 0, sizeof(config));
    
    // 设置基本配置
    config.initial_stream_window_size = 256 * 1024; // 初始窗口大小，根据需要调整
    config.max_stream_window_size = 1024 * 1024;   // 最大窗口大小
    config.max_streams = 32;    // 最大并发流数，根据内存限制调整
    config.enable_keepalive = true;
    config.keepalive_interval_ms = 30000; // 30秒keepalive间隔
    
    // 设置回调
    config.write_fn = my_write_function;             // 写数据回调
    config.user_conn_ctx = (void*)(intptr_t)socket_fd;  // 连接上下文
    config.on_new_stream = my_new_stream_callback;     // 新流回调
    config.on_stream_data = my_stream_data_callback;   // 流数据回调
    config.on_stream_close = my_stream_close_callback; // 流关闭回调
    
    // 创建yamux会话
    void* session_user_data = NULL; // 可选的会话用户数据
    return yamux_session_new(&config, is_client, session_user_data);
}
```

### 7.3. 创建和使用流

一旦会话建立，可以创建流并收发数据：

```c
// 创建新流
uint32_t create_stream(yamux_session_t* session) {
    void* stream_user_data = malloc(sizeof(MyStreamContext)); // 创建流的用户上下文
    // 初始化流用户上下文...
    
    // 打开流
    uint32_t stream_id = yamux_session_open_stream(session, &stream_user_data);
    if (stream_id == 0) {
        printf("打开流失败\n");
        free(stream_user_data);
        return 0;
    }
    
    printf("成功打开流，ID: %u\n", stream_id);
    return stream_id;
}

// 发送数据到流
int send_data(yamux_session_t* session, uint32_t stream_id, const uint8_t* data, size_t len) {
    return yamux_stream_write(session, stream_id, data, len);
}

// 关闭流
int close_stream(yamux_session_t* session, uint32_t stream_id) {
    // 0表示正常关闭，非零值表示以错误码发送RST
    return yamux_stream_close(session, stream_id, 0);
}
```

### 7.4. 处理接收数据

Yamux库需要将接收到的数据传递给会话处理：

```c
// 主循环中处理接收数据
int handle_incoming_data(yamux_session_t* session, int socket_fd) {
    uint8_t buffer[4096]; // 接收缓冲区，根据内存限制调整大小
    
    // 从套接字读取数据
    ssize_t bytes_read = wrapped_read(socket_fd, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        // 处理错误或连接关闭
        return bytes_read;
    }
    
    // 将数据传递给yamux会话处理
    int processed = yamux_session_receive(session, buffer, bytes_read);
    if (processed < 0) {
        printf("处理接收数据失败\n");
        return -1;
    }
    
    return processed;
}
```

### 7.5. 管理会话生命周期

定期调用`yamux_session_tick`以处理内部定时任务（如keepalive）：

```c
// 定期维护会话
void maintain_session(yamux_session_t* session) {
    // 处理内部计时器事件（如keepalive）
    yamux_session_tick(session);
}

// 关闭会话
void close_session(yamux_session_t* session) {
    // 释放会话资源
    yamux_session_free(session);
}
```

### 7.6. 完整示例(服务器)

下面是一个简化的服务器示例，展示了如何集成Yamux：

```c
void run_yamux_server(int listen_fd) {
    // 接受连接
    int client_fd = wrapped_accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        printf("接受连接失败\n");
        return;
    }
    
    // 创建yamux会话(服务器模式)
    yamux_session_t* session = create_yamux_session(client_fd, false);
    if (!session) {
        printf("创建yamux会话失败\n");
        wrapped_close(client_fd);
        return;
    }
    
    // 主循环
    bool running = true;
    while (running) {
        // 处理接收数据
        int result = handle_incoming_data(session, client_fd);
        if (result < 0) {
            // 处理错误
            running = false;
        }
        
        // 定期维护会话
        maintain_session(session);
        
        // ... 其他事件处理 ...
    }
    
    // 清理资源
    close_session(session);
    wrapped_close(client_fd);
}
```

### 7.7. 完整示例(客户端)

下面是一个简化的客户端示例：

```c
void run_yamux_client(const char* server_addr, int server_port) {
    // 连接服务器
    int socket_fd = connect_to_server(server_addr, server_port);
    if (socket_fd < 0) {
        printf("连接服务器失败\n");
        return;
    }
    
    // 创建yamux会话(客户端模式)
    yamux_session_t* session = create_yamux_session(socket_fd, true);
    if (!session) {
        printf("创建yamux会话失败\n");
        wrapped_close(socket_fd);
        return;
    }
    
    // 创建流
    uint32_t stream_id = create_stream(session);
    if (stream_id == 0) {
        printf("创建流失败\n");
        close_session(session);
        wrapped_close(socket_fd);
        return;
    }
    
    // 发送数据
    const char* data = "Hello, Yamux!";
    int sent = send_data(session, stream_id, (const uint8_t*)data, strlen(data));
    if (sent < 0) {
        printf("发送数据失败\n");
    }
    
    // 主循环
    bool running = true;
    while (running) {
        // 处理接收数据
        int result = handle_incoming_data(session, socket_fd);
        if (result < 0) {
            // 处理错误
            running = false;
        }
        
        // 定期维护会话
        maintain_session(session);
        
        // ... 其他事件处理 ...
    }
    
    // 关闭流
    close_stream(session, stream_id);
    
    // 清理资源
    close_session(session);
    wrapped_close(socket_fd);
}
```

### 7.8. 嵌入式环境中的注意事项

在嵌入式环境中使用Yamux时，需要特别注意：

1. **内存管理**：
   - 根据设备内存限制，适当调整缓冲区大小、窗口大小和最大流数量
   - 避免大量动态内存分配，考虑使用静态或池化内存

2. **依赖最小化**：
   - 本实现只依赖基本的标准C库和POSIX包装器
   - 不使用高级库或依赖特定平台的功能

3. **错误处理**：
   - 在资源受限环境中，更加重视错误处理和恢复
   - 确保即使在出错情况下也能正确释放资源

4. **移植适应**：
   - 通过wrapper模块隔离平台相关代码
   - 根据目标平台调整内存对齐、字节序和数据类型大小 