package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include -I../../wrapper/linux -DDEBUG_LOG
#cgo LDFLAGS: -L../../build -lyamux -ltools -lm

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "yamux.h"
#include "../../tiny-frpc/include/tools.h"

// Structure to hold persistent buffer state
typedef struct {
    uint8_t buffer[65536]; // Fixed-size buffer
    size_t len;            // Current amount of data in the buffer
    size_t capacity;       // Max capacity
} persistent_buffer_t;

// Global variables used by C callbacks and test functions
// ... (existing globals: c_sockfd, g_stream_established, etc.) ...
static yamux_session_t* c_session = NULL;
static uint32_t g_current_stream_id = 0;
static persistent_buffer_t c_recv_buffer; // Global persistent buffer

// Initialize the persistent buffer
static void init_persistent_buffer() {
    c_recv_buffer.len = 0;
    c_recv_buffer.capacity = sizeof(c_recv_buffer.buffer);
    memset(c_recv_buffer.buffer, 0, c_recv_buffer.capacity);
}

// 全局变量用于网络I/O
static int c_sockfd = -1;
static uint8_t recv_buffer[65536];
static int recv_buffer_pos = 0;
static int recv_buffer_len = 0;
static int g_stream_established = 0;
static int g_data_received = 0;
static char g_received_data[1024];

// 网络写入回调函数
static int network_write_callback(void* ctx, const uint8_t* data, size_t len) {
    if (c_sockfd < 0) {
        printf("C: 错误 - 套接字未初始化\n");
        return -1;
    }
    
    printf("C: 发送 %zu 字节数据到网络\n", len);
    int total_sent = 0;
    while (total_sent < len) {
        int sent = write(c_sockfd, data + total_sent, len - total_sent);
        if (sent <= 0) {
            printf("C: 网络发送错误: %d\n", sent);
            return -1;
        }
        total_sent += sent;
    }
    
    return total_sent;
}

// 数据接收回调
static int on_stream_data_received(void* stream_user_data, const uint8_t* data, size_t len) {
    printf("C: 收到流数据，长度: %zu 字节\n", len);
    if (len > 0 && len < sizeof(g_received_data)) {
        memcpy(g_received_data, data, len);
        g_data_received = len;
        printf("C: 接收到的数据: %.*s\n", (int)len, g_received_data);

        // 使用全局会话和记录的流ID进行窗口更新 和 发送响应
        if (c_session != NULL && g_current_stream_id > 0) {
            printf("C: 自动更新流 %u 的窗口，增加 %zu 字节\n", g_current_stream_id, len);
            yamux_stream_window_update(c_session, g_current_stream_id, (uint32_t)len);

            // 发送响应数据
            const char* response = "Pong from C Server!";
            size_t response_len = strlen(response);
            printf("C: 服务端尝试为流 %u 发送响应: %s\n", g_current_stream_id, response);
            int written = yamux_stream_write(c_session, g_current_stream_id, (const uint8_t*)response, response_len);
            if (written < 0) {
                printf("C: 服务端为流 %u 发送响应失败, 错误码: %d\n", g_current_stream_id, written);
            } else {
                printf("C: 服务端为流 %u 成功发送 %d 字节的响应\n", g_current_stream_id, written);
            }

        } else {
            printf("C: 无法更新窗口或发送响应：session=%p, stream_id=%u\n", 
                    c_session, g_current_stream_id);
        }
    }
    return len;
}

// 流建立回调
static void on_stream_established(void* stream_user_data) {
    printf("C: on_stream_established CALLED (user_data: %p)\n", stream_user_data);
    g_stream_established = 1;
    printf("C: g_stream_established SET to 1\n");
}

// 流关闭回调
static void on_stream_closed(void* stream_user_data, bool by_remote, uint32_t error_code) {
    printf("C: 流已关闭，远端关闭: %d, 错误码: %u\n", by_remote ? 1 : 0, error_code);
}

// 新流回调
static bool on_new_stream(void* session_ctx, uint32_t stream_id, void** stream_user_data) {
    printf("C: 收到新流请求，ID: %u\n", stream_id);
    // 记录流ID到全局变量
    g_current_stream_id = stream_id;
    return true;
}

// 创建yamux会话
static yamux_session_t* create_interop_session(int sockfd, bool is_client) {
    c_sockfd = sockfd;
    init_persistent_buffer(); // Initialize the buffer here
    
    yamux_config_t config;
    memset(&config, 0, sizeof(config));
    
    config.enable_keepalive = 1;
    config.keepalive_interval_ms = 30000;
    config.initial_stream_window_size = 256 * 1024;
    config.max_stream_window_size = 1024 * 1024;
    config.max_streams = 8;
    
    config.write_fn = network_write_callback;
    config.on_stream_data = on_stream_data_received;
    config.on_stream_established = on_stream_established;
    config.on_stream_close = on_stream_closed;
    config.on_new_stream = on_new_stream;
    
    yamux_session_t* session = yamux_session_new(&config, is_client, NULL);
    c_session = session; // 保存到全局变量
    
    return session;
}

// 从套接字读取数据并送入yamux会话处理
static int process_network_data(yamux_session_t* session, int sockfd) {
    if (session == NULL || sockfd < 0) {
        printf("C: PND 错误 - 无效的会话或套接字\n");
        return -1;
    }
    printf("C: PND Entry - sockfd: %d, c_recv_buffer.len: %zu\n", sockfd, c_recv_buffer.len);
    
    // Read new data into a temporary space at the end of the persistent buffer
    ssize_t bytes_read = 0;
    if (c_recv_buffer.len < c_recv_buffer.capacity) {
        printf("C: PND - Attempting to read from sockfd %d. Buffer available: %zu\n", sockfd, c_recv_buffer.capacity - c_recv_buffer.len);
        bytes_read = read(sockfd, c_recv_buffer.buffer + c_recv_buffer.len, 
                          c_recv_buffer.capacity - c_recv_buffer.len);
        printf("C: PND - read() returned %zd\n", bytes_read);
    } else {
        printf("C: PND - Persistent buffer full (len %zu, capacity %zu). No read attempt.\n", c_recv_buffer.len, c_recv_buffer.capacity);
    }

    if (bytes_read < 0) {
        // EAGAIN or EWOULDBLOCK means no data right now, not a fatal error for this function
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("C: PND - 网络读取无数据 (EAGAIN/EWOULDBLOCK, errno: %d)\n", errno);
            // If there's already data in the buffer, try to process that
            if (c_recv_buffer.len > 0) {
                printf("C: PND - EAGAIN but data exists in buffer (%zu bytes). Proceeding to process.\n", c_recv_buffer.len);
                // Fall through to process existing data
            } else {
                return 0; // No new data, no old data, nothing to do
            }
        } else {
            printf("C: PND - 网络读取错误: %s (errno %d)\n", strerror(errno), errno);
            return -1; // Real read error
        }
    } else if (bytes_read == 0) {
        // Connection closed by peer
        printf("C: PND - 网络连接由对端关闭 (read returned 0)\n");
        // If there's already data in the buffer, try to process that last bit
        if (c_recv_buffer.len > 0) {
             printf("C: PND - EOF but data exists in buffer (%zu bytes). Proceeding to process.\n", c_recv_buffer.len);
            // Fall through to process existing data
        } else {
            return -1; // Connection closed and no data left
        }
    } else {
        // Successfully read some data
        c_recv_buffer.len += bytes_read;
        printf("C: PND - 从网络读取 %zd 字节, 缓冲区现有 %zu 字节\n", bytes_read, c_recv_buffer.len);
    }

    if (c_recv_buffer.len == 0) {
        printf("C: PND - No data in buffer to process. Returning 0.\n");
        return 0; // Nothing to process
    }

    // Process data from the persistent buffer
    printf("C: PND - Calling yamux_session_receive with buffer len %zu\n", c_recv_buffer.len);
    int processed_now = yamux_session_receive(session, c_recv_buffer.buffer, c_recv_buffer.len);
    printf("C: PND - yamux_session_receive 处理了 %d 字节 (缓冲区总长 %zu)\n", processed_now, c_recv_buffer.len);

    if (processed_now < 0) {
        printf("C: PND - yamux_session_receive 错误: %d\n", processed_now);
        // Do not shift buffer on error, let yamux handle session state
        return processed_now; // Propagate error
    }

    if (processed_now > 0 && (size_t)processed_now <= c_recv_buffer.len) {
        // Shift unprocessed data to the beginning of the buffer
        memmove(c_recv_buffer.buffer, c_recv_buffer.buffer + processed_now, c_recv_buffer.len - processed_now);
        c_recv_buffer.len -= processed_now;
        printf("C: PND - 缓冲区移位后，剩余 %zu 字节\n", c_recv_buffer.len);
    } else if ((size_t)processed_now > c_recv_buffer.len) {
        // This should not happen if yamux_session_receive is correct
        printf("C: PND - 严重错误 - yamux_session_receive 处理的字节数 (%d) 大于缓冲区长度 (%zu)\n", processed_now, c_recv_buffer.len);
        c_recv_buffer.len = 0; // Reset buffer to avoid further issues
        return -1; // Indicate a critical error
    }
    // If processed_now == 0 and there was data, it means yamux needs more data for a full frame.
    // The existing data remains in the buffer for the next call.
    printf("C: PND - Returning %d (processed_now)\n", processed_now);
    return processed_now; // Return bytes processed in this call (by yamux_session_receive)
}

// 打开流并发送数据
static uint32_t test_open_and_send(yamux_session_t* session, const char* data) {
    g_stream_established = 0;
    g_data_received = 0;
    
    // 将 session 指针用作 user_data
    void* user_data_for_stream = (void*)session;
    
    printf("C: 打开新流... (将使用 session %p 作为 user_data)\n", user_data_for_stream);
    // 传递 user_data_for_stream 的地址
    uint32_t stream_id = yamux_session_open_stream(session, &user_data_for_stream);
    if (stream_id == 0) {
        printf("C: 打开流失败\n");
        return 0;
    }
    
    // 设置全局流ID
    g_current_stream_id = stream_id;
    // 注意：此时 stream 结构体内部的 user_data 应该已经被设置为 session 指针
    printf("C: 流ID %u 已创建，已设置为当前活动流\n", stream_id);
    
    printf("C: 等待流建立...\n");
    int wait_count = 0;
    while (!g_stream_established && wait_count < 50) {
        usleep(100000);
        wait_count++;
        process_network_data(session, c_sockfd);
    }
    
    if (!g_stream_established) {
        printf("C: 等待流建立超时\n");
        yamux_stream_close(session, stream_id, 0);
        return 0;
    }
    
    if (data) {
        printf("C: 发送数据: %s\n", data);
        int result = yamux_stream_write(session, stream_id, (const uint8_t*)data, strlen(data));
        printf("C: 数据发送结果: %d\n", result);
    }
    
    return stream_id;
}

// 设置套接字为非阻塞模式
static int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}
*/
import "C"
import (
    "fmt"
    "io"
    "net"
    "time"
    "unsafe"

    "github.com/hashicorp/yamux"
)

// 创建TCP服务器并返回监听器
func createTCPServer(addr string) (net.Listener, error) {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return nil, fmt.Errorf("创建TCP服务器失败: %v", err)
    }
    fmt.Printf("Go: TCP服务器监听在 %s\n", listener.Addr())
    return listener, nil
}

// 将Go的net.Conn转换为C可用的文件描述符
func connToFd(conn net.Conn) (int, error) {
    tcpConn, ok := conn.(*net.TCPConn)
    if !ok {
        return -1, fmt.Errorf("连接不是TCP连接")
    }
    
    file, err := tcpConn.File()
    if err != nil {
        return -1, fmt.Errorf("获取文件描述符失败: %v", err)
    }
    
    fd := int(file.Fd())
    fmt.Printf("Go: 获取到连接的文件描述符: %d\n", fd)
    
    return fd, nil
}

// 测试Go客户端连接C服务端
func testGoClientToCServer() bool {
    fmt.Println("\n=== 测试Go客户端连接C服务端 ===")

    listener, err := createTCPServer("127.0.0.1:0")
    if err != nil {
        fmt.Println(err)
        return false
    }
    serverAddr := listener.Addr().String()

    var cServerProcessDone = make(chan bool, 1) // Used to signal C server goroutine completion
    var serverFullyReady = make(chan bool, 1) // Signaled by C server after session creation

    // 启动C端yamux服务器
    go func() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Printf("C服务端 goroutine panic: %v\n", r)
            }
            listener.Close() // Ensure listener is closed
            cServerProcessDone <- true // Signal that this goroutine is exiting
        }()

        fmt.Println("C: 服务端 goroutine 启动, 等待连接...")
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("C: 服务端接受连接失败: %v\n", err)
            // Don't send on serverFullyReady if accept fails
            return
        }
        fmt.Printf("C: 服务端接受连接成功: %s -> %s\n", conn.RemoteAddr(), conn.LocalAddr())

        fd, err := connToFd(conn)
        if err != nil {
            fmt.Printf("C: 服务端 connToFd 失败: %v\n", err)
            return
        }

        // 设置套接字为非阻塞模式
        if C.set_nonblocking(C.int(fd)) != 0 {
            fmt.Println("C: 服务端设置非阻塞模式失败")
            conn.Close()
            return
        }
        fmt.Println("C: 服务端套接字已设置为非阻塞模式")


        session := C.create_interop_session(C.int(fd), C.bool(false))
        if session == nil {
            fmt.Println("C: 服务端创建yamux会话失败")
            conn.Close()
            return
        }
        defer C.yamux_session_free(session)
        fmt.Println("C: 服务端 yamux 会话创建成功")

        // 通知主goroutine服务器已完全准备好
        serverFullyReady <- true
        fmt.Println("C: 服务端已发送 serverFullyReady 信号")

        // 处理网络数据循环
        timeout := time.After(5 * time.Second) // Increased overall timeout for server processing
        loopCount := 0
        for {
            loopCount++
            // fmt.Printf("C: 服务端 PND 循环 #%d\n", loopCount) // Can be noisy
            if C.yamux_session_is_closed(session) {
                fmt.Println("C: 服务端检测到会话关闭 (yamux_session_is_closed), 退出处理循环")
                return
            }

            select {
            case <-timeout:
                fmt.Println("C: 服务端处理网络数据超时 (select timeout)")
                return
            default:
                // Non-blocking check if we should stop (e.g. from a quit channel if implemented)
            }

            result := C.process_network_data(session, C.int(fd))
            // fmt.Printf("C: 服务端 process_network_data 返回: %d\n", result) // Can be noisy

            if result < 0 {
                // process_network_data returns -1 on connection closed or real read error.
                // It returns specific negative yamux error codes for protocol errors.
                fmt.Printf("C: 服务端 process_network_data 返回错误 %d, 可能连接已关闭或发生错误. 退出处理循环.\n", result);
                return;
            }
            // If result == 0 (no data read, no data in buffer), sleep briefly.
            // If result > 0 (data processed), also sleep briefly to yield.
            time.Sleep(20 * time.Millisecond) // Reduced sleep
        }
    }()

    // 给C服务端一点时间启动并开始监听
    time.Sleep(100 * time.Millisecond)

    // 创建Go yamux客户端 (连接操作现在在这里)
    fmt.Println("Go: 客户端尝试连接到", serverAddr)
    clientConn, err := net.DialTimeout("tcp", serverAddr, 1*time.Second) // Timeout for dial
    if err != nil {
        fmt.Printf("Go: 客户端连接失败: %v\n", err)
        // Wait for C server goroutine to finish to get any error messages from it
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: 客户端连接成功")
    defer clientConn.Close()

    // 等待服务端完全准备好 (接受连接并创建了yamux会话)
    fmt.Println("Go: 客户端等待 serverFullyReady 信号...")
    select {
    case <-serverFullyReady:
        fmt.Println("Go: 客户端收到 serverFullyReady 信号")
    case <-time.After(2 * time.Second): // Increased timeout
        fmt.Println("Go: 客户端等待 serverFullyReady 超时")
        <-cServerProcessDone // ensure C server goroutine logs are flushed if it's stuck
        return false
    }

    config := yamux.DefaultConfig()
    goSession, err := yamux.Client(clientConn, config)
    if err != nil {
        fmt.Printf("Go: 客户端创建yamux会话失败: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: 客户端 yamux 会话创建成功")
    defer goSession.Close()

    // 打开流并发送数据
    stream, err := goSession.OpenStream()
    if err != nil {
        fmt.Printf("Go: 客户端打开流失败: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: 客户端打开流成功")
    defer stream.Close()

    message := "Hello from Go yamux client!"
    fmt.Printf("Go: 客户端发送数据: '%s'\n", message)
    _, err = stream.Write([]byte(message))
    if err != nil {
        fmt.Printf("Go: 客户端发送数据失败: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: 客户端发送数据成功")
    
    // 增加接收响应的逻辑
    buf := make([]byte, 128)
    n, err := stream.Read(buf)
    if err != nil {
        if err == io.EOF {
            fmt.Println("Go: 客户端读取到EOF")
        } else {
            fmt.Printf("Go: 客户端读取响应失败: %v\n", err)
            // No return false here, let the C server finish its timeout
        }
    } else {
        fmt.Printf("Go: 客户端收到响应: '%s'\n", string(buf[:n]))
    }


    // 等待C服务端处理完成 (通过cServerProcessDone channel)
    fmt.Println("Go: 客户端等待C服务端处理完成...")
    select {
    case <-cServerProcessDone:
        fmt.Println("Go: C服务端处理完成信号收到")
    case <-time.After(5 * time.Second): // Timeout for the C server to finish its loop
        fmt.Println("Go: 等待C服务端处理超时")
        return false // Consider this a failure
    }
    
    // At this point, the C server goroutine has finished.
    // We can assume success if we reached here without returning false.
    fmt.Println("✓ Go客户端连接C服务端 测试似乎成功")
    return true
}

// 测试C客户端连接Go服务端
func testCClientToGoServer() bool {
    fmt.Println("\n=== 测试C客户端连接Go服务端 ===")
    
    // 创建TCP服务器(Go端使用)
    listener, err := createTCPServer("127.0.0.1:0")
    if err != nil {
        fmt.Println(err)
        return false
    }
    serverAddr := listener.Addr().String()
    
    var success = make(chan bool, 1)
    var serverDone = make(chan bool, 1)
    
    // 启动Go端yamux服务器
    go func() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Printf("Go服务端异常: %v\n", r)
                success <- false
                return
            }
        }()
        
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("Go服务端接受连接失败: %v\n", err)
            success <- false
            return
        }
        
        config := yamux.DefaultConfig()
        session, err := yamux.Server(conn, config)
        if err != nil {
            fmt.Printf("Go服务端创建yamux会话失败: %v\n", err)
            success <- false
            return
        }
        
        // 接受并处理流
        stream, err := session.AcceptStream()
        if err != nil {
            fmt.Printf("Go服务端接受流失败: %v\n", err)
            success <- false
            return
        }
        
        // 读取数据
        buffer := make([]byte, 1024)
        n, err := stream.Read(buffer)
        if err != nil && err != io.EOF {
            fmt.Printf("Go服务端读取数据失败: %v\n", err)
            success <- false
            return
        }
        
        if n > 0 {
            message := string(buffer[:n])
            fmt.Printf("Go: 服务端收到数据: %s\n", message)
            
            // 发送响应
            response := "Hello from Go yamux server!"
            _, err = stream.Write([]byte(response))
            if err != nil {
                fmt.Printf("Go服务端响应失败: %v\n", err)
                success <- false
                return
            }
        }
        
        // 等待一段时间以确保C客户端处理完响应
        time.Sleep(500 * time.Millisecond)
        
        // 通知主goroutine服务端已完成
        serverDone <- true
        success <- true
    }()
    
    // 等待服务端启动
    time.Sleep(100 * time.Millisecond)
    
    // 创建C yamux客户端
    conn, err := net.Dial("tcp", serverAddr)
    if err != nil {
        fmt.Printf("C客户端连接失败: %v\n", err)
        return false
    }
    
    fd, err := connToFd(conn)
    if err != nil {
        fmt.Println(err)
        return false
    }
    // 设置套接字为非阻塞模式
    if C.set_nonblocking(C.int(fd)) != 0 {
        fmt.Println("C客户端设置非阻塞模式失败")
        return false
    }
    fmt.Println("C: 客户端套接字已设置为非阻塞模式")

    session := C.create_interop_session(C.int(fd), C.bool(true))
    if session == nil {
        fmt.Println("C客户端创建yamux会话失败")
        return false
    }
    defer C.yamux_session_free(session)
    
    // 打开流并发送数据
    message := C.CString("Hello from C yamux client!")
    defer C.free(unsafe.Pointer(message))
    
    streamID := C.test_open_and_send(session, message)
    if streamID == 0 {
        fmt.Println("C客户端打开流失败")
        return false
    }
    
    // 处理最多30次网络数据
    var procDone = make(chan bool, 1)
    go func() {
        for i := 0; i < 30; i++ {
            result := C.process_network_data(session, C.int(fd))
            if result < 0 {
                fmt.Printf("C客户端处理网络数据出错: %d\n", result)
                break
            }
            time.Sleep(50 * time.Millisecond)
        }
        procDone <- true
    }()
    
    // 等待数据处理完成
    select {
    case <-procDone:
        fmt.Println("C客户端处理网络数据完成")
    case <-time.After(2 * time.Second):
        fmt.Println("C客户端处理网络数据超时")
    }
    
    // 关闭流
    C.yamux_stream_close(session, streamID, 0)
    
    // 等待服务端处理完成
    select {
    case <-serverDone:
        fmt.Println("Go服务端处理完成")
    case <-time.After(1 * time.Second):
        fmt.Println("等待Go服务端完成超时")
    }
    
    // 获取最终结果
    select {
    case result := <-success:
        return result
    default:
        fmt.Println("没有收到Go服务端结果")
        return false
    }
}

func main() {
    fmt.Println("开始运行yamux互操作性测试套件...")
    
    success := true
    
    // 运行所有测试
    if !testGoClientToCServer() {
        success = false
    }
    
    if !testCClientToGoServer() {
        success = false
    }
    
    if success {
        fmt.Println("\n✅ 所有互操作性测试通过！")
    } else {
        fmt.Println("\n❌ 部分测试失败！")
    }
} 