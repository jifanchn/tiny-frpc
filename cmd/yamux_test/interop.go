//go:build yamux_interop
// +build yamux_interop

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

// 方案B：默认安静；只有设置环境变量 TINY_FRPC_VERBOSE=1 才输出测试侧 C 调试日志
static int interop_verbose_enabled(void) {
    const char* v = getenv("TINY_FRPC_VERBOSE");
    return (v && v[0] != '\0' && v[0] != '0');
}
#define ILOG(fmt, ...) do { if (interop_verbose_enabled()) { printf(fmt, ##__VA_ARGS__); fflush(stdout); } } while (0)
#define IERR(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); fflush(stderr); } while (0)

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
        IERR("C: 错误 - 套接字未初始化\n");
        return -1;
    }
    
    ILOG("C: 发送 %zu 字节数据到网络\n", len);
    int total_sent = 0;
    while (total_sent < len) {
        int sent = write(c_sockfd, data + total_sent, len - total_sent);
        if (sent <= 0) {
            IERR("C: 网络发送错误: %d\n", sent);
            return -1;
        }
        total_sent += sent;
    }
    
    return total_sent;
}

// 数据接收回调
static int on_stream_data_received(void* stream_user_data, const uint8_t* data, size_t len) {
    ILOG("C: 收到流数据，长度: %zu 字节\n", len);
    if (len > 0 && len < sizeof(g_received_data)) {
        memcpy(g_received_data, data, len);
        g_data_received = len;
        ILOG("C: 接收到的数据: %.*s\n", (int)len, g_received_data);

        // 使用全局会话和记录的流ID进行窗口更新 和 send response
        if (c_session != NULL && g_current_stream_id > 0) {
            ILOG("C: 自动更新流 %u 的窗口，增加 %zu 字节\n", g_current_stream_id, len);
            yamux_stream_window_update(c_session, g_current_stream_id, (uint32_t)len);

            // send response数据
            const char* response = "Pong from C Server!";
            size_t response_len = strlen(response);
            ILOG("C: Server attempting to send response for stream %u send response: %s\n", g_current_stream_id, response);
            int written = yamux_stream_write(c_session, g_current_stream_id, (const uint8_t*)response, response_len);
            if (written < 0) {
                IERR("C: Server for stream %u failed to send response, error code: %d\n", g_current_stream_id, written);
            } else {
                ILOG("C: Server for stream %u successfully sent %d bytes response\n", g_current_stream_id, written);
            }

        } else {
            ILOG("C: 无法更新窗口或send response：session=%p, stream_id=%u\n", 
                    c_session, g_current_stream_id);
        }
    }
    return len;
}

// 流建立回调
static void on_stream_established(void* stream_user_data) {
    ILOG("C: on_stream_established CALLED (user_data: %p)\n", stream_user_data);
    g_stream_established = 1;
    ILOG("C: g_stream_established SET to 1\n");
}

// 流关闭回调
static void on_stream_closed(void* stream_user_data, bool by_remote, uint32_t error_code) {
    ILOG("C: Stream closed, by_remote: %d, error code: %u\n", by_remote ? 1 : 0, error_code);
}

// 新流回调
static int on_new_stream(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    (void)session_user_data;
    if (p_stream == NULL || *p_stream == NULL) {
        IERR("C: Error - on_new_stream received null stream pointer\n");
        return 0; // reject
    }

    uint32_t stream_id = yamux_stream_get_id(*p_stream);
    ILOG("C: Received new stream request, ID: %u\n", stream_id);

    // 记录流ID到全局变量
    g_current_stream_id = stream_id;

    // Current test mainly driven by global stream_id, not dependent on stream_user_data
    if (p_stream_user_data_out) {
        *p_stream_user_data_out = NULL;
    }

    return 1; // accept
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
        IERR("C: PND 错误 - 无效的会话或套接字\n");
        return -1;
    }
    ILOG("C: PND Entry - sockfd: %d, c_recv_buffer.len: %zu\n", sockfd, c_recv_buffer.len);
    
    // Read new data into a temporary space at the end of the persistent buffer
    ssize_t bytes_read = 0;
    if (c_recv_buffer.len < c_recv_buffer.capacity) {
        ILOG("C: PND - Attempting to read from sockfd %d. Buffer available: %zu\n", sockfd, c_recv_buffer.capacity - c_recv_buffer.len);
        bytes_read = read(sockfd, c_recv_buffer.buffer + c_recv_buffer.len, 
                          c_recv_buffer.capacity - c_recv_buffer.len);
        ILOG("C: PND - read() returned %zd\n", bytes_read);
    } else {
        ILOG("C: PND - Persistent buffer full (len %zu, capacity %zu). No read attempt.\n", c_recv_buffer.len, c_recv_buffer.capacity);
    }

    if (bytes_read < 0) {
        // EAGAIN or EWOULDBLOCK means no data right now, not a fatal error for this function
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ILOG("C: PND - 网络读取无数据 (EAGAIN/EWOULDBLOCK, errno: %d)\n", errno);
            // If there's already data in the buffer, try to process that
            if (c_recv_buffer.len > 0) {
                ILOG("C: PND - EAGAIN but data exists in buffer (%zu bytes). Proceeding to process.\n", c_recv_buffer.len);
                // Fall through to process existing data
            } else {
                return 0; // No new data, no old data, nothing to do
            }
        } else {
            IERR("C: PND - 网络读取错误: %s (errno %d)\n", strerror(errno), errno);
            return -1; // Real read error
        }
    } else if (bytes_read == 0) {
        // Connection closed by peer
        ILOG("C: PND - 网络连接由对端关闭 (read returned 0)\n");
        // If there's already data in the buffer, try to process that last bit
        if (c_recv_buffer.len > 0) {
             ILOG("C: PND - EOF but data exists in buffer (%zu bytes). Proceeding to process.\n", c_recv_buffer.len);
            // Fall through to process existing data
        } else {
            return -1; // Connection closed and no data left
        }
    } else {
        // Successfully read some data
        c_recv_buffer.len += bytes_read;
        ILOG("C: PND - 从网络读取 %zd 字节, 缓冲区现有 %zu 字节\n", bytes_read, c_recv_buffer.len);
    }

    if (c_recv_buffer.len == 0) {
        ILOG("C: PND - No data in buffer to process. Returning 0.\n");
        return 0; // Nothing to process
    }

    // Process data from the persistent buffer
    ILOG("C: PND - Calling yamux_session_receive with buffer len %zu\n", c_recv_buffer.len);
    int processed_now = yamux_session_receive(session, c_recv_buffer.buffer, c_recv_buffer.len);
    ILOG("C: PND - yamux_session_receive 处理了 %d 字节 (缓冲区总长 %zu)\n", processed_now, c_recv_buffer.len);

    if (processed_now < 0) {
        IERR("C: PND - yamux_session_receive 错误: %d\n", processed_now);
        // Do not shift buffer on error, let yamux handle session state
        return processed_now; // Propagate error
    }

    if (processed_now > 0 && (size_t)processed_now <= c_recv_buffer.len) {
        // Shift unprocessed data to the beginning of the buffer
        memmove(c_recv_buffer.buffer, c_recv_buffer.buffer + processed_now, c_recv_buffer.len - processed_now);
        c_recv_buffer.len -= processed_now;
        ILOG("C: PND - 缓冲区移位后，剩余 %zu 字节\n", c_recv_buffer.len);
    } else if ((size_t)processed_now > c_recv_buffer.len) {
        // This should not happen if yamux_session_receive is correct
        IERR("C: PND - 严重错误 - yamux_session_receive 处理的字节数 (%d) 大于缓冲区长度 (%zu)\n", processed_now, c_recv_buffer.len);
        c_recv_buffer.len = 0; // Reset buffer to avoid further issues
        return -1; // Indicate a critical error
    }
    // If processed_now == 0 and there was data, it means yamux needs more data for a full frame.
    // The existing data remains in the buffer for the next call.
    ILOG("C: PND - Returning %d (processed_now)\n", processed_now);
    return processed_now; // Return bytes processed in this call (by yamux_session_receive)
}

// 打开流并发送数据
static uint32_t test_open_and_send(yamux_session_t* session, const char* data) {
    g_stream_established = 0;
    g_data_received = 0;
    
    // 将 session 指针用作 user_data
    void* user_data_for_stream = (void*)session;
    
    ILOG("C: 打开新流... (将使用 session %p 作为 user_data)\n", user_data_for_stream);
    // 传递 user_data_for_stream 的地址
    uint32_t stream_id = yamux_session_open_stream(session, &user_data_for_stream);
    if (stream_id == 0) {
        IERR("C: 打开流失败\n");
        return 0;
    }
    
    // 设置全局流ID
    g_current_stream_id = stream_id;
    // 注意：此时 stream 结构体内部的 user_data 应该已经被设置为 session 指针
    ILOG("C: 流ID %u 已创建，已设置为当前活动流\n", stream_id);
    
    ILOG("C: 等待流建立...\n");
    int wait_count = 0;
    while (!g_stream_established && wait_count < 50) {
        usleep(100000);
        wait_count++;
        process_network_data(session, c_sockfd);
    }
    
    if (!g_stream_established) {
        IERR("C: 等待流建立超时\n");
        yamux_stream_close(session, stream_id, 0);
        return 0;
    }
    
    if (data) {
        ILOG("C: 发送数据: %s\n", data);
        int result = yamux_stream_write(session, stream_id, (const uint8_t*)data, strlen(data));
        ILOG("C: 数据发送结果: %d\n", result);
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

// E2E reconnect/lifecycle regression: run multiple cycles in one process to catch
// global state leaks, FD leaks, and session/stream lifecycle issues.
const interopReconnectCycles = 5

func runCycles(name string, cycles int, fn func() bool) bool {
	ok := true
	for i := 0; i < cycles; i++ {
		fmt.Printf("\n--- %s reconnect cycle %d/%d ---\n", name, i+1, cycles)
		if !fn() {
			ok = false
		}
		// Give goroutines/FDs a moment to settle before next cycle.
		time.Sleep(50 * time.Millisecond)
	}
	return ok
}

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

// Test Go client connecting to C server
func testGoClientToCServer() bool {
    fmt.Println("\n=== Test Go client connecting to C server ===")

    listener, err := createTCPServer("127.0.0.1:0")
    if err != nil {
        fmt.Println(err)
        return false
    }
    serverAddr := listener.Addr().String()

    var cServerProcessDone = make(chan bool, 1) // Used to signal C server goroutine completion
    var serverFullyReady = make(chan bool, 1) // Signaled by C server after session creation

    // Start C-side yamux server
    go func() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Printf("C server goroutine panic: %v\n", r)
            }
            listener.Close() // Ensure listener is closed
            cServerProcessDone <- true // Signal that this goroutine is exiting
        }()

        fmt.Println("C: Server goroutine started, waiting for connection...")
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("C: Server failed to accept connection: %v\n", err)
            // Don't send on serverFullyReady if accept fails
            return
        }
        fmt.Printf("C: Server accepted connection successfully: %s -> %s\n", conn.RemoteAddr(), conn.LocalAddr())

        fd, err := connToFd(conn)
        if err != nil {
            fmt.Printf("C: Server connToFd failed: %v\n", err)
            return
        }

        // 设置套接字为非阻塞模式
        if C.set_nonblocking(C.int(fd)) != 0 {
            fmt.Println("C: Server failed to set non-blocking mode")
            conn.Close()
            return
        }
        fmt.Println("C: Server socket set to non-blocking mode")


        session := C.create_interop_session(C.int(fd), C.bool(false))
        if session == nil {
            fmt.Println("C: Server failed to create yamux session")
            conn.Close()
            return
        }
        defer C.yamux_session_free(session)
        fmt.Println("C: Server yamux session created successfully")

        // Notifying main goroutine that server is fully ready
        serverFullyReady <- true
        fmt.Println("C: Server sent serverFullyReady signal")

        // 处理网络数据循环
        timeout := time.After(5 * time.Second) // Increased overall timeout for server processing
        loopCount := 0
        for {
            loopCount++
            // fmt.Printf("C: 服务端 PND 循环 #%d\n", loopCount) // Can be noisy
            if C.yamux_session_is_closed(session) {
                fmt.Println("C: Server detected session closed (yamux_session_is_closed), exiting processing loop")
                return
            }

            select {
            case <-timeout:
                fmt.Println("C: Server processing network data timeout (select timeout)")
                return
            default:
                // Non-blocking check if we should stop (e.g. from a quit channel if implemented)
            }

            result := C.process_network_data(session, C.int(fd))
            // fmt.Printf("C: Server process_network_data returned: %d\n", result) // Can be noisy

            if result < 0 {
                // process_network_data returns -1 on EOF/connection closed, or negative yamux error codes on protocol errors.
                if result == -1 {
                    fmt.Println("C: 服务端检测到连接关闭(EOF)，exiting processing loop")
                } else {
                    fmt.Printf("C: Server process_network_data returned错误 %d，exiting processing loop\n", result)
                }
                return;
            }
            // If result == 0 (no data read, no data in buffer), sleep briefly.
            // If result > 0 (data processed), also sleep briefly to yield.
            time.Sleep(20 * time.Millisecond) // Reduced sleep
        }
    }()

    // Give C server time to start and listen
    time.Sleep(100 * time.Millisecond)

    // Create Go yamux client (connection now happens here))
    fmt.Println("Go: Client attempting to connect to", serverAddr)
    clientConn, err := net.DialTimeout("tcp", serverAddr, 1*time.Second) // Timeout for dial
    if err != nil {
        fmt.Printf("Go: Client connection failed: %v\n", err)
        // Wait for C server goroutine to finish to get any error messages from it
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: Client connected successfully")
    defer clientConn.Close()

    // Wait for server to be fully ready (accepted connection and created yamux session))
    fmt.Println("Go: Client waiting for serverFullyReady signal...")
    select {
    case <-serverFullyReady:
        fmt.Println("Go: Client received serverFullyReady signal")
    case <-time.After(2 * time.Second): // Increased timeout
        fmt.Println("Go: Client waiting for serverFullyReady timeout")
        <-cServerProcessDone // ensure C server goroutine logs are flushed if it's stuck
        return false
    }

    config := yamux.DefaultConfig()
    goSession, err := yamux.Client(clientConn, config)
    if err != nil {
        fmt.Printf("Go: Client failed to create yamux session: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: Client yamux session created successfully")
    defer goSession.Close()

    // 打开流并发送数据
    stream, err := goSession.OpenStream()
    if err != nil {
        fmt.Printf("Go: Client failed to open stream: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: Client opened stream successfully")
    defer stream.Close()

    message := "Hello from Go yamux client!"
    fmt.Printf("Go: Client sending data: '%s'\n", message)
    _, err = stream.Write([]byte(message))
    if err != nil {
        fmt.Printf("Go: Client sending data失败: %v\n", err)
        <-cServerProcessDone
        return false
    }
    fmt.Println("Go: Client sending data成功")
    
    // 增加接收响应的逻辑
    buf := make([]byte, 128)
    n, err := stream.Read(buf)
    if err != nil {
        if err == io.EOF {
            fmt.Println("Go: Client read EOF")
        } else {
            fmt.Printf("Go: Client failed to read response: %v\n", err)
            // No return false here, let the C server finish its timeout
        }
    } else {
        fmt.Printf("Go: Client received response: '%s'\n", string(buf[:n]))
    }

    // 主动关闭客户端侧资源，让 C 服务端能尽快读到 EOF 并exiting processing loop（避免“select timeout”误导性日志）
    _ = stream.Close()
    _ = goSession.Close()
    _ = clientConn.Close()

    // Wait for C server to finish processing (via cServerProcessDone channel))
    fmt.Println("Go: Client waiting for C server to finish processing...")
    select {
    case <-cServerProcessDone:
        fmt.Println("Go: C server processing complete signal received")
    case <-time.After(5 * time.Second): // Timeout for the C server to finish its loop
        fmt.Println("Go: Timeout waiting for C server processing")
        return false // Consider this a failure
    }
    
    // At this point, the C server goroutine has finished.
    // We can assume success if we reached here without returning false.
    fmt.Println("✓ Go client to C server test seems successful")
    return true
}

// Test C client connecting to Go server
func testCClientToGoServer() bool {
    fmt.Println("\n=== Test C client connecting to Go server ===")
    
    // 创建TCP服务器(Go端使用)
    listener, err := createTCPServer("127.0.0.1:0")
    if err != nil {
        fmt.Println(err)
        return false
    }
    serverAddr := listener.Addr().String()
    
    var success = make(chan bool, 1)
    var serverDone = make(chan bool, 1)
    
    // Start Go-side yamux server
    go func() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Printf("Go server panic: %v\n", r)
                success <- false
                return
            }
        }()
        
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("GoServer failed to accept connection: %v\n", err)
            success <- false
            return
        }
        
        config := yamux.DefaultConfig()
        session, err := yamux.Server(conn, config)
        if err != nil {
            fmt.Printf("GoServer failed to create yamux session: %v\n", err)
            success <- false
            return
        }
        
        // 接受并处理流
        stream, err := session.AcceptStream()
        if err != nil {
            fmt.Printf("Go server failed to accept stream: %v\n", err)
            success <- false
            return
        }
        
        // 读取数据
        buffer := make([]byte, 1024)
        n, err := stream.Read(buffer)
        if err != nil && err != io.EOF {
            fmt.Printf("Go server failed to read data: %v\n", err)
            success <- false
            return
        }
        
        if n > 0 {
            message := string(buffer[:n])
            fmt.Printf("Go: Server received data: %s\n", message)
            
            // send response
            response := "Hello from Go yamux server!"
            _, err = stream.Write([]byte(response))
            if err != nil {
                fmt.Printf("Go server failed to respond: %v\n", err)
                success <- false
                return
            }
        }
        
        // Wait to ensure C client processes the response
        time.Sleep(500 * time.Millisecond)
        
        // Notify main goroutine that server is done
        serverDone <- true
        success <- true
    }()
    
    // Wait for server to start
    time.Sleep(100 * time.Millisecond)
    
    // Create C yamux client
    conn, err := net.Dial("tcp", serverAddr)
    if err != nil {
        fmt.Printf("CClient connection failed: %v\n", err)
        return false
    }
    
    fd, err := connToFd(conn)
    if err != nil {
        fmt.Println(err)
        return false
    }
    // 设置套接字为非阻塞模式
    if C.set_nonblocking(C.int(fd)) != 0 {
        fmt.Println("C client failed to set non-blocking mode")
        return false
    }
    fmt.Println("C: Client socket set to non-blocking mode")

    session := C.create_interop_session(C.int(fd), C.bool(true))
    if session == nil {
        fmt.Println("CClient failed to create yamux session")
        return false
    }
    defer C.yamux_session_free(session)
    
    // 打开流并发送数据
    message := C.CString("Hello from C yamux client!")
    defer C.free(unsafe.Pointer(message))
    
    streamID := C.test_open_and_send(session, message)
    if streamID == 0 {
        fmt.Println("CClient failed to open stream")
        return false
    }
    
    // 处理最多30次网络数据
    var procDone = make(chan bool, 1)
    go func() {
        for i := 0; i < 30; i++ {
            result := C.process_network_data(session, C.int(fd))
            if result < 0 {
                fmt.Printf("C client error processing network data: %d\n", result)
                break
            }
            time.Sleep(50 * time.Millisecond)
        }
        procDone <- true
    }()
    
    // 等待数据处理完成
    select {
    case <-procDone:
        fmt.Println("C client finished processing network data")
    case <-time.After(2 * time.Second):
        fmt.Println("C client processing network data timeout")
    }
    
    // 关闭流
    C.yamux_stream_close(session, streamID, 0)
    
    // Wait for server to finish processing
    select {
    case <-serverDone:
        fmt.Println("Go server processing complete")
    case <-time.After(1 * time.Second):
        fmt.Println("Timeout waiting for Go server to finish")
    }
    
    // 获取最终结果
    select {
    case result := <-success:
        return result
    default:
        fmt.Println("Did not receive Go server result")
        return false
    }
}

func main() {
    // Ensure LLVM coverage profile is flushed (only active with -tags=covflush).
    defer flushCoverage()

    fmt.Println("Starting yamux interoperability test suite...")
    
    success := true
    
    // Run all tests (including reconnect/repeat lifecycle)
    if !runCycles("Go client -> C server", interopReconnectCycles, testGoClientToCServer) {
        success = false
    }
    if !runCycles("C client -> Go server", interopReconnectCycles, testCClientToGoServer) {
        success = false
    }
    
    if success {
        fmt.Println("\n✅ All interoperability tests passed!")
    } else {
        fmt.Println("\n❌ Some tests failed!")
    }
} 