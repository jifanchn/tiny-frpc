//go:build yamux_basic
// +build yamux_basic

package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include -I../../wrapper/linux -DDEBUG_LOG
#cgo LDFLAGS: -L../../build -lyamux -ltools -lwrapper -lm

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>  // 添加unistd.h以支持usleep
#include "yamux.h"

// 全局变量用于测试回调
static uint8_t test_buffer[65536];
static int test_buffer_pos = 0;

// 基础写入回调
static int basic_write_callback(void* ctx, const uint8_t* data, size_t len) {
    printf("Write called with %zu bytes\n", len);
    if (test_buffer_pos + len > sizeof(test_buffer)) {
        return -1;
    }
    memcpy(test_buffer + test_buffer_pos, data, len);
    test_buffer_pos += len;
    return (int)len;
}

// 数据接收回调
static int on_stream_data(void* stream_user_data, const uint8_t* data, size_t len) {
    printf("Stream received %zu bytes\n", len);
    
    // 获取stream_id和session
    // 注意：在这个测试中，我们将stream_id编码在高32位，session指针在低32位
    yamux_session_t* session = NULL;
    uint32_t stream_id = 0;
    
    if (stream_user_data) {
        uintptr_t ptr_val = (uintptr_t)stream_user_data;
        stream_id = (uint32_t)(ptr_val >> 32);  // 提取高32位作为stream_id
        session = (yamux_session_t*)(ptr_val & 0xFFFFFFFF);  // 提取低32位作为session指针
    }
    
    // 确保我们有流ID和会话
    if (stream_id > 0 && session != NULL) {
        // 立即更新窗口，使用原始增量
        printf("立即更新流ID %u的窗口，增加 %zu 字节\n", stream_id, len);
        yamux_stream_window_update(session, stream_id, (uint32_t)len);
    } else {
        printf("无法更新窗口：stream_id=%u, session=%p\n", stream_id, session);
    }
    
    return (int)len;  // 返回处理的字节数
}

// 流建立回调
static void on_stream_established(void* stream_user_data) {
    printf("Stream established\n");
}

// 流关闭回调
static void on_stream_closed(void* stream_user_data, bool by_remote, uint32_t error_code) {
    printf("Stream closed, by_remote=%d, error_code=%u\n", by_remote ? 1 : 0, error_code);
}

// 新流回调
static int on_new_stream(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    (void)session_user_data;
    if (p_stream == NULL || *p_stream == NULL) {
        return 0; // reject
    }

    uint32_t stream_id = yamux_stream_get_id(*p_stream);
    printf("New stream request, id=%u\n", stream_id);

    if (p_stream_user_data_out) {
        *p_stream_user_data_out = NULL;
    }
    return 1; // accept
}

// 创建测试会话
static yamux_session_t* create_test_session(bool is_client) {
    yamux_config_t config;
    memset(&config, 0, sizeof(config));
    
    // 基本配置
    config.enable_keepalive = 1;
    config.keepalive_interval_ms = 30000;
    config.initial_stream_window_size = 256 * 1024;
    config.max_stream_window_size = 1024 * 1024;
    config.max_streams = 8;
    
    // 回调设置
    config.write_fn = basic_write_callback;
    config.on_stream_data = on_stream_data;
    config.on_stream_established = on_stream_established;
    config.on_stream_close = on_stream_closed;
    config.on_new_stream = on_new_stream;
    
    return yamux_session_new(&config, is_client, NULL);
}

// 测试流操作
static int test_stream_operations(yamux_session_t* session) {
    // 重置测试缓冲区
    test_buffer_pos = 0;
    
    // 测试数据
    const char* test_data = "Hello, yamux!";
    size_t data_len = strlen(test_data);
    
    // 打开新流
    // 将stream_id和session编码到user_data中
    // 我们会在stream_id打开后，将其存入user_data的高32位，将session指针存入低32位
    void* stream_user_data = NULL;
    uint32_t stream_id = yamux_session_open_stream(session, &stream_user_data);
    if (stream_id == 0) {
        printf("Failed to open stream\n");
        return -1;
    }
    
    // 创建一个编码了stream_id和session的user_data
    uintptr_t encoded_data = ((uintptr_t)stream_id << 32) | ((uintptr_t)session & 0xFFFFFFFF);
    stream_user_data = (void*)encoded_data;
    
    printf("打开流ID %u，设置user_data: %p (编码了stream_id和session)\n", 
           stream_id, stream_user_data);
    
    // 更新窗口大小，为写入数据做准备
    printf("更新流ID %u的接收窗口\n", stream_id);
    yamux_stream_window_update(session, stream_id, 1024 * 1024);
    
    // 写入测试数据，尝试多次直到成功
    int result = 0;
    int total_sent = 0;
    int retry_count = 0;
    const int max_retries = 5;
    
    while (total_sent < data_len && retry_count < max_retries) {
        result = yamux_stream_write(session, stream_id, 
                          (const uint8_t*)test_data + total_sent, 
                          data_len - total_sent);
        
        printf("写入尝试 %d: 结果 = %d\n", retry_count + 1, result);
        
        if (result > 0) {
            total_sent += result;
            printf("已发送 %d 字节，总计: %d/%zu\n", result, total_sent, data_len);
            break; // 成功发送数据，跳出循环
        } else if (result == YAMUX_ERR_WINDOW) { // YAMUX_ERR_WINDOW
            printf("窗口已满，等待...\n");
            usleep(50000); // 等待50ms
            retry_count++;
        } else {
            printf("写入错误: %d\n", result);
            return -1;
        }
    }
    
    // 检查是否全部发送
    if (total_sent == data_len) {
        printf("成功发送所有数据\n");
    } else {
        printf("尝试 %d 次后仍未能发送所有数据\n", max_retries);
    }
    
    // 等待一段时间处理
    usleep(200000); // 200ms
    
    // 关闭流
    yamux_stream_close(session, stream_id, 0);
    
    // 严格：必须发送成功
    if (total_sent != (int)data_len) {
        printf("未能发送全部数据，总计: %d/%zu\n", total_sent, data_len);
        return -1;
    }
    return 0;
}
*/
import "C"
import (
    "fmt"
    "time"
)

// 基本连接测试
func testBasicConnection() bool {
    fmt.Println("\n=== 运行基本连接测试 ===")
    
    session := C.create_test_session(true)
    if session == nil {
        fmt.Println("❌ 会话创建失败")
        return false
    }
    
    fmt.Println("✓ 会话创建成功")
    C.yamux_session_free(session)
    fmt.Println("✓ 会话已正确释放")
    return true
}

// 流操作测试
func testStreamOperations() bool {
    fmt.Println("\n=== 运行流操作测试 ===")
    
    session := C.create_test_session(true)
    if session == nil {
        fmt.Println("❌ 会话创建失败")
        return false
    }
    defer C.yamux_session_free(session)
    
    result := C.test_stream_operations(session)
    if result != 0 {
        fmt.Println("❌ 流操作测试失败")
        return false
    }
    
    fmt.Println("✓ 流操作测试成功")
    return true
}

// 会话配置测试
func testSessionConfig() bool {
    fmt.Println("\n=== 运行会话配置测试 ===")
    
    // 创建客户端会话
    clientSession := C.create_test_session(true)
    if clientSession == nil {
        fmt.Println("❌ 客户端会话创建失败")
        return false
    }
    defer C.yamux_session_free(clientSession)
    
    // 创建服务端会话
    serverSession := C.create_test_session(false)
    if serverSession == nil {
        fmt.Println("❌ 服务端会话创建失败")
        return false
    }
    defer C.yamux_session_free(serverSession)
    
    // 运行一段时间让keepalive生效
    time.Sleep(100 * time.Millisecond)
    
    fmt.Println("✓ 会话配置测试成功")
    return true
}

func main() {
    // Ensure LLVM coverage profile is flushed (only active with -tags=covflush).
    defer flushCoverage()

    fmt.Println("开始运行yamux基础测试套件...")
    
    success := true
    
    // 运行所有测试
    if !testBasicConnection() {
        success = false
    }
    
    if !testStreamOperations() {
        success = false
    }
    
    if !testSessionConfig() {
        success = false
    }
    
    if success {
        fmt.Println("\n✅ 所有基础测试通过！")
    } else {
        fmt.Println("\n❌ 部分测试失败！")
    }
} 