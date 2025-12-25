#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "yamux.h"

// 说明：
// 这个文件最初用于把 Go 实现的回调“桥接”到 C 的 yamux 实现上。
// 当前 cmd/yamux_test 下的测试用例并不依赖这些桥接函数，但 Go 的构建系统会编译同目录下的 .c 文件。
// 为了避免在未提供 Go 回调实现时导致链接失败，这里提供 weak 的默认实现（Go 若提供同名强符号会覆盖）。

#if defined(__GNUC__) || defined(__clang__)
#define YAMUX_WEAK __attribute__((weak))
#else
#define YAMUX_WEAK
#endif

// 默认 weak 实现（未被使用时也不会影响测试）
YAMUX_WEAK int go_write_callback_impl(void* conn_ctx, const unsigned char* data, size_t len) {
    (void)conn_ctx; (void)data; (void)len;
    return -1;
}
YAMUX_WEAK int go_on_stream_data_callback_impl(void* stream_user_data, const unsigned char* data, size_t len) {
    (void)stream_user_data; (void)data; (void)len;
    return -1;
}
YAMUX_WEAK int go_on_new_stream_callback_impl(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    (void)session_user_data; (void)p_stream;
    if (p_stream_user_data_out) {
        *p_stream_user_data_out = NULL;
    }
    return 0; // reject by default
}
YAMUX_WEAK void go_on_stream_close_callback_impl(void* stream_user_data, int by_remote, uint32_t error_code) {
    (void)stream_user_data; (void)by_remote; (void)error_code;
}
YAMUX_WEAK void go_on_stream_established_callback_impl(void* stream_user_data) {
    (void)stream_user_data;
}
YAMUX_WEAK void go_on_stream_data_eof_callback_impl(void* stream_user_data) {
    (void)stream_user_data;
}
YAMUX_WEAK void go_on_stream_write_window_updated_callback_impl(void* stream_user_data, uint32_t new_window_size) {
    (void)stream_user_data; (void)new_window_size;
}
YAMUX_WEAK void go_on_session_close_callback_impl(void* session_user_data, int by_remote, uint32_t error_code) {
    (void)session_user_data; (void)by_remote; (void)error_code;
}

// 封装函数，确保类型兼容
int go_write_callback(void* conn_ctx, const uint8_t* data, size_t len) {
    return go_write_callback_impl(conn_ctx, data, len);
}

int go_on_stream_data_callback(void* stream_user_data, const uint8_t* data, size_t len) {
    return go_on_stream_data_callback_impl(stream_user_data, data, len);
}

int go_on_new_stream_callback(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out) {
    return go_on_new_stream_callback_impl(session_user_data, p_stream, p_stream_user_data_out);
}

void go_on_stream_close_callback(void* stream_user_data, bool by_remote, uint32_t error_code) {
    go_on_stream_close_callback_impl(stream_user_data, by_remote ? 1 : 0, error_code);
}

void go_on_stream_established_callback(void* stream_user_data) {
    go_on_stream_established_callback_impl(stream_user_data);
}

void go_on_stream_data_eof_callback(void* stream_user_data) {
    go_on_stream_data_eof_callback_impl(stream_user_data);
}

void go_on_stream_write_window_updated_callback(void* stream_user_data, uint32_t new_window_size) {
    go_on_stream_write_window_updated_callback_impl(stream_user_data, new_window_size);
}

void go_on_session_close_callback(void* session_user_data, bool by_remote, uint32_t error_code) {
    go_on_session_close_callback_impl(session_user_data, by_remote ? 1 : 0, error_code);
}

// 创建yamux配置的辅助函数
yamux_config_t* create_yamux_config() {
    yamux_config_t* cfg = (yamux_config_t*)malloc(sizeof(yamux_config_t));
    if (!cfg) return NULL;
    
    memset(cfg, 0, sizeof(yamux_config_t));
    
    // 设置默认配置
    cfg->initial_stream_window_size = 256 * 1024;
    cfg->max_stream_window_size = 1024 * 1024;
    cfg->max_streams = 8;
    cfg->enable_keepalive = 1;
    cfg->keepalive_interval_ms = 30000;
    
    // 设置回调函数
    cfg->write_fn = go_write_callback;
    cfg->on_stream_data = go_on_stream_data_callback;
    cfg->on_new_stream = go_on_new_stream_callback;
    cfg->on_stream_close = go_on_stream_close_callback;
    cfg->on_stream_established = go_on_stream_established_callback;
    cfg->on_stream_data_eof = go_on_stream_data_eof_callback;
    cfg->on_stream_write_window_updated = go_on_stream_write_window_updated_callback;
    cfg->on_session_close = go_on_session_close_callback;
    
    return cfg;
}

// 调试辅助函数
void debug_print(const char* msg) {
    printf("[DEBUG C] %s\n", msg);
    fflush(stdout);
} 