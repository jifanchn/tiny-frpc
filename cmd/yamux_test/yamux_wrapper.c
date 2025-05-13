#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "yamux.h"

// 声明来自Go的回调函数
extern int go_write_callback_impl(void* conn_ctx, const unsigned char* data, size_t len);
extern int go_on_stream_data_callback_impl(void* stream_user_data, const unsigned char* data, size_t len);
extern int go_on_new_stream_callback_impl(void* session_ctx, uint32_t stream_id, void** stream_user_data);
extern void go_on_stream_close_callback_impl(void* stream_user_data, int by_remote, uint32_t error_code);
extern void go_on_stream_established_callback_impl(void* stream_user_data);
extern void go_on_stream_data_eof_callback_impl(void* stream_user_data);
extern void go_on_stream_write_window_updated_callback_impl(void* stream_user_data, uint32_t new_window_size);
extern void go_on_session_close_callback_impl(void* session_user_data, int by_remote, uint32_t error_code);

// 封装函数，确保类型兼容
int go_write_callback(void* conn_ctx, const uint8_t* data, size_t len) {
    return go_write_callback_impl(conn_ctx, data, len);
}

int go_on_stream_data_callback(void* stream_user_data, const uint8_t* data, size_t len) {
    return go_on_stream_data_callback_impl(stream_user_data, data, len);
}

bool go_on_new_stream_callback(void* session_ctx, uint32_t stream_id, void** stream_user_data) {
    int result = go_on_new_stream_callback_impl(session_ctx, stream_id, stream_user_data);
    return (result != 0) ? true : false;
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