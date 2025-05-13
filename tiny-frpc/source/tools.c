/**
 * @file tools.c
 * @brief 轻量级工具函数实现
 */
#include "../include/tools.h"

/* 检测系统字节序 */
static int is_little_endian(void) {
    static uint32_t test = 1;
    return *((uint8_t*)&test) == 1;
}

/* 字节序转换函数实现 */
uint32_t tools_htonl(uint32_t hostlong) {
    if (is_little_endian()) {
        return ((hostlong & 0xFF) << 24) |
               ((hostlong & 0xFF00) << 8) |
               ((hostlong & 0xFF0000) >> 8) |
               ((hostlong & 0xFF000000) >> 24);
    }
    return hostlong;
}

uint16_t tools_htons(uint16_t hostshort) {
    if (is_little_endian()) {
        return ((hostshort & 0xFF) << 8) | ((hostshort & 0xFF00) >> 8);
    }
    return hostshort;
}

uint32_t tools_ntohl(uint32_t netlong) {
    return tools_htonl(netlong); /* 网络序和主机序互转是同一个操作 */
}

uint16_t tools_ntohs(uint16_t netshort) {
    return tools_htons(netshort); /* 网络序和主机序互转是同一个操作 */
}

/* 
 * 时间戳函数
 * 注意：这是一个平台相关的函数，需要根据实际平台替换
 * 下面提供一个基于计数器的简单实现，实际应用中需替换
 */
static uint64_t time_counter = 0;

uint64_t tools_get_time_ms(void) {
    /* 
     * 嵌入式平台应当根据自身硬件特性实现此函数
     * 例如使用定时器中断、RTC等
     */
    return time_counter++;
}

void tools_init(void) {
    /* 初始化时间计数器等资源 */
    time_counter = 0;
} 