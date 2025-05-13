/**
 * @file tools.h
 * @brief 轻量级工具函数，适用于嵌入式环境
 */
#ifndef TINY_FRPC_TOOLS_H
#define TINY_FRPC_TOOLS_H

#include <stdint.h>

/**
 * @brief 字节序转换函数 - 主机序到网络序(32位)
 */
uint32_t tools_htonl(uint32_t hostlong);

/**
 * @brief 字节序转换函数 - 主机序到网络序(16位)
 */
uint16_t tools_htons(uint16_t hostshort);

/**
 * @brief 字节序转换函数 - 网络序到主机序(32位)
 */
uint32_t tools_ntohl(uint32_t netlong);

/**
 * @brief 字节序转换函数 - 网络序到主机序(16位)
 */
uint16_t tools_ntohs(uint16_t netshort);

/**
 * @brief 获取当前时间戳(毫秒)
 * 不同平台需要特定实现
 */
uint64_t tools_get_time_ms(void);

/**
 * @brief 初始化工具库
 * 用于初始化可能需要的内部状态
 */
void tools_init(void);

#endif /* TINY_FRPC_TOOLS_H */ 