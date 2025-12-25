/**
 * @file tools.h
 * @brief Lightweight utility helpers for embedded-friendly environments
 */
#ifndef TINY_FRPC_TOOLS_H
#define TINY_FRPC_TOOLS_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Byte-order conversion: host to network (32-bit)
 */
uint32_t tools_htonl(uint32_t hostlong);

/**
 * @brief Byte-order conversion: host to network (16-bit)
 */
uint16_t tools_htons(uint16_t hostshort);

/**
 * @brief Byte-order conversion: network to host (32-bit)
 */
uint32_t tools_ntohl(uint32_t netlong);

/**
 * @brief Byte-order conversion: network to host (16-bit)
 */
uint16_t tools_ntohs(uint16_t netshort);

/**
 * @brief Get current timestamp (milliseconds)
 * Platform-specific implementation may be required.
 */
uint64_t tools_get_time_ms(void);

/**
 * @brief Initialize the tools module.
 * Used to initialize internal state if needed.
 */
void tools_init(void);

/**
 * @brief Compute MD5 and output a 32-byte lowercase hex string (NUL-terminated)
 *
 * @param data Input bytes
 * @param len  Input length
 * @param out_hex Output buffer, at least 33 bytes
 * @return 0 on success, <0 on failure
 */
int tools_md5_hex(const uint8_t* data, size_t len, char out_hex[33]);

/**
 * @brief Compute FRP auth key (equivalent to Go: util.GetAuthKey(token, timestamp))
 *
 * Computes MD5(token + strconv.FormatInt(timestamp, 10)) and outputs lowercase hex.
 *
 * @param token Auth token (or STCP secret key)
 * @param timestamp Unix timestamp (seconds)
 * @param out_hex Output buffer, at least 33 bytes
 * @return 0 on success, <0 on failure
 */
int tools_get_auth_key(const char* token, int64_t timestamp, char out_hex[33]);

#endif /* TINY_FRPC_TOOLS_H */ 