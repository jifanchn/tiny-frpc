/**
 * @file frpc_protocol.c
 * @brief Implementation of the FRP protocol for tiny-frpc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__linux__)
#include <endian.h>
#else
#define htobe64(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define be64toh(x) ((((uint64_t)ntohl(x)) << 32) + ntohl((x) >> 32))
#endif

#include "frpc_protocol.h"
#include "frpc.h"

/**
 * @brief Read a message header from a buffer
 * 
 * @param buffer Buffer containing serialized message header
 * @param header Header structure to fill
 * @return 0 on success, -1 on error
 */
int frpc_protocol_read_header(const uint8_t *buffer, frpc_msg_header_t *header) {
    if (!buffer || !header) {
        return -1;
    }
    
    /* Read type (1 byte) */
    header->type = buffer[0];
    
    /* Read sequence number (8 bytes, network byte order) */
    memcpy(&header->seq, buffer + 1, 8);
    header->seq = be64toh(header->seq);
    
    /* Read content length (4 bytes, network byte order) */
    memcpy(&header->content_length, buffer + 9, 4);
    header->content_length = ntohl(header->content_length);
    
    return 0;
}

/**
 * @brief Write a message header to a buffer
 * 
 * @param header Header structure to serialize
 * @param buffer Buffer to write the serialized header to
 * @return 0 on success, -1 on error
 */
int frpc_protocol_write_header(const frpc_msg_header_t *header, uint8_t *buffer) {
    if (!buffer || !header) {
        return -1;
    }
    
    /* Write type (1 byte) */
    buffer[0] = header->type;
    
    /* Write sequence number (8 bytes, network byte order) */
    uint64_t seq_net = htobe64(header->seq);
    memcpy(buffer + 1, &seq_net, 8);
    
    /* Write content length (4 bytes, network byte order) */
    uint32_t len_net = htonl(header->content_length);
    memcpy(buffer + 9, &len_net, 4);
    
    return 0;
}

/**
 * @brief Create a login message
 * 
 * @param version Client version
 * @param user Username
 * @param token Authentication token
 * @param buffer Buffer to store the serialized message
 * @param buffer_size Size of the buffer
 * @param header_out Header structure to fill with the message header
 * @return Size of the message on success, -1 on error
 */
int frpc_protocol_create_login(const char *version, const char *user, 
                              const char *token, uint8_t *buffer, 
                              size_t buffer_size, frpc_msg_header_t *header_out) {
    if (!version || !buffer || buffer_size < 100 || !header_out) {
        return -1;
    }
    
    /* Format the JSON content */
    char content[512];
    int content_len = snprintf(content, sizeof(content),
                              "{\"version\":\"%s\","
                              "\"hostname\":\"tiny-frpc\","
                              "\"os\":\"embedded\","
                              "\"arch\":\"generic\","
                              "\"user\":\"%s\","
                              "\"privilege_key\":\"%s\","
                              "\"timestamp\":%lld,"
                              "\"run_id\":\"%016llx\"}",
                              version, 
                              user ? user : "", 
                              token ? token : "",
                              (long long)time(NULL),
                              (long long)rand());
    
    if (content_len < 0 || (size_t)content_len >= sizeof(content)) {
        return -1;
    }
    
    /* Create header */
    header_out->type = FRPC_MSG_TYPE_LOGIN;
    header_out->seq = 1;  /* First message */
    header_out->content_length = (uint32_t)content_len;
    
    /* Check buffer size */
    if (buffer_size < 13 + content_len) {
        return -1;
    }
    
    /* Write header */
    frpc_protocol_write_header(header_out, buffer);
    
    /* Write content */
    memcpy(buffer + 13, content, content_len);
    
    return 13 + content_len;
}

/**
 * @brief Parse a login response message
 * 
 * @param buffer Buffer containing the serialized message content (without header)
 * @param buffer_size Size of the buffer
 * @param error_code Error code output
 * @param error_msg Error message output buffer
 * @param error_msg_size Size of the error message buffer
 * @return 0 on success, -1 on error
 */
int frpc_protocol_parse_login_resp(const uint8_t *buffer, size_t buffer_size, 
                                  int *error_code, char *error_msg, 
                                  size_t error_msg_size) {
    if (!buffer || !error_code || !error_msg || error_msg_size == 0) {
        return -1;
    }
    
    /* For now, just set a dummy success result */
    *error_code = 0;
    strncpy(error_msg, "Success", error_msg_size - 1);
    error_msg[error_msg_size - 1] = '\0';
    
    /* TODO: Parse the JSON content properly */
    
    return 0;
}

/**
 * @brief Create a new proxy message
 * 
 * @param name Proxy name
 * @param proxy_type Proxy type
 * @param remote_port Remote port
 * @param buffer Buffer to store the serialized message
 * @param buffer_size Size of the buffer
 * @param header_out Header structure to fill with the message header
 * @return Size of the message on success, -1 on error
 */
int frpc_protocol_create_new_proxy(const char *name, int proxy_type, 
                                 uint16_t remote_port, uint8_t *buffer, 
                                 size_t buffer_size, frpc_msg_header_t *header_out) {
    if (!name || !buffer || buffer_size < 100 || !header_out) {
        return -1;
    }
    
    /* Format the JSON content */
    char content[512];
    int content_len = snprintf(content, sizeof(content),
                              "{\"name\":\"%s\","
                              "\"type\":\"%s\","
                              "\"remote_port\":%d}",
                              name,
                              proxy_type == FRPC_PROXY_TYPE_TCP ? "tcp" :
                              proxy_type == FRPC_PROXY_TYPE_UDP ? "udp" :
                              proxy_type == FRPC_PROXY_TYPE_HTTP ? "http" :
                              proxy_type == FRPC_PROXY_TYPE_HTTPS ? "https" :
                              proxy_type == FRPC_PROXY_TYPE_STCP ? "stcp" :
                              proxy_type == FRPC_PROXY_TYPE_XTCP ? "xtcp" :
                              "tcp",
                              remote_port);
    
    if (content_len < 0 || (size_t)content_len >= sizeof(content)) {
        return -1;
    }
    
    /* Create header */
    header_out->type = FRPC_MSG_TYPE_NEW_PROXY;
    header_out->seq = 2;  /* Second message */
    header_out->content_length = (uint32_t)content_len;
    
    /* Check buffer size */
    if (buffer_size < 13 + content_len) {
        return -1;
    }
    
    /* Write header */
    frpc_protocol_write_header(header_out, buffer);
    
    /* Write content */
    memcpy(buffer + 13, content, content_len);
    
    return 13 + content_len;
}

/**
 * @brief Create a ping message
 * 
 * @param buffer Buffer to store the serialized message
 * @param buffer_size Size of the buffer
 * @param seq Sequence number for the ping
 * @param header_out Header structure to fill with the message header
 * @return Size of the message on success, -1 on error
 */
int frpc_protocol_create_ping(uint8_t *buffer, size_t buffer_size, 
                            uint64_t seq, frpc_msg_header_t *header_out) {
    if (!buffer || buffer_size < 13 || !header_out) {
        return -1;
    }
    
    /* Create header - ping has no content */
    header_out->type = FRPC_MSG_TYPE_PING;
    header_out->seq = seq;
    header_out->content_length = 0;
    
    /* Write header */
    frpc_protocol_write_header(header_out, buffer);
    
    return 13;  /* Header size only */
}

/**
 * @brief Create a new work connection message
 * 
 * @param buffer Buffer to store the serialized message
 * @param buffer_size Size of the buffer
 * @param seq Sequence number
 * @param header_out Header structure to fill with the message header
 * @return Size of the message on success, -1 on error
 */
int frpc_protocol_create_work_conn(uint8_t *buffer, size_t buffer_size, 
                                 uint64_t seq, frpc_msg_header_t *header_out) {
    if (!buffer || buffer_size < 13 || !header_out) {
        return -1;
    }
    
    /* Create header - new work connection has no content */
    header_out->type = FRPC_MSG_TYPE_NEW_WORK_CONN;
    header_out->seq = seq;
    header_out->content_length = 0;
    
    /* Write header */
    frpc_protocol_write_header(header_out, buffer);
    
    return 13;  /* Header size only */
}

/**
 * @brief Create a new visitor message
 * 
 * @param name Proxy name
 * @param sk Secret key
 * @param buffer Buffer to store the serialized message
 * @param buffer_size Size of the buffer
 * @param header_out Header structure to fill with the message header
 * @return Size of the message on success, -1 on error
 */
int frpc_protocol_create_visitor(const char *name, const char *sk, uint8_t *buffer, 
                               size_t buffer_size, frpc_msg_header_t *header_out) {
    if (!name || !sk || !buffer || buffer_size < 100 || !header_out) {
        return -1;
    }
    
    /* Format the JSON content */
    char content[512];
    int content_len = snprintf(content, sizeof(content),
                              "{\"name\":\"%s\","
                              "\"sk\":\"%s\"}",
                              name, sk);
    
    if (content_len < 0 || (size_t)content_len >= sizeof(content)) {
        return -1;
    }
    
    /* Create header */
    header_out->type = FRPC_MSG_TYPE_NEW_VISITOR;
    header_out->seq = 1;  /* First message for visitor */
    header_out->content_length = (uint32_t)content_len;
    
    /* Check buffer size */
    if (buffer_size < 13 + content_len) {
        return -1;
    }
    
    /* Write header */
    frpc_protocol_write_header(header_out, buffer);
    
    /* Write content */
    memcpy(buffer + 13, content, content_len);
    
    return 13 + content_len;
}
