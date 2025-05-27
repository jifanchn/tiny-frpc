/**
 * @file frpc_protocol.h
 * @brief FRP protocol definitions for tiny-frpc
 * 
 * This file contains protocol-level definitions and structures
 * for the frp client-server communication.
 */

#ifndef FRPC_PROTOCOL_H
#define FRPC_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol version */
#define FRPC_VERSION "0.1.0"

/* Protocol message types */
typedef enum {
    FRPC_MSG_TYPE_LOGIN           = 0,  /**< Login message */
    FRPC_MSG_TYPE_LOGIN_RESP      = 1,  /**< Login response */
    FRPC_MSG_TYPE_NEW_PROXY       = 2,  /**< Register new proxy */
    FRPC_MSG_TYPE_NEW_PROXY_RESP  = 3,  /**< New proxy response */
    FRPC_MSG_TYPE_PING            = 4,  /**< Ping message */
    FRPC_MSG_TYPE_PONG            = 5,  /**< Pong message */
    FRPC_MSG_TYPE_NEW_WORK_CONN   = 6,  /**< New work connection */
    FRPC_MSG_TYPE_NEW_VISITOR     = 7,  /**< New visitor message */
    FRPC_MSG_TYPE_NEW_VISITOR_RESP = 8, /**< New visitor response */
    FRPC_MSG_TYPE_START_WORKCONN  = 9   /**< Start work connection */
} frpc_msg_type_t;

/* Message header */
typedef struct {
    uint8_t type;      /**< Message type */
    uint64_t seq;      /**< Message sequence */
    uint32_t content_length; /**< Content length */
} frpc_msg_header_t;

/* Error codes */
typedef enum {
    FRPC_ERROR_NONE = 0,
    FRPC_ERROR_AUTH_FAILURE,
    FRPC_ERROR_CONN_FAILURE,
    FRPC_ERROR_PROXY_FAILURE,
    FRPC_ERROR_NOT_IMPLEMENTED,
    FRPC_ERROR_INVALID_PARAM
} frpc_error_code_t;

/* Function declarations */
int frpc_protocol_read_header(const uint8_t *buffer, frpc_msg_header_t *header);
int frpc_protocol_write_header(const frpc_msg_header_t *header, uint8_t *buffer);
int frpc_protocol_create_login(const char *version, const char *user, 
                              const char *token, uint8_t *buffer, 
                              size_t buffer_size, frpc_msg_header_t *header_out);
int frpc_protocol_parse_login_resp(const uint8_t *buffer, size_t buffer_size, 
                                  int *error_code, char *error_msg, 
                                  size_t error_msg_size);
int frpc_protocol_create_new_proxy(const char *name, int proxy_type, 
                                 uint16_t remote_port, uint8_t *buffer, 
                                 size_t buffer_size, frpc_msg_header_t *header_out);
int frpc_protocol_create_ping(uint8_t *buffer, size_t buffer_size, 
                            uint64_t seq, frpc_msg_header_t *header_out);
int frpc_protocol_create_work_conn(uint8_t *buffer, size_t buffer_size, 
                                 uint64_t seq, frpc_msg_header_t *header_out);
int frpc_protocol_create_visitor(const char *name, const char *sk, uint8_t *buffer, 
                               size_t buffer_size, frpc_msg_header_t *header_out);

#ifdef __cplusplus
}
#endif

#endif /* FRPC_PROTOCOL_H */
