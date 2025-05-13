#include "../include/yamux.h"
#include "../include/tools.h"

// 前向声明
static int handleWindowUpdate(struct yamux_session* s, yamux_frame_header_t* hdr, uint16_t flags);
static int processStreamFlags(struct yamux_session* s, struct yamux_stream* stream, uint16_t flags);

/* 配置选项 */
/* 定义YAMUX_DEBUG开启调试输出，嵌入式环境通常关闭 */
#define YAMUX_DEBUG  // FORCE ENABLE FOR INTEROP TEST DEBUGGING

#ifdef YAMUX_DEBUG
#include <stdio.h> /* 仅调试模式使用 */
#define YAMUX_LOG(fmt, ...) do { printf("Yamux: " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define YAMUX_ERROR(fmt, ...) do { fprintf(stderr, "Yamux Error: " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define YAMUX_WARN(fmt, ...) do { fprintf(stderr, "Yamux Warn: " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#else
#define YAMUX_LOG(fmt, ...) ((void)0)
#define YAMUX_ERROR(fmt, ...) ((void)0)
#define YAMUX_WARN(fmt, ...) ((void)0)
#endif

/* 核心依赖库 */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy, memset */
#include <time.h>   /* clock_gettime */

// 定义最大帧负载大小
#define YAMUX_MAX_FRAME_PAYLOAD_SIZE (1024 * 1024) // 1MB

// 获取当前时间的函数声明
uint64_t yamux_time_now(void);

/* 错误码定义 */
/* 可替换为自定义错误码，不依赖errno.h */
#define YAMUX_ERR_NONE       0
#define YAMUX_ERR_INVALID   -1
#define YAMUX_ERR_MEM       -2
#define YAMUX_ERR_PROTO     -3
#define YAMUX_ERR_IO        -4
#define YAMUX_ERR_EOF       -5
#define YAMUX_ERR_CLOSED    -6
#define YAMUX_ERR_TIMEOUT   -7
#define YAMUX_ERR_NOTFOUND  -8
#define YAMUX_ERR_WINDOW    -9

// Internal stream states
enum yamux_stream_state {
    YAMUX_STREAM_STATE_IDLE,            // Initial state before SYN is sent or received
    YAMUX_STREAM_STATE_SYN_SENT,        // SYN sent, waiting for ACK (client)
    YAMUX_STREAM_STATE_SYN_RECEIVED,    // SYN received, waiting for app to accept & ACK (server)
    YAMUX_STREAM_STATE_ESTABLISHED,     // Stream is open for data transfer
    YAMUX_STREAM_STATE_LOCAL_FIN,       // FIN sent, can still receive (half-closed local)
    YAMUX_STREAM_STATE_REMOTE_FIN,      // FIN received, can still send (half-closed remote)
    YAMUX_STREAM_STATE_CLOSED,          // Both FINs exchanged, or RST occurred
    YAMUX_STREAM_STATE_RST_SENT,        // RST sent
    YAMUX_STREAM_STATE_RST_RECEIVED     // RST received
};

// Internal structure for a Yamux stream
// This is the actual definition for the opaque yamux_stream_t in yamux.h
struct yamux_stream {
    uint32_t id;
    struct yamux_session* session;      // Back pointer to parent session
    enum yamux_stream_state state;
    uint32_t peer_window_size;          // How much data we can send to peer (credits)
    uint32_t local_window_size;         // How much data peer can send to us (our receive window capacity)
    
    // TODO: Add buffers for send/receive data if internal buffering is desired
    // For now, data is passed directly to/from user callbacks.
    // uint8_t* recv_buffer;
    // size_t recv_buffer_capacity;
    // size_t recv_buffer_len;
    // uint8_t* send_buffer;
    // size_t send_buffer_capacity;
    // size_t send_buffer_len;

    void* user_data;                    // Stream-specific user data, set by on_new_stream or open_stream

    struct yamux_stream* next;          // For linked list in session
    struct yamux_stream* prev;          // For doubly linked list
};

// Internal structure for a Yamux session
// This is the actual definition for the opaque yamux_session_t in yamux.h
struct yamux_session {
    yamux_config_t config;              // Copied configuration
    bool is_client;                     // True if this session acts as a client
    uint32_t next_stream_id;            // Next stream ID to allocate for locally initiated streams
    
    struct yamux_stream* streams_head;  // Head of the linked list of active streams
    struct yamux_stream* streams_tail;  // Tail for efficient additions
    uint32_t active_streams_count;      // Count of active streams

    void* session_user_data;            // Session-specific user data, passed by user in yamux_session_new

    int last_error;                     // Stores the last significant error code (e.g., from write_fn)
    bool goaway_sent;                   // True if GoAway has been sent
    bool goaway_received;               // True if GoAway has been received
    uint32_t remote_goaway_last_stream_id; // Last stream ID processed by remote before GoAway

    // TODO: Keep-alive state (last_ping_sent_time, last_data_received_time etc.)
    uint64_t last_ping_sent_time_ms;
    uint32_t last_ping_opaque_id;
    uint64_t last_data_received_time_ms; // or last frame received time

    // 心跳相关
    uint64_t last_ping_time;
};

// --- Helper Functions for Frame (De)Serialization ---

// Serializes the header and converts fields to network byte order.
void yamux_serialize_frame_header(const yamux_frame_header_t* local_header, uint8_t* buffer) {
    uint16_t flags_n = tools_htons(local_header->flags);
    uint32_t stream_id_n = tools_htonl(local_header->stream_id);
    uint32_t length_n = tools_htonl(local_header->length);

    buffer[0] = local_header->version;
    buffer[1] = local_header->type;
    memcpy(buffer + 2, &flags_n, sizeof(flags_n));
    memcpy(buffer + 4, &stream_id_n, sizeof(stream_id_n));
    memcpy(buffer + 8, &length_n, sizeof(length_n));
}

// Deserializes the header and converts fields to host byte order.
void yamux_deserialize_frame_header(const uint8_t* buffer, yamux_frame_header_t* local_header) {
    local_header->version = buffer[0];
    local_header->type = buffer[1];
    memcpy(&local_header->flags, buffer + 2, sizeof(local_header->flags));
    memcpy(&local_header->stream_id, buffer + 4, sizeof(local_header->stream_id));
    memcpy(&local_header->length, buffer + 8, sizeof(local_header->length));

    local_header->flags = tools_ntohs(local_header->flags);
    local_header->stream_id = tools_ntohl(local_header->stream_id);
    local_header->length = tools_ntohl(local_header->length);
}

// --- End Helper Functions ---

// --- Private helper functions for session/stream management ---

// Find a stream by its ID
static struct yamux_stream* find_stream(struct yamux_session* s, uint32_t stream_id) {
    if (!s) return NULL;
    struct yamux_stream* current = s->streams_head;
    while (current) {
        if (current->id == stream_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Remove a stream from the session's list and free its memory
// Returns true if stream was found and removed, false otherwise.
static bool remove_and_free_stream(struct yamux_session* s, uint32_t stream_id, bool by_remote, uint32_t error_code_if_rst) {
    if (!s || !s->streams_head) return false;

    struct yamux_stream* current = s->streams_head;
    struct yamux_stream* prev_stream = NULL;

    while(current) {
        if (current->id == stream_id) {
            if (prev_stream) {
                prev_stream->next = current->next;
            } else {
                s->streams_head = current->next;
            }
            if (current->next) {
                current->next->prev = prev_stream;
            } else { // current was the tail
                s->streams_tail = prev_stream;
            }
            
            s->active_streams_count--;

            if (s->config.on_stream_close) {
                s->config.on_stream_close(current->user_data, by_remote, error_code_if_rst);
            }
            YAMUX_LOG("Freeing stream ID %u during session free", current->id);
            free(current);
            return true;
        }
        prev_stream = current;
        current = current->next;
    }
    return false; // Not found
}

// Helper to send a frame
static int send_frame(struct yamux_session* s, yamux_frame_header_t* header, const uint8_t* payload) {
    if (!s || !header) return YAMUX_ERR_INVALID;
    
    // Log frame details before sending
    YAMUX_LOG(">> Sending Frame: SID=%u, Type=0x%x, Flags=0x%x, Len=%u, Payload Ptr=%p", 
              header->stream_id, header->type, header->flags, header->length, payload);
              
    if (s->goaway_sent) {
        // Don't send anything if GoAway was already sent, except perhaps a final GoAway.
        YAMUX_LOG("   (Skipped send, GoAway already sent)");
        return YAMUX_ERR_CLOSED;
    }
    
    if (!s->config.write_fn) {
        YAMUX_ERROR("write_fn callback is not set");
        s->last_error = YAMUX_ERR_INVALID;
        return YAMUX_ERR_INVALID;
    }

    uint8_t header_buf[YAMUX_FRAME_HEADER_SIZE];
    yamux_serialize_frame_header(header, header_buf);

    // 发送帧头
    size_t header_sent = 0;
    while (header_sent < YAMUX_FRAME_HEADER_SIZE) {
        // Use a temporary variable for the result of write_fn
        ssize_t written_now = s->config.write_fn(s->config.user_conn_ctx, 
                                           header_buf + header_sent, 
                                           YAMUX_FRAME_HEADER_SIZE - header_sent);
        if (written_now <= 0) {
            // 写入错误
            YAMUX_ERROR("Failed to write frame header at offset %zu/%d (error: %zd)", 
                        header_sent, YAMUX_FRAME_HEADER_SIZE, written_now);
            s->last_error = YAMUX_ERR_IO;
            return YAMUX_ERR_IO;
        }
        header_sent += written_now;
    }
    YAMUX_LOG("   (Sent %zu header bytes)", header_sent);

    // 发送荷载（如果有）
    if (header->length > 0 && payload != NULL) {
        YAMUX_LOG("   (Attempting to send %u payload bytes from %p)", header->length, payload);
        size_t payload_sent = 0;
        while (payload_sent < header->length) {
            size_t remaining = header->length - payload_sent;
            // Use a temporary variable for the result of write_fn
            ssize_t written_now = s->config.write_fn(s->config.user_conn_ctx, 
                                               payload + payload_sent, 
                                               remaining);
            if (written_now <= 0) {
                // 写入错误
                YAMUX_ERROR("Failed to write frame payload at offset %zu/%u (error: %zd)",
                            payload_sent, header->length, written_now);
                s->last_error = YAMUX_ERR_IO;
                return YAMUX_ERR_IO;
            }
            payload_sent += written_now;
        }
        YAMUX_LOG("   (Sent %zu payload bytes)", payload_sent);
    } else if (header->length > 0 && payload == NULL) {
        YAMUX_LOG("   (Skipped sending payload, header.length=%u but payload is NULL)", header->length);
    }
    
    YAMUX_LOG("<< Frame Sent Successfully: SID=%u, Type=0x%x", header->stream_id, header->type);
    return YAMUX_ERR_NONE;
}

static int send_rst_frame(struct yamux_session* s, uint32_t stream_id) {
    yamux_frame_header_t rst_header;
    rst_header.version = YAMUX_VERSION;
    // RST flag can be on Data or WindowUpdate. Let's use WindowUpdate as it has no payload.
    rst_header.type = YAMUX_TYPE_WINDOW_UPDATE;
    rst_header.flags = YAMUX_FLAG_RST;
    rst_header.stream_id = stream_id;
    rst_header.length = 0;
    YAMUX_LOG("Sending RST for stream ID %u", stream_id);
    return send_frame(s, &rst_header, NULL);
}

static int send_ack_frame(struct yamux_session* s, uint32_t stream_id) {
    yamux_frame_header_t ack_header;
    ack_header.version = YAMUX_VERSION;
    // ACK flag can be on Data or WindowUpdate. Let's use WindowUpdate.
    ack_header.type = YAMUX_TYPE_WINDOW_UPDATE;
    ack_header.flags = YAMUX_FLAG_ACK;
    ack_header.stream_id = stream_id;
    ack_header.length = 0; // No payload for ACK typically
    YAMUX_LOG("Sending ACK for stream ID %u", stream_id);
    return send_frame(s, &ack_header, NULL);
}

static int send_goaway_frame(struct yamux_session* s, uint32_t error_code) {
    if (s->goaway_sent) { // Avoid sending multiple GoAway frames
        return YAMUX_ERR_NONE;
    }
    yamux_frame_header_t goaway_header;
    goaway_header.version = YAMUX_VERSION;
    goaway_header.type = YAMUX_TYPE_GO_AWAY;
    goaway_header.flags = 0;
    goaway_header.stream_id = 0; // StreamID must be 0 for GoAway
    goaway_header.length = sizeof(uint32_t); // Length is for the error code

    uint32_t error_code_n = tools_htonl(error_code);

    YAMUX_LOG("Sending GoAway with error code %u", error_code);
    int ret = send_frame(s, &goaway_header, (const uint8_t*)&error_code_n);
    if (ret == YAMUX_ERR_NONE) {
        s->goaway_sent = true;
        // After sending GoAway, we should not accept new streams or send more data on existing ones.
        // The session should eventually be closed.
    }
    return ret;
}

// --- Public API Functions ---

yamux_session_t* yamux_session_new(const yamux_config_t* config, bool is_client, void* session_user_data) {
    if (!config) {
        YAMUX_ERROR("Configuration cannot be NULL");
        return NULL;
    }
    if (!config->write_fn) {
        YAMUX_ERROR("write_fn callback in configuration cannot be NULL");
        return NULL;
    }

    struct yamux_session* s = (struct yamux_session*)malloc(sizeof(struct yamux_session));
    if (!s) {
        YAMUX_ERROR("Failed to allocate memory for session");
        return NULL;
    }
    memset(s, 0, sizeof(struct yamux_session));

    s->config = *config; // Copy config
    s->is_client = is_client;
    s->session_user_data = session_user_data;
    s->streams_head = NULL;
    s->streams_tail = NULL;
    s->active_streams_count = 0;
    s->last_error = YAMUX_ERR_NONE;
    s->goaway_sent = false;
    s->goaway_received = false;

    // Default initial window size if not set or invalid in config
    if (s->config.initial_stream_window_size == 0) {
        s->config.initial_stream_window_size = 256 * 1024; // Default 256KB
    }
    if (s->config.max_stream_window_size == 0) {
        s->config.max_stream_window_size = 1024 * 1024; // Default 1MB
    }
    if (s->config.max_streams == 0) { // 0 means "default" rather than unlimited for safety
        s->config.max_streams = 256; // A reasonable default limit
    }

    if (is_client) {
        s->next_stream_id = 1; // Clients use odd IDs
    } else {
        s->next_stream_id = 2; // Servers use even IDs
    }
    
    // TODO: Initialize keep-alive timers if enabled
    // s->last_data_received_time_ms = tools_get_time_ms(); 

    // 心跳相关
    s->last_ping_time = yamux_time_now();

    YAMUX_LOG("Session created (client: %d, user_conn_ctx: %p)", is_client, s->config.user_conn_ctx);
    return s;
}

void yamux_session_free(yamux_session_t* session) {
    if (!session) return;
    struct yamux_session* s = (struct yamux_session*)session;

    YAMUX_LOG("Freeing session (client: %d, conn_ctx: %p)", s->is_client, s->config.user_conn_ctx);
    
    // TODO: Send GoAway if not already done and appropriate (e.g. YAMUX_GOAWAY_NORMAL)
    if (!s->goaway_sent) {
        // Consider sending GoAway here, but it might require a blocking write or complex async logic
        // For now, we'll just close streams.
    }

    struct yamux_stream* current = s->streams_head;
    while(current) {
        struct yamux_stream* next_stream = current->next;
        // Forcibly close all streams, notify user
        if (s->config.on_stream_close) {
            // Indicate not by remote, and no specific RST error code (session is just being freed)
            s->config.on_stream_close(current->user_data, false, 0);
        }
        YAMUX_LOG("Freeing stream ID %u during session free", current->id);
        free(current);
        current = next_stream;
    }
    s->streams_head = NULL;
    s->streams_tail = NULL;
    s->active_streams_count = 0;

    // User is responsible for freeing config.user_conn_ctx and session_user_data if they were heap allocated.
    free(s);
}


uint32_t yamux_session_open_stream(yamux_session_t* session, void** stream_user_data_out) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) {
        YAMUX_ERROR("Session is null");
        return 0; // 0 is not a valid stream ID, indicates error
    }
    if (s->goaway_received && s->next_stream_id > s->remote_goaway_last_stream_id) {
         YAMUX_ERROR("Session received GoAway, cannot open new streams past ID %u", s->remote_goaway_last_stream_id);
         s->last_error = YAMUX_ERR_CLOSED;
         return 0;
    }
    if (s->goaway_sent) {
        YAMUX_ERROR("Session has sent GoAway, cannot open new streams");
        s->last_error = YAMUX_ERR_CLOSED;
        return 0;
    }

    if (s->active_streams_count >= s->config.max_streams) {
        YAMUX_ERROR("Max streams limit reached (%u)", s->config.max_streams);
        s->last_error = YAMUX_ERR_INVALID;
        return 0;
    }

    struct yamux_stream* stream = (struct yamux_stream*)malloc(sizeof(struct yamux_stream));
    if (!stream) {
        YAMUX_ERROR("Failed to allocate memory for stream");
        s->last_error = YAMUX_ERR_MEM;
        return 0;
    }
    memset(stream, 0, sizeof(struct yamux_stream));

    stream->id = s->next_stream_id;
    s->next_stream_id += 2; // Increment by 2 to keep odd/even parity
    stream->session = s;
    stream->state = YAMUX_STREAM_STATE_SYN_SENT;
    stream->local_window_size = s->config.initial_stream_window_size;
    stream->peer_window_size = s->config.initial_stream_window_size; // Assume peer also has this initial window

    // 正确设置 stream 结构中的 user_data
    if (stream_user_data_out) {
        stream->user_data = *stream_user_data_out; 
        YAMUX_LOG("Assigning user_data %p to new stream %u", stream->user_data, stream->id);
    } else {
        stream->user_data = NULL;
        YAMUX_LOG("No user_data provided for new stream %u", stream->id);
    }

    // Add to session's stream list (doubly linked list)
    if (!s->streams_head) {
        s->streams_head = stream;
        s->streams_tail = stream;
        stream->prev = NULL;
    } else {
        s->streams_tail->next = stream;
        stream->prev = s->streams_tail;
        s->streams_tail = stream;
    }
    stream->next = NULL;
    s->active_streams_count++;

    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_DATA; 
    header.flags = YAMUX_FLAG_SYN;
    header.stream_id = stream->id;
    header.length = 0; 

    YAMUX_LOG("Client opening stream ID %u (user_data: %p), sending SYN (type:0x%x, flags:0x%x, len:%u)", 
           stream->id, stream->user_data, header.type, header.flags, header.length);

    if (send_frame(s, &header, NULL) != YAMUX_ERR_NONE) {
        // Rollback stream creation
        if (stream->prev) {
            stream->prev->next = NULL;
            s->streams_tail = stream->prev;
        } else { // stream was the only one
            s->streams_head = NULL;
            s->streams_tail = NULL;
        }
        s->active_streams_count--;
        free(stream);
        // next_stream_id was already incremented, this might lead to a gap, which is fine.
        return 0; // Error
    }
    
    YAMUX_LOG("Stream ID %u SYN sent", stream->id);
    return stream->id;
}

// Placeholder for yamux_session_accept_stream - this is driven by on_new_stream callback
// The old yamux_session_accept_stream is not directly applicable with the callback model.
// Users will get new streams via the on_new_stream callback.

// Placeholder for yamux_stream_read - driven by on_stream_data callback
// ssize_t yamux_stream_read(yamux_stream_t* stream, void* buf, size_t len) -> user calls on_stream_data

// 流数据写入函数，完全按照Go yamux的实现逻辑
int yamux_stream_write(yamux_session_t* session, uint32_t stream_id, const uint8_t* data, size_t len) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s || !data) {
        if(s) s->last_error = YAMUX_ERR_INVALID;
        return YAMUX_ERR_INVALID;
    }
    
    // 如果长度为0，直接返回成功
    if (len == 0) {
        return 0;
    }
    
    // 查找流
    struct yamux_stream* st = find_stream(s, stream_id);
    if (!st) {
        YAMUX_ERROR("Stream ID %u not found for write", stream_id);
        s->last_error = YAMUX_ERR_NOTFOUND;
        return YAMUX_ERR_NOTFOUND;
    }
    
    // 检查流状态 - 类似Go实现的状态检查
    if (st->state != YAMUX_STREAM_STATE_ESTABLISHED && 
        st->state != YAMUX_STREAM_STATE_REMOTE_FIN /* 对方关闭了，我们还可以写入 */) {
        YAMUX_ERROR("Stream ID %u not in a writable state (%d)", stream_id, st->state);
        s->last_error = YAMUX_ERR_CLOSED;
        return YAMUX_ERR_CLOSED;
    }
    
    if (st->state == YAMUX_STREAM_STATE_LOCAL_FIN || 
        st->state == YAMUX_STREAM_STATE_CLOSED || 
        st->state == YAMUX_STREAM_STATE_RST_SENT || 
        st->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_ERROR("Stream ID %u is closing or closed, cannot write", stream_id);
        s->last_error = YAMUX_ERR_CLOSED;
        return YAMUX_ERR_CLOSED;
    }

    // 检查对方窗口大小
    YAMUX_LOG("流 %u 当前对方窗口大小：%u，尝试写入 %zu 字节", 
             stream_id, st->peer_window_size, len);
             
    // 这与Go的实现完全一致，当窗口为0时，返回窗口错误
    if (st->peer_window_size == 0) {
        YAMUX_WARN("流 %u 对方窗口已满 (size=0)，无法写入", stream_id);
        return YAMUX_ERR_WINDOW; // 窗口为0，无法写入
    }

    // 计算本次实际可发送的数据量（取窗口大小和数据长度的较小值）
    size_t bytes_to_send = len;
    if (bytes_to_send > st->peer_window_size) {
        bytes_to_send = st->peer_window_size;
        YAMUX_LOG("受窗口限制：流 %u 只能发送 %zu/%zu 字节", 
                 stream_id, bytes_to_send, len);
    }
    
    // 限制为单次最大帧大小，与Go yamux的MaxFrameSize一致
    const size_t max_payload_per_frame = 32768; // 32KB，Go yamux默认值
    if (bytes_to_send > max_payload_per_frame) {
        bytes_to_send = max_payload_per_frame;
        YAMUX_LOG("受帧大小限制：流 %u 只能发送 %zu/%zu 字节", 
                 stream_id, bytes_to_send, len);
    }
    
    // 处理标志 - 类似Go中的sendFlags()
    uint16_t flags = 0;
    
    // 根据流状态设置适当的标志
    switch (st->state) {
    case YAMUX_STREAM_STATE_IDLE:
        flags |= YAMUX_FLAG_SYN;
        st->state = YAMUX_STREAM_STATE_SYN_SENT;
        YAMUX_LOG("流 %u 状态从IDLE转为SYN_SENT", stream_id);
        break;
    case YAMUX_STREAM_STATE_SYN_RECEIVED:
        flags |= YAMUX_FLAG_ACK;
        st->state = YAMUX_STREAM_STATE_ESTABLISHED;
        YAMUX_LOG("流 %u 状态从SYN_RECEIVED转为ESTABLISHED", stream_id);
        break;
    default:
        // 其他状态不需要额外标志
        break;
    }
    
    // Note: The argument order is bytes_to_send (size_t), stream_id (uint32_t), st->peer_window_size (uint32_t)
    YAMUX_LOG("准备为流 %u 发送 %zu 字节 (对方窗口: %u)",
              stream_id, bytes_to_send, st->peer_window_size);

    // 准备数据帧
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_DATA;
    header.flags = flags; // 包含可能的控制标志
    header.stream_id = stream_id;
    header.length = (uint32_t)bytes_to_send;

    // 发送帧
    int ret = send_frame(s, &header, data);
    if (ret != YAMUX_ERR_NONE) {
        YAMUX_ERROR("无法发送数据帧，流ID %u：错误 %d", stream_id, ret);
        return ret;
    }

    // 成功发送后，减少对方窗口大小
    st->peer_window_size -= bytes_to_send;
    YAMUX_LOG("发送后：流 %u 对方窗口减少到 %u", stream_id, st->peer_window_size);
    
    // 返回实际发送的字节数，而不是错误码
    // 这与Go的返回值行为一致
    return (int)bytes_to_send;
}

int yamux_stream_close(yamux_session_t* session, uint32_t stream_id, uint32_t error_code_if_rst) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return YAMUX_ERR_INVALID;

    struct yamux_stream* st = find_stream(s, stream_id);
    if (!st) {
        YAMUX_ERROR("Stream ID %u not found for close/reset", stream_id);
        s->last_error = YAMUX_ERR_NOTFOUND;
        return YAMUX_ERR_NOTFOUND;
    }

    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.stream_id = stream_id;
    header.length = 0;

    if (error_code_if_rst != 0) { // Send RST
        if (st->state == YAMUX_STREAM_STATE_RST_SENT || st->state == YAMUX_STREAM_STATE_CLOSED) {
             YAMUX_LOG("Stream %u already reset or closed. Ignoring reset request", stream_id);
             return YAMUX_ERR_NONE; // Idempotent
        }
        header.type = YAMUX_TYPE_WINDOW_UPDATE; // Per spec, RST is a flag on Data or WindowUpdate
        header.flags = YAMUX_FLAG_RST;
        // The 'error_code_if_rst' is for local callback, not directly sent in frame for yamux stream RST.
        // GoAway has error codes, stream RST just terminates.
        YAMUX_LOG("Sending RST for stream ID %u", stream_id);
        if (send_frame(s, &header, NULL) != YAMUX_ERR_NONE) {
            return s->last_error;
        }
        st->state = YAMUX_STREAM_STATE_RST_SENT;
        // Remove stream immediately after sending RST
        remove_and_free_stream(s, stream_id, false /*not by_remote*/, error_code_if_rst);
    } else { // Send FIN (graceful close)
        if (st->state == YAMUX_STREAM_STATE_LOCAL_FIN || st->state == YAMUX_STREAM_STATE_CLOSED || st->state == YAMUX_STREAM_STATE_RST_SENT) {
            YAMUX_LOG("Stream %u FIN already sent or stream closing/closed. Ignoring FIN request", stream_id);
            return YAMUX_ERR_NONE; // Idempotent or already further along
        }
        header.type = YAMUX_TYPE_DATA; // FIN can be on Data or WindowUpdate
        header.flags = YAMUX_FLAG_FIN;
        YAMUX_LOG("Sending FIN for stream ID %u", stream_id);
        if (send_frame(s, &header, NULL) != YAMUX_ERR_NONE) {
            return s->last_error;
        }
        st->state = YAMUX_STREAM_STATE_LOCAL_FIN;
        if (st->state == YAMUX_STREAM_STATE_REMOTE_FIN) { // Peer already sent FIN
            YAMUX_LOG("Both sides FIN'd stream %u. Closing", stream_id);
            st->state = YAMUX_STREAM_STATE_CLOSED;
            remove_and_free_stream(s, stream_id, false, 0);
        }
    }
    return YAMUX_ERR_NONE;
}


int yamux_stream_window_update(yamux_session_t* session, uint32_t stream_id, uint32_t increment) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return YAMUX_ERR_INVALID;
    
    // 如果增量为0，无需更新
    if (increment == 0) {
        return YAMUX_ERR_NONE;
    }

    struct yamux_stream* st = find_stream(s, stream_id);
    if (!st) {
        YAMUX_ERROR("Stream ID %u not found for window update", stream_id);
        s->last_error = YAMUX_ERR_NOTFOUND;
        return YAMUX_ERR_NOTFOUND;
    }
    
    // 检查流状态，如果流已关闭则不需要发送窗口更新
    if (st->state == YAMUX_STREAM_STATE_CLOSED || 
        st->state == YAMUX_STREAM_STATE_RST_SENT || 
        st->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_WARN("Stream %u is closed/reset, ignoring window update", stream_id);
        return YAMUX_ERR_NONE;
    }
    
    // 计算新窗口大小
    uint32_t max_window = s->config.max_stream_window_size;
    uint32_t cur_window = st->local_window_size;
    
    YAMUX_LOG("窗口更新前：流 %u 当前窗口 %u，最大窗口 %u，请求增加 %u", 
              stream_id, cur_window, max_window, increment);
    
    // 防止超过最大窗口大小
    if (cur_window + increment > max_window) {
        YAMUX_WARN("流 %u 窗口增量 %u 会超过最大值 %u，调整为 %u", 
                 stream_id, increment, max_window, max_window - cur_window);
        
        increment = max_window - cur_window;
        
        // 如果当前窗口已经是最大值，则不需要更新
        if (increment == 0) {
            YAMUX_WARN("Stream %u window already at maximum (%u), skipping update", 
                     stream_id, max_window);
            return YAMUX_ERR_NONE;
        }
    }
    
    // 更新本地窗口大小
    st->local_window_size += increment;
    
    // 准备窗口更新帧
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_WINDOW_UPDATE;
    header.flags = 0; 
    header.stream_id = stream_id;
    header.length = increment; // 窗口增量

    YAMUX_LOG("发送窗口更新：流 %u，增量 %u，新窗口大小 %u", 
              stream_id, increment, st->local_window_size);
    
    // 发送窗口更新帧
    int ret = send_frame(s, &header, NULL);
    if (ret != YAMUX_ERR_NONE) {
        YAMUX_ERROR("Failed to send window update frame for stream %u", stream_id);
        return s->last_error;
    }
    
    return YAMUX_ERR_NONE;
}


// --- yamux_session_tick ---
// This function should be called periodically to handle background tasks.
void yamux_session_tick(yamux_session_t* session) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return;
    
    // 1. 处理心跳
    if (s->config.enable_keepalive) {
        uint64_t current_time = yamux_time_now();
        
        // 如果last_ping_time为0，初始化为当前时间减去一个周期
        // 这样第一次不会立即发送PING
        if (s->last_ping_time == 0) {
            s->last_ping_time = current_time;
            return;
        }
        
        uint64_t time_since_last_ping = current_time - s->last_ping_time;
        
        // 检查是否需要发送心跳
        if (time_since_last_ping >= s->config.keepalive_interval_ms) {
            YAMUX_LOG("发送心跳PING帧");
            
            // 生成随机PING值 (可用作不透明值)
            uint32_t ping_value = (uint32_t)current_time;
            ping_value = tools_htonl(ping_value); // 转换为网络字节序
            
            // 准备PING帧
            yamux_frame_header_t header;
            header.version = YAMUX_VERSION;
            header.type = YAMUX_TYPE_PING;
            header.flags = 0; // 不带标志表示请求PING
            header.stream_id = 0; // PING使用流ID 0
            header.length = sizeof(uint32_t); // PING值长度
            
            // 发送PING帧
            int ret = send_frame(s, &header, (const uint8_t*)&ping_value);
            if (ret != YAMUX_ERR_NONE) {
                YAMUX_ERROR("Failed to send PING frame: %d", ret);
                return;
            }
            
            // 更新最后发送时间和PING ID
            s->last_ping_time = current_time;
            s->last_ping_opaque_id = ping_value;
        }
    }
    
    // 2. 处理其他周期性任务（如果有）
    // TODO: 超时检查等
}

// --- yamux_session_receive ---
// This function is called by the user when new data arrives on the underlying connection.
int yamux_session_receive(yamux_session_t* session, const uint8_t* data, size_t len) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s || (!data && len > 0)) { // Allow data == NULL only if len == 0 (EOF)
        if (s) s->last_error = YAMUX_ERR_INVALID;
        return YAMUX_ERR_INVALID;
    }

    YAMUX_LOG(">> yamux_session_receive called with len=%zu, data=%p", len, data);

    if (len == 0) { // User might call with 0 to indicate EOF on their side.
        YAMUX_LOG("yamux_session_receive called with 0 len (EOF indication)");
        // Optional: Handle EOF, e.g., send GoAway
        // if (!s->goaway_sent) {
        //     send_goaway_frame(s, YAMUX_GOAWAY_NORMAL);
        // }
        return 0;
    }

    if (s->goaway_received || s->goaway_sent) {
        // If GoAway process has started, we might only process specific frames or just discard.
        // For now, if GoAway is active, stop processing further incoming general data.
        // This might be too strict.
        YAMUX_LOG("GoAway active, ignoring %zu received bytes.", len);
        return (int)len; // Pretend we consumed it
    }

    size_t consumed_total = 0;
    const uint8_t* current_data = data;
    size_t remaining_len = len;

    while (remaining_len >= YAMUX_FRAME_HEADER_SIZE) {
        YAMUX_LOG(">> Loop start: remaining_len=%zu, consumed_total=%zu, current_data offset=%td", 
                  remaining_len, consumed_total, (current_data - data));
        
        yamux_frame_header_t header;
        yamux_deserialize_frame_header(current_data, &header);
        YAMUX_LOG(">> Deserialized: V=%u T=0x%x F=0x%x ID=%u L=%u",
                  header.version, header.type, header.flags, header.stream_id, header.length);

        if (header.version != YAMUX_VERSION) {
            YAMUX_ERROR("Received frame with invalid version %u (expected %u)", header.version, YAMUX_VERSION);
            send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
            s->last_error = YAMUX_ERR_PROTO;
            return YAMUX_ERR_PROTO; // Fatal error for the session
        }
        
        // Check for excessively large frame length early
        if (header.length > YAMUX_MAX_FRAME_PAYLOAD_SIZE) { // Define YAMUX_MAX_FRAME_PAYLOAD_SIZE e.g., 1MB
            YAMUX_ERROR("Received frame with excessive length %u > max %u", header.length, YAMUX_MAX_FRAME_PAYLOAD_SIZE);
            send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
            s->last_error = YAMUX_ERR_PROTO;
            return YAMUX_ERR_PROTO;
        }

        size_t frame_total_size = YAMUX_FRAME_HEADER_SIZE + header.length;
        YAMUX_LOG(">> Calculated frame_total_size=%zu (hdr=%d, payload=%u)", 
                 frame_total_size, YAMUX_FRAME_HEADER_SIZE, header.length);

        if (remaining_len < frame_total_size) {
             YAMUX_LOG(">> Incomplete frame (need %zu, have %zu), breaking loop.", frame_total_size, remaining_len);
             break;
        }

        const uint8_t* payload = current_data + YAMUX_FRAME_HEADER_SIZE;

        YAMUX_LOG("Processing Frame: SID=%u, Type=0x%x, Flags=0x%x, Len=%u", header.stream_id, header.type, header.flags, header.length);

        if (header.stream_id == 0) { // Session control messages
            switch (header.type) {
                case YAMUX_TYPE_PING:
                    if (header.length != sizeof(uint32_t) && header.length != 0) { // Ping payload must be 4 bytes (opaque) or 0 for older draft
                         YAMUX_ERROR("Ping frame with invalid length %u", header.length);
                         send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
                         s->last_error = YAMUX_ERR_PROTO;
                         return YAMUX_ERR_PROTO;
                    }
                    if (header.flags == 0) { // Ping request
                        YAMUX_LOG("Received PING request (SID 0), sending PONG");
                        yamux_frame_header_t pong_header;
                        pong_header.version = YAMUX_VERSION;
                        pong_header.type = YAMUX_TYPE_PING;
                        pong_header.flags = YAMUX_FLAG_ACK; // Pong is an ACK
                        pong_header.stream_id = 0;
                        pong_header.length = header.length; // Echo opaque data
                        send_frame(s, &pong_header, payload); 
                    } else if (header.flags & YAMUX_FLAG_ACK) { // Ping response (PONG)
                        YAMUX_LOG("Received PONG (SID 0)");
                        // TODO: Match opaque data if keepalive implemented, calculate RTT
                        // s->last_data_received_time_ms = tools_get_time_ms(); // or specific pong received time
                    } else {
                        YAMUX_ERROR("Ping frame with invalid flags 0x%x", header.flags);
                        // Go spec says "ignore", let's do that.
                    }
                    break;
                case YAMUX_TYPE_GO_AWAY:
                    YAMUX_LOG("Received GoAway frame (SID 0).");
                    s->goaway_received = true;
                    if (header.length == sizeof(uint32_t)) {
                        memcpy(&s->remote_goaway_last_stream_id, payload, sizeof(uint32_t));
                        s->remote_goaway_last_stream_id = tools_ntohl(s->remote_goaway_last_stream_id);
                        uint32_t goaway_error_code; // we can also get the error code from payload
                        memcpy(&goaway_error_code, payload, sizeof(uint32_t)); // assuming length is 4
                        goaway_error_code = tools_ntohl(goaway_error_code);

                        YAMUX_LOG("GoAway from peer, last processed StreamID: %u, error code: %u", 
                               s->remote_goaway_last_stream_id, goaway_error_code);
                        // If we also sent GoAway, this is a confirmation.
                        // If not, this is the peer initiating shutdown.
                        // TODO: Close streams with ID > remote_goaway_last_stream_id if they were locally initiated.
                        // TODO: Trigger on_session_close callback if defined.
                    } else {
                        YAMUX_WARN("GoAway frame with unexpected length %u, expected %zu", header.length, sizeof(uint32_t));
                        // Still treat as GoAway received
                    }
                    // The session should now be considered draining. No new streams should be opened.
                    // Existing streams might continue until remote_goaway_last_stream_id or they complete.
                    // For simplicity now, once goaway_received, we might stop most operations.
                    if (s->config.on_session_close) {
                         s->config.on_session_close(s->session_user_data, true /*by_remote*/, 0 /*TODO: map goaway code*/);
                    }
                    // We should also send our own GoAway if we haven't already.
                    if (!s->goaway_sent) {
                        send_goaway_frame(s, YAMUX_GOAWAY_NORMAL); // Acknowledge GoAway
                    }
                    // After receiving GoAway, we typically stop processing further frames from the peer,
                    // except possibly ACKs for frames we already sent.
                    // For now, we will break the loop and consume all data.
                    current_data += frame_total_size;
                    consumed_total += frame_total_size;
                    remaining_len -= frame_total_size;
                    return (int)len; // Consumed all data and stopping due to GoAway
                default:
                    YAMUX_WARN("Received unknown frame type 0x%x on StreamID 0", header.type);
                    // Per spec, unknown types should be ignored.
                    break;
            }
        } else { // Stream-specific messages
            struct yamux_stream* st = find_stream(s, header.stream_id);

            if (header.flags & YAMUX_FLAG_SYN) {
                YAMUX_LOG(">> ENTERING SYN processing block for Stream %u", header.stream_id);
                if (st) {
                    YAMUX_ERROR("Received SYN for existing StreamID %u. Sending RST", header.stream_id);
                    send_rst_frame(s, header.stream_id);
                } else {
                    bool stream_id_is_even = (header.stream_id % 2 == 0);
                    if ((s->is_client && stream_id_is_even) || (!s->is_client && !stream_id_is_even)) {
                        if (s->active_streams_count >= s->config.max_streams) {
                            YAMUX_ERROR("Max streams limit (%u) reached. Rejecting new StreamID %u with RST", s->config.max_streams, header.stream_id);
                            send_rst_frame(s, header.stream_id);
                        } else if (s->goaway_sent || s->goaway_received) {
                            YAMUX_WARN("Session is closing (GoAway). Rejecting new StreamID %u with RST", header.stream_id);
                            send_rst_frame(s, header.stream_id);
                        } else {
                            void* stream_user_data = NULL;
                            bool accepted = false;
                            if (s->config.on_new_stream) {
                                YAMUX_LOG(">> Calling on_new_stream for Stream %u (user_data_ptr: %p)", header.stream_id, &stream_user_data);
                                accepted = s->config.on_new_stream(s->session_user_data, header.stream_id, &stream_user_data);
                                YAMUX_LOG(">> on_new_stream for Stream %u returned: %d, user_data_val: %p", header.stream_id, accepted, stream_user_data);
                            }
                            if (accepted) {
                                YAMUX_LOG("New stream %u accepted and created.", header.stream_id);
                                struct yamux_stream* new_stream = (struct yamux_stream*)malloc(sizeof(struct yamux_stream));
                                if (!new_stream) {
                                    YAMUX_ERROR("Failed to allocate memory for new stream");
                                    send_rst_frame(s, header.stream_id); // Can't accept if out of memory
                                    s->last_error = YAMUX_ERR_MEM;
                                    // This is a local error, but we RST the peer's attempt.
                                } else {
                                    memset(new_stream, 0, sizeof(struct yamux_stream));
                                    new_stream->id = header.stream_id;
                                    new_stream->session = s;
                                    new_stream->state = YAMUX_STREAM_STATE_ESTABLISHED; // Goes to established after ACK
                                    new_stream->local_window_size = s->config.initial_stream_window_size;
                                    new_stream->peer_window_size = s->config.initial_stream_window_size; // Assume peer starts with this
                                    new_stream->user_data = stream_user_data;

                                    // Add to session's stream list
                                    if (!s->streams_head) {
                                        s->streams_head = new_stream;
                                        s->streams_tail = new_stream;
                                    } else {
                                        s->streams_tail->next = new_stream;
                                        new_stream->prev = s->streams_tail;
                                        s->streams_tail = new_stream;
                                    }
                                    s->active_streams_count++;
                                    
                                    send_ack_frame(s, header.stream_id);
                                    // If ACK send fails, we should clean up the stream. TODO.
                                }
                            } else {
                                YAMUX_WARN("App rejected new StreamID %u. Sending RST", header.stream_id);
                                send_rst_frame(s, header.stream_id);
                            }
                        }
                    } else {
                        YAMUX_ERROR("Protocol violation. %s received SYN on %s StreamID %u. Sending GoAway",
                                s->is_client ? "Client" : "Server",
                                stream_id_is_even ? "even" : "odd",
                                header.stream_id);
                        send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
                        s->last_error = YAMUX_ERR_PROTO;
                        return YAMUX_ERR_PROTO;
                    }
                }
                YAMUX_LOG("<< LEAVING SYN processing block for Stream %u", header.stream_id);
            } else if (!st) {
                YAMUX_WARN("Frame for unknown/non-SYN StreamID %u (Type=0x%x, Flags=0x%x). Ignoring.", header.stream_id, header.type, header.flags);
            } else {
                // Existing stream
                switch (header.type) {
                    case YAMUX_TYPE_WINDOW_UPDATE:
                        YAMUX_LOG(">> ENTERING WINDOW_UPDATE processing block for Stream %u", header.stream_id);
                        handleWindowUpdate(s, &header, header.flags);
                        YAMUX_LOG("<< LEAVING WINDOW_UPDATE processing block for Stream %u", header.stream_id);
                        break;
                    case YAMUX_TYPE_DATA:
                        YAMUX_LOG(">> ENTERING DATA processing block for Stream %u", header.stream_id);
                        // ... (actual data processing, window checks, on_stream_data call)
                        // Ensure the YAMUX_LOG from previous steps for local_window_size vs header.length is present here.
                        if (header.length > st->local_window_size) {
                           YAMUX_ERROR("DATA frame length %u > local_window %u for stream %u. Sending RST.", header.length, st->local_window_size, header.stream_id);
                           send_rst_frame(s, header.stream_id);
                           s->last_error = YAMUX_ERR_PROTO;
                           return YAMUX_ERR_PROTO;
                        }
                        st->local_window_size -= header.length;
                        YAMUX_LOG("Stream %u: local_window_size reduced by %u to %u", header.stream_id, header.length, st->local_window_size);
                        if (header.flags) { processStreamFlags(s, st, header.flags); }
                        if (header.length > 0 && s->config.on_stream_data) {
                           YAMUX_LOG(">> Calling on_stream_data for Stream %u, length %u", header.stream_id, header.length);
                           s->config.on_stream_data(st->user_data, payload, header.length);
                           YAMUX_LOG("<< Returned from on_stream_data for Stream %u", header.stream_id);
                           // Automatic window update logic can be logged here too if it's complex
                        }
                        YAMUX_LOG("<< LEAVING DATA processing block for Stream %u", header.stream_id);
                        break;
                    default:
                        YAMUX_WARN("Received unknown frame type 0x%x for StreamID %u. Ignoring", header.type, header.stream_id);
                        break;
                }
            }
        }

        // Update pointers/counters AFTER processing the frame
        YAMUX_LOG(">> Updating pointers: consuming %zu bytes for frame [T=0x%x, ID=%u]", 
                  frame_total_size, header.type, header.stream_id);
        current_data += frame_total_size;
        consumed_total += frame_total_size;
        remaining_len -= frame_total_size;
        YAMUX_LOG(">> Loop end after update: remaining_len=%zu, consumed_total=%zu", remaining_len, consumed_total);
    } // end while

    YAMUX_LOG("<< yamux_session_receive returning %d (consumed %zu / received %zu bytes)", 
              (int)consumed_total, consumed_total, len);
    return (int)consumed_total;
}

// 获取当前时间（毫秒）
uint64_t yamux_time_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// 检查 yamux 会话是否已关闭
bool yamux_session_is_closed(yamux_session_t* session) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return true;  // Null 会话视为已关闭
    
    // 如果收到或发送了 GoAway，则会话已关闭
    if (s->goaway_received || s->goaway_sent) {
        return true;
    }
    
    // 如果发生了严重错误，会话也视为关闭
    if (s->last_error != YAMUX_ERR_NONE && 
        s->last_error != YAMUX_ERR_TIMEOUT &&
        s->last_error != YAMUX_ERR_WINDOW) {
        return true;
    }
    
    return false;
}

// 关闭yamux会话
int yamux_session_close(yamux_session_t* session) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return YAMUX_ERR_INVALID;
    
    if (s->goaway_sent) {
        return YAMUX_ERR_NONE; // 已经发送了GoAway，不需要再次关闭
    }
    
    // 发送GoAway帧，表示会话正常关闭
    int ret = send_goaway_frame(s, YAMUX_GOAWAY_NORMAL);
    if (ret != YAMUX_ERR_NONE) {
        YAMUX_ERROR("Failed to send GoAway frame: %d", ret);
        // 即使发送失败，也将会话标记为已关闭，因为我们的意图是关闭它
    }
    
    s->goaway_sent = true;
    
    // 通知会话关闭
    if (s->config.on_session_close) {
        s->config.on_session_close(s->session_user_data, false, YAMUX_GOAWAY_NORMAL);
    }
    
    return YAMUX_ERR_NONE;
}

// 处理窗口更新函数
static int handleWindowUpdate(struct yamux_session* s, yamux_frame_header_t* hdr, uint16_t flags) {
    if (!s || !hdr) return YAMUX_ERR_INVALID;
    
    uint32_t stream_id = hdr->stream_id;
    uint32_t increment = hdr->length;
    
    YAMUX_LOG("接收到窗口更新：流 %u，增量 %u，标志 0x%x", stream_id, increment, flags);
    
    // 获取流对象
    struct yamux_stream* stream = find_stream(s, stream_id);
    if (!stream) {
        YAMUX_WARN("WindowUpdate for unknown stream ID %u, ignoring", stream_id);
        return YAMUX_ERR_NONE; // 忽略未知流的窗口更新
    }
    
    // 处理可能的标志（如ACK、FIN、RST）
    if (flags) {
        int ret = processStreamFlags(s, stream, flags);
        if (ret != YAMUX_ERR_NONE) return ret;
    }
    
    // 如果流已关闭，忽略窗口更新
    if (stream->state == YAMUX_STREAM_STATE_CLOSED || 
        stream->state == YAMUX_STREAM_STATE_RST_SENT || 
        stream->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_WARN("Stream %u is closed/reset, ignoring window update", stream_id);
        return YAMUX_ERR_NONE;
    }
    
    // 如果是纯窗口更新（没有其他标志且有实际增量值）
    if (increment > 0) {
        YAMUX_LOG("窗口更新前：流 %u 当前发送窗口 %u", stream_id, stream->peer_window_size);
        
        // 更新前检查溢出风险
        uint32_t current_window = stream->peer_window_size;
        uint32_t max_window = s->config.max_stream_window_size;
        uint32_t new_window = current_window + increment;
        
        // 检查溢出（新窗口小于当前窗口）
        if (new_window < current_window) {
            YAMUX_ERROR("流 %u：窗口更新会导致溢出 (%u + %u)，协议错误",
                       stream_id, current_window, increment);
            send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
            return YAMUX_ERR_PROTO;
        }
        
        // 检查是否超出最大窗口大小
        if (max_window > 0 && new_window > max_window) {
            YAMUX_WARN("流 %u：窗口更新超出最大值 (%u + %u > %u)，限制为最大值",
                      stream_id, current_window, increment, max_window);
            new_window = max_window;
        }
        
        // 增加发送窗口
        stream->peer_window_size = new_window;
        YAMUX_LOG("流 %u：发送窗口增加 %u 到 %u", 
                 stream_id, increment, new_window);
        
        // 如果配置了回调，通知窗口更新
        if (s->config.on_stream_write_window_updated) {
            YAMUX_LOG("调用窗口更新回调，流 %u，新窗口大小 %u", stream_id, new_window);
            s->config.on_stream_write_window_updated(stream->user_data, new_window);
        }
    }
    
    return YAMUX_ERR_NONE;
}

// 处理流的标志（如SYN、ACK、FIN、RST）
static int processStreamFlags(struct yamux_session* s, struct yamux_stream* stream, uint16_t flags) {
    if (!s || !stream) return YAMUX_ERR_INVALID;
    
    if (flags & YAMUX_FLAG_SYN) {
        YAMUX_LOG("Processing SYN for stream %u", stream->id);
        // 处理SYN标志...
    }
    
    if (flags & YAMUX_FLAG_ACK) {
        YAMUX_LOG("Processing ACK for stream %u", stream->id);
        if (stream->state == YAMUX_STREAM_STATE_SYN_SENT) {
            stream->state = YAMUX_STREAM_STATE_ESTABLISHED;
            YAMUX_LOG("Stream %u established", stream->id);
            // 调用流建立回调
            if (s->config.on_stream_established) {
                YAMUX_LOG("Stream %u: Calling on_stream_established callback (user_data: %p)", stream->id, stream->user_data);
                s->config.on_stream_established(stream->user_data);
                YAMUX_LOG("Stream %u: Returned from on_stream_established callback", stream->id);
            } else {
                 YAMUX_LOG("Stream %u: on_stream_established callback is NULL", stream->id);
            }
        }
    }
    
    if (flags & YAMUX_FLAG_FIN) {
        YAMUX_LOG("Processing FIN for stream %u", stream->id);
        // 根据当前状态处理FIN
        if (stream->state == YAMUX_STREAM_STATE_LOCAL_FIN) {
            // 双向关闭
            stream->state = YAMUX_STREAM_STATE_CLOSED;
            // 通知关闭
            if (s->config.on_stream_close) {
                s->config.on_stream_close(stream->user_data, true, 0);
            }
            // 释放流资源
            remove_and_free_stream(s, stream->id, true, 0);
        } else if (stream->state != YAMUX_STREAM_STATE_CLOSED && 
                   stream->state != YAMUX_STREAM_STATE_RST_SENT &&
                   stream->state != YAMUX_STREAM_STATE_RST_RECEIVED) {
            // 远端关闭流
            stream->state = YAMUX_STREAM_STATE_REMOTE_FIN;
            // 通知EOF
            if (s->config.on_stream_data_eof) {
                s->config.on_stream_data_eof(stream->user_data);
            }
        }
    }
    
    if (flags & YAMUX_FLAG_RST) {
        YAMUX_LOG("Processing RST for stream %u", stream->id);
        stream->state = YAMUX_STREAM_STATE_RST_RECEIVED;
        // 通知流被重置
        if (s->config.on_stream_close) {
            s->config.on_stream_close(stream->user_data, true, YAMUX_ERR_CLOSED);
        }
        // 释放流资源
        remove_and_free_stream(s, stream->id, true, YAMUX_ERR_CLOSED);
    }
    
    return YAMUX_ERR_NONE;
}