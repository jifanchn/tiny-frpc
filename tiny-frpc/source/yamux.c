#include "../include/yamux.h"
#include "../include/tools.h"

// Forward declarations
static int handleWindowUpdate(struct yamux_session* s, yamux_frame_header_t* hdr, uint16_t flags);
static int processStreamFlags(struct yamux_session* s, struct yamux_stream* stream, uint16_t flags);

/* Configuration */
/* Define YAMUX_DEBUG to enable debug logs (usually off on embedded targets). */
#ifdef DEBUG_LOG
#define YAMUX_DEBUG
#endif

#ifdef YAMUX_DEBUG
#include <stdio.h> /* debug-only */
#define YAMUX_LOG(fmt, ...) do { printf("Yamux: " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define YAMUX_ERROR(fmt, ...) do { fprintf(stderr, "Yamux Error: " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define YAMUX_WARN(fmt, ...) do { fprintf(stderr, "Yamux Warn: " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#else
#define YAMUX_LOG(fmt, ...) ((void)0)
#define YAMUX_ERROR(fmt, ...) ((void)0)
#define YAMUX_WARN(fmt, ...) ((void)0)
#endif

/* Core dependencies */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy, memset */
#include <time.h>   /* clock_gettime */

// Max frame payload size
#define YAMUX_MAX_FRAME_PAYLOAD_SIZE (1024 * 1024) // 1MB

// Time helper declaration
uint64_t yamux_time_now(void);

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

    // Keepalive related
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

    // NOTE: Alignment with third-party/yamux:
    // - Only DATA frames carry payload; header.length is payload byte length.
    // - WINDOW_UPDATE / PING / GO_AWAY carry no payload; header.length is a semantic field (delta/ping_id/goaway_code).
    uint32_t payload_len = 0;
    if (header->type == YAMUX_TYPE_DATA) {
        payload_len = header->length;
    }

    uint8_t header_buf[YAMUX_FRAME_HEADER_SIZE];
    yamux_serialize_frame_header(header, header_buf);

    // Send frame header.
    size_t header_sent = 0;
    while (header_sent < YAMUX_FRAME_HEADER_SIZE) {
        // Use a temporary variable for the result of write_fn
        ssize_t written_now = s->config.write_fn(s->config.user_conn_ctx, 
                                           header_buf + header_sent, 
                                           YAMUX_FRAME_HEADER_SIZE - header_sent);
        if (written_now <= 0) {
            // Write error.
            YAMUX_ERROR("Failed to write frame header at offset %zu/%d (error: %zd)", 
                        header_sent, YAMUX_FRAME_HEADER_SIZE, written_now);
            s->last_error = YAMUX_ERR_IO;
            return YAMUX_ERR_IO;
        }
        header_sent += written_now;
    }
    YAMUX_LOG("   (Sent %zu header bytes)", header_sent);

    // Send payload (DATA frames only).
    if (payload_len > 0) {
        if (payload == NULL) {
            YAMUX_ERROR("DATA frame payload is NULL but length=%u", payload_len);
            s->last_error = YAMUX_ERR_INVALID;
            return YAMUX_ERR_INVALID;
        }
        YAMUX_LOG("   (Attempting to send %u payload bytes from %p)", payload_len, payload);
        size_t payload_sent = 0;
        while (payload_sent < payload_len) {
            size_t remaining = payload_len - payload_sent;
            // Use a temporary variable for the result of write_fn
            ssize_t written_now = s->config.write_fn(s->config.user_conn_ctx, 
                                               payload + payload_sent, 
                                               remaining);
            if (written_now <= 0) {
                // Write error.
                YAMUX_ERROR("Failed to write frame payload at offset %zu/%u (error: %zd)",
                            payload_sent, payload_len, written_now);
                s->last_error = YAMUX_ERR_IO;
                return YAMUX_ERR_IO;
            }
            payload_sent += written_now;
        }
        YAMUX_LOG("   (Sent %zu payload bytes)", payload_sent);
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
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_DATA;
    header.flags = YAMUX_FLAG_ACK;
    header.stream_id = stream_id;
    header.length = 0; // ACK typically has no payload unless combined

    struct yamux_stream* st = find_stream(s, stream_id);
    if (st && !s->is_client && st->state == YAMUX_STREAM_STATE_SYN_RECEIVED) {
         YAMUX_LOG("Server: Sending ACK for stream %u, current stream state SYN_RECEIVED", stream_id);
    } else if (st && s->is_client && st->state == YAMUX_STREAM_STATE_ESTABLISHED) {
         YAMUX_LOG("Client: Sending ACK for stream %u (likely window update ack), current stream state ESTABLISHED", stream_id);
    } else if (st) {
         YAMUX_LOG("Sending ACK for stream %u, current stream state %d", stream_id, st->state);
    } else {
         YAMUX_LOG("Sending ACK for stream %u (stream not found or ACK for non-data frame)", stream_id);
    }
    return send_frame(s, &header, NULL);
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
    // Alignment with third-party/yamux: GoAway has no payload; length is the error code.
    goaway_header.length = error_code;

    YAMUX_LOG("Sending GoAway with error code %u", error_code);
    int ret = send_frame(s, &goaway_header, NULL);
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

    // Keepalive related.
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
    if (!s || s->goaway_sent || s->goaway_received) {
        YAMUX_ERROR("Session is closing or already closed");
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

    // Correctly set stream->user_data.
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

    // Send SYN frame
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_DATA;
    header.flags = YAMUX_FLAG_SYN;
    header.stream_id = stream->id;
    header.length = 0; // SYN itself typically has no payload here; window size is implicit or separate.
                       // Or, initial window size can be sent as payload for SYN.
                       // For fatedier/yamux, SYN itself doesn't carry window size in payload.
                       // The stream->local_window_size is our initial window for the peer.

    YAMUX_LOG("Client: Opening stream ID %u (user_data: %p), sending SYN", stream->id, *stream_user_data_out);

    if (send_frame(s, &header, NULL) != YAMUX_ERR_NONE) {
        YAMUX_ERROR("Client: Failed to send SYN for stream %u", stream->id);
        remove_and_free_stream(s, stream->id, false, 0);
        return 0; // Error
    }
    stream->state = YAMUX_STREAM_STATE_SYN_SENT;
    YAMUX_LOG("Client: Stream %u SYN sent, state: SYN_SENT", stream->id); // extra trace
    return stream->id;
}

// Placeholder for yamux_session_accept_stream - this is driven by on_new_stream callback
// The old yamux_session_accept_stream is not directly applicable with the callback model.
// Users will get new streams via the on_new_stream callback.

// Placeholder for yamux_stream_read - driven by on_stream_data callback
// ssize_t yamux_stream_read(yamux_stream_t* stream, void* buf, size_t len) -> user calls on_stream_data

// Stream write implementation aligned with upstream Go yamux behavior.
int yamux_stream_write(yamux_session_t* session, uint32_t stream_id, const uint8_t* data, size_t len) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s || !data) {
        if(s) s->last_error = YAMUX_ERR_INVALID;
        return YAMUX_ERR_INVALID;
    }
    
    // If len is 0, succeed immediately.
    if (len == 0) {
        return 0;
    }
    
    // Find stream.
    struct yamux_stream* st = find_stream(s, stream_id);
    if (!st) {
        YAMUX_ERROR("Stream ID %u not found for write", stream_id);
        s->last_error = YAMUX_ERR_NOTFOUND;
        return YAMUX_ERR_NOTFOUND;
    }
    
    if (st->state == YAMUX_STREAM_STATE_LOCAL_FIN || 
        st->state == YAMUX_STREAM_STATE_CLOSED || 
        st->state == YAMUX_STREAM_STATE_RST_SENT || 
        st->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_ERROR("Stream ID %u is closing or closed, cannot write", stream_id);
        s->last_error = YAMUX_ERR_CLOSED;
        return YAMUX_ERR_CLOSED;
    }

    // Check peer window.
    YAMUX_LOG("stream %u peer window: %u, trying to write %zu bytes",
             stream_id, st->peer_window_size, len);
             
    // Match Go behavior: when window is 0, return a window error.
    if (st->peer_window_size == 0) {
        YAMUX_WARN("stream %u peer window is full (size=0), cannot write", stream_id);
        return YAMUX_ERR_WINDOW; // window is 0, cannot write
    }

    // Compute bytes to send: min(peer window, requested length).
    size_t bytes_to_send = len;
    if (bytes_to_send > st->peer_window_size) {
        bytes_to_send = st->peer_window_size;
        YAMUX_LOG("window-limited: stream %u can only send %zu/%zu bytes",
                 stream_id, bytes_to_send, len);
    }
    
    // Limit to one frame max payload size (matches Go yamux MaxFrameSize).
    const size_t max_payload_per_frame = 32768; // 32KB (Go yamux default)
    if (bytes_to_send > max_payload_per_frame) {
        bytes_to_send = max_payload_per_frame;
        YAMUX_LOG("frame-size-limited: stream %u can only send %zu/%zu bytes",
                 stream_id, bytes_to_send, len);
    }
    
    // Flags handling (similar to Go's sendFlags()).
    uint16_t flags = 0;
    
    // Set flags based on stream state.
    switch (st->state) {
    case YAMUX_STREAM_STATE_IDLE:
        flags |= YAMUX_FLAG_SYN;
        st->state = YAMUX_STREAM_STATE_SYN_SENT;
        YAMUX_LOG("stream %u state: IDLE -> SYN_SENT", stream_id);
        break;
    case YAMUX_STREAM_STATE_SYN_RECEIVED:
        flags |= YAMUX_FLAG_ACK;
        st->state = YAMUX_STREAM_STATE_ESTABLISHED;
        YAMUX_LOG("stream %u state: SYN_RECEIVED -> ESTABLISHED", stream_id);
        break;
    default:
        // No extra flags needed for other states.
        break;
    }
    
    // Note: The argument order is bytes_to_send (size_t), stream_id (uint32_t), st->peer_window_size (uint32_t)
    YAMUX_LOG("preparing to send %zu bytes on stream %u (peer window: %u)",
              bytes_to_send, stream_id, st->peer_window_size);

    // Prepare data frame.
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_DATA;
    header.flags = flags; // may include control flags (SYN/ACK)
    header.stream_id = stream_id;
    header.length = (uint32_t)bytes_to_send;

    // Send frame.
    int ret = send_frame(s, &header, data);
    if (ret != YAMUX_ERR_NONE) {
        YAMUX_ERROR("failed to send data frame: stream_id=%u, err=%d", stream_id, ret);
        return ret;
    }

    // After a successful send, decrease peer window.
    st->peer_window_size -= bytes_to_send;
    YAMUX_LOG("after send: stream %u peer window reduced to %u", stream_id, st->peer_window_size);
    
    // Return the number of bytes sent (not an error code), matching Go behavior.
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
    
    // If increment is 0, nothing to do.
    if (increment == 0) {
        return YAMUX_ERR_NONE;
    }

    struct yamux_stream* st = find_stream(s, stream_id);
    if (!st) {
        YAMUX_ERROR("Stream ID %u not found for window update", stream_id);
        s->last_error = YAMUX_ERR_NOTFOUND;
        return YAMUX_ERR_NOTFOUND;
    }
    
    // Check stream state; if the stream is closed/reset, do not send window updates.
    if (st->state == YAMUX_STREAM_STATE_CLOSED || 
        st->state == YAMUX_STREAM_STATE_RST_SENT || 
        st->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_WARN("Stream %u is closed/reset, ignoring window update", stream_id);
        return YAMUX_ERR_NONE;
    }
    
    // Compute new window size.
    uint32_t max_window = s->config.max_stream_window_size;
    uint32_t cur_window = st->local_window_size;
    
    YAMUX_LOG("before window update: stream %u window=%u max=%u requested_inc=%u",
              stream_id, cur_window, max_window, increment);
    
    // Clamp so we don't exceed the max window size.
    if (cur_window + increment > max_window) {
        YAMUX_WARN("stream %u window increment %u would exceed max %u, clamping to %u",
                 stream_id, increment, max_window, max_window - cur_window);
        
        increment = max_window - cur_window;
        
        // If already at max window, nothing to do.
        if (increment == 0) {
            YAMUX_WARN("Stream %u window already at maximum (%u), skipping update", 
                     stream_id, max_window);
            return YAMUX_ERR_NONE;
        }
    }
    
    // Update local window size.
    st->local_window_size += increment;
    
    // Prepare WindowUpdate frame.
    yamux_frame_header_t header;
    header.version = YAMUX_VERSION;
    header.type = YAMUX_TYPE_WINDOW_UPDATE;
    header.flags = 0; 
    header.stream_id = stream_id;
    header.length = increment; // window delta

    YAMUX_LOG("sending window update: stream %u inc=%u new_window=%u",
              stream_id, increment, st->local_window_size);
    
    // Send WindowUpdate frame.
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
    
    // 1) Keepalive
    if (s->config.enable_keepalive) {
        uint64_t current_time = yamux_time_now();
        
        // If last_ping_time is 0, initialize it and skip sending immediately.
        if (s->last_ping_time == 0) {
            s->last_ping_time = current_time;
            return;
        }
        
        uint64_t time_since_last_ping = current_time - s->last_ping_time;
        
        // Check if we should send a keepalive ping.
        if (time_since_last_ping >= s->config.keepalive_interval_ms) {
            YAMUX_LOG("sending keepalive PING frame");
            
            // Alignment with third-party/yamux: PING has no payload; length carries the opaque id.
            // Request uses SYN; response uses ACK.
            uint32_t ping_id = (uint32_t)current_time;
            
            // Prepare PING frame.
            yamux_frame_header_t header;
            header.version = YAMUX_VERSION;
            header.type = YAMUX_TYPE_PING;
            header.flags = YAMUX_FLAG_SYN; // Ping request
            header.stream_id = 0; // Ping uses stream ID 0
            header.length = ping_id; // Ping opaque id
            
            // Send PING frame.
            int ret = send_frame(s, &header, NULL);
            if (ret != YAMUX_ERR_NONE) {
                YAMUX_ERROR("Failed to send PING frame: %d", ret);
                return;
            }
            
            // Update last send time and ping id.
            s->last_ping_time = current_time;
            s->last_ping_opaque_id = ping_id;
        }
    }
    
    // 2) Other periodic tasks (if any)
    // TODO: timeouts, etc.
}

// --- yamux_session_receive ---
// This function is called by the user when new data arrives on the underlying connection.
int yamux_session_receive(yamux_session_t* session, const uint8_t* data, size_t len) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s || !data || len == 0) {
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
        
        // Alignment with third-party/yamux: only DATA frames carry payload; other types treat length as a semantic field.
        uint32_t payload_len = 0;
        if (header.type == YAMUX_TYPE_DATA) {
            payload_len = header.length;
            if (payload_len > YAMUX_MAX_FRAME_PAYLOAD_SIZE) {
                YAMUX_ERROR("Received DATA frame with excessive payload length %u > max %u", payload_len, YAMUX_MAX_FRAME_PAYLOAD_SIZE);
                send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
                s->last_error = YAMUX_ERR_PROTO;
                return YAMUX_ERR_PROTO;
            }
        }

        size_t frame_total_size = YAMUX_FRAME_HEADER_SIZE + payload_len;
        YAMUX_LOG(">> Calculated frame_total_size=%zu (hdr=%d, payload=%u)", 
                 frame_total_size, YAMUX_FRAME_HEADER_SIZE, payload_len);

        if (remaining_len < frame_total_size) {
             YAMUX_LOG(">> Incomplete frame (need %zu, have %zu), breaking loop.", frame_total_size, remaining_len);
             break;
        }

        const uint8_t* payload = current_data + YAMUX_FRAME_HEADER_SIZE;

        YAMUX_LOG("Processing Frame: SID=%u, Type=0x%x, Flags=0x%x, Len=%u", header.stream_id, header.type, header.flags, header.length);

        if (header.stream_id == 0) { // Session control messages
            switch (header.type) {
                case YAMUX_TYPE_PING:
                    // Alignment with third-party/yamux: PING has no payload; length carries the opaque id.
                    // Request uses SYN; response uses ACK.
                    if (header.flags & YAMUX_FLAG_SYN) { // Ping request
                        YAMUX_LOG("Received PING request (SID 0), sending PONG");
                        yamux_frame_header_t pong_header;
                        pong_header.version = YAMUX_VERSION;
                        pong_header.type = YAMUX_TYPE_PING;
                        pong_header.flags = YAMUX_FLAG_ACK;
                        pong_header.stream_id = 0;
                        pong_header.length = header.length; // Echo ping id
                        (void)send_frame(s, &pong_header, NULL);
                    } else if (header.flags & YAMUX_FLAG_ACK) { // Ping response
                        YAMUX_LOG("Received PONG (SID 0), id=%u", header.length);
                    } else {
                        // Per upstream behavior: ignore other flag combinations.
                        YAMUX_WARN("Ping frame with unexpected flags 0x%x, ignoring", header.flags);
                    }
                    break;
                case YAMUX_TYPE_GO_AWAY:
                    YAMUX_LOG("Received GoAway frame (SID 0).");
                    s->goaway_received = true;
                    // Alignment with third-party/yamux: GoAway has no payload; length is the error code.
                    s->remote_goaway_last_stream_id = 0;
                    YAMUX_LOG("GoAway from peer, error code: %u", header.length);
                    // The session should now be considered draining. No new streams should be opened.
                    // Existing streams might continue until remote_goaway_last_stream_id or they complete.
                    // For simplicity now, once goaway_received, we might stop most operations.
                    if (s->config.on_session_close) {
                         s->config.on_session_close(s->session_user_data, true /*by_remote*/, header.length);
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
                            struct yamux_stream* provisional_stream = (struct yamux_stream*)malloc(sizeof(struct yamux_stream));
                            if (!provisional_stream) {
                                YAMUX_ERROR("Failed to allocate memory for provisional stream %u", header.stream_id);
                                send_goaway_frame(s, YAMUX_GOAWAY_INTERNAL_ERROR);
                                s->last_error = YAMUX_ERR_MEM;
                                return YAMUX_ERR_MEM; // Fatal for session
                            }
                            memset(provisional_stream, 0, sizeof(struct yamux_stream));
                            provisional_stream->id = header.stream_id;
                            provisional_stream->session = s;
                            provisional_stream->state = YAMUX_STREAM_STATE_SYN_RECEIVED; // Tentative state
                            provisional_stream->local_window_size = s->config.initial_stream_window_size;
                            provisional_stream->peer_window_size = s->config.initial_stream_window_size;

                            void* stream_user_data_out = NULL;
                            int accepted_by_app = 0; // 0 = reject, 1 = accept, <0 = error

                            if (s->config.on_new_stream) {
                                YAMUX_LOG(">> Calling on_new_stream for Stream %u (provisional stream: %p, user_data_ptr_out: %p)", 
                                          header.stream_id, (void*)provisional_stream, &stream_user_data_out);
                                
                                struct yamux_stream* stream_ptr_arg = provisional_stream;
                                accepted_by_app = s->config.on_new_stream(s->session_user_data, &stream_ptr_arg, &stream_user_data_out);
                                // stream_ptr_arg could potentially be modified by callback, but we use provisional_stream.

                                YAMUX_LOG(">> on_new_stream for Stream %u returned: %d, user_data_val: %p", 
                                          header.stream_id, accepted_by_app, stream_user_data_out);
                            } else {
                                YAMUX_WARN("on_new_stream callback is NULL. Rejecting stream %u.", header.stream_id);
                                accepted_by_app = 0; // No callback, effectively rejected
                            }

                            if (accepted_by_app == 1) { // Application accepted
                                YAMUX_LOG("New stream %u accepted and being finalized.", header.stream_id);
                                provisional_stream->user_data = stream_user_data_out;
                                provisional_stream->state = YAMUX_STREAM_STATE_ESTABLISHED; // Set after ACK sent

                                if (!s->streams_head) {
                                    s->streams_head = provisional_stream;
                                    s->streams_tail = provisional_stream;
                                } else {
                                    s->streams_tail->next = provisional_stream;
                                    provisional_stream->prev = s->streams_tail;
                                    s->streams_tail = provisional_stream;
                                }
                                s->active_streams_count++;
                                
                                send_ack_frame(s, header.stream_id);
                                // TODO: If ACK send fails, should clean up stream.
                            } else { // Application rejected (0) or error (<0)
                                YAMUX_WARN("App rejected new StreamID %u (code: %d). Sending RST.", header.stream_id, accepted_by_app);
                                free(provisional_stream); 
                                send_rst_frame(s, header.stream_id);
                                // Optionally handle accepted_by_app < 0 (error from callback)
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

// Get current time (milliseconds).
uint64_t yamux_time_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// Check whether a Yamux session is closed.
bool yamux_session_is_closed(yamux_session_t* session) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return true;  // NULL session is considered closed
    
    // If GoAway is sent or received, the session is considered closed.
    if (s->goaway_received || s->goaway_sent) {
        return true;
    }
    
    // Fatal errors also mark the session as closed.
    if (s->last_error != YAMUX_ERR_NONE && 
        s->last_error != YAMUX_ERR_TIMEOUT &&
        s->last_error != YAMUX_ERR_WINDOW) {
        return true;
    }
    
    return false;
}

// Close a Yamux session (send GoAway).
int yamux_session_close(yamux_session_t* session) {
    struct yamux_session* s = (struct yamux_session*)session;
    if (!s) return YAMUX_ERR_INVALID;
    
    if (s->goaway_sent) {
        return YAMUX_ERR_NONE; // GoAway already sent; no need to close again
    }
    
    // Send GoAway to indicate a graceful session shutdown.
    int ret = send_goaway_frame(s, YAMUX_GOAWAY_NORMAL);
    if (ret != YAMUX_ERR_NONE) {
        YAMUX_ERROR("Failed to send GoAway frame: %d", ret);
        // Even if sending fails, we still mark the session as closed because our intent is to shut it down.
    }
    
    s->goaway_sent = true;
    
    // Notify session close.
    if (s->config.on_session_close) {
        s->config.on_session_close(s->session_user_data, false, YAMUX_GOAWAY_NORMAL);
    }
    
    return YAMUX_ERR_NONE;
}

// Handle WindowUpdate frames.
static int handleWindowUpdate(struct yamux_session* s, yamux_frame_header_t* hdr, uint16_t flags) {
    if (!s || !hdr) return YAMUX_ERR_INVALID;
    
    uint32_t stream_id = hdr->stream_id;
    uint32_t increment = hdr->length;
    
    YAMUX_LOG("received WindowUpdate: stream %u inc=%u flags=0x%x", stream_id, increment, flags);
    
    // Lookup stream.
    struct yamux_stream* stream = find_stream(s, stream_id);
    if (!stream) {
        YAMUX_WARN("WindowUpdate for unknown stream ID %u, ignoring", stream_id);
        return YAMUX_ERR_NONE; // ignore window updates for unknown streams
    }
    
    // Process flags carried on WindowUpdate (ACK/FIN/RST, etc.).
    if (flags) {
        int ret = processStreamFlags(s, stream, flags);
        if (ret != YAMUX_ERR_NONE) return ret;
    }
    
    // If stream is closed, ignore window updates.
    if (stream->state == YAMUX_STREAM_STATE_CLOSED || 
        stream->state == YAMUX_STREAM_STATE_RST_SENT || 
        stream->state == YAMUX_STREAM_STATE_RST_RECEIVED) {
        YAMUX_WARN("Stream %u is closed/reset, ignoring window update", stream_id);
        return YAMUX_ERR_NONE;
    }
    
    // Pure window update (increment > 0).
    if (increment > 0) {
        YAMUX_LOG("before window update: stream %u send_window=%u", stream_id, stream->peer_window_size);
        
        // Check overflow / bounds before applying.
        uint32_t current_window = stream->peer_window_size;
        uint32_t max_window = s->config.max_stream_window_size;
        uint32_t new_window = current_window + increment;
        
        // Overflow check (new window wraps around).
        if (new_window < current_window) {
            YAMUX_ERROR("stream %u: window update overflow (%u + %u), protocol error",
                       stream_id, current_window, increment);
            send_goaway_frame(s, YAMUX_GOAWAY_PROTOCOL_ERROR);
            return YAMUX_ERR_PROTO;
        }
        
        // Clamp to max window size.
        if (max_window > 0 && new_window > max_window) {
            YAMUX_WARN("stream %u: window update exceeds max (%u + %u > %u), clamping",
                      stream_id, current_window, increment, max_window);
            new_window = max_window;
        }
        
        // Increase send window.
        stream->peer_window_size = new_window;
        YAMUX_LOG("stream %u: send window increased by %u to %u",
                 stream_id, increment, new_window);
        
        // Notify via callback if configured.
        if (s->config.on_stream_write_window_updated) {
            YAMUX_LOG("calling window update callback: stream %u new_window=%u", stream_id, new_window);
            s->config.on_stream_write_window_updated(stream->user_data, new_window);
        }
    }
    
    return YAMUX_ERR_NONE;
}

// Process stream flags (SYN/ACK/FIN/RST).
static int processStreamFlags(struct yamux_session* s, struct yamux_stream* stream, uint16_t flags) {
    if (!s || !stream) return YAMUX_ERR_INVALID;
    
    if (flags & YAMUX_FLAG_SYN) {
        YAMUX_LOG("Processing SYN for stream %u", stream->id);
        // This path (processing SYN on an *existing* stream object) should ideally not be hit often,
        // as new SYNs are handled by creating a new stream object in yamux_session_receive.
        // However, if flags are processed late, this might occur.
    }
    
    if (flags & YAMUX_FLAG_ACK) {
        YAMUX_LOG("Processing ACK for stream %u", stream->id);
        if (stream->state == YAMUX_STREAM_STATE_SYN_SENT) {
            stream->state = YAMUX_STREAM_STATE_ESTABLISHED;
            YAMUX_LOG("Stream %u established", stream->id);
            // Call stream-established callback.
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
        // Handle FIN based on current state.
        if (stream->state == YAMUX_STREAM_STATE_LOCAL_FIN) {
            // Both sides have FIN'd: close stream.
            stream->state = YAMUX_STREAM_STATE_CLOSED;
            // Notify close.
            if (s->config.on_stream_close) {
                s->config.on_stream_close(stream->user_data, true, 0);
            }
            // Free stream resources.
            remove_and_free_stream(s, stream->id, true, 0);
        } else if (stream->state != YAMUX_STREAM_STATE_CLOSED && 
                   stream->state != YAMUX_STREAM_STATE_RST_SENT &&
                   stream->state != YAMUX_STREAM_STATE_RST_RECEIVED) {
            // Remote half-close.
            stream->state = YAMUX_STREAM_STATE_REMOTE_FIN;
            // Notify EOF to application (if configured).
            if (s->config.on_stream_data_eof) {
                s->config.on_stream_data_eof(stream->user_data);
            }
        }
    }
    
    if (flags & YAMUX_FLAG_RST) {
        YAMUX_LOG("Processing RST for stream %u", stream->id);
        stream->state = YAMUX_STREAM_STATE_RST_RECEIVED;
        // Notify stream reset.
        if (s->config.on_stream_close) {
            s->config.on_stream_close(stream->user_data, true, YAMUX_ERR_CLOSED);
        }
        // Free stream resources.
        remove_and_free_stream(s, stream->id, true, YAMUX_ERR_CLOSED);
    }
    
    return YAMUX_ERR_NONE;
}

// Function to get the ID of a stream
uint32_t yamux_stream_get_id(yamux_stream_t* stream) {
    if (!stream) return 0;
    struct yamux_stream* s = (struct yamux_stream*)stream;
    return s->id;
}