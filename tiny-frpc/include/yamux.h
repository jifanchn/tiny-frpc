#ifndef YAMUX_H
#define YAMUX_H

#include <stdint.h>
#include <stddef.h> // For size_t
#include <stdbool.h> // For bool type

// Forward declare yamux_stream_t for use in yamux_config_t
// Full typedef will be later, but this allows pointers in the config struct.
// typedef struct yamux_stream yamux_stream_t; // Original position, moved up

// Yamux Stream - Forward declaration needed for config struct below
typedef struct yamux_stream yamux_stream_t;

// Default yamux version
#define YAMUX_VERSION 0

// Frame types
#define YAMUX_TYPE_DATA         0x0
#define YAMUX_TYPE_WINDOW_UPDATE 0x1
#define YAMUX_TYPE_PING         0x2
#define YAMUX_TYPE_GO_AWAY      0x3

// Frame flags
#define YAMUX_FLAG_SYN          0x0001 // Stream open
#define YAMUX_FLAG_ACK          0x0002 // Stream acknowledge
#define YAMUX_FLAG_FIN          0x0004 // Stream finish (FIN)
#define YAMUX_FLAG_RST          0x0008 // Stream reset (RST)

// GoAway error codes
#define YAMUX_GOAWAY_NORMAL         0x0
#define YAMUX_GOAWAY_PROTOCOL_ERROR 0x1
#define YAMUX_GOAWAY_INTERNAL_ERROR 0x2

// Standard frame header size
#define YAMUX_FRAME_HEADER_SIZE 12

// Error codes returned by yamux APIs (negative on error)
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

// Yamux configuration
typedef struct yamux_config_s {
    bool accept_backlog;            // TODO: Define usage
    bool enable_keepalive;
    uint32_t keepalive_interval_ms; // Keepalive interval in milliseconds
    uint32_t write_timeout_ms;      // Write timeout in milliseconds
    uint32_t max_stream_window_size;
    uint32_t initial_stream_window_size;
    uint32_t max_streams;           // Maximum number of concurrent streams
    // Callback for accepting a new stream (server side)
    // Returns true if accepted, false if rejected (will send RST)
    int (*on_new_stream)(void* session_user_data, yamux_stream_t** p_stream, void** p_stream_user_data_out);
    // Callback for when a stream receives data
    // Returns number of bytes processed, or < 0 on error (will send RST)
    int (*on_stream_data)(void* stream_user_data, const uint8_t* data, size_t len);
    // Callback for when a stream is closed (either by FIN/RST from peer or locally).
    // `by_remote` is true if the peer initiated the close/reset.
    // `error_code` is non-zero if closed due to RST (can be a local or remote error indication).
    void (*on_stream_close)(void* stream_user_data, bool by_remote, uint32_t error_code);
    // Called when a locally initiated stream is successfully established (ACK received for SYN).
    void (*on_stream_established)(void* stream_user_data);
    // Called when the peer has signaled EOF on a stream (FIN received) and will send no more data.
    // The stream might still be writable from our side.
    void (*on_stream_data_eof)(void* stream_user_data);
    // Called when the peer updates our stream's write window (WindowUpdate received).
    // `new_window_size` is the total current window size available for writing.
    void (*on_stream_write_window_updated)(void* stream_user_data, uint32_t new_window_size);
    // Called when the session is being closed, e.g. due to GoAway or fatal error.
    // `by_remote` is true if initiated by peer's GoAway.
    // `error_code` can indicate reason (e.g. YAMUX_GOAWAY_... codes).
    void (*on_session_close)(void* session_user_data, bool by_remote, uint32_t error_code);
    // Callback to write raw data to the underlying connection
    // Returns number of bytes written, or < 0 on error.
    int (*write_fn)(void* user_conn_ctx, const uint8_t* data, size_t len);
    void* user_conn_ctx; // User context for the underlying connection
} yamux_config_t;

// Yamux frame header
typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} __attribute__((packed)) yamux_frame_header_t; // Ensure 12 bytes

// Yamux Session
typedef struct yamux_session yamux_session_t;

// Yamux Stream - This is the original position of the typedef
// typedef struct yamux_stream yamux_stream_t; // MOVED UP

// Function to get the ID of a stream
uint32_t yamux_stream_get_id(yamux_stream_t* stream);

// Session management
// Creates a new yamux session.
// `is_client` determines if new streams initiated by this session use odd (client) or even (server) IDs.
yamux_session_t* yamux_session_new(const yamux_config_t* config, bool is_client, void* session_user_data);

// Frees a yamux session and all associated resources.
// Sends GoAway if not already sent, and closes all streams.
void yamux_session_free(yamux_session_t* session);

// Closes a yamux session by sending a GoAway frame.
// This signals the peer that no more streams should be created.
// Returns 0 on success, negative on error.
int yamux_session_close(yamux_session_t* session);

// Processes incoming raw bytes from the underlying connection.
// This function will parse frames and dispatch them.
// Returns 0 on success, negative on error (e.g., connection error, protocol error).
int yamux_session_receive(yamux_session_t* session, const uint8_t* data, size_t len);

/**
 * Periodic maintenance function.
 * Call this function periodically to handle time-based events like keepalives.
 * 
 * @param session The session to maintain.
 */
void yamux_session_tick(yamux_session_t* session);

/**
 * Checks if a yamux session is closed.
 * A session is considered closed if it has sent or received a GoAway frame,
 * or encountered a fatal error.
 *
 * @param session The session to check.
 * @return true if the session is closed, false otherwise.
 */
bool yamux_session_is_closed(yamux_session_t* session);

// Opens a new stream.
// Returns the new stream_id on success, or 0 on error (e.g., max streams reached).
// `stream_user_data` will be associated with this stream and passed to callbacks.
uint32_t yamux_session_open_stream(yamux_session_t* session, void** stream_user_data);

// Closes a stream gracefully (sends FIN).
// If `error_code` is non-zero, it sends RST with the given code instead of FIN.
// Returns 0 on success, negative on error.
int yamux_stream_close(yamux_session_t* session, uint32_t stream_id, uint32_t error_code_if_rst);

// Sends data on a stream.
// Returns number of bytes accepted for sending (might be less than len due to window size),
// or negative on error.
int yamux_stream_write(yamux_session_t* session, uint32_t stream_id, const uint8_t* data, size_t len);

// Call this when application has processed `len` bytes of data for a stream,
// to update the receive window for the remote peer.
// Returns 0 on success, negative on error.
int yamux_stream_window_update(yamux_session_t* session, uint32_t stream_id, uint32_t increment);


#endif // YAMUX_H 