# Yamux Notes (source-of-truth: `third-party/yamux`)

This document summarizes Yamux protocol concepts used by this repository.
If anything here conflicts with upstream source code, upstream wins.

## Overview

Yamux is a multiplexing protocol that carries multiple independent, bidirectional streams over a single underlying connection (e.g., TCP).

Source: https://github.com/hashicorp/yamux (fatedier's fork at `third-party/yamux`)

## Frames

Yamux exchanges frames. Every frame starts with a fixed 12-byte header; some frame types carry a payload.

### Frame Header (12 bytes)

Source: `third-party/yamux/const.go`

| Field     | Size (bytes) | Offset | Notes                          |
|----------|--------------|--------|--------------------------------|
| Version  | 1            | 0      | Protocol version (currently 0) |
| Type     | 1            | 1      | Frame type                     |
| Flags    | 2            | 2      | Big-endian, bitmask            |
| StreamID | 4            | 4      | Big-endian, stream identifier  |
| Length   | 4            | 8      | Big-endian, meaning varies     |

```go
const (
    sizeOfVersion  = 1
    sizeOfType     = 1
    sizeOfFlags    = 2
    sizeOfStreamID = 4
    sizeOfLength   = 4
    headerSize     = 12
)
```

### Frame Types

```go
const (
    typeData         uint8 = 0  // Data frames, followed by payload
    typeWindowUpdate uint8 = 1  // Flow control, no payload
    typePing         uint8 = 2  // Keepalive/RTT, no payload
    typeGoAway       uint8 = 3  // Graceful shutdown, no payload
)
```

| Type | Value | Description                                  |
|------|-------|----------------------------------------------|
| Data | 0x0   | Carries application bytes (has payload)      |
| WindowUpdate | 0x1 | Flow control update (no payload)        |
| Ping | 0x2   | Keepalive / RTT measurement (no payload)     |
| GoAway | 0x3 | Graceful shutdown (no payload)               |

### Flags

```go
const (
    flagSYN uint16 = 1 << iota  // 0x0001 - Stream open
    flagACK                      // 0x0002 - Stream acknowledge
    flagFIN                      // 0x0004 - Stream finish (half-close)
    flagRST                      // 0x0008 - Stream reset (abort)
)
```

| Flag | Value  | Description                        |
|------|--------|------------------------------------|
| SYN  | 0x0001 | Open a stream (request)            |
| ACK  | 0x0002 | Acknowledge stream open (response) |
| FIN  | 0x0004 | Graceful half-close                |
| RST  | 0x0008 | Abort / reset the stream           |

### `Length` Semantics (critical)

**`Length` is NOT always a payload length** - its meaning depends on frame type:

| Frame Type   | Length Meaning              | Payload? |
|--------------|----------------------------|----------|
| Data         | Payload byte length         | Yes      |
| WindowUpdate | Window delta (increment)    | No       |
| Ping         | Opaque ping ID              | No       |
| GoAway       | Error code                  | No       |

For **Ping** frames:
- Request: Flags = `SYN`, Length = opaque ID
- Response: Flags = `ACK`, Length = echoed opaque ID
- StreamID must be 0

For **GoAway** frames:
- StreamID must be 0
- Length is the error code (0=normal, 1=protocol error, 2=internal error)

### GoAway Error Codes

```go
const (
    goAwayNormal      uint32 = 0  // Normal termination
    goAwayProtoErr    uint32 = 1  // Protocol error
    goAwayInternalErr uint32 = 2  // Internal error
)
```

### Initial Stream Window Size

```go
const (
    initialStreamWindow uint32 = 256 * 1024  // 256 KB
)
```

## Sessions

A session represents the underlying transport connection and manages all streams multiplexed on top of it.

Key behaviors:

- **Stream ID allocation**
  - Client-initiated streams use **odd** IDs (1, 3, 5, ...)
  - Server-initiated streams use **even** IDs (2, 4, 6, ...)
  - StreamID 0 is reserved for session-level frames (Ping/GoAway)
- **Keepalive**
  - Sessions may periodically send Ping frames when idle
  - Ping request uses `SYN` flag, response uses `ACK` flag
- **GoAway**
  - After GoAway is received, new streams must not be created
  - Existing streams may continue until completion

## Streams

A stream is a reliable, ordered, bidirectional byte stream within a session.

### Stream Lifecycle

```
           SYN
  IDLE ──────────→ SYN_SENT
           │              │
           │ SYN recv     │ ACK recv
           ↓              ↓
    SYN_RECEIVED ←───→ ESTABLISHED
           │              │
           │ FIN          │ FIN
           ↓              ↓
     LOCAL_FIN ←────→ REMOTE_FIN
           │              │
           └──────────────┘
                  │
                  ↓
               CLOSED
```

Key behaviors:

- **Open**: `SYN`/`ACK` handshake
- **Close**
  - `FIN` for graceful half-close (full close after both sides FIN)
  - `RST` for abort/reset
- **Flow control**
  - Each stream has a receive window (default 256 KB)
  - Sender must not exceed the peer's available window
  - Receiver sends `WindowUpdate` after consuming data

## C Integration in This Repository

The public C API is defined in `tiny-frpc/include/yamux.h`.

### Key Constants

```c
#define YAMUX_VERSION             0
#define YAMUX_TYPE_DATA           0x0
#define YAMUX_TYPE_WINDOW_UPDATE  0x1
#define YAMUX_TYPE_PING           0x2
#define YAMUX_TYPE_GO_AWAY        0x3
#define YAMUX_FLAG_SYN            0x0001
#define YAMUX_FLAG_ACK            0x0002
#define YAMUX_FLAG_FIN            0x0004
#define YAMUX_FLAG_RST            0x0008
#define YAMUX_FRAME_HEADER_SIZE   12
```

### Typical Usage Pattern

```c
// 1. Create configuration with callbacks
yamux_config_t config = {
    .write_fn = my_write_callback,
    .on_new_stream = my_new_stream_callback,
    .on_stream_data = my_data_callback,
    .on_stream_close = my_close_callback,
    .on_stream_established = my_established_callback,
    // ...
};

// 2. Create session (is_client=true for client, false for server)
yamux_session_t* session = yamux_session_new(&config, is_client, user_data);

// 3. Feed incoming bytes to session
yamux_session_receive(session, data, len);

// 4. Open a stream (client-initiated)
uint32_t stream_id = yamux_session_open_stream(session, &stream_user_data);

// 5. Write data to stream
yamux_stream_write(session, stream_id, data, len);

// 6. Call periodically for keepalive
yamux_session_tick(session);

// 7. Cleanup
yamux_session_free(session);
```

### Callback Signatures

```c
// Send raw bytes to underlying connection
int (*write_fn)(void* user_conn_ctx, const uint8_t* data, size_t len);

// New incoming stream (return 1 to accept, 0 to reject)
int (*on_new_stream)(void* session_user_data, 
                     yamux_stream_t** p_stream, 
                     void** p_stream_user_data_out);

// Data received on stream
int (*on_stream_data)(void* stream_user_data, 
                      const uint8_t* data, 
                      size_t len);

// Stream closed
void (*on_stream_close)(void* stream_user_data, 
                        bool by_remote, 
                        uint32_t error_code);

// Stream established (ACK received for SYN)
void (*on_stream_established)(void* stream_user_data);
```

## Implementation Status

| Feature              | Status | Notes                           |
|---------------------|--------|----------------------------------|
| Frame serialization | ✅     | All types supported              |
| Stream lifecycle    | ✅     | SYN/ACK/FIN/RST                  |
| Flow control        | ✅     | WindowUpdate handled             |
| Ping/Pong           | ✅     | SYN request, ACK response        |
| GoAway              | ✅     | Graceful shutdown                |
| Keepalive           | ✅     | Periodic tick                    |
| CGO interop tests   | ✅     | `make yamux-test`                |
