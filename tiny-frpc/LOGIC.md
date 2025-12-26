# TINY-FRPC Implementation Notes

This document describes the intended architecture and the key alignment points against upstream FRP/Yamux sources.

## Goals

- Provide a minimal, portable C implementation suitable for embedded / resource-constrained environments.
- Keep dependencies to the bare minimum (standard C + a replaceable POSIX wrapper layer).
- Match protocol behavior to upstream source code (`third-party/frp`, `third-party/yamux`).

## High-level Architecture

```
+-------------+      +----------------+      +-------------+
| Application |<---->|   tiny-frpc    |<---->|    frps     |
+-------------+      +----------------+      +-------------+
                         |
                         v
                  +--------------+
                  |  wrapper/*   |   (replaceable portability layer)
                  +--------------+
                         |
                         v
                  +--------------+
                  |   syscalls   |
                  +--------------+
```

## Components

### Protocol Core (`tiny-frpc/`)

| File | Description |
|------|-------------|
| `source/frpc.c` | FRP message framing, control connection, Login/LoginResp |
| `source/frpc-stcp.c` | STCP Visitor and Server API |
| `source/yamux.c` | Yamux multiplexing protocol |
| `source/tools.c` | Byte-order helpers, time abstraction, MD5, auth key |
| `source/crypto.c` | AES-128-CFB encryption for post-Login messages |

### Headers (`tiny-frpc/include/`)

| File | Description |
|------|-------------|
| `frpc.h` | FRP client interface |
| `frpc-stcp.h` | STCP proxy interface |
| `yamux.h` | Yamux session/stream interface |
| `tools.h` | Utility functions |
| `crypto.h` | Encryption interface |

### Portability Layer (`wrapper/`)

| Path | Description |
|------|-------------|
| `wrapper/linux/` | POSIX wrapper (sockets, read/write, getaddrinfo, etc.) |

## Protocol Alignment Checkpoints

### Yamux (`third-party/yamux`)

1. **Frame `Length` semantics depend on `Type`**
   - `Data`: `Length` is payload byte length; payload follows the header.
   - `WindowUpdate`: `Length` is window delta; no payload.
   - `Ping`: `Length` is opaque id; no payload. Request uses `SYN`, response uses `ACK`.
   - `GoAway`: `Length` is error code, `StreamID` must be 0; no payload.

2. **Stream IDs**
   - Client-initiated streams are odd, server-initiated streams are even.
   - StreamID 0 is reserved for session-level frames.

3. **Ping flags**
   - Request: `SYN` flag set
   - Response: `ACK` flag set (echoes the opaque id in Length)

### FRP (`third-party/frp`)

1. **Control message framing**
   - FRP uses `golib/msg/json`: `1 byte type` + `8 bytes big-endian int64 length` + `JSON payload`.

2. **Message types** (see `FRP-PROTOCOL.md` for full list)
   - Login = 'o', LoginResp = '1'
   - NewProxy = 'p', NewProxyResp = '2'
   - NewVisitorConn = 'v', NewVisitorConnResp = '3'
   - Ping = 'h', Pong = '4'

3. **Auth key derivation**
   - `util.GetAuthKey(token, timestamp)` is `md5(token + strconv.FormatInt(timestamp, 10))` in lowercase hex.
   - In C we expose the equivalent helper as `tools_get_auth_key()`.

4. **Post-Login encryption**
   - After Login, messages are encrypted with AES-128-CFB.
   - Key derived via PBKDF2(token, "frp", 64, 16, SHA1).
   - IV is sent as the first 16 bytes of the encrypted stream.

## STCP Implementation Details

### Visitor Flow

1. `frpc_client_connect()` - Login to frps, get run_id
2. `frpc_dial_server()` - Open new TCP connection for visitor
3. Send `NewVisitorConn` message with sign_key = md5(sk + timestamp)
4. Receive `NewVisitorConnResp`
5. Initialize Yamux client session on the connection
6. `yamux_session_open_stream()` - Open data stream
7. `frpc_stcp_send()` / `frpc_stcp_receive()` - Exchange data

### Server Flow

1. `frpc_client_connect()` - Login to frps, get run_id
2. `frpc_stcp_server_register()` - Send NewProxy, get NewProxyResp
3. Initialize Yamux server session (waits for work connections)
4. `on_new_stream` callback - Accept incoming streams from visitors
5. `frpc_stcp_send()` / `frpc_stcp_receive()` - Exchange data

### Data Send Gating

**STCP data send is gated by Yamux stream existence, not by `is_connected`**

In `frpc-stcp.c`, `frpc_stcp_send()` sends when:
- Yamux session exists (`proxy->yamux_session != NULL`)
- Active stream exists (`proxy->active_stream_id != 0`)

This makes server-side echo possible immediately after accepting a new incoming stream (server does not receive an ACK - it sends the ACK to the client).

The `is_connected` flag is currently best treated as an informational state used for callbacks/logging, not a strict precondition for sending.

## Testing Strategy

| Directory | Description |
|-----------|-------------|
| `tests/` | Pure C unit tests for the C libraries |
| `cmd/yamux_test/` | CGO interop tests for Yamux |
| `cmd/frpc_test/` | CGO interop tests for STCP |

Run all tests:
```bash
make test
```

## Logging

- Default: quiet (minimal output)
- `V=1`: Enable verbose Makefile output
- `TINY_FRPC_VERBOSE=1`: Enable extra C-side debug logs
- `#define DEBUG_LOG`: Compile-time debug logging in yamux.c
