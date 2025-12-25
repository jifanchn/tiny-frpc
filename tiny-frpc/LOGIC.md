# TINY-FRPC implementation notes

This document describes the intended architecture and the key alignment points against upstream FRP/Yamux sources.

## Goals

- Provide a minimal, portable C implementation suitable for embedded / resource-constrained environments.
- Keep dependencies to the bare minimum (standard C + a replaceable POSIX wrapper layer).
- Match protocol behavior to upstream source code (`third-party/frp`, `third-party/yamux`).

## High-level architecture

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

- **Protocol core**
  - `tiny-frpc/source/frpc.c`: FRP message framing + a minimal control-connection skeleton.
  - `tiny-frpc/source/frpc-stcp.c`: STCP API surface and test harness glue (full end-to-end STCP is still WIP).
  - `tiny-frpc/source/yamux.c`: Yamux protocol implementation.
- **Utilities**
  - `tiny-frpc/source/tools.c`: byte-order helpers, time abstraction, MD5 helper, FRP auth key helper.
- **Portability**
  - `wrapper/linux/`: POSIX wrapper layer (sockets, read/write, getaddrinfo, etc.).

## Protocol alignment checkpoints (must match upstream)

### Yamux (`third-party/yamux`)

1. **Frame `Length` semantics depend on `Type`**
   - `Data`: `Length` is payload byte length; payload follows the header.
   - `WindowUpdate`: `Length` is window delta; no payload.
   - `Ping`: `Length` is opaque id; no payload. Request uses `SYN`, response uses `ACK`.
   - `GoAway`: `Length` is error code, `StreamID` must be 0; no payload.

2. **Stream IDs**
   - Client-initiated streams are odd, server-initiated streams are even.
   - StreamID 0 is reserved for session-level frames.

### FRP (`third-party/frp`)

1. **Control message framing**
   - FRP uses `golib/msg/json`: `1 byte type` + `8 bytes big-endian int64 length` + `JSON payload`.

2. **Auth key derivation**
   - `util.GetAuthKey(token, timestamp)` is `md5(token + strconv.FormatInt(timestamp, 10))` in lowercase hex.
   - In C we expose the equivalent helper as `tools_get_auth_key`.

3. **TCPMux staged bring-up**
   - `frps` enables `Transport.TCPMux=true` by default (control connection enters a mux session).
   - For incremental bring-up, tests may temporarily disable TCPMux; the long-term goal is strict C↔Go alignment with TCPMux enabled.

## Practical STCP send/recv notes (current implementation)

- **STCP data send is gated by Yamux stream existence, not by `is_connected`**
  - In `tiny-frpc/source/frpc-stcp.c`, `frpc_stcp_send()` sends when a Yamux session exists and `active_stream_id != 0`.
  - This makes server-side echo possible immediately after accepting a new incoming stream (server does not receive an ACK).
  - The `is_connected` flag is currently best treated as an informational state used for callbacks/logging, not a strict precondition for sending.

## Testing strategy

- `tests/`: pure C unit tests for the C libraries.
- `cmd/`: CGO interoperability tests that validate behavior against upstream Go peers.

## Logging

- `TINY_FRPC_VERBOSE=1` enables extra C-side debug logs (kept off by default to reduce noise).