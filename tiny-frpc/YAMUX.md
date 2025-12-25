# Yamux notes (source-of-truth: `third-party/yamux`)

This document summarizes Yamux protocol concepts used by this repository.
If anything here conflicts with upstream source code, upstream wins.

## Overview

Yamux is a multiplexing protocol that carries multiple independent, bidirectional streams over a single underlying connection (e.g., TCP).

## Frames

Yamux exchanges frames. Every frame starts with a fixed 12-byte header; some frame types carry a payload.

### Frame header (12 bytes)

| Field     | Size (bytes) | Notes |
|----------|--------------|-------|
| Version  | 1            | Protocol version (currently 0) |
| Type     | 1            | Frame type |
| Flags    | 2            | Bitmask: SYN/ACK/FIN/RST |
| StreamID | 4            | Stream identifier |
| Length   | 4            | Meaning depends on `Type` |

### Frame types

- `0x0 (Data)`: carries application bytes.
- `0x1 (WindowUpdate)`: flow control; no payload.
- `0x2 (Ping)`: keepalive / RTT; no payload.
- `0x3 (GoAway)`: graceful shutdown; no payload.

### Flags

- `0x1 (SYN)`: open a stream (request).
- `0x2 (ACK)`: acknowledge stream open (response).
- `0x4 (FIN)`: graceful half-close.
- `0x8 (RST)`: abort / reset the stream.

### `Length` semantics (critical)

`Length` is not always a payload length:

- **Data**: `Length` is payload byte length; payload follows the header.
- **WindowUpdate**: `Length` is the window delta; no payload.
- **Ping**: `Length` is the opaque id; no payload. `StreamID` must be 0.
  - Request: `SYN`
  - Response: `ACK` (echoes the opaque id)
- **GoAway**: `Length` is the error code; no payload. `StreamID` must be 0.

## Sessions

A session represents the underlying transport connection and manages all streams multiplexed on top of it.

Key behaviors:

- **Stream ID allocation**
  - Client-initiated streams use odd IDs.
  - Server-initiated streams use even IDs.
  - StreamID 0 is reserved for session-level frames (Ping/GoAway).
- **Keepalive**
  - Sessions may periodically send Ping frames when idle.
- **GoAway**
  - After GoAway is received, new streams must not be created.
  - Existing streams may continue until completion.

## Streams

A stream is a reliable, ordered, bidirectional byte stream within a session.

Key behaviors:

- **Open**: `SYN`/`ACK` handshake.
- **Close**
  - `FIN` for graceful half-close (full close after both sides FIN).
  - `RST` for abort/reset.
- **Flow control**
  - Each stream has a receive window.
  - Sender must not exceed the peer’s available window.
  - Receiver sends `WindowUpdate` after consuming data.

## C integration in this repository

The public C API is defined in `tiny-frpc/include/yamux.h`.

Typical usage pattern:

- Create a session with `yamux_session_new()`, providing callbacks:
  - `write_fn`: send raw bytes to the underlying transport.
  - `on_new_stream`, `on_stream_data`, `on_stream_close`, `on_stream_established`: stream lifecycle hooks.
- Feed incoming bytes to `yamux_session_receive()`.
- Call `yamux_session_tick()` periodically (keepalive, internal timers).

