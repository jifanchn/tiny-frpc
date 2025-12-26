# FRP STCP Notes (source-of-truth: `third-party/frp`)

This document captures the STCP (Secret TCP) flow as implemented in upstream FRP.
If anything here conflicts with upstream source code, upstream wins.

## What is STCP?

STCP is a proxy type in FRP that forwards TCP traffic to an internal service and adds a shared-secret-based authentication step.
There are two roles:

- **STCP Proxy (server-side)**: runs inside the private network and registers itself to `frps` as a `stcp` proxy.
- **STCP Visitor (client-side)**: runs where it can reach `frps`, and requests a connection to the `stcp` proxy by presenting a signature derived from the shared secret.

## High-level Flow

### 1) STCP Proxy (Server) registers to frps

The proxy connects to `frps`, authenticates via `Login/LoginResp`, then registers the proxy via `NewProxy/NewProxyResp`.

Relevant upstream types (from `third-party/frp/pkg/msg/msg.go`):

- `msg.Login`, `msg.LoginResp`
- `msg.NewProxy`, `msg.NewProxyResp`

NewProxy message for STCP:
```json
{
  "proxy_name": "my_stcp_server",
  "proxy_type": "stcp",
  "sk": "shared_secret_key",
  "allow_users": ["*"],
  "use_encryption": false,
  "use_compression": false
}
```

### 2) STCP Visitor requests a connection

For each incoming user connection, the visitor establishes a **fresh connection** to `frps` (called "visitorConn" in upstream) and sends `NewVisitorConn`:

```json
{
  "run_id": "<frpc run_id from login>",
  "proxy_name": "<target server proxy name>",
  "sign_key": "<md5(sk + timestamp)>",
  "timestamp": 1234567890,
  "use_encryption": false,
  "use_compression": false
}
```

- `RunID`: the frpc run_id allocated by frps at login
- `ProxyName`: the *server* name (the STCP proxy name to connect to)
- `SignKey`: `util.GetAuthKey(secretKey, timestamp)` = `md5(sk + timestamp_string)`
- `Timestamp`: `time.Now().Unix()`
- `UseEncryption`, `UseCompression`: transport options

Then it waits for `NewVisitorConnResp`. If no error, traffic is forwarded over that connection, optionally wrapped with encryption/compression.

Upstream reference: `third-party/frp/client/visitor/stcp.go`

## Auth Key Derivation (critical)

Upstream computes the signature as:

```go
// third-party/frp/pkg/util/util/util.go
func GetAuthKey(token string, timestamp int64) (key string) {
    md5Ctx := md5.New()
    md5Ctx.Write([]byte(token))
    md5Ctx.Write([]byte(strconv.FormatInt(timestamp, 10)))
    data := md5Ctx.Sum(nil)
    return hex.EncodeToString(data)
}
```

Result: `md5(token + strconv.FormatInt(timestamp, 10))` in lowercase hex (32 chars).

In this repository, the equivalent helper is exposed as `tools_get_auth_key()` in `tiny-frpc/include/tools.h`.

## Connection Flow Diagram

```
┌─────────────┐                     ┌─────────┐                    ┌─────────────┐
│ STCP Server │                     │  frps   │                    │STCP Visitor │
└──────┬──────┘                     └────┬────┘                    └──────┬──────┘
       │                                 │                                │
       │──── TCP Connect ───────────────→│                                │
       │──── Login ─────────────────────→│                                │
       │←─── LoginResp ──────────────────│                                │
       │                                 │                                │
       │──── NewProxy (stcp) ───────────→│                                │
       │←─── NewProxyResp ───────────────│                                │
       │                                 │                                │
       │     [Server registered]         │                                │
       │                                 │                                │
       │                                 │←─── TCP Connect ───────────────│
       │                                 │←─── Login ─────────────────────│
       │                                 │──── LoginResp ────────────────→│
       │                                 │                                │
       │                                 │←─── TCP Connect (new) ─────────│
       │                                 │←─── NewVisitorConn ────────────│
       │                                 │                                │
       │                                 │ [Verify sign_key matches sk]   │
       │                                 │                                │
       │                                 │──── NewVisitorConnResp ───────→│
       │                                 │                                │
       │←─── [Data relay] ──────────────→│←─────── [Data relay] ─────────→│
       │                                 │                                │
```

## TCPMux / "invalid protocol version" Note

Upstream `frps` enables `Transport.TCPMux=true` by default, which means the control connection is treated as a Yamux mux session.
If the client does not speak the expected mux protocol on that connection, frps may log errors like:

- `accept new mux stream error: invalid protocol version`

For staged bring-up, `cmd/frpc_test` may temporarily disable TCPMux in the embedded frps config. The long-term goal is strict alignment with TCPMux enabled.

## Upstream Files Worth Reading

- `third-party/frp/client/visitor/stcp.go` - STCP visitor implementation
- `third-party/frp/server/visitor.go` - Server-side visitor handling
- `third-party/frp/pkg/msg/msg.go` - Message schema definitions
- `third-party/frp/pkg/util/util/util.go` - `GetAuthKey` implementation

## tiny-frpc Implementation Notes

### STCP API

The C API for STCP is defined in `tiny-frpc/include/frpc-stcp.h`:

- `frpc_stcp_proxy_new()` - Create STCP proxy (server or visitor)
- `frpc_stcp_proxy_start()` - Start the proxy
- `frpc_stcp_visitor_connect()` - Visitor: connect to server via frps
- `frpc_stcp_server_register()` - Server: register with frps
- `frpc_stcp_send()` / `frpc_stcp_receive()` - Data transfer

### Data Plane

After the FRP control handshake, data flows through Yamux:

1. Visitor opens a Yamux stream after `NewVisitorConnResp`
2. Server accepts incoming Yamux streams from work connections
3. `frpc_stcp_send()` writes via `yamux_stream_write()`
4. `frpc_stcp_receive()` feeds bytes to `yamux_session_receive()`

### Stream Lifecycle

- For **visitor**: after `NewVisitorConnResp` success, immediately open a Yamux stream and send data.
- For **server**: wait for incoming Yamux stream via `on_new_stream` callback, then echo/process data.

### Key Implementation Detail

STCP data send is gated by **Yamux stream existence** (`active_stream_id != 0`), not by the `is_connected` flag:

- Server-side: When accepting a new stream, the server does **not** receive an ACK (it sends the ACK to the client).
- Therefore, sending data should be gated by stream existence rather than waiting for an "established" callback on the server side.

### Current Status

- ✅ STCP Visitor and Server roles implemented
- ✅ CGO interop tests pass (`make frpc-test`)
- ✅ Bidirectional data exchange verified
- ✅ Reconnection cycle tests pass
