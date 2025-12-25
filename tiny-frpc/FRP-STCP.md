# FRP STCP notes (source-of-truth: `third-party/frp`)

This document captures the STCP (Secret TCP) flow as implemented in upstream FRP.
If anything here conflicts with upstream source code, upstream wins.

## What is STCP?

STCP is a proxy type in FRP that forwards TCP traffic to an internal service and adds a shared-secret-based authentication step.
There are two roles:

- **STCP Proxy (server-side)**: runs inside the private network and registers itself to `frps` as a `stcp` proxy.
- **STCP Visitor (client-side)**: runs where it can reach `frps`, and requests a connection to the `stcp` proxy by presenting a signature derived from the shared secret.

## High-level flow

### 1) STCP Proxy registers to frps

The proxy connects to `frps`, authenticates via `Login/LoginResp`, then registers the proxy via `NewProxy/NewProxyResp`.

Relevant upstream types:

- `msg.Login`, `msg.LoginResp`
- `msg.NewProxy`, `msg.NewProxyResp`

### 2) STCP Visitor requests a connection

For each incoming user connection, the visitor establishes a fresh connection to `frps` (called “visitorConn” in upstream) and sends `NewVisitorConn`:

- `RunID`: the frpc run_id allocated by frps at login
- `ProxyName`: the *server* name (the STCP proxy name)
- `SignKey`: `util.GetAuthKey(secretKey, timestamp)`
- `Timestamp`: `time.Now().Unix()`
- `UseEncryption`, `UseCompression`: transport options

Then it waits for `NewVisitorConnResp`. If no error, traffic is forwarded over that connection, optionally wrapped with encryption/compression.

Upstream reference: `client/visitor/stcp.go`

## Auth key derivation (critical)

Upstream computes the signature as:

- `util.GetAuthKey(tokenOrSecretKey, timestamp)` = `md5(token + strconv.FormatInt(timestamp, 10))` in lowercase hex.

In this repository, the equivalent helper is exposed as `tools_get_auth_key()` in `tiny-frpc/include/tools.h`.

## TCPMux / “invalid protocol version” note

Upstream `frps` enables `Transport.TCPMux=true` by default, which means the control connection is treated as a mux session.
If the client does not speak the expected mux protocol on that connection, frps may log errors like:

- `accept new mux stream error: invalid protocol version`

For staged bring-up, `cmd/frpc_test` may temporarily disable TCPMux in the embedded frps config. The long-term goal is strict alignment with TCPMux enabled.

## Upstream files worth reading

- `client/visitor/stcp.go`
- `server/visitor/visitor.go` (auth verification + allow-users)
- `pkg/msg/msg.go` (message schema)
- `pkg/util/util/util.go` (`GetAuthKey`)

## tiny-frpc implementation notes (demo/testing)

- In `demo/stcp/`, the data-plane is a direct TCP connection carrying **Yamux frames** (for local debugging only).
- For a server-side accepted Yamux stream, the server does **not** receive an ACK (it sends the ACK to the client).
  - Therefore, sending data back should be gated by **stream existence** (`active_stream_id != 0`) rather than waiting for an ACK-driven "established" callback on the server side.