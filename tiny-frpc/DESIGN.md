# Tiny-FRPC Design & Implementation

This document consolidates the technical design, protocol specifications, and implementation details of `tiny-frpc`. It serves as the single source of truth for understanding the codebase architecture, matching upstream behaviors, and proper usage.

## 1. Architecture

`tiny-frpc` is designed as a minimal, portable C library that implements the core FRP (Fast Reverse Proxy) client protocol. It is suitable for embedded systems or environments where a full Go runtime is undesirable.

```
+-------------+      +----------------+      +-------------+
| Application |<---->|   tiny-frpc    |<---->|    frps     |
| (C/Py/Node) |      | (Core Logic)   |      | (Go Server) |
+-------------+      +----------------+      +-------------+
                         |
                         v
                  +--------------+
                  |  wrapper/*   |  (Platform Abstraction Layer)
                  +--------------+
                         |
                         v
                  +--------------+
                  |   OS / HW    |  (Sockets, Time, RNG)
                  +--------------+
```

### Components

| Component | Path | Description |
|-----------|------|-------------|
| **Core Protocol** | `source/frpc.c` | FRP framing, Control connection management, Login logic. |
| **STCP Logic** | `source/frpc-stcp.c` | Secret TCP (P2P-like) proxy and visitor implementation. |
| **Utils** | `source/tools.c` | MD5, Time, Parsing helpers. |
| **Crypto** | `source/crypto.c` | AES-128-CFB encryption implementation. |
| **Wrapper** | `wrapper/` | Replaceable OS abstraction (Linux/POSIX implementation provided). |

---

## 2. Protocol Specifications

### Framing & Encryption

FRP uses a custom framing protocol over TCP:

```
[Type (1B)] + [Length (8B, Big-Endian)] + [Payload (JSON)]
```

- **Handshake**: The initial `Login` (Type 'o') and `LoginResp` (Type '1') messages are sent in **plaintext** (unless TLS is used at the transport layer).
- **Encryption**: Immediately after a successful Login, the connection switches to **AES-128-CFB** encryption.
  - **Key**: PBKDF2(token, salt="frp", iter=64, keyLen=16, hash=SHA1).
  - **IV**: A random 16-byte IV is prefixed to the encrypted stream.

### Authentication

`tiny-frpc` implements the standard FRP token-based authentication:

1.  **Privilege Key**: `MD5(token + timestamp_string)`.
2.  **Login Message**: Includes `timestamp` and `privilege_key`.
3.  **STCP Sign Key**: For STCP visitors, `MD5(sk + timestamp_string)`, where `sk` is the shared secret.

---

## 3. STCP (Secret TCP) Implementation

STCP allows secure, direct traffic forwarding between a Visitor and a Server (Proxy) via the FRPS relay.

### Flow Diagram

```
[Visitor]                  [FRPS]                   [Server]
    |                        |                         |
    |---(1) Login ---------->|                         |
    |                        |<-----(1) Login ---------|
    |                        |<-----(2) NewProxy ------|
    |                        |      (Register API)     |
    |                        |                         |
    |---(3) NewVisitorConn ->|                         |
    |   (Target: "Server")   |                         |
    |                        |-----(4) ReqWorkConn --->|
    |                        |                         |
    |                        |<-----(5) NewWorkConn ---|
    |                        |      (New TCP Conn)     |
    |                        |                         |
    |<--(6) NewVisConnResp --|-----(7) StartWorkConn ->|
    |                        |                         |
    |<=====(Data Tunnel)====>|<=====(Data Tunnel)=====>|
```

### Key Implementation Details

1.  **Visitor Polling**:
    *   The Visitor must periodically poll its connection for incoming data (e.g., broadcast messages from the Server). This is handled by `frpc_tunnel_tick()`.
2.  **Work Connections**:
    *   The Server maintains a pool of "Work Connections". When `ReqWorkConn` is received, it opens a fresh connection to FRPS to handle the specific visitor session.
3.  **Direct TCP Mode**:
    *   Data is sent raw over the socket.
    *   **Note**: This implementation only supports Direct Mode (`tcp_mux=false`). Yamux multiplexing (`tcp_mux=true`) is not supported.

---

## 4. Development Status

**Current State**: ✅ Feature Complete / Maintenance

| Feature | Status | Notes |
| :--- | :--- | :--- |
| **Core C Library** | ✅ | Stable, portable, no external dependencies. |
| **STCP Support** | ✅ | Full bidirectional support (Visitor & Server). |
| **Bindings** | ✅ | **Python** (ctypes), **Node.js** (N-API), **Rust** (FFI). |
| **Platforms** | ✅ | **Linux** (Primary), **macOS** (Dev), **Windows** (via MinGW). |
| **Testing** | ✅ | Comprehensive C unit tests + Multi-language E2E tests. |

### Usage

**Build**:
```bash
make       # Build libraries
make test  # Run C unit tests
make e2e   # Run E2E integration tests (requires Go installed)
make p3    # Run 3-Process Demo (Python + Node + Rust)
```

**Language Bindings**:
- **Python**: `bindings/python/` - `pip install .`
- **Node.js**: `bindings/nodejs/` - `npm install`
- **Rust**: `bindings/rust/` - `cargo build`
