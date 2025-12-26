# FRP Protocol Deep Dive

This document provides a detailed analysis of the FRP (Fast Reverse Proxy) protocol,
based on reverse-engineering the official `frp` implementation (v0.62.1).

## Overview

FRP uses a message-based protocol over TCP. Messages are serialized as JSON with a
binary header containing the message type and length.

## Message Format

```
+------+----------+------------------+
| Type | Length   | JSON Payload     |
| 1B   | 8B (BE)  | Variable         |
+------+----------+------------------+
```

- **Type**: 1 byte, identifies the message type (see below)
- **Length**: 8 bytes, big-endian, length of JSON payload
- **Payload**: JSON-encoded message body

## Message Types

| Type | Char | Direction      | Message          |
|------|------|----------------|------------------|
| 'o'  | 111  | Client→Server  | Login            |
| '1'  |  49  | Server→Client  | LoginResp        |
| 'h'  | 104  | Client→Server  | Ping             |
| 'i'  | 105  | Server→Client  | Pong             |
| 'p'  | 112  | Client→Server  | NewProxy         |
| '2'  |  50  | Server→Client  | NewProxyResp     |
| 'v'  | 118  | Client→Server  | NewVisitorConn   |
| '3'  |  51  | Server→Client  | NewVisitorConnResp |
| 'b'  |  98  | Server→Client  | ReqWorkConn      |
| 'c'  |  99  | Client→Server  | NewWorkConn      |
| 'd'  | 100  | Server→Client  | StartWorkConn    |

## Connection Modes

### 1. TCPMux Mode (Default)

When `transport.tcpMux = true` (default), the connection flow is:

```
┌─────────┐                                    ┌─────────┐
│  frpc   │                                    │  frps   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │─────────────── TCP Connect ─────────────────→│
     │                                              │
     │  [Yamux Session Created by frps]             │
     │                                              │
     │←─────────── Yamux Stream 0 ─────────────────→│
     │              (Control Channel)               │
     │                                              │
     │── Login (Type 'o') ────────────────────────→│
     │←── LoginResp (Type '1') ───────────────────│
     │                                              │
     │── NewProxy (Type 'p') ─────────────────────→│
     │←── NewProxyResp (Type '2') ────────────────│
     │                                              │
     │── Ping (Type 'h') ─────────────────────────→│
     │←── Pong (Type 'i') ────────────────────────│
```

In TCPMux mode:
- frps creates a Yamux session as the **server** side
- Each control message is sent over a Yamux stream
- After Login, subsequent messages are **encrypted with AES-128-CFB**

### 2. Non-TCPMux Mode

When `transport.tcpMux = false`:

```
┌─────────┐                                    ┌─────────┐
│  frpc   │                                    │  frps   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │─────────────── TCP Connect ─────────────────→│
     │                                              │
     │── Login (Type 'o') [PLAINTEXT] ────────────→│
     │←── LoginResp (Type '1') [PLAINTEXT] ────────│
     │                                              │
     │  [Encryption enabled after Login]            │
     │                                              │
     │── NewProxy (Type 'p') [ENCRYPTED] ─────────→│
     │←── NewProxyResp (Type '2') [ENCRYPTED] ─────│
```

**Important**: Even in non-TCPMux mode, messages after Login are encrypted!

## Encryption Details

FRP uses AES-128-CFB encryption for control messages after Login:

### Key Derivation

```go
key := pbkdf2.Key(token, []byte("frp"), 64, 16, sha1.New)
```

- **Input**: Auth token (or empty string if no auth)
- **Salt**: "frp" (hardcoded)
- **Iterations**: 64
- **Key Length**: 16 bytes (AES-128)
- **Hash**: SHA1

### Encryption/Decryption

```go
// Writer (frpc → frps)
iv := random_16_bytes()
write(iv)                              // First write sends IV
ciphertext := aes_cfb_encrypt(key, iv, plaintext)
write(ciphertext)

// Reader (frps → frpc)
iv := read(16)                         // First read gets IV
plaintext := aes_cfb_decrypt(key, iv, ciphertext)
```

### When Encryption is Used

| Mode      | Login   | After Login    |
|-----------|---------|----------------|
| TCPMux    | Plain   | Encrypted      |
| Non-TCPMux| Plain   | Encrypted      |

## STCP Protocol Flow

Secret TCP (STCP) allows peer-to-peer communication through frps:

### Server Side (Exposing Service)

```
frpc (server) ──Login──→ frps
frpc (server) ──NewProxy(type="stcp")──→ frps
              ←──NewProxyResp──
              
              [Wait for visitor connection]
```

### Visitor Side (Accessing Service)

```
frpc (visitor) ──Login──→ frps
frpc (visitor) ──[new connection]──→ frps
               ──NewVisitorConn──→ frps
               ←──NewVisitorConnResp──
               
               [Yamux stream established for data]
```

### Data Flow

After visitor connects:
1. Visitor sends NewVisitorConn to frps
2. frps matches visitor to server proxy
3. Both sides establish Yamux session
4. Data flows through Yamux streams

## Authentication

### Token Authentication

```json
{
  "version": "tiny-frpc",
  "timestamp": 1234567890,
  "privilege_key": "md5(token + timestamp)",
  "run_id": "",
  "pool_count": 0
}
```

- `privilege_key = md5(token + timestamp_string)`
- Even with empty token, `privilege_key = md5(timestamp_string)`

## Differences: Mock FRPS vs Real FRPS

| Feature           | Mock FRPS        | Real FRPS          |
|-------------------|------------------|--------------------|
| TCPMux            | No               | Yes (default)      |
| Post-Login Crypto | No               | Yes                |
| WorkConn Pool     | No               | Yes                |
| Proxy Routing     | No               | Yes                |
| Authentication    | Basic            | Full (Token/OIDC)  |

## tiny-frpc Implementation Status

| Feature                      | Status  | Notes                              |
|------------------------------|---------|-------------------------------------|
| Message Encoding/Decoding    | ✅      | Correct format                      |
| Login/LoginResp              | ✅      | Working                             |
| Token Authentication         | ✅      | md5(token + timestamp)              |
| NewProxy/NewProxyResp        | ✅      | Works with mock and real FRPS       |
| NewVisitorConn/Resp          | ✅      | Works with mock and real FRPS       |
| Ping/Pong                    | ✅      | Working                             |
| Post-Login Encryption        | ✅      | AES-128-CFB with PBKDF2-SHA1 key    |
| TCPMux (Yamux)               | ⚠️      | Yamux implemented for data, not control |
| Real FRPS Compatibility      | ✅      | Full STCP support with encryption   |

## API for Encryption Control

The `use_encryption` option controls whether to use AES-128-CFB encryption after Login:

- **Python**: `FRPCClient(addr, port, token, use_encryption=True)`
- **Node.js**: `new FRPCClient(addr, port, token, { useEncryption: true })`
- **C**: `frpc_set_encryption(handle, true)`

Default is `true` for real FRPS compatibility. Set to `false` for testing with mock FRPS.

## Next Steps

1. **TCPMux support for control**: frpc should support Yamux multiplexing for control channel
2. **WorkConn handling**: Implement ReqWorkConn/NewWorkConn flow for TCP/UDP proxies
3. **Full bidirectional data verification**: Add echo server tests for data correctness
