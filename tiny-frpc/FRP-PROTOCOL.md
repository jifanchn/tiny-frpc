# FRP Protocol Deep Dive

This document provides a detailed analysis of the FRP (Fast Reverse Proxy) protocol,
based on the official `frp` implementation (v0.62.1) in `third-party/frp`.

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
- **Length**: 8 bytes, big-endian int64, length of JSON payload
- **Payload**: JSON-encoded message body

## Message Types

Source: `third-party/frp/pkg/msg/msg.go`

| Type | Char | ASCII | Direction      | Message              |
|------|------|-------|----------------|----------------------|
| 'o'  | o    | 111   | Client→Server  | Login                |
| '1'  | 1    |  49   | Server→Client  | LoginResp            |
| 'p'  | p    | 112   | Client→Server  | NewProxy             |
| '2'  | 2    |  50   | Server→Client  | NewProxyResp         |
| 'c'  | c    |  99   | Client→Server  | CloseProxy           |
| 'w'  | w    | 119   | Client→Server  | NewWorkConn          |
| 'r'  | r    | 114   | Server→Client  | ReqWorkConn          |
| 's'  | s    | 115   | Server→Client  | StartWorkConn        |
| 'v'  | v    | 118   | Client→Server  | NewVisitorConn       |
| '3'  | 3    |  51   | Server→Client  | NewVisitorConnResp   |
| 'h'  | h    | 104   | Client→Server  | Ping                 |
| '4'  | 4    |  52   | Server→Client  | Pong                 |
| 'u'  | u    | 117   | Both           | UDPPacket            |
| 'i'  | i    | 105   | Client→Server  | NatHoleVisitor       |
| 'n'  | n    | 110   | Client→Server  | NatHoleClient        |
| 'm'  | m    | 109   | Server→Client  | NatHoleResp          |
| '5'  | 5    |  53   | Both           | NatHoleSid           |
| '6'  | 6    |  54   | Client→Server  | NatHoleReport        |

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
     │←── Pong (Type '4') ────────────────────────│
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

## Authentication

### Token Authentication

Source: `third-party/frp/pkg/util/util/util.go`

```go
func GetAuthKey(token string, timestamp int64) (key string) {
    md5Ctx := md5.New()
    md5Ctx.Write([]byte(token))
    md5Ctx.Write([]byte(strconv.FormatInt(timestamp, 10)))
    data := md5Ctx.Sum(nil)
    return hex.EncodeToString(data)
}
```

Login message structure:
```json
{
  "version": "tiny-frpc",
  "hostname": "",
  "os": "darwin",
  "arch": "arm64",
  "user": "",
  "timestamp": 1234567890,
  "privilege_key": "<md5(token + timestamp_string)>",
  "run_id": "",
  "pool_count": 0
}
```

- `privilege_key = md5(token + strconv.FormatInt(timestamp, 10))`
- Even with empty token, `privilege_key = md5("" + timestamp_string) = md5(timestamp_string)`

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
               
               [Data flows on this connection]
```

### Data Flow

After visitor connects:
1. Visitor sends NewVisitorConn to frps (on a separate connection)
2. frps matches visitor to server proxy via proxy_name and sk verification
3. frps relays data between visitor and server work connections
4. Data flows directly on the visitor connection (may use Yamux for multiplexing)

## Key Message Structures

### Login

```go
type Login struct {
    Version      string            `json:"version,omitempty"`
    Hostname     string            `json:"hostname,omitempty"`
    Os           string            `json:"os,omitempty"`
    Arch         string            `json:"arch,omitempty"`
    User         string            `json:"user,omitempty"`
    PrivilegeKey string            `json:"privilege_key,omitempty"`
    Timestamp    int64             `json:"timestamp,omitempty"`
    RunID        string            `json:"run_id,omitempty"`
    Metas        map[string]string `json:"metas,omitempty"`
    PoolCount    int               `json:"pool_count,omitempty"`
}
```

### NewProxy (for STCP)

```go
type NewProxy struct {
    ProxyName      string   `json:"proxy_name,omitempty"`
    ProxyType      string   `json:"proxy_type,omitempty"`  // "stcp"
    Sk             string   `json:"sk,omitempty"`          // secret key
    AllowUsers     []string `json:"allow_users,omitempty"` // ["*"] = all
    UseEncryption  bool     `json:"use_encryption,omitempty"`
    UseCompression bool     `json:"use_compression,omitempty"`
}
```

### NewVisitorConn

```go
type NewVisitorConn struct {
    RunID          string `json:"run_id,omitempty"`
    ProxyName      string `json:"proxy_name,omitempty"`  // target server name
    SignKey        string `json:"sign_key,omitempty"`    // md5(sk + timestamp)
    Timestamp      int64  `json:"timestamp,omitempty"`
    UseEncryption  bool   `json:"use_encryption,omitempty"`
    UseCompression bool   `json:"use_compression,omitempty"`
}
```

## tiny-frpc Implementation Status

| Feature                      | Status  | Notes                       |
|------------------------------|---------|------------------------------|
| Message Encoding/Decoding    | ✅      | Correct format               |
| Login/LoginResp              | ✅      | Working                      |
| Token Authentication         | ✅      | md5(token + timestamp)       |
| NewProxy/NewProxyResp        | ✅      | Working                      |
| NewVisitorConn/Resp          | ✅      | Working                      |
| Ping/Pong                    | ✅      | Working                      |
| Post-Login Encryption        | ✅      | AES-128-CFB with PBKDF2      |
| Yamux Multiplexing           | ✅      | Full implementation          |
| STCP Server Role             | ✅      | CGO interop tests pass       |
| STCP Visitor Role            | ✅      | CGO interop tests pass       |

## Differences: Mock FRPS vs Real FRPS

| Feature           | Mock FRPS        | Real FRPS          |
|-------------------|------------------|--------------------|
| TCPMux            | No               | Yes (default)      |
| Post-Login Crypto | No               | Yes                |
| WorkConn Pool     | No               | Yes                |
| Proxy Routing     | No               | Yes                |
| Authentication    | Basic            | Full (Token/OIDC)  |
