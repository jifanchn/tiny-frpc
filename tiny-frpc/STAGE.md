# Tiny-FRPC Project Stages

This file tracks development stages and major milestones for the repository.

## Current Status: All Stages Complete ✅

All major development stages have been completed. The project provides a working C implementation of FRP STCP (Visitor and Server) with full Yamux multiplexing support.

---

## Stage 1: Yamux Implementation + CGO Alignment Tests

- **Status:** ✅ Complete
- **Date started:** 2024-05-12
- **Date completed:** 2025-12-25

### Deliverables

- C Yamux implementation (`tiny-frpc/source/yamux.c`, `tiny-frpc/include/yamux.h`)
- Core utilities (`tiny-frpc/source/tools.c`, `tiny-frpc/include/tools.h`)
- CGO alignment tests (`cmd/yamux_test/`: basic / protocol / interop)
- Makefile targets for strict build + test execution

### Key Features

- Full Yamux protocol support (Data, WindowUpdate, Ping, GoAway)
- SYN/ACK/FIN/RST stream lifecycle
- Flow control with window updates
- Keepalive with Ping/Pong

---

## Stage 2: FRP STCP Implementation (Visitor + Server)

- **Status:** ✅ Complete
- **Date started:** 2024-05-13
- **Date completed:** 2025-12-25

### Deliverables

- STCP Visitor and Server API (`tiny-frpc/include/frpc-stcp.h`, `tiny-frpc/source/frpc-stcp.c`)
- FRP client core (`tiny-frpc/include/frpc.h`, `tiny-frpc/source/frpc.c`)
- Post-login encryption (`tiny-frpc/include/crypto.h`, `tiny-frpc/source/crypto.c`)
- CGO integration tests (`cmd/frpc_test/`)
- POSIX demo (`demo/stcp/`)

### Key Features

- Login/LoginResp with token authentication
- NewProxy/NewProxyResp for STCP registration
- NewVisitorConn/NewVisitorConnResp for visitor connection
- md5(sk + timestamp) signature verification
- Bidirectional data exchange via Yamux

---

## Stage 3: POSIX Wrapper Layer

- **Status:** ✅ Complete

### Deliverables

- `wrapper/linux/wrapper.c` - POSIX wrapper implementation
- `wrapper/linux/wrapper.h` - Wrapper interface

The wrapper layer provides platform-agnostic access to:
- Socket operations (socket, connect, read, write, close)
- DNS resolution (getaddrinfo, freeaddrinfo)
- Time functions (clock_gettime equivalent)
- Error handling (errno abstraction)

---

## Stage 4: Full FRP Integration Testing (CGO)

- **Status:** ✅ Complete
- **Date started:** 2025-12-25
- **Date completed:** 2025-12-25

### Deliverables

- Robust Yamux interop tests with upstream Go implementation
- STCP end-to-end validation (C client ↔ Go server)
- Reconnection cycle tests
- Multi-channel communication tests

---

## Milestones

### 2025-12-25 (Protocol Alignment)

1. **Yamux protocol alignment fixes**
   - Fixed `Length` semantics for `WindowUpdate` / `Ping` / `GoAway` (semantic field, no payload)
   - Fixed Ping flags (`SYN` request / `ACK` response) and GoAway rules (`StreamID=0`, `Length=error_code`)

2. **Strict CGO test execution**
   - Updated Makefile targets to run tests in strict mode (no `|| true` swallowing failures)
   - Ensured Go builds use `go build -a` (and cache clean) to avoid stale static library linkage

3. **Submodule pinning**
   - Pinned `third-party/frp` to `v0.62.1`
   - Root `go.mod` uses `replace => ./third-party/*` to avoid module-vs-submodule drift

4. **Logging strategy (quiet by default)**
   - Default runs are quiet; `V=1` and/or `TINY_FRPC_VERBOSE=1` enable additional diagnostics

5. **Coverage build isolation**
   - Separated `build/` (normal) vs `build-cov/` (coverage) to avoid instrumented artifacts contaminating normal builds

6. **Disconnect callback de-duplication**
   - Avoided double `on_connection(0, ...)` notifications when `yamux_session_free()` already triggers stream close callbacks

### 2025-12-25 (STCP Finalized)

1. **STCP (Visitor + Server) finalized**
   - Full C API for STCP with robust CGO interop tests (`cmd/frpc_test/frpc_stcp.go`)
   - Bidirectional data exchange and reconnect cycle tests pass

2. **Stage 4 (TCPMux) integration complete**
   - Core building blocks (Yamux, FRP message framing) are aligned
   - All `make test` targets pass

### 2025-12-26 (Documentation Update)

1. **Documentation synchronized with source code**
   - Updated FRP-PROTOCOL.md with correct message types from `third-party/frp/pkg/msg/msg.go`
   - Updated FRP-STCP.md with accurate flow diagrams and implementation details
   - Updated YAMUX.md with precise protocol specifications from `third-party/yamux/const.go`
   - Updated LOGIC.md with current architecture and implementation notes

---

## Build & Test Commands

```bash
# Install dependencies
make install

# Build all libraries
make all

# Run Yamux CGO interop tests
make yamux-test

# Run STCP CGO interop tests
make frpc-test

# Run all tests
make test

# Clean build artifacts
make clean
```

---

## Next Steps (Future Work)

1. **Language Bindings**
   - `bindings/nodejs/` - Node.js FFI bindings
   - `bindings/python/` - Python ctypes bindings
   - `bindings/rust/` - Rust FFI bindings

2. **Platform Porting**
   - Implement `wrapper/` for other platforms (RTOS, bare-metal, etc.)

3. **Additional Proxy Types**
   - TCP, UDP, HTTP, HTTPS proxy types (if needed)

4. **TCPMux on Control Connection**
   - Enable Yamux on the main control connection (currently disabled for simplicity)
