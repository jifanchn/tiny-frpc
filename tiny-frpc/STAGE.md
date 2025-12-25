# Tiny-FRPC project stages

This file tracks development stages and major milestones for the repository.

## Stage 1: Yamux implementation + CGO alignment tests

- **Status:** Complete (strict alignment tests passing)
- **Date started:** 2024-05-12
- **Date completed:** 2025-12-25

### Deliverables

- C Yamux implementation (`tiny-frpc/source/yamux.c`, `tiny-frpc/include/yamux.h`)
- Core utilities (`tiny-frpc/source/tools.c`, `tiny-frpc/include/tools.h`)
- CGO alignment tests (`cmd/yamux_test/`: basic / protocol / interop)
- Makefile targets for strict build + test execution

## Stage 2: FRP STCP implementation (Visitor + Server)

- **Status:** In progress
- **Date started:** 2024-05-13

### Current scope

- Provide a minimal C API for STCP Visitor and STCP Server roles (`tiny-frpc/include/frpc-stcp.h`).
- Use upstream FRP (`third-party/frp`) as the protocol reference.
- Validate behavior via CGO integration tests under `cmd/frpc_test/`.
- Provide a small POSIX demo under `demo/stcp/` for local development/debugging.

### Known gaps / next work

- Complete the real upstream STCP message flow (instead of placeholders), including:
  - `NewVisitorConn` / `NewVisitorConnResp`
  - `NewProxy` / `NewProxyResp`
  - Work connection handling and data forwarding
- Tighten protocol alignment and re-enable TCPMux in strict tests.
- Improve error handling and resource cleanup for embedded constraints.

## Stage 3: POSIX wrapper layer

- **Status:** Complete

`wrapper/linux` provides POSIX wrappers (socket/read/write/select/getaddrinfo, etc.) for building and testing on a desktop OS. Platform-specific differences must remain in the wrapper layer.

## Stage 4: Full FRP integration testing (CGO)

- **Status:** Not started / pending Stage 2 completion

Goal: strict end-to-end alignment tests with TCPMux enabled, using upstream Go `frps` as the reference peer.

## Milestones

### 2025-12-25 (must keep)

1. **Yamux protocol alignment fixes**
   - Fixed `Length` semantics for `WindowUpdate` / `Ping` / `GoAway` (semantic field, no payload).
   - Fixed Ping flags (`SYN` request / `ACK` response) and GoAway rules (`StreamID=0`, `Length=error_code`).

2. **Strict CGO test execution**
   - Updated Makefile targets to run tests in strict mode (no `|| true` swallowing failures).
   - Ensured Go builds use `go build -a` (and cache clean) to avoid stale static library linkage.

3. **Submodule pinning**
   - Pinned `third-party/frp` to `v0.62.1`.
   - Root `go.mod` uses `replace => ./third-party/*` to avoid module-vs-submodule drift.

4. **Logging strategy (quiet by default)**
   - Default runs are quiet; `V=1` and/or `TINY_FRPC_VERBOSE=1` enable additional diagnostics.

5. **Coverage build isolation**
   - Separated `build/` (normal) vs `build-cov/` (coverage) to avoid instrumented artifacts contaminating normal builds.

6. **Disconnect callback de-duplication**
   - Avoided double `on_connection(0, ...)` notifications when `yamux_session_free()` already triggers stream close callbacks.

