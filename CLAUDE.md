# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

## Non-negotiables (highest priority)

1. **Minimal, portable C for embedded targets**
   - `tiny-frpc/` contains the core C implementation of `frpc` targeting embedded / resource-constrained environments.
   - Keep dependencies minimal, APIs stable, and memory usage disciplined. Follow Linux C conventions.
   - **Note**: Only Direct TCP mode (`tcp_mux=false`) is supported. Yamux multiplexing is not implemented.

2. **Protocol core must NOT own platform I/O (no listen/accept in `tiny-frpc/`)**
   - The protocol core must stay **platform-agnostic**: no `listen(2)`, `accept(2)`, or OS-specific polling loops inside `tiny-frpc/`.
   - All network syscalls (dial/read/write/select, and any “listening” behavior if needed) must live in `wrapper/*` or the application layer.
   - STCP in `tiny-frpc/` is treated as a **send/receive state machine**:
     - Caller feeds inbound bytes into `frpc_stcp_receive()`
     - Core emits outbound bytes via the configured write callback
     - Core reports lifecycle via `on_connection` and delivers payload via `on_data`

3. **Upstream source is the protocol specification**
   - FRP behavior must match `third-party/frp`.
   - If unsure, read upstream source first. Do not guess protocol behavior.

4. **`wrapper/linux` is a portability layer**
   - `wrapper/linux` provides POSIX wrappers (socket/read/write/select/getaddrinfo, etc.) for building/testing on Linux/POSIX.
   - Platform-specific differences must stay in the wrapper layer, not scattered across the protocol core.

5. **Testing layers**
   - `tests/`: pure C unit tests for the C libraries (no Go dependency).
   - `cmd/`: C ↔ Go interoperability tests (CGO). Go implementations are the reference.

6. **Development order**
   - Make `tests/` solid first (edge cases, repeatable).
   - Then fix `cmd/` interop tests until strictly passing (`frpc-stcp`).
   - Ensure `wrapper/linux` builds/links reliably in the build system (Makefile/CMake).
   - Only then touch `bindings/` (Node/Python/Rust) and make examples/tests pass.

7. **Dependency management**
   - `third-party/frp` and `third-party/yamux` are git submodules (yamux is kept for FRP's Go dependency).
   - Prefer `go.mod` `replace => ./third-party/*` to avoid module-vs-submodule drift.

8. **Build artifacts**
   - `build/` and `build-cov/` are build outputs and must be ignored and never committed.

## Project overview

TINY-FRPC is a lightweight C implementation of the FRP (Fast Reverse Proxy) client protocol, focused on STCP (Secret TCP) and designed for embedded systems. The project uses C for the portable core and Go (via CGO) for interoperability tests that validate protocol alignment against upstream Go implementations.

## Architecture

### Core components

- `tiny-frpc/`: core C implementation
  - `include/`: public headers
  - `source/`: C sources
- `wrapper/linux/`: POSIX API wrapper layer (replaceable on non-POSIX targets)
- `third-party/`: upstream dependencies (git submodules)
- `tests/`: pure C tests for the C libraries
- `cmd/`: CGO-based C ↔ Go alignment tests
- `build/`: build outputs (ignored)

### Built libraries

The Makefile builds these static libraries:

- `libtools.a`: small utilities (byte order, time helper, MD5 helper, etc.)
- `libcrypto.a`: AES-128-CFB encryption implementation
- `libfrpc.a`: FRP protocol implementation (client core + STCP pieces)
- `libwrapper.a`: POSIX wrapper implementation
- `libfrpc-bindings.a`: simplified C API used by language bindings

## Build & test commands

```bash
make install
make all
make frpc-test
make test
make clean
```

Notes:

- CGO can accidentally link stale static libraries due to build cache. The Makefile uses `go build -a` (and cache clean) for strict interop testing.
- Set `V=1` to enable verbose logs; set `TINY_FRPC_VERBOSE=1` for additional C-side debug output.
- All code, comments and documents must be in English.