# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

## Non-negotiables (highest priority)

1. **Minimal, portable C for embedded targets**
   - `tiny-frpc/` contains the core C implementation of `frpc` and `yamux` targeting embedded / resource-constrained environments.
   - Keep dependencies minimal, APIs stable, and memory usage disciplined. Follow Linux C conventions.

2. **Upstream source is the protocol specification**
   - FRP behavior must match `third-party/frp`.
   - Yamux behavior must match `third-party/yamux`.
   - If unsure, read upstream source first. Do not guess protocol behavior.

3. **`wrapper/linux` is a portability layer**
   - `wrapper/linux` provides POSIX wrappers (socket/read/write/select/getaddrinfo, etc.) for building/testing on Linux/POSIX.
   - Platform-specific differences must stay in the wrapper layer, not scattered across the protocol core.

4. **Testing layers**
   - `tests/`: pure C unit tests for the C libraries (no Go dependency).
   - `cmd/`: C ↔ Go interoperability tests (CGO). Go implementations are the reference.

5. **Development order**
   - Make `tests/` solid first (edge cases, repeatable).
   - Then fix `cmd/` interop tests until strictly passing (`yamux` + `frpc-stcp`).
   - Ensure `wrapper/linux` builds/links reliably in the build system (Makefile/CMake).
   - Only then touch `bindings/` (Node/Python/Rust) and make examples/tests pass.

6. **Dependency management**
   - `third-party/frp` and `third-party/yamux` are git submodules and must be kept in sync with the Go tests.
   - Prefer `go.mod` `replace => ./third-party/*` to avoid module-vs-submodule drift.

7. **Build artifacts**
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
- `libyamux.a`: Yamux protocol implementation
- `libfrpc.a`: FRP protocol implementation (client core + STCP pieces)
- `libwrapper.a`: POSIX wrapper implementation
- `libfrpc-bindings.a`: simplified C API used by language bindings

## Build & test commands

```bash
make install
make all
make yamux-test
make frpc-test
make test
make clean
```

Notes:

- CGO can accidentally link stale static libraries due to build cache. The Makefile uses `go build -a` (and cache clean) for strict interop testing.
- Set `V=1` to enable verbose logs; set `TINY_FRPC_VERBOSE=1` for additional C-side debug output.
- All code, comments and documents must be in English.