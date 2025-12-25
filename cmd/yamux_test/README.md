# Yamux test suite

This directory contains the CGO-based test suite that validates the C Yamux implementation against a Go Yamux peer.

## Test files

### 1) `basic.go`

Basic functionality tests:

- Session creation and teardown
- Stream lifecycle (open, write, read, close)
- Session configuration sanity checks (keepalive, windows, max streams)

### 2) `protocol.go`

Protocol feature tests:

- Ping/Pong semantics (keepalive, RTT)
- Flow control (window updates)
- GoAway handling (graceful shutdown)

### 3) `interop.go`

Interoperability tests (C ↔ Go):

1. Go client → C server
2. C client → Go server

Each scenario validates:

- Session establishment
- Stream creation
- Data transfer
- Stream close
- Session close / GoAway

## Running the suite

From the repository root:

```bash
make yamux-test
```

The Makefile builds the executables into `build/` and runs them:

- `build/yamux_basic_test`
- `build/yamux_protocol_test`
- `build/yamux_interop_test`

## Notes

- Run `make all` first to ensure the C static libraries are up to date.
- The tests use loopback networking for deterministic behavior.
- Use `V=1` (and optionally `TINY_FRPC_VERBOSE=1`) to get more logs when debugging.