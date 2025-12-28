# P3 (Three-Process) Tests

P3 tests verify the complete STCP data path with a real FRPS server:

```
Visitor -> FRPS -> Server (work connection)
```

## Structure

```
demo/p3/
├── python/          # Python P3 tests
│   └── test_p3.py
├── rust/            # Rust P3 tests (TODO)
├── node/            # Node.js P3 tests (TODO)
└── common/          # Shared scripts
    └── start_frps.sh
```

## Running Tests

```bash
# Run all P3 tests
make p3

# Run Python tests only
make p3-python

# Run Rust tests only
make p3-rust

# Run Node.js tests only
make p3-node
```

## Test Cases

### Python Tests

1. **Single Visitor Communication**
   - One visitor connects and sends a message to the server
   - Server receives the message via data callback

2. **Multiple Visitors Communication**
   - Multiple visitors (Alice, Bob, Charlie) connect
   - Each visitor sends messages to the server
   - Server receives all messages

3. **Disconnect Detection**
   - Visitor sends a message, then disconnects
   - Attempt to send after disconnect fails gracefully
   - No crashes or resource leaks

4. **Rapid Message Sending**
   - Visitor sends 10 messages in quick succession
   - Server receives all messages (possibly coalesced by TCP)

## Prerequisites

- Build FRPS: `make frps-build`
- Build shared library: `make bindings-shared`
