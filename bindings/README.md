# TINY-FRPC Language Bindings

This directory contains language bindings for the TINY-FRPC C library, enabling easy integration with multiple programming languages.

## Supported Languages

- **Python** - Using ctypes for FFI
- **Node.js** - Using a native N-API addon (node-gyp)  
- **Rust** - Using direct FFI with safe wrappers (links to the shared bindings library)
- **Go** - Using CGO (existing implementation)

## Architecture

The bindings are built on top of a simplified C API (`frpc-bindings.h/c`) that provides:

- Unified interface for all tunnel types
- Simplified configuration structures
- Callback-based event handling
- Thread-safe operations
- Comprehensive error handling

## Building

### Prerequisites

1. Build the core C libraries first:
```bash
cd ../
make all
```

2. Build the shared library used by bindings:

```bash
cd ../
make bindings-shared
```

### Building Bindings

```bash
# Test individual language bindings
make python-e2e-test
make nodejs-e2e-test
make rust-e2e-test

# Run all E2E tests
make e2e

# Run P3 (Three-Process) tests with real FRPS
make p3
```

## Usage Examples

### Python

```python
from frpc_python import FRPCClient, TunnelType

# Create client
client = FRPCClient("127.0.0.1", 7000, "token")

# Create STCP server tunnel
tunnel = client.create_tunnel(
    TunnelType.STCP_SERVER,
    "my_tunnel",
    secret_key="secret",
    local_addr="127.0.0.1",
    local_port=8080
)

# Connect and start
client.connect()
tunnel.start()
```

### Node.js

```javascript
const { FRPCClient, TunnelType } = require('./frpc_node');

// Create client
const client = new FRPCClient('127.0.0.1', 7000, 'token');

// Create STCP visitor tunnel
const tunnel = client.createTunnel(TunnelType.STCP_VISITOR, 'my_tunnel', {
    secretKey: 'secret',
    remoteName: 'server_tunnel',
    bindAddr: '127.0.0.1',
    bindPort: 9090
});

// Connect and start
client.connect();
```

### Rust

```rust
use frpc_rs::{FrpcClient, TunnelConfig, TunnelType};

// Create client
let mut client = FrpcClient::new("127.0.0.1", 7000, Some("token"))?;

// Create tunnel config
let config = TunnelConfig {
    tunnel_type: TunnelType::StcpServer,
    tunnel_name: "my_tunnel".to_string(),
    secret_key: Some("secret".to_string()),
    local_addr: Some("127.0.0.1".to_string()),
    local_port: Some(8080),
    // ... other fields
};

// Create and start tunnel
let tunnel = client.create_tunnel(config, None)?;
client.connect()?;
tunnel.start()?;
```

## API Reference

### Core Classes

#### FRPCClient
- `new(server_addr, server_port, token)` - Create client
- `connect()` - Connect to FRP server
- `disconnect()` - Disconnect from server
- `create_tunnel(type, name, options)` - Create new tunnel
- `is_connected()` - Check connection status

#### FRPCTunnel  
- `start()` - Start the tunnel
- `stop()` - Stop the tunnel
- `send_data(data)` - Send data through tunnel
- `get_stats()` - Get tunnel statistics
- `is_active()` - Check if tunnel is active

### Tunnel Types

- `STCP_SERVER` - STCP server (accepts connections)
- `STCP_VISITOR` - STCP visitor (initiates connections)
- `TCP` - Direct TCP forwarding
- `UDP` - UDP forwarding
- `HTTP` - HTTP proxy
- `HTTPS` - HTTPS proxy

### Configuration Options

**STCP Server:**
- `secret_key` - Shared secret for authentication
- `local_addr` - Local service address
- `local_port` - Local service port

**STCP Visitor:**
- `secret_key` - Shared secret for authentication  
- `remote_name` - Name of remote STCP server
- `bind_addr` - Local bind address
- `bind_port` - Local bind port

### Event Callbacks

- `data_callback(data)` - Called when data is received
- `connection_callback(connected, error_code)` - Called on connection changes
- `log_callback(level, message)` - Called for log messages

## Multi-Language Integration

The bindings are designed to work together seamlessly:

1. **Python STCP Server** ↔ **Node.js STCP Visitor**
2. **Rust STCP Server** ↔ **Go STCP Visitor** 
3. **Mixed language deployments** with shared FRP server

### Example Integration Test

```bash
# Smoke tests (no real FRPS required)
make bindings-test
```

## Performance Considerations

- **Python**: Good for prototyping and scripting, moderate performance
- **Node.js**: Excellent for I/O intensive applications, event-driven
- **Rust**: Best performance, zero-cost abstractions, memory safety
- **Go**: Good balance of performance and ease of use

## Error Handling

All bindings provide comprehensive error handling:

- **Python**: `FRPCException` with error codes
- **Node.js**: `FRPCError` class with error details
- **Rust**: `Result<T, FrpcError>` pattern
- **Go**: Standard Go error interface

## Thread Safety

- All bindings are thread-safe for concurrent operations
- Event callbacks are called from background threads
- Use appropriate synchronization in callback handlers

## Debugging

Enable debug logging in all languages:

```python
# Python
set_log_callback(lambda level, msg: print(f"[{level}] {msg}"))
```

```javascript
// Node.js
setLogCallback((level, message) => console.log(`[${level}] ${message}`));
```

```rust
// Rust - implement TunnelEventHandler trait for custom logging
```

## Contributing

1. Follow language-specific conventions
2. Add comprehensive tests for new features
3. Update documentation and examples
4. Ensure cross-language compatibility

## License

Same as the main TINY-FRPC project.