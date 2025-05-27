# tiny-frpc

A portable C implementation of the [frpc](https://github.com/fatedier/frp) client, originally written in Go.

## Overview

The tiny-frpc project implements the frp client protocol in C that can be easily ported to embedded systems. It uses [tiny-yamux](https://github.com/jifanchn/tiny-yamux) for multiplexing capabilities and is designed to work seamlessly with the official frps server written in Go.

Key features of this implementation:
- Platform-agnostic with clear porting interfaces
- Avoids non-standard functions unsuitable for embedded systems
- Minimal memory footprint
- Simple API surface
- Clear separation between platform-specific I/O and protocol logic
- Compatible with the official frps server

## Features

- Compatible with Go-based frps server
- Support for TCP and UDP forwarding
- Visitor mode support for P2P connections
- Authentication with token
- TLS encryption support
- Minimal memory and CPU usage
- Suitable for embedded systems
- Cross-platform compatibility

## Project Status

**tiny-frpc** is currently under development with the following components:

- **Core Protocol**: Implementation of the frp client protocol in C
- **Portability**: Designed with a clear porting layer for easy adaptation to various platforms
- **Go Interoperability**: Ensures compatibility with the Go implementation of frps
- **Testing**: Includes CGO tests to validate C and Go interoperability

## Directory Structure

```
tiny-frpc/
├── include/          # Public header files
├── src/              # Implementation source files
├── tests/            # Test files
│   ├── c_tests/      # Pure C tests
│   └── cgo_tests/    # CGO integration tests
├── examples/         # Example usage
├── build/            # Build output directory (created by CMake)
├── CMakeLists.txt    # CMake build system
├── LICENSE           # MIT License
├── README.md         # This file
└── docs/             # Protocol specification and related documents
```

## Building

### Using CMake

```bash
# Create a build directory
mkdir -p build && cd build

# Configure the build
cmake ..

# Build the library and examples
make

# To include CGO interoperability tests (recommended):
# Configure with BUILD_CGO_TESTS=ON. This will build the 'frpc_cgo_test' executable.
cmake -DBUILD_CGO_TESTS=ON ..
make
# Alternatively, to build only the CGO test target after configuration:
# make frpc_cgo_test

# Run all registered tests (including CGO tests if built)
ctest
# Alternatively, you can run the CGO test executable directly (if built):
# ./frpc_cgo_test (from the build directory)
# Or pass arguments:
# ./frpc_cgo_test --standard=true --visitor=true

# Install the library (optional)
make install
```

## Usage

tiny-frpc provides a clear and simple API for integration with any platform:

### Basic Usage Example

```c
#include "frpc.h"

// Platform-specific I/O callbacks (PORTING REQUIRED)
int my_socket_read(void *ctx, uint8_t *buf, size_t len) {
    // Read from your transport layer (e.g., socket, UART, etc.)
    socket_t *sock = (socket_t *)ctx;
    return socket_read(sock, buf, len); // Return actual bytes read or -1 on error
}

int my_socket_write(void *ctx, const uint8_t *buf, size_t len) {
    // Write to your transport layer
    socket_t *sock = (socket_t *)ctx;
    return socket_write(sock, buf, len); // Return actual bytes written or -1 on error
}

// Initialize frpc
socket_t *sock = create_socket(); // Platform-specific socket creation
frpc_config_t config = {
    .server_addr = "x.x.x.x",
    .server_port = 7000,
    .token = "optional_auth_token",
    .user = "optional_user"
};

void *frpc = frpc_init(my_socket_read, my_socket_write, sock, &config);

// Add a TCP proxy
frpc_proxy_config_t proxy = {
    .name = "ssh",
    .type = FRPC_PROXY_TYPE_TCP,
    .local_ip = "127.0.0.1",
    .local_port = 22,
    .remote_port = 6000
};

frpc_add_proxy(frpc, &proxy);

// Start the frpc client
frpc_start(frpc);

// Process in event loop (call regularly)
while (running) {
    frpc_process(frpc);
    // Your event loop logic
    sleep_ms(10);
}

// Clean up when done
frpc_stop(frpc);
frpc_destroy(frpc);
```

### Example with Visitor Mode

```c
#include "frpc.h"

// I/O callbacks setup...

// Initialize frpc
frpc_config_t config = {
    .server_addr = "x.x.x.x",
    .server_port = 7000,
    .token = "optional_auth_token"
};

void *frpc = frpc_init(my_socket_read, my_socket_write, sock, &config);

// Add a visitor proxy
frpc_proxy_config_t visitor_proxy = {
    .name = "stcp_ssh_visitor",
    .type = FRPC_PROXY_TYPE_STCP, // Use STCP for secure P2P
    .server_name = "stcp_ssh_server", // Matches the STCP server proxy name on the other client
    .sk = "shared_secret_key",
    .bind_port = 6010 // Local port the visitor will listen on
};

frpc_add_proxy(frpc, &visitor);

// Start and process...
```

## Porting to Different Platforms

tiny-frpc is designed with clear platform abstraction to make it easy to port to different systems:

### I/O Callback Functions

The most critical porting requirement is implementing the I/O callbacks for your specific platform:

```c
// Read callback - Must be implemented
int my_read(void *ctx, uint8_t *buf, size_t len) {
    // Platform-specific read implementation
    // - Should return bytes read (>0) on success
    // - Return 0 on connection closed
    // - Return -1 on error
}

// Write callback - Must be implemented
int my_write(void *ctx, const uint8_t *buf, size_t len) {
    // Platform-specific write implementation
    // - Should return bytes written (>0) on success
    // - Return 0 if no bytes were written
    // - Return -1 on error
}
```

### Memory Management

By default, tiny-frpc uses standard malloc/free for memory management. For systems with custom memory management, you can provide custom allocators:

```c
// Custom memory allocator example
void* my_malloc(size_t size) {
    return custom_memory_allocate(size);
}

void my_free(void* ptr) {
    custom_memory_free(ptr);
}

// Configure frpc to use custom allocators
frpc_set_allocators(my_malloc, my_free);
```

## Integration with tiny-yamux

tiny-frpc uses tiny-yamux for multiplexing capabilities. The integration is seamless and handled internally:

```c
#include "frpc.h"
#include "yamux.h" // Only if direct access to yamux features is needed

// Initialize frpc (yamux is initialized internally)
void *frpc = frpc_init(my_socket_read, my_socket_write, sock, &config);

// Everything else works as usual
```

## C and Go Interoperability

A key focus of this project is ensuring seamless interoperability between the C implementation (tiny-frpc) and the original Go implementation (fatedier/frp).

The implementation has been carefully designed to:
- Handle all protocol details correctly
- Maintain backward compatibility with frps
- Support all essential features of the frp protocol

## License

tiny-frpc is licensed under the MIT License. See the LICENSE file for details.
