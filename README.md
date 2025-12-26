# TINY-FRPC

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Platform](https://img.shields.io/badge/platform-embedded%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

**TINY-FRPC** is a lightweight, portable C implementation of the [FRP](https://github.com/fatedier/frp) client protocol, focused on **STCP (Secret TCP)** and designed for embedded / resource-constrained environments.

## ✨ Features

- 🔌 **Minimal dependencies** – pure C core, no external runtime required
- 📦 **Portable** – runs on embedded systems, Linux, and macOS
- 🔐 **STCP support** – Secret TCP with shared-key authentication
- 🔄 **Yamux multiplexing** – full protocol implementation
- 🌐 **Multi-language bindings** – Python, Node.js, Rust, Go (CGO)
- ✅ **Protocol alignment** – validated against upstream Go implementations

## 📁 Repository Layout

```
tiny-frpc/
├── include/              # Public C headers
├── source/               # C implementation (yamux, frpc, tools)
└── *.md                  # Protocol documentation

wrapper/linux/            # POSIX wrapper layer (portable I/O)

bindings/
├── python/               # Python bindings (ctypes)
├── nodejs/               # Node.js bindings (N-API)
└── rust/                 # Rust bindings (FFI)

cmd/                      # CGO alignment tests (Go ↔ C)
tests/                    # Pure C unit tests
demo/stcp/                # STCP demo applications

third-party/
├── frp/                  # Upstream FRP (git submodule)
└── yamux/                # Upstream Yamux (git submodule)
```

## 🚀 Quick Start

### Prerequisites

- **C compiler**: GCC or Clang
- **Go**: see `go.mod` for version
- **Git**: for submodules

### Build

```bash
# Clone and initialize submodules
git submodule update --init --recursive

# Install Go dependencies (recommended for China networks)
GOPROXY=https://goproxy.cn,direct make install

# Build all libraries
make all
```

### Test

```bash
# Run all tests (C unit tests + CGO alignment tests)
make test

# Run language bindings tests
make test-bindings
```

## 📚 Built Libraries

| Library                | Description                                      |
|------------------------|--------------------------------------------------|
| `libtools.a`           | Utilities (byte order, time, MD5)                |
| `libyamux.a`           | Yamux protocol implementation                    |
| `libfrpc.a`            | FRP client core + STCP                           |
| `libwrapper.a`         | POSIX wrapper layer                              |
| `libfrpc-bindings.a`   | Simplified API for language bindings             |
| `libfrpc-bindings.so`  | Shared library for bindings                      |

## 🔧 Build Targets

| Target               | Description                                      |
|----------------------|--------------------------------------------------|
| `make all`           | Build all C static libraries                     |
| `make test`          | Run C unit tests + CGO alignment tests           |
| `make test-bindings` | Run Python + Node.js + Rust binding tests        |
| `make yamux-test`    | Run Yamux CGO alignment tests                    |
| `make frpc-test`     | Run FRP/STCP CGO tests                           |
| `make demo`          | Build and run STCP demo                          |
| `make coverage`      | Generate code coverage report                    |
| `make clean`         | Remove build outputs                             |

## 💡 Usage Examples

### Python

```python
from frpc_python import FRPCClient, TunnelType

client = FRPCClient("127.0.0.1", 7000, "token")
tunnel = client.create_tunnel(
    TunnelType.STCP_SERVER,
    "my_tunnel",
    secret_key="secret",
    local_addr="127.0.0.1",
    local_port=8080
)
client.connect()
tunnel.start()
```

### Node.js

```javascript
const { FRPCClient, TunnelType } = require('./frpc_node');

const client = new FRPCClient('127.0.0.1', 7000, 'token');
const tunnel = client.createTunnel(TunnelType.STCP_VISITOR, 'my_tunnel', {
    secretKey: 'secret',
    remoteName: 'server_tunnel',
    bindAddr: '127.0.0.1',
    bindPort: 9090
});
client.connect();
```

### Rust

```rust
use frpc_rs::{FrpcClient, TunnelConfig, TunnelType};

let mut client = FrpcClient::new("127.0.0.1", 7000, Some("token"))?;
let config = TunnelConfig {
    tunnel_type: TunnelType::StcpServer,
    tunnel_name: "my_tunnel".to_string(),
    secret_key: Some("secret".to_string()),
    local_addr: Some("127.0.0.1".to_string()),
    local_port: Some(8080),
    ..Default::default()
};
let tunnel = client.create_tunnel(config, None)?;
client.connect()?;
tunnel.start()?;
```

## 🛠️ Development

### Verbose Output

```bash
make test V=1                    # Verbose Go build/test logs
TINY_FRPC_VERBOSE=1 make test   # Enable C-side diagnostics
```

### Architecture Notes

- **Hybrid C/Go**: C implements portable core, Go (CGO) provides alignment tests against upstream
- **Upstream pinning**: `go.mod` uses `replace => ./third-party/*` to avoid drift
- **Coverage builds**: Separated into `build-cov/` to avoid contaminating normal builds

### Project Status

| Stage | Description                        | Status      |
|-------|------------------------------------|-------------|
| 1     | Yamux implementation + CGO tests   | ✅ Complete |
| 2     | FRP STCP (Visitor + Server)        | ✅ Complete |
| 3     | POSIX wrapper layer                | ✅ Complete |
| 4     | Full FRP integration (TCPMux)      | ✅ Complete |

## 📖 Documentation

- [`tiny-frpc/FRP-STCP.md`](tiny-frpc/FRP-STCP.md) – STCP protocol notes
- [`tiny-frpc/LOGIC.md`](tiny-frpc/LOGIC.md) – Architecture logic and flow
- [`tiny-frpc/YAMUX.md`](tiny-frpc/YAMUX.md) – Yamux protocol notes
- [`tiny-frpc/STAGE.md`](tiny-frpc/STAGE.md) – Project milestones
- [`bindings/README.md`](bindings/README.md) – Language bindings guide

## 📝 License

MIT License. See [LICENSE](LICENSE) for details.