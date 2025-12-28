# P3 (Three-Process) Tests and Demos

P3 tests verify the complete STCP data path with a **real FRPS server** using multiple processes:

```
┌─────────┐     ┌──────┐     ┌────────┐
│ Visitor │────▶│ FRPS │◀────│ Server │
└─────────┘     └──────┘     └────────┘
     ▲                            ▲
     │      Work Connection       │
     └────────────────────────────┘
```

## Quick Start

### Prerequisites

1. Build the project:
```bash
make all
make bindings-shared
make frps-build
```

### Run All P3 Tests

```bash
make p3          # Run all P3 tests (Python + Node.js + Rust)
make p3-python   # Python only
make p3-node     # Node.js only
make p3-rust     # Rust only
```

## Directory Structure

```
demo/p3/
├── common/
│   └── start_frps.sh      # Helper script to start FRPS
├── python/
│   ├── p3_server.py       # Python STCP server
│   ├── p3_visitor.py      # Python STCP visitor
│   └── test_p3.py         # Automated test runner
├── node/
│   ├── p3_server.js       # Node.js STCP server
│   ├── p3_visitor.js      # Node.js STCP visitor
│   └── test_p3.py         # Automated test runner
├── rust/
│   ├── src/bin/
│   │   ├── p3_server.rs   # Rust STCP server
│   │   └── p3_visitor.rs  # Rust STCP visitor
│   ├── test_p3.py         # Automated test runner
│   └── Cargo.toml
└── README.md              # This file
```

## Interactive Demo (Multiple Terminal Windows)

This section shows how to run the P3 demo interactively in separate terminal windows, which is great for understanding the data flow.

### Platform-Specific Setup

#### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential python3 nodejs npm

# Build
cd /path/to/tiny-frpc
make all bindings-shared frps-build
```

#### macOS (Intel & Apple Silicon)

```bash
# Install dependencies (using Homebrew)
brew install python3 node

# Build
cd /path/to/tiny-frpc
make all bindings-shared frps-build
```

#### Windows (using MSYS2/MinGW)

```bash
# Install MSYS2 first, then:
pacman -S mingw-w64-x86_64-gcc make python nodejs

# Build
cd /c/path/to/tiny-frpc
make WRAPPER_DIR=wrapper/windows all bindings-shared
# Note: frps-build requires Go, download frps from releases instead
```

---

## Running Interactive Demo

### Step 1: Start FRPS Server

**Terminal 1:**

```bash
cd /path/to/tiny-frpc
./demo/p3/common/start_frps.sh

# Or manually with custom port:
./build/frps -c frps_demo.toml
```

Create `frps_demo.toml`:
```toml
bindPort = 7001

[auth]
method = "token"
token = "test_token"

[transport]
tcpMux = false

[log]
level = "debug"
```

### Step 2: Start STCP Server (Choose Your Language)

**Terminal 2:**

<details>
<summary><b>Python Server</b></summary>

```bash
cd /path/to/tiny-frpc
python3 demo/p3/python/p3_server.py 127.0.0.1 7001

# Output:
# Server started. Waiting for visitors...
# > 
```
</details>

<details>
<summary><b>Node.js Server</b></summary>

```bash
cd /path/to/tiny-frpc
# Set library path first
export DYLD_LIBRARY_PATH=$PWD/build:$DYLD_LIBRARY_PATH  # macOS
export LD_LIBRARY_PATH=$PWD/build:$LD_LIBRARY_PATH      # Linux

node demo/p3/node/p3_server.js 127.0.0.1 7001
```
</details>

<details>
<summary><b>Rust Server</b></summary>

```bash
cd /path/to/tiny-frpc/demo/p3/rust
cargo build
./target/debug/p3_server 127.0.0.1 7001
```
</details>

### Step 3: Start STCP Visitor(s)

**Terminal 3 (Visitor Alice):**

<details>
<summary><b>Python Visitor</b></summary>

```bash
cd /path/to/tiny-frpc
python3 demo/p3/python/p3_visitor.py 127.0.0.1 7001 Alice

# Output:
# Visitor started.
# >
```
</details>

<details>
<summary><b>Node.js Visitor</b></summary>

```bash
cd /path/to/tiny-frpc
export DYLD_LIBRARY_PATH=$PWD/build:$DYLD_LIBRARY_PATH  # macOS
export LD_LIBRARY_PATH=$PWD/build:$LD_LIBRARY_PATH      # Linux

node demo/p3/node/p3_visitor.js 127.0.0.1 7001 Alice
```
</details>

<details>
<summary><b>Rust Visitor</b></summary>

```bash
cd /path/to/tiny-frpc/demo/p3/rust
./target/debug/p3_visitor 127.0.0.1 7001 Alice
```
</details>

**Terminal 4 (Visitor Bob):**

```bash
# Same as above but with name "Bob"
python3 demo/p3/python/p3_visitor.py 127.0.0.1 7001 Bob
```

### Step 4: Send Messages

Now you can type messages in any terminal and they will be received by the connected parties:

```
# In Visitor Alice's terminal:
> Hello from Alice
[Received] [Server] Got your message!

# In Server's terminal:
[Received] [Alice] Hello from Alice
> Server broadcast
```

---

## Test Cases

The automated tests verify:

1. **Single Visitor Communication**
   - One visitor connects and sends a message to the server
   - Server receives the message via data callback

2. **Multiple Visitors Communication**
   - Multiple visitors (Alice, Bob) connect simultaneously
   - Each visitor sends messages to the server
   - Server receives all messages correctly

3. **Bidirectional Communication**
   - Server broadcasts a message
   - All connected visitors receive the message

4. **Disconnect Detection**
   - Visitor sends a message, then disconnects
   - Server handles disconnect gracefully

---

## Using Pre-built Release

If you're using a pre-built release package:

### Linux/macOS

```bash
# Extract the release
tar -xzf tiny-frpc-linux-x86_64.tar.gz
cd release

# Set library path
export LD_LIBRARY_PATH=$PWD/lib:$LD_LIBRARY_PATH      # Linux
export DYLD_LIBRARY_PATH=$PWD/lib:$DYLD_LIBRARY_PATH  # macOS

# Python (library already in bindings/python/)
cd bindings/python
python3 example_stcp_server.py

# Node.js (library already in bindings/nodejs/build/)
cd bindings/nodejs
node example_stcp_visitor.js
```

### Windows

```cmd
REM Extract the release ZIP
REM Ensure DLLs are in PATH or same directory

cd release\bindings\python
python example_stcp_server.py

cd release\bindings\nodejs
node example_stcp_visitor.js
```

---

## Troubleshooting

### "Library not found" errors

Ensure the shared library path is set:

```bash
# Linux
export LD_LIBRARY_PATH=/path/to/tiny-frpc/build:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/path/to/tiny-frpc/build:$DYLD_LIBRARY_PATH

# Windows: Copy libfrpc-bindings.dll to the same directory as the script
```

### "Connection refused" errors

1. Check FRPS is running: `netstat -tlnp | grep 7001`
2. Verify the token matches between frps.toml and the bindings
3. Ensure `tcpMux = false` is set in frps config

### Rust build fails

```bash
# Ensure you're in the right directory
cd demo/p3/rust
cargo build

# If library linking fails, set:
export TINY_FRPC_LIB_PATH=/path/to/tiny-frpc/build
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TINY_FRPC_VERBOSE` | Set to `1` for verbose logging |
| `LD_LIBRARY_PATH` | Library search path (Linux) |
| `DYLD_LIBRARY_PATH` | Library search path (macOS) |
| `FRPS_PORT` | FRPS port (default: 7001) |
| `FRPS_TOKEN` | FRPS auth token (default: test_token) |

---

## CI/CD Integration

P3 tests run automatically in CI on Linux and macOS:

```yaml
# .github/workflows/ci.yml
- name: Run P3 tests
  run: make p3
```

The test matrix covers:
- Python bindings
- Node.js bindings  
- Rust bindings
- Linux (ubuntu-latest)
- macOS (macos-latest)
