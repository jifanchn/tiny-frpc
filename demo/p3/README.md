# P3 (Three-Process) Demo and Tests

P3 demonstrates the complete STCP data flow with a **real FRPS server** using multiple processes in separate terminal windows.

```
┌─────────┐     ┌──────┐     ┌────────┐
│ Visitor │────▶│ FRPS │◀────│ Server │
└─────────┘     └──────┘     └────────┘
     │                            │
     │      Work Connection       │
     └────────────────────────────┘
```

## Quick Start

### Step 1: Get FRPS Server

**Option A: Download pre-built binary (Recommended)**

```bash
# Run the download script (auto-detects platform)
./demo/p3/common/download_frps.sh

# Or specify version
./demo/p3/common/download_frps.sh 0.62.1
```

**Option B: Build from source (requires Go)**

```bash
make frps-build
```

The FRPS binary will be at `build/frps`.

### Step 2: Build the Project

```bash
make all
make bindings-shared
```

### Step 3: Run Tests

```bash
make p3          # Run all P3 tests (Python + Node.js + Rust)
make p3-python   # Python only
make p3-node     # Node.js only
make p3-rust     # Rust only
```

---

## Interactive Demo (Step-by-Step)

This is the most important example - showing how multiple processes communicate through FRPS.

### Overview

You will open **4 terminal windows**:
1. **Terminal 1**: FRPS server
2. **Terminal 2**: STCP Server (receives messages)
3. **Terminal 3**: Visitor Alice (sends messages)
4. **Terminal 4**: Visitor Bob (sends messages)

### Terminal 1: Start FRPS Server

```bash
cd /path/to/tiny-frpc

# Start the FRPS server
./demo/p3/common/start_frps.sh

# Or manually with custom config:
./build/frps -c frps_demo.toml
```

**Expected Output:**
```
==================================================
  FRPS Server - Three Process Test
==================================================
Bind Port: 7001
Token: test_token
Config: /tmp/frps_demo.xxxxx.toml
==================================================

Starting FRPS...

2024/12/28 16:00:00 [I] frps is running on port 7001
```

**Create `frps_demo.toml` manually (optional):**
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

---

### Terminal 2: Start STCP Server

Choose your language:

<details open>
<summary><b>🐍 Python Server</b></summary>

```bash
cd /path/to/tiny-frpc
python3 demo/p3/python/p3_server.py 127.0.0.1 7001
```

**Expected Output:**
```
Starting STCP Server connecting to 127.0.0.1:7001...
Server started. Waiting for visitors...
Type message and press Enter to send (or 'quit' to exit):
>
```
</details>

<details>
<summary><b>📦 Node.js Server</b></summary>

```bash
cd /path/to/tiny-frpc

# Set library path
export DYLD_LIBRARY_PATH=$PWD/build:$DYLD_LIBRARY_PATH  # macOS
export LD_LIBRARY_PATH=$PWD/build:$LD_LIBRARY_PATH      # Linux

node demo/p3/node/p3_server.js 127.0.0.1 7001
```

**Expected Output:**
```
Starting Node.js STCP Server connecting to 127.0.0.1:7001...
Server started. Waiting for visitors...
Type message and press Enter to send:
>
```
</details>

<details>
<summary><b>🦀 Rust Server</b></summary>

```bash
cd /path/to/tiny-frpc/demo/p3/rust
cargo build
./target/debug/p3_server 127.0.0.1 7001
```

**Expected Output:**
```
Starting Rust STCP Server connecting to 127.0.0.1:7001...
Server started. Waiting for visitors...
Type message and press Enter to send (or 'quit' to exit):
>
```
</details>

---

### Terminal 3: Start Visitor Alice

<details open>
<summary><b>🐍 Python Visitor</b></summary>

```bash
cd /path/to/tiny-frpc
python3 demo/p3/python/p3_visitor.py 127.0.0.1 7001 Alice
```

**Expected Output:**
```
Starting STCP Visitor 'Alice' connecting to 127.0.0.1:7001...
Visitor started.
Type message and press Enter to send (or 'quit' to exit):
>
```
</details>

<details>
<summary><b>📦 Node.js Visitor</b></summary>

```bash
cd /path/to/tiny-frpc
export DYLD_LIBRARY_PATH=$PWD/build:$DYLD_LIBRARY_PATH  # macOS
export LD_LIBRARY_PATH=$PWD/build:$LD_LIBRARY_PATH      # Linux

node demo/p3/node/p3_visitor.js 127.0.0.1 7001 Alice
```
</details>

<details>
<summary><b>🦀 Rust Visitor</b></summary>

```bash
cd /path/to/tiny-frpc/demo/p3/rust
./target/debug/p3_visitor 127.0.0.1 7001 Alice
```
</details>

---

### Terminal 4: Start Visitor Bob

```bash
# Same as Alice, but with different name
python3 demo/p3/python/p3_visitor.py 127.0.0.1 7001 Bob
```

---

### Interact!

Now you have 4 terminals running. Try sending messages:

**In Terminal 3 (Alice), type:**
```
> Hello from Alice!
```

**You should see in Terminal 2 (Server):**
```
[Received] [Alice] Hello from Alice!
>
```

**In Terminal 4 (Bob), type:**
```
> Hello from Bob!
```

**You should see in Terminal 2 (Server):**
```
[Received] [Bob] Hello from Bob!
>
```

**In Terminal 2 (Server), type:**
```
> Server broadcast message!
```

**You should see in Terminal 3 (Alice) and Terminal 4 (Bob):**
```
[Received] [Server] Server broadcast message!
>
```

---

## Directory Structure

```
demo/p3/
├── common/
│   ├── start_frps.sh          # Start FRPS with test config
│   └── download_frps.sh       # Download FRPS binary (NEW!)
├── python/
│   ├── p3_server.py           # Python STCP server
│   ├── p3_visitor.py          # Python STCP visitor
│   └── test_p3.py             # Automated test runner
├── node/
│   ├── p3_server.js           # Node.js STCP server
│   ├── p3_visitor.js          # Node.js STCP visitor
│   └── test_p3.py             # Automated test runner
├── rust/
│   ├── src/bin/
│   │   ├── p3_server.rs       # Rust STCP server
│   │   └── p3_visitor.rs      # Rust STCP visitor
│   ├── test_p3.py             # Automated test runner
│   └── Cargo.toml
└── README.md                  # This file
```

---

## Platform-Specific Setup

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential python3 nodejs npm

# Build
cd /path/to/tiny-frpc
make all bindings-shared

# Get FRPS
./demo/p3/common/download_frps.sh
```

### macOS (Intel & Apple Silicon)

```bash
# Install dependencies (using Homebrew)
brew install python3 node

# Build
cd /path/to/tiny-frpc
make all bindings-shared

# Get FRPS
./demo/p3/common/download_frps.sh
```

### Windows (using MSYS2/MinGW)

```bash
# Install MSYS2 first, then:
pacman -S mingw-w64-x86_64-gcc make python nodejs

# Build
cd /c/path/to/tiny-frpc
make WRAPPER_DIR=wrapper/windows all bindings-shared

# Download FRPS manually from:
# https://github.com/fatedier/frp/releases
# Extract and copy frps.exe to build/
```

---

## Using Pre-built Release

If you're using a pre-built release package:

### Linux/macOS

```bash
# Extract the release
tar -xzf tiny-frpc-linux-x86_64.tar.gz
cd release

# Download FRPS (the script is not included in release, get it manually)
curl -LO https://github.com/fatedier/frp/releases/download/v0.62.1/frp_0.62.1_linux_amd64.tar.gz
tar -xzf frp_0.62.1_linux_amd64.tar.gz
cp frp_0.62.1_linux_amd64/frps ./

# Set library path
export LD_LIBRARY_PATH=$PWD/lib:$LD_LIBRARY_PATH

# Start FRPS
./frps -c frps.toml &

# Run Python example
cd bindings/python
python3 example_stcp_server.py
```

### Windows

```cmd
REM Extract the release ZIP
REM Download FRPS from: https://github.com/fatedier/frp/releases
REM Extract and copy frps.exe to the release folder

cd release
frps.exe -c frps.toml

REM In another terminal:
cd release\bindings\python
python example_stcp_server.py
```

---

## Test Cases

The automated tests (`test_p3.py`) verify:

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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TINY_FRPC_VERBOSE` | Set to `1` for verbose logging |
| `LD_LIBRARY_PATH` | Library search path (Linux) |
| `DYLD_LIBRARY_PATH` | Library search path (macOS) |
| `FRPS_PORT` | FRPS port (default: 7001) |
| `FRPS_TOKEN` | FRPS auth token (default: test_token) |

---

## Troubleshooting

### "Library not found" errors

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

### FRPS not starting

```bash
# Check if port is in use
lsof -i :7001

# Use a different port
FRPS_PORT=17001 ./demo/p3/common/start_frps.sh
```

### Rust build fails

```bash
# Ensure you're in the right directory
cd demo/p3/rust
cargo build

# If library linking fails, set:
export TINY_FRPC_LIB_PATH=/path/to/tiny-frpc/build
```

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
