## demo/stcp

This directory contains a Linux/POSIX demo that uses `wrapper/linux` + `tiny-frpc` STCP API to exchange data
over TCP connections.

### Components

- `mock_frps.c` - A minimal FRP server mock for local testing
- `stcp_server.c` - STCP server-side demo
- `stcp_visitor.c` - STCP visitor-side demo
- `local_client.c` - Local TCP client for testing

### Message Types Reference

FRP message types used in mock_frps.c (source: `third-party/frp/pkg/msg/msg.go`):

| Type | Char | Description          |
|------|------|----------------------|
| 'o'  | o    | Login                |
| '1'  | 1    | LoginResp            |
| 'p'  | p    | NewProxy             |
| '2'  | 2    | NewProxyResp         |
| 'v'  | v    | NewVisitorConn       |
| '3'  | 3    | NewVisitorConnResp   |
| 'h'  | h    | Ping                 |
| '4'  | 4    | Pong                 |

**Note**: TypePong is '4' (ASCII 52), NOT 'i' (which is TypeNatHoleVisitor).

### Build

Use Makefile targets:
- `make demo-stcp`
- `make demo-stcp-run` (runs a few handshake cycles on localhost; default 3 cycles)

### Manual run (3 terminals)

Notes:
- `make demo-stcp-run` uses ports **17001** (mock frps) and **19001** (data-plane) to avoid conflicts with `cmd/frpc_test` defaults.
- You can use the same ports manually, or keep the default ports shown below.
- `demo_stcp_server` has an `--accept-timeout-sec` option (default 10) to avoid waiting forever when launched alone.

Terminal 1:

`./build/demo_stcp_frps --listen-addr 127.0.0.1 --listen-port 7001 --run-id demo_run`

Terminal 2:

`./build/demo_stcp_server --frps-addr 127.0.0.1 --frps-port 7001 --listen-addr 127.0.0.1 --listen-port 9001 --proxy-name demo_stcp --sk demo_secret -v`

Terminal 3 (once mode):

`./build/demo_stcp_visitor --frps-addr 127.0.0.1 --frps-port 7001 --connect-addr 127.0.0.1 --connect-port 9001 --server-name demo_stcp --proxy-name demo_stcp_visitor --sk demo_secret --mode once --message "hello" -v`

### Local forward example

Terminal 3 (local-forward mode):

`./build/demo_stcp_visitor --frps-addr 127.0.0.1 --frps-port 7001 --connect-addr 127.0.0.1 --connect-port 9001 --server-name demo_stcp --proxy-name demo_stcp_visitor --sk demo_secret --mode local-forward --bind-addr 127.0.0.1 --bind-port 6000 -v`

Then in another terminal:

`./build/demo_stcp_local_client --connect-addr 127.0.0.1 --connect-port 6000 --message "hello from local client\n"`

### Stress Testing

A stress test tool is included to verify stability and measure performance:

```bash
# Quick stress test (30 seconds)
make demo-stcp-stress

# Or run manually for more control:
# Terminal 1: Mock FRPS
./build/demo_stcp_frps --listen-port 17001

# Terminal 2: Stress Server
./build/demo_stcp_stress --mode server --frps-port 17001 --data-port 19001 -vvv

# Terminal 3: Stress Visitor
./build/demo_stcp_stress --mode visitor --frps-port 17001 --data-port 19001 \
    --duration 60 --interval 10 --min-payload 256 --max-payload 2048 -vvv
```

#### Stress Test Options

- `-v` : Show connection info
- `-vv` : Show message info  
- `-vvv` : Show all packets (raw data, payloads)
- `--json` : Output final stats as JSON (for automation)
- `--duration N` : Test duration in seconds (default: 30)
- `--interval N` : Message interval in ms (default: 100)
- `--min-payload N` : Minimum payload size (default: 64)
- `--max-payload N` : Maximum payload size (default: 1024)

#### Multi-Channel Stress Test

Run multiple parallel visitor-server pairs for higher load:

```bash
# 4 channels, 30 seconds each
make demo-stcp-stress-multi

# Custom: 8 channels, 60 seconds, 20ms interval
DEMO_STCP_STRESS_CHANNELS=8 DEMO_STCP_STRESS_DURATION=60 DEMO_STCP_STRESS_INTERVAL=20 make demo-stcp-stress-multi

# Or use the script directly:
./demo/stcp/multi_stress.sh 8 60 20 128 1024
```

#### Expected Performance

Single channel on localhost with mock FRPS:
- ~85 msg/s at 10ms interval
- ~98 KB/s throughput with 256-2048 byte payloads
- ~0.3ms average latency
- Zero errors over 60+ second runs

Multi-channel (8 channels):
- ~340 msg/s aggregate
- ~200 KB/s aggregate throughput
- Zero errors over 60+ second runs

#### Latency Histogram

Final stats include a latency distribution:
```
  Latency histogram:
    <=   1ms:    598 ( 97.6%)
    <=   2ms:      4 (  0.7%)
    <=   5ms:      5 (  0.8%)
    <=  10ms:      4 (  0.7%)
    <=  20ms:      2 (  0.3%)
```

#### JSON Output

For automation, use `--json` flag:
```bash
./build/demo_stcp_stress --mode visitor ... --json 2>&1 | grep "^{" | jq .
```

Output format:
```json
{
  "role": "visitor",
  "duration_sec": 10.0,
  "messages_sent": 100,
  "messages_recv": 100,
  "bytes_sent": 30000,
  "bytes_recv": 29000,
  "msg_rate": 10.0,
  "bytes_rate": 3000.0,
  "errors": 0,
  "latency_avg_ms": 0.5,
  "latency_min_ms": 0.1,
  "latency_max_ms": 2.0
}
```

### Testing with CGO

For full end-to-end testing with real FRP protocol alignment, use:

```bash
make frpc-test
```

This runs CGO interop tests that use the upstream Go FRP implementation as the reference.
