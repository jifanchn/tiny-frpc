## demo/stcp

This directory contains a Linux/POSIX demo that uses `wrapper/linux` + `tiny-frpc` STCP API to exchange data
over a direct TCP "work" connection.

Notes:
- This is **not** a full FRP E2E demo yet. Current `tiny-frpc/source/frpc-stcp.c` still has placeholder control-plane messages.
- A minimal mock `frps` is provided to satisfy `frpc_client_connect()` (Login/LoginResp only).

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


