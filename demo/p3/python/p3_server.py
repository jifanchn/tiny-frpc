#!/usr/bin/env python3
import sys
import os
import threading
import time

# Find frpc_python module:
# 1. First try current directory (for release package)
# 2. Then try bindings/python (for development)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Release package: demo/p3/python contains libfrpc-bindings.so directly
sys.path.insert(0, SCRIPT_DIR)
# Development: ../../../bindings/python
sys.path.insert(0, os.path.join(SCRIPT_DIR, '../../../bindings/python'))
# Also set library path for current directory
if sys.platform == 'darwin':
    os.environ['DYLD_LIBRARY_PATH'] = SCRIPT_DIR + ':' + os.environ.get('DYLD_LIBRARY_PATH', '')
else:
    os.environ['LD_LIBRARY_PATH'] = SCRIPT_DIR + ':' + os.environ.get('LD_LIBRARY_PATH', '')

from frpc_python import FRPCClient, TunnelType

def on_data(data):
    msg = data.decode('utf-8', errors='replace').strip()
    print(f"\n[Received] {msg}")
    print("> ", end="", flush=True)

def on_connection(connected, error):
    status = "Connected" if connected else "Disconnected"
    print(f"\n[Status] {status} (error: {error})")
    print("> ", end="", flush=True)

def input_loop(tunnel):
    print("Type message and press Enter to send (or 'quit' to exit):")
    print("> ", end="", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == 'quit':
            return
        if line:
            # Format: [Server] <msg>
            msg = f"[Server] {line}"
            tunnel.send_data(msg.encode('utf-8'))
        print("> ", end="", flush=True)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <server_addr> <server_port>")
        sys.exit(1)
        
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print(f"Starting STCP Server connecting to {host}:{port}...")
    
    # Enable verbose logging for debug
    os.environ["TINY_FRPC_VERBOSE"] = "1"
    
    client = FRPCClient(host, port, "test_token", use_encryption=True)
    tunnel = client.create_tunnel(
        TunnelType.STCP_SERVER,
        "p3_test_stcp",
        secret_key="p3_test_secret",
        local_addr="127.0.0.1",
        local_port=0,
        data_callback=on_data,
        connection_callback=on_connection
    )
    
    # Fix: connect() likely returns None on success, don't check validity with `not`
    ret = client.connect()
    print(f"connect() returned: {ret}")
    if ret is False: 
        print("Failed to connect to FRPS")
        sys.exit(1)
        
    tunnel.start()
    print("Server started. Waiting for visitors...")
    
    try:
        input_loop(tunnel)
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
