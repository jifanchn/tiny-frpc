#!/usr/bin/env python3
"""
End-to-End tests for Python bindings using mock FRPS server.

This test:
1. Starts a mock FRPS server (demo_stcp_frps)
2. Creates STCP server and visitor tunnels
3. Verifies tunnel creation and basic data flow
4. Cleans up all resources

Usage:
  python3 test_e2e.py [--frps-path /path/to/demo_stcp_frps]
"""

import argparse
import os
import socket
import subprocess
import sys
import time

# Add parent directory to path for importing frpc_python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from frpc_python import FRPCClient, TunnelType, LogLevel, set_log_callback, cleanup


def find_free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait for a port to become available."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.1)
    return False


class FRPSServer:
    """Manages a mock FRPS server process (demo_stcp_frps)."""

    def __init__(self, frps_path: str, bind_port: int):
        self.frps_path = frps_path
        self.bind_port = bind_port
        self.process = None

    def start(self) -> bool:
        """Start the mock FRPS server."""
        self.process = subprocess.Popen(
            [
                self.frps_path,
                "--listen-addr", "127.0.0.1",
                "--listen-port", str(self.bind_port),
                "--run-id", "e2e_test_run",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if not wait_for_port("127.0.0.1", self.bind_port, timeout=10.0):
            self.stop()
            return False
        
        print(f"Mock FRPS started on port {self.bind_port}")
        return True

    def stop(self):
        """Stop the FRPS server."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None


def log_handler(level, message):
    """Handle log messages from FRPC (verbose mode)."""
    level_names = {
        LogLevel.DEBUG: "DEBUG",
        LogLevel.INFO: "INFO",
        LogLevel.WARN: "WARN",
        LogLevel.ERROR: "ERROR",
    }
    verbose = os.environ.get("VERBOSE", "0") == "1"
    if verbose:
        print(f"[FRPC {level_names.get(level, 'UNKNOWN')}] {message}")


def test_stcp_e2e(frps: FRPSServer) -> bool:
    """
    Test STCP tunnel end-to-end.
    
    Verifies:
    1. Connection to FRPS
    2. STCP server tunnel creation and registration
    3. STCP visitor tunnel creation and registration
    4. Data sending (bytes_sent increases)
    5. Proper cleanup
    """
    print("\n=== Testing STCP E2E ===")
    
    set_log_callback(log_handler)
    
    server_client = None
    visitor_client = None
    server_tunnel = None
    visitor_tunnel = None
    
    try:
        # === Create STCP Server ===
        print("Creating STCP server tunnel...")
        server_client = FRPCClient("127.0.0.1", frps.bind_port, None)
        
        server_tunnel = server_client.create_tunnel(
            TunnelType.STCP_SERVER,
            "e2e_stcp_server",
            secret_key="e2e_secret",
            local_addr="127.0.0.1",
            local_port=8080,
        )
        
        print("Connecting server to FRPS...")
        server_client.connect()
        assert server_client.is_connected(), "Server should be connected"
        print("✓ Server connected to FRPS")
        
        print("Starting server tunnel...")
        server_tunnel.start()
        time.sleep(0.3)
        assert server_tunnel.is_active(), "Server tunnel should be active"
        print("✓ Server tunnel started and registered")
        
        # === Create STCP Visitor ===
        print("\nCreating STCP visitor tunnel...")
        visitor_client = FRPCClient("127.0.0.1", frps.bind_port, None)
        
        visitor_tunnel = visitor_client.create_tunnel(
            TunnelType.STCP_VISITOR,
            "e2e_stcp_visitor",
            secret_key="e2e_secret",
            remote_name="e2e_stcp_server",
            bind_addr="127.0.0.1",
            bind_port=find_free_port(),
        )
        
        print("Connecting visitor to FRPS...")
        visitor_client.connect()
        assert visitor_client.is_connected(), "Visitor should be connected"
        print("✓ Visitor connected to FRPS")
        
        print("Starting visitor tunnel...")
        visitor_tunnel.start()
        time.sleep(0.3)
        assert visitor_tunnel.is_active(), "Visitor tunnel should be active"
        print("✓ Visitor tunnel started")
        
        # === Test Data Send ===
        print("\nTesting data send...")
        test_message = b"Hello from E2E test!"
        sent = visitor_tunnel.send_data(test_message)
        print(f"Sent {sent} bytes via send_data")
        
        time.sleep(0.5)
        
        # Verify stats
        visitor_stats = visitor_tunnel.get_stats()
        print(f"Visitor stats: {visitor_stats}")
        
        # Verify bytes were sent
        assert visitor_stats['bytes_sent'] > 0, "Visitor should have sent bytes"
        print(f"✓ Data sent successfully ({visitor_stats['bytes_sent']} bytes)")
        
        # === Verify connection counts ===
        server_stats = server_tunnel.get_stats()
        print(f"Server stats: {server_stats}")
        
        assert server_stats['connections_total'] >= 1, "Server should have at least 1 connection"
        assert visitor_stats['connections_total'] >= 1, "Visitor should have at least 1 connection"
        print("✓ Connection counts verified")
        
        print("\n=== STCP E2E test PASSED! ===")
        return True
        
    except AssertionError as e:
        print(f"\n✗ STCP E2E test FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n✗ STCP E2E test FAILED with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        for tunnel in [visitor_tunnel, server_tunnel]:
            if tunnel:
                try:
                    tunnel.stop()
                    tunnel.close()
                except Exception:
                    pass
        for client in [visitor_client, server_client]:
            if client:
                try:
                    client.close()
                except Exception:
                    pass


def main():
    parser = argparse.ArgumentParser(description="E2E tests for Python FRPC bindings")
    parser.add_argument(
        "--frps-path",
        default=os.path.join(
            os.path.dirname(__file__), "..", "..", "build", "demo_stcp_frps"
        ),
        help="Path to demo_stcp_frps (mock FRPS) binary",
    )
    args = parser.parse_args()
    
    frps_path = os.path.abspath(args.frps_path)
    
    if not os.path.exists(frps_path):
        print(f"ERROR: demo_stcp_frps binary not found at {frps_path}")
        print("Build it with: make demo-stcp")
        return 1
    
    print(f"Using mock frps: {frps_path}")
    
    frps_port = find_free_port()
    frps = FRPSServer(frps_path, frps_port)
    
    try:
        if not frps.start():
            print("ERROR: Failed to start mock FRPS")
            return 1
        
        success = test_stcp_e2e(frps)
        
        return 0 if success else 1
            
    finally:
        cleanup()
        frps.stop()
        print("Cleanup completed")


if __name__ == "__main__":
    sys.exit(main())
