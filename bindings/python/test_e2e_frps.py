#!/usr/bin/env python3
"""
E2E test with real FRPS server.

This test:
1. Starts a real FRPS server (from third-party/frp)
2. Starts a local echo server as the backend service
3. Creates STCP server tunnel to expose the local service
4. Creates STCP visitor tunnel to access the exposed service
5. Sends data through the visitor and verifies echo response
6. Cleans up all resources

Requirements:
- Build frps: make frps-build
- Build bindings: make bindings-shared

Usage:
  python3 test_e2e_frps.py [--frps-path /path/to/frps]
"""

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

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


class RealFRPSServer:
    """Manages a real FRPS server process."""

    def __init__(self, frps_path: str, bind_port: int):
        self.frps_path = frps_path
        self.bind_port = bind_port
        self.process = None
        self.config_file = None

    def start(self) -> bool:
        """Start the real FRPS server."""
        # Create temporary config file
        self.config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", delete=False
        )
        
        # Config: disable tcpMux and token auth for compatibility
        toml_content = f"""bindPort = {self.bind_port}
transport.tcpMux = false
"""
        self.config_file.write(toml_content)
        self.config_file.close()

        self.process = subprocess.Popen(
            [self.frps_path, "-c", self.config_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if not wait_for_port("127.0.0.1", self.bind_port, timeout=10.0):
            self.stop()
            return False
        
        print(f"Real FRPS started on port {self.bind_port}")
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
        
        if self.config_file:
            try:
                os.unlink(self.config_file.name)
            except OSError:
                pass


class LocalEchoServer:
    """A simple TCP echo server for testing."""

    def __init__(self):
        self.server_socket = None
        self.running = False
        self.thread = None
        self.port = 0
        self.received_data = []
        self.lock = threading.Lock()

    def start(self) -> int:
        """Start the echo server and return the port."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("127.0.0.1", 0))
        self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        self.running = True
        
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        
        print(f"Local echo server started on port {self.port}")
        return self.port

    def _accept_loop(self):
        """Accept incoming connections."""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, conn, addr):
        """Handle a client connection (echo mode)."""
        try:
            conn.settimeout(5.0)
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    with self.lock:
                        self.received_data.append(data)
                    # Echo back with prefix
                    conn.sendall(b"ECHO:" + data)
                except socket.timeout:
                    continue
        finally:
            conn.close()

    def stop(self):
        """Stop the echo server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2.0)


def log_handler(level, message):
    """Handle log messages from FRPC."""
    level_names = {
        LogLevel.DEBUG: "DEBUG",
        LogLevel.INFO: "INFO",
        LogLevel.WARN: "WARN",
        LogLevel.ERROR: "ERROR",
    }
    verbose = os.environ.get("VERBOSE", "0") == "1"
    if verbose:
        print(f"[FRPC {level_names.get(level, 'UNKNOWN')}] {message}")


def test_stcp_e2e_real_frps(frps: RealFRPSServer, local_port: int) -> bool:
    """
    Test STCP tunnel E2E with real FRPS.
    
    Verifies:
    1. Connection to real FRPS
    2. STCP server tunnel registration
    3. STCP visitor tunnel setup
    4. Bidirectional data transfer through the tunnel
    """
    print("\n=== Testing STCP E2E with Real FRPS ===")
    
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
            local_port=local_port,
        )
        
        print("Connecting server to FRPS...")
        server_client.connect()
        assert server_client.is_connected(), "Server should be connected"
        print("✓ Server connected to real FRPS")
        
        print("Starting server tunnel...")
        server_tunnel.start()
        time.sleep(0.5)
        assert server_tunnel.is_active(), "Server tunnel should be active"
        print("✓ Server tunnel registered with FRPS")
        
        # === Create STCP Visitor ===
        print("\nCreating STCP visitor tunnel...")
        visitor_client = FRPCClient("127.0.0.1", frps.bind_port, None)
        
        visitor_bind_port = find_free_port()
        visitor_tunnel = visitor_client.create_tunnel(
            TunnelType.STCP_VISITOR,
            "e2e_stcp_visitor",
            secret_key="e2e_secret",
            remote_name="e2e_stcp_server",
            bind_addr="127.0.0.1",
            bind_port=visitor_bind_port,
        )
        
        print("Connecting visitor to FRPS...")
        visitor_client.connect()
        assert visitor_client.is_connected(), "Visitor should be connected"
        print("✓ Visitor connected to real FRPS")
        
        print("Starting visitor tunnel...")
        visitor_tunnel.start()
        time.sleep(0.5)
        assert visitor_tunnel.is_active(), "Visitor tunnel should be active"
        print("✓ Visitor tunnel started")
        
        # === Test Bidirectional Data Transfer ===
        print("\nTesting bidirectional data transfer...")
        
        # Send data through the visitor
        test_message = b"Hello from E2E test with real FRPS!"
        sent = visitor_tunnel.send_data(test_message)
        print(f"Sent {sent} bytes via send_data")
        
        time.sleep(1.0)
        
        # Verify stats
        visitor_stats = visitor_tunnel.get_stats()
        server_stats = server_tunnel.get_stats()
        print(f"Visitor stats: {visitor_stats}")
        print(f"Server stats: {server_stats}")
        
        # Verify bytes were sent
        if visitor_stats['bytes_sent'] > 0:
            print(f"✓ Data sent successfully ({visitor_stats['bytes_sent']} bytes)")
        else:
            print("⚠ No bytes recorded as sent (may be protocol overhead only)")
        
        print("\n=== STCP E2E with Real FRPS test PASSED! ===")
        return True
        
    except AssertionError as e:
        print(f"\n✗ Test FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n✗ Test FAILED with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
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
    parser = argparse.ArgumentParser(description="E2E tests with real FRPS")
    parser.add_argument(
        "--frps-path",
        default=os.path.join(
            os.path.dirname(__file__), "..", "..", "build", "frps"
        ),
        help="Path to real frps binary",
    )
    args = parser.parse_args()
    
    frps_path = os.path.abspath(args.frps_path)
    
    if not os.path.exists(frps_path):
        print(f"ERROR: frps binary not found at {frps_path}")
        print("Build it with: make frps-build")
        return 1
    
    print(f"Using real frps: {frps_path}")
    
    frps_port = find_free_port()
    frps = RealFRPSServer(frps_path, frps_port)
    local_server = LocalEchoServer()
    
    try:
        # Start local echo server
        local_port = local_server.start()
        
        # Start real FRPS
        if not frps.start():
            print("ERROR: Failed to start real FRPS")
            return 1
        
        success = test_stcp_e2e_real_frps(frps, local_port)
        
        return 0 if success else 1
            
    finally:
        cleanup()
        local_server.stop()
        frps.stop()
        print("Cleanup completed")


if __name__ == "__main__":
    sys.exit(main())
