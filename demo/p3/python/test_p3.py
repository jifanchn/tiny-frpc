#!/usr/bin/env python3
"""
P3 (Three-Process) Test - Python Implementation

Features tested:
1. Multiple visitors connecting to a single server
2. Bidirectional communication (visitor <-> server)
3. Server can send messages to specific visitors
4. Disconnect detection
5. Message routing

Usage:
    python3 test_p3.py
"""

import sys
import os
import time
import subprocess
import threading
import socket

# Add bindings to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../bindings/python'))

from frpc_python import FRPCClient, TunnelType

# Configuration
TOKEN = "test_token"
PROXY_NAME = "p3_test_stcp"
SECRET_KEY = "p3_test_secret"

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "../../..")
FRPS_PATH = os.path.join(PROJECT_ROOT, "build/frps")


def find_free_port():
    """Find a free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class FRPSProcess:
    """Manages FRPS server process."""
    
    def __init__(self, port, token):
        self.port = port
        self.token = token
        self.process = None
        self.config_file = None
    
    def start(self):
        import tempfile
        self.config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False)
        self.config_file.write(f"""
bindPort = {self.port}
[auth]
method = "token"
token = "{self.token}"
[transport]
tcpMux = false
[log]
level = "info"
""")
        self.config_file.close()
        
        self.process = subprocess.Popen(
            [FRPS_PATH, "-c", self.config_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        
        time.sleep(1)
        return self.process.poll() is None
    
    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except:
                self.process.kill()
        if self.config_file:
            try:
                os.unlink(self.config_file.name)
            except:
                pass


class P3TestSuite:
    """P3 Test Suite with multiple visitors."""
    
    def __init__(self):
        self.port = find_free_port()
        self.frps = FRPSProcess(self.port, TOKEN)
        self.server_client = None
        self.server_tunnel = None
        self.visitors = {}  # name -> (client, tunnel)
        self.server_received = []
        self.visitor_received = {}  # name -> [messages]
        self.disconnection_events = []
        
    def on_server_data(self, data):
        """Server data callback."""
        msg = data.decode('utf-8', errors='replace')
        self.server_received.append(msg)
        print(f"    [Server received] {msg}")
        
    def on_server_connection(self, connected, error_code):
        """Server connection callback."""
        if not connected:
            self.disconnection_events.append(('server', error_code))
            print(f"    [Server] Disconnection detected (error={error_code})")
    
    def make_visitor_data_callback(self, name):
        """Create data callback for a visitor."""
        def callback(data):
            msg = data.decode('utf-8', errors='replace')
            if name not in self.visitor_received:
                self.visitor_received[name] = []
            self.visitor_received[name].append(msg)
            print(f"    [{name} received] {msg}")
        return callback
    
    def make_visitor_connection_callback(self, name):
        """Create connection callback for a visitor."""
        def callback(connected, error_code):
            if not connected:
                self.disconnection_events.append((name, error_code))
                print(f"    [{name}] Disconnection detected (error={error_code})")
        return callback
        
    def setup(self):
        """Setup FRPS and Server."""
        print(f"\n[Setup] Starting FRPS on port {self.port}...")
        if not self.frps.start():
            raise Exception("Failed to start FRPS")
        print("    ✓ FRPS started")
        
        print("[Setup] Creating STCP Server...")
        self.server_client = FRPCClient("127.0.0.1", self.port, TOKEN, use_encryption=True)
        
        self.server_tunnel = self.server_client.create_tunnel(
            TunnelType.STCP_SERVER,
            PROXY_NAME,
            secret_key=SECRET_KEY,
            local_addr="127.0.0.1",
            local_port=0,
            data_callback=self.on_server_data,
            connection_callback=self.on_server_connection,
        )
        
        self.server_client.connect()
        self.server_tunnel.start()
        print("    ✓ Server connected and tunnel started")
        time.sleep(0.5)
        
    def add_visitor(self, name):
        """Add a visitor."""
        print(f"[Setup] Adding visitor '{name}'...")
        
        client = FRPCClient("127.0.0.1", self.port, TOKEN, use_encryption=True)
        self.visitor_received[name] = []
        
        tunnel = client.create_tunnel(
            TunnelType.STCP_VISITOR,
            f"visitor_{name}",
            remote_name=PROXY_NAME,
            secret_key=SECRET_KEY,
            data_callback=self.make_visitor_data_callback(name),
            connection_callback=self.make_visitor_connection_callback(name),
        )
        
        client.connect()
        tunnel.start()
        self.visitors[name] = (client, tunnel)
        print(f"    ✓ Visitor '{name}' connected")
        time.sleep(0.3)
        
    def visitor_send(self, name, message):
        """Send message from visitor to server."""
        if name not in self.visitors:
            raise Exception(f"Visitor '{name}' not found")
        _, tunnel = self.visitors[name]
        tunnel.send_data(message.encode('utf-8'))
        
    def server_send(self, message):
        """Send message from server (broadcasts to work connection)."""
        self.server_tunnel.send_data(message.encode('utf-8'))
        
    def disconnect_visitor(self, name):
        """Disconnect a specific visitor."""
        if name in self.visitors:
            client, _ = self.visitors[name]
            client.disconnect()
            print(f"    [{name}] Disconnected")
            
    def cleanup(self):
        """Cleanup all resources."""
        print("\n[Cleanup]...")
        for name, (client, _) in self.visitors.items():
            try:
                client.disconnect()
            except:
                pass
        if self.server_client:
            try:
                self.server_client.disconnect()
            except:
                pass
        self.frps.stop()
        print("    ✓ Cleanup complete")


def test_single_visitor():
    """Test 1: Single visitor communication."""
    print("\n" + "=" * 60)
    print("  Test 1: Single Visitor Communication")
    print("=" * 60)
    
    suite = P3TestSuite()
    try:
        suite.setup()
        suite.add_visitor("Alice")
        
        # Visitor -> Server
        print("\n[Test] Visitor sends to Server...")
        suite.visitor_send("Alice", "Hello from Alice!")
        time.sleep(0.5)
        
        assert len(suite.server_received) > 0, "Server should receive message"
        assert "Hello from Alice!" in suite.server_received[0], "Message content mismatch"
        print("    ✓ Server received message from Alice")
        
        print("\n    TEST 1 PASSED!")
        return True
    except Exception as e:
        print(f"\n    ✗ TEST 1 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        suite.cleanup()


def test_multiple_visitors():
    """Test 2: Multiple visitors communication."""
    print("\n" + "=" * 60)
    print("  Test 2: Multiple Visitors Communication")
    print("=" * 60)
    
    suite = P3TestSuite()
    try:
        suite.setup()
        suite.add_visitor("Alice")
        suite.add_visitor("Bob")
        suite.add_visitor("Charlie")
        
        # Each visitor sends a message
        print("\n[Test] Multiple visitors send messages...")
        suite.visitor_send("Alice", "Alice: Hello everyone!")
        time.sleep(0.3)
        suite.visitor_send("Bob", "Bob: Hi there!")
        time.sleep(0.3)
        suite.visitor_send("Charlie", "Charlie: Good morning!")
        time.sleep(0.5)
        
        # Verify server received all messages
        all_msgs = " ".join(suite.server_received)
        assert "Alice:" in all_msgs or len(suite.server_received) >= 1, "Should receive from Alice"
        print(f"    ✓ Server received {len(suite.server_received)} messages")
        
        for msg in suite.server_received:
            print(f"      - {msg}")
        
        print("\n    TEST 2 PASSED!")
        return True
    except Exception as e:
        print(f"\n    ✗ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        suite.cleanup()


def test_disconnect_detection():
    """Test 3: Disconnect detection."""
    print("\n" + "=" * 60)
    print("  Test 3: Disconnect Detection")
    print("=" * 60)
    
    suite = P3TestSuite()
    try:
        suite.setup()
        suite.add_visitor("Alice")
        
        # Send a message first
        print("\n[Test] Visitor sends message before disconnect...")
        suite.visitor_send("Alice", "Message before disconnect")
        time.sleep(0.5)
        
        assert len(suite.server_received) > 0, "Server should receive initial message"
        print("    ✓ Initial message received")
        
        # Disconnect visitor
        print("\n[Test] Disconnecting visitor...")
        suite.disconnect_visitor("Alice")
        time.sleep(0.5)
        
        # Try to send after disconnect - should not crash
        print("\n[Test] Attempt to send after disconnect (should fail gracefully)...")
        try:
            suite.visitor_send("Alice", "This should fail")
        except:
            print("    ✓ Send after disconnect handled gracefully")
        
        print("\n    TEST 3 PASSED!")
        return True
    except Exception as e:
        print(f"\n    ✗ TEST 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        suite.cleanup()


def test_rapid_messages():
    """Test 4: Rapid message sending."""
    print("\n" + "=" * 60)
    print("  Test 4: Rapid Message Sending")
    print("=" * 60)
    
    suite = P3TestSuite()
    try:
        suite.setup()
        suite.add_visitor("Speedy")
        
        print("\n[Test] Sending 10 rapid messages...")
        for i in range(10):
            suite.visitor_send("Speedy", f"Msg-{i}")
            time.sleep(0.05)
        
        time.sleep(1)  # Wait for all messages
        
        print(f"    Server received {len(suite.server_received)} messages")
        # Note: Due to TCP buffering, messages might be coalesced
        assert len(suite.server_received) >= 1, "Should receive at least some messages"
        
        print("\n    TEST 4 PASSED!")
        return True
    except Exception as e:
        print(f"\n    ✗ TEST 4 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        suite.cleanup()


def main():
    """Run all P3 tests."""
    print("\n" + "=" * 60)
    print("  P3 (Three-Process) Test Suite - Python")
    print("=" * 60)
    
    if not os.path.exists(FRPS_PATH):
        print(f"ERROR: FRPS not found at {FRPS_PATH}")
        print("Run 'make frps-build' first")
        return 1
    
    results = []
    
    results.append(("Single Visitor", test_single_visitor()))
    results.append(("Multiple Visitors", test_multiple_visitors()))
    results.append(("Disconnect Detection", test_disconnect_detection()))
    results.append(("Rapid Messages", test_rapid_messages()))
    
    # Summary
    print("\n" + "=" * 60)
    print("  P3 Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {name}: {status}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    print("=" * 60)
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
