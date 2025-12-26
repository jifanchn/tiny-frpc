#!/usr/bin/env python3
"""
Example: STCP Visitor using Python FRPC bindings
This example acts as a client (visitor) that connects to a remote STCP service.
"""

import sys
import time
import socket
import threading
from frpc_python import FRPCClient, TunnelType, LogLevel, set_log_callback, cleanup

def log_handler(level, message):
    """Handle log messages from FRPC"""
    level_names = {
        LogLevel.DEBUG: "DEBUG",
        LogLevel.INFO: "INFO", 
        LogLevel.WARN: "WARN",
        LogLevel.ERROR: "ERROR"
    }
    print(f"[{level_names.get(level, 'UNKNOWN')}] {message}")

def on_data_received(data):
    """Handle data received from tunnel"""
    print(f"Visitor received data: {data.decode('utf-8', errors='ignore')}")

def on_connection_changed(connected, error_code):
    """Handle connection status changes"""
    if connected:
        print("Visitor tunnel connected successfully")
    else:
        print(f"Visitor tunnel disconnected (error: {error_code})")

def main():
    # Configuration
    server_addr = "127.0.0.1"
    server_port = 7000
    token = None  # No token for testing; set actual token if frps requires authentication
    
    # STCP Visitor Config
    tunnel_name = "python_stcp_visitor"
    server_name = "python_stcp_server" # Must match the server's tunnel name
    secret_key = "python_secret"       # Must match the server's secret
    bind_addr = "127.0.0.1"
    bind_port = 9090
    
    print("Python FRPC STCP Visitor Example")
    print(f"Connecting to FRP server: {server_addr}:{server_port}")
    print(f"Target Tunnel: {server_name}")
    print(f"Listening on: {bind_addr}:{bind_port}")
    print("Press Ctrl+C to exit\n")
    
    # Set up logging
    set_log_callback(log_handler)
    
    client = None
    tunnel = None
    
    try:
        # Create FRPC client
        client = FRPCClient(server_addr, server_port, token)
        
        # Create STCP visitor tunnel
        # Note: 'data_callback' is optional for visitors. 
        # If you want to intercept data transparently, you can use it,
        # but normally visitors just open a local port (bind_port).
        tunnel = client.create_tunnel(
            TunnelType.STCP_VISITOR,
            tunnel_name,
            secret_key=secret_key,
            remote_name=server_name,
            bind_addr=bind_addr,
            bind_port=bind_port,
            connection_callback=on_connection_changed
        )
        
        # Connect to FRP server
        print("Connecting to FRP server...")
        client.connect()
        
        # Start the tunnel
        print("Starting STCP visitor tunnel...")
        tunnel.start()
        
        print(f"Visitor is running. You can now connect to {bind_addr}:{bind_port}")
        
        # Keep the program running and show stats periodically
        while True:
            time.sleep(5)
            if client.is_connected() and tunnel.is_active():
                stats = tunnel.get_stats()
                print(f"Stats - Sent: {stats['bytes_sent']} bytes, "
                      f"Received: {stats['bytes_received']} bytes, "
                      f"Active connections: {stats['connections_active']}")
            else:
                print("Warning: Client disconnected or tunnel inactive")
                
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Cleanup
        if tunnel:
            tunnel.close()
        if client:
            client.close()
        cleanup()
        print("Cleanup completed")

if __name__ == "__main__":
    main()
