#!/usr/bin/env python3
"""
Example: STCP Server using Python FRPC bindings
This example creates an STCP server that forwards connections to a local service.
"""

import sys
import time
import signal
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
    print(f"Server received data: {data.decode('utf-8', errors='ignore')}")

def on_connection_changed(connected, error_code):
    """Handle connection status changes"""
    if connected:
        print("Server tunnel connected successfully")
    else:
        print(f"Server tunnel disconnected (error: {error_code})")

def main():
    # Configuration
    server_addr = "127.0.0.1"
    server_port = 7000
    token = "test_token"
    tunnel_name = "python_stcp_server"
    secret_key = "python_secret"
    local_addr = "127.0.0.1"
    local_port = 8080
    
    print("Python FRPC STCP Server Example")
    print(f"Connecting to FRP server: {server_addr}:{server_port}")
    print(f"Tunnel: {tunnel_name}")
    print(f"Local service: {local_addr}:{local_port}")
    print("Press Ctrl+C to exit\n")
    
    # Set up logging
    set_log_callback(log_handler)
    
    client = None
    tunnel = None
    
    try:
        # Create FRPC client
        client = FRPCClient(server_addr, server_port, token)
        
        # Create STCP server tunnel
        tunnel = client.create_tunnel(
            TunnelType.STCP_SERVER,
            tunnel_name,
            secret_key=secret_key,
            local_addr=local_addr,
            local_port=local_port,
            data_callback=on_data_received,
            connection_callback=on_connection_changed
        )
        
        # Connect to FRP server
        print("Connecting to FRP server...")
        client.connect()
        
        # Start the tunnel
        print("Starting STCP server tunnel...")
        tunnel.start()
        
        print("STCP server is running. Waiting for connections...")
        
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