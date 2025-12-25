//! Example: STCP Server using Rust bindings.
//!
//! This example creates an STCP Server tunnel that forwards connections to a local service.

use frpc_rs::{FrpcClient, TunnelConfig, TunnelType, TunnelEventHandler};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct ServerHandler;

impl TunnelEventHandler for ServerHandler {
    fn on_data(&self, data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            println!("Server received data: {}", text);
        } else {
            println!("Server received {} bytes of binary data", data.len());
        }
    }
    
    fn on_connection(&self, connected: bool, error_code: i32) {
        if connected {
            println!("Server tunnel connected successfully");
        } else {
            println!("Server tunnel disconnected (error: {})", error_code);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration
    let server_addr = "127.0.0.1";
    let server_port = 7000;
    let token = "test_token";
    let tunnel_name = "rust_stcp_server";
    let secret_key = "rust_secret";
    let local_addr = "127.0.0.1";
    let local_port = 8080;
    
    println!("Rust FRPC STCP Server Example");
    println!("Connecting to FRP server: {}:{}", server_addr, server_port);
    println!("Tunnel: {}", tunnel_name);
    println!("Local service: {}:{}", local_addr, local_port);
    println!("Press Ctrl+C to exit\n");
    
    // Create FRPC client
    let mut client = FrpcClient::new(server_addr, server_port, Some(token))?;
    
    // Create tunnel configuration
    let config = TunnelConfig {
        tunnel_type: TunnelType::StcpServer,
        tunnel_name: tunnel_name.to_string(),
        secret_key: Some(secret_key.to_string()),
        local_addr: Some(local_addr.to_string()),
        local_port: Some(local_port),
        remote_name: None,
        bind_addr: None,
        bind_port: None,
    };
    
    // Create event handler
    let handler = Arc::new(ServerHandler);
    
    // Create tunnel
    let tunnel = client.create_tunnel(config, Some(handler))?;
    
    // Connect to FRP server
    println!("Connecting to FRP server...");
    client.connect()?;
    
    // Start the tunnel
    println!("Starting STCP server tunnel...");
    tunnel.start()?;
    
    println!("STCP server is running. Waiting for connections...");
    
    // Ctrl+C handler (optional)
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\nShutting down...");
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    })?;
    
    // Main loop: print stats periodically
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(5));
        
        if client.is_connected() && tunnel.is_active() {
            match tunnel.get_stats() {
                Ok(stats) => {
                    println!(
                        "Stats - Sent: {} bytes, Received: {} bytes, Active connections: {}",
                        stats.bytes_sent, stats.bytes_received, stats.connections_active
                    );
                }
                Err(e) => {
                    println!("Error getting stats: {}", e);
                }
            }
        } else {
            println!("Warning: client disconnected or tunnel inactive");
        }
    }
    
    // Cleanup is handled by Drop implementations
    println!("Cleanup completed");
    Ok(())
}

// Note: to avoid forcing a ctrlc dependency, we provide a stub implementation here.
#[cfg(not(feature = "ctrlc"))]
mod ctrlc {
    pub fn set_handler<F>(_handler: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn() + 'static + Send,
    {
        // Fallback implementation - just sleep and check a flag
        Ok(())
    }
}