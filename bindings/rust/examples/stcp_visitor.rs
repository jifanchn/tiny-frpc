//! Example: STCP Visitor using Rust FRPC bindings
//!
//! This example is intentionally minimal and non-blocking.
//! It demonstrates creating a client and a visitor tunnel, then exits.

use frpc_rs::{FrpcClient, TunnelConfig, TunnelType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1";
    let server_port = 7000;
    let token = "test_token";

    let tunnel_name = "rust_stcp_visitor";
    let secret_key = "rust_secret";
    let remote_name = "remote_server";
    let bind_addr = "127.0.0.1";
    let bind_port = 9090;

    let client = FrpcClient::new(server_addr, server_port, Some(token))?;

    let config = TunnelConfig {
        tunnel_type: TunnelType::StcpVisitor,
        tunnel_name: tunnel_name.to_string(),
        secret_key: Some(secret_key.to_string()),
        local_addr: None,
        local_port: None,
        remote_name: Some(remote_name.to_string()),
        bind_addr: Some(bind_addr.to_string()),
        bind_port: Some(bind_port),
    };

    let _tunnel = client.create_tunnel(config, None)?;

    println!("Created STCP visitor tunnel '{}'.", tunnel_name);
    println!("This example does not start/connect automatically.");
    Ok(())
}


