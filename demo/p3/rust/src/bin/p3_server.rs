use frpc::{FrpcClient, TunnelConfig, TunnelType, TunnelEventHandler};
use std::sync::Arc;
use std::io::{self, Write};
use std::env;

struct ServerHandler;

impl TunnelEventHandler for ServerHandler {
    fn on_data(&self, data: &[u8]) {
        let msg = String::from_utf8_lossy(data);
        print!("\r\x1b[K"); // Clear line
        println!("[Received] {}", msg.trim());
        print!("> ");
        io::stdout().flush().unwrap();
    }

    fn on_connection(&self, connected: bool, error_code: i32) {
        print!("\r\x1b[K");
        let status = if connected { "Connected" } else { "Disconnected" };
        println!("[Status] {} (error: {})", status, error_code);
        print!("> ");
        io::stdout().flush().unwrap();
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <server_addr> <server_port>", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let port: u16 = args[2].parse()?;

    println!("Starting Rust STCP Server connecting to {}:{}...", host, port);

    let mut client = FrpcClient::new(host, port, Some("test_token"))?;
    client.set_encryption(true);

    let handler = Arc::new(ServerHandler);

    let config = TunnelConfig {
        tunnel_type: TunnelType::StcpServer,
        tunnel_name: "p3_test_stcp".to_string(),
        secret_key: Some("p3_test_secret".to_string()),
        local_addr: Some("127.0.0.1".to_string()),
        local_port: Some(0),
        remote_name: None,
        bind_addr: None,
        bind_port: None,
    };

    let tunnel = client.create_tunnel(config, Some(handler))?;
    client.connect()?;
    tunnel.start()?;

    println!("Server started. Waiting for visitors...");
    println!("Type message and press Enter to send (or 'quit' to exit):");
    print!("> ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut line = String::new();
    while stdin.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if trimmed == "quit" {
            break;
        }
        if !trimmed.is_empty() {
            let msg = format!("[Server] {}", trimmed);
            tunnel.send_data(msg.as_bytes())?;
        }
        print!("> ");
        io::stdout().flush()?;
        line.clear();
    }

    client.disconnect()?;
    Ok(())
}
