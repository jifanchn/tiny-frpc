//! Rust bindings for TINY-FRPC.
//!
//! Notes:
//! - Uses the simplified C API from `tiny-frpc/include/frpc-bindings.h` via FFI.
//! - Aims to provide safe wrappers, but ABI alignment and lifetime management must be handled
//!   carefully (especially for callbacks).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Use libc::size_t only in the FFI layer; prefer Rust primitives for integer types to avoid deprecated aliases.
pub use libc::size_t;

/// Log levels for FRPC logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

/// Tunnel types supported by FRPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TunnelType {
    StcpServer = 0,
    StcpVisitor = 1,
    Tcp = 2,
    Udp = 3,
    Http = 4,
    Https = 5,
}

/// Error codes returned by FRPC operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    Success = 0,
    InvalidParam = -1,
    Memory = -2,
    Network = -3,
    Auth = -4,
    Timeout = -5,
    Proto = -6,
    Internal = -7,
    ConnectionClosed = -8,
    ConnectionClosedByRemote = -9,
    StreamNotWritable = -10,
}

impl From<c_int> for ErrorCode {
    fn from(code: c_int) -> Self {
        match code {
            0 => ErrorCode::Success,
            -1 => ErrorCode::InvalidParam,
            -2 => ErrorCode::Memory,
            -3 => ErrorCode::Network,
            -4 => ErrorCode::Auth,
            -5 => ErrorCode::Timeout,
            -6 => ErrorCode::Proto,
            -7 => ErrorCode::Internal,
            -8 => ErrorCode::ConnectionClosed,
            -9 => ErrorCode::ConnectionClosedByRemote,
            -10 => ErrorCode::StreamNotWritable,
            _ => ErrorCode::Internal,
        }
    }
}

/// FRPC error type
#[derive(Debug)]
pub struct FrpcError {
    pub code: ErrorCode,
    pub message: String,
}

impl std::fmt::Display for FrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FRPC Error {:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for FrpcError {}

impl From<ErrorCode> for FrpcError {
    fn from(code: ErrorCode) -> Self {
        let message = unsafe {
            let msg_ptr = frpc_get_error_message(code as c_int);
            if msg_ptr.is_null() {
                "Unknown error".to_string()
            } else {
                CStr::from_ptr(msg_ptr).to_string_lossy().into_owned()
            }
        };
        
        FrpcError { code, message }
    }
}

pub type Result<T> = std::result::Result<T, FrpcError>;

/// Tunnel statistics
#[derive(Debug, Clone)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections_active: u32,
    pub connections_total: u32,
    pub last_activity_time: u64,
}

/// Callback trait for handling tunnel events
pub trait TunnelEventHandler: Send + Sync {
    /// Called when data is received on the tunnel
    fn on_data(&self, data: &[u8]);
    
    /// Called when connection status changes
    fn on_connection(&self, connected: bool, error_code: i32);
}

/// Configuration for creating tunnels
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub tunnel_type: TunnelType,
    pub tunnel_name: String,
    pub secret_key: Option<String>,
    pub local_addr: Option<String>,
    pub local_port: Option<u16>,
    pub remote_name: Option<String>,
    pub bind_addr: Option<String>,
    pub bind_port: Option<u16>,
}

// C FFI declarations
extern "C" {
    fn frpc_init() -> c_int;
    fn frpc_cleanup();
    fn frpc_create(server_addr: *const c_char, server_port: u16, token: *const c_char) -> *mut c_void;
    fn frpc_destroy(handle: *mut c_void);
    fn frpc_connect(handle: *mut c_void) -> c_int;
    fn frpc_disconnect(handle: *mut c_void) -> c_int;
    fn frpc_create_tunnel(handle: *mut c_void, config: *const CTunnelConfig) -> *mut c_void;
    fn frpc_destroy_tunnel(tunnel: *mut c_void);
    fn frpc_start_tunnel(tunnel: *mut c_void) -> c_int;
    fn frpc_stop_tunnel(tunnel: *mut c_void) -> c_int;
    fn frpc_send_data(tunnel: *mut c_void, data: *const u8, len: size_t) -> c_int;
    fn frpc_process_events(handle: *mut c_void) -> c_int;
    fn frpc_get_tunnel_stats(tunnel: *mut c_void, stats: *mut CTunnelStats) -> c_int;
    fn frpc_get_error_message(error_code: c_int) -> *const c_char;
    fn frpc_is_connected(handle: *mut c_void) -> bool;
    fn frpc_is_tunnel_active(tunnel: *mut c_void) -> bool;
    fn frpc_tunnel_inject_yamux_frame(tunnel: *mut c_void, data: *const u8, len: size_t) -> c_int;
}

// C callback types
type CLogCallback = extern "C" fn(level: c_int, message: *const c_char);
type CDataCallback = extern "C" fn(tunnel: *mut c_void, data: *const u8, len: size_t, user_data: *mut c_void);
type CConnectionCallback = extern "C" fn(tunnel: *mut c_void, connected: c_int, error_code: c_int, user_data: *mut c_void);

// C structures
const FRPC_MAX_CUSTOM_DOMAINS: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
struct CTunnelOptions {
    // HTTP/HTTPS specific options
    host_header_rewrite: *const c_char,
    custom_domains: [*const c_char; FRPC_MAX_CUSTOM_DOMAINS],
    custom_domain_count: size_t,
    enable_websocket: bool,
    http_user: *const c_char,
    http_password: *const c_char,
    locations: [*const c_char; FRPC_MAX_CUSTOM_DOMAINS],
    location_count: size_t,

    // TCP/UDP specific options
    enable_multiplexing: bool,
    connection_pool_size: u32,
    max_connections: u32,
    bandwidth_limit_mbps: u32,

    // Security options
    enable_tls: bool,
    tls_cert_path: *const c_char,
    tls_key_path: *const c_char,
    tls_ca_cert_path: *const c_char,
    tls_verify_peer: bool,

    // Performance options
    buffer_size: u32,
    enable_compression: bool,
    compression_level: u32,

    // WebSocket specific options
    ws_enable_compression: bool,
    ws_max_message_size: u32,
    ws_ping_interval: u32,

    // Load balancing options
    group_name: *const c_char,
    group_key: *const c_char,
    weight: u32,
}

impl Default for CTunnelOptions {
    fn default() -> Self {
        CTunnelOptions {
            host_header_rewrite: ptr::null(),
            custom_domains: [ptr::null(); FRPC_MAX_CUSTOM_DOMAINS],
            custom_domain_count: 0,
            enable_websocket: false,
            http_user: ptr::null(),
            http_password: ptr::null(),
            locations: [ptr::null(); FRPC_MAX_CUSTOM_DOMAINS],
            location_count: 0,
            enable_multiplexing: false,
            connection_pool_size: 0,
            max_connections: 0,
            bandwidth_limit_mbps: 0,
            enable_tls: false,
            tls_cert_path: ptr::null(),
            tls_key_path: ptr::null(),
            tls_ca_cert_path: ptr::null(),
            tls_verify_peer: false,
            buffer_size: 0,
            enable_compression: false,
            compression_level: 0,
            ws_enable_compression: false,
            ws_max_message_size: 0,
            ws_ping_interval: 0,
            group_name: ptr::null(),
            group_key: ptr::null(),
            weight: 0,
        }
    }
}

#[repr(C)]
struct CTunnelConfig {
    server_addr: *const c_char,
    server_port: u16,
    token: *const c_char,
    use_tls: bool,
    tunnel_type: c_int,
    tunnel_name: *const c_char,
    secret_key: *const c_char,
    local_addr: *const c_char,
    local_port: u16,
    remote_name: *const c_char,
    bind_addr: *const c_char,
    bind_port: u16,
    options: CTunnelOptions,
    log_callback: Option<CLogCallback>,
    data_callback: Option<CDataCallback>,
    connection_callback: Option<CConnectionCallback>,
    user_data: *mut c_void,
}

#[repr(C)]
struct CTunnelStats {
    bytes_sent: u64,
    bytes_received: u64,
    connections_active: u32,
    connections_total: u32,
    last_activity_time: u64,
}

// Global callback handlers
extern "C" fn data_callback_wrapper(
    _tunnel: *mut c_void,
    data: *const u8,
    len: size_t,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    
    // user_data points to the Arc inside Box<Arc<dyn TunnelEventHandler>> (see FrpcTunnel::new).
    let handler = unsafe { &*(user_data as *const Arc<dyn TunnelEventHandler>) };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
    handler.on_data(data_slice);
}

extern "C" fn connection_callback_wrapper(
    _tunnel: *mut c_void,
    connected: c_int,
    error_code: c_int,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    
    let handler = unsafe { &*(user_data as *const Arc<dyn TunnelEventHandler>) };
    handler.on_connection(connected != 0, error_code);
}

/// FRPC Client for connecting to FRP servers
pub struct FrpcClient {
    handle: *mut c_void,
    _server_addr: CString,
    _token: Option<CString>,
    event_thread: Option<thread::JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
}

unsafe impl Send for FrpcClient {}
unsafe impl Sync for FrpcClient {}

impl FrpcClient {
    /// Create a new FRPC client
    pub fn new(server_addr: &str, server_port: u16, token: Option<&str>) -> Result<Self> {
        // Initialize library
        unsafe {
            let ret = frpc_init();
            if ret != 0 {
                return Err(ErrorCode::from(ret).into());
            }
        }
        
        let server_addr_c = CString::new(server_addr).map_err(|_| FrpcError {
            code: ErrorCode::InvalidParam,
            message: "Invalid server address".to_string(),
        })?;
        
        let token_c = token.map(|t| CString::new(t)).transpose().map_err(|_| FrpcError {
            code: ErrorCode::InvalidParam,
            message: "Invalid token".to_string(),
        })?;
        
        let handle = unsafe {
            frpc_create(
                server_addr_c.as_ptr(),
                server_port,
                token_c.as_ref().map_or(ptr::null(), |t| t.as_ptr()),
            )
        };
        
        if handle.is_null() {
            return Err(ErrorCode::Memory.into());
        }
        
        Ok(FrpcClient {
            handle,
            _server_addr: server_addr_c,
            _token: token_c,
            event_thread: None,
            running: Arc::new(Mutex::new(false)),
        })
    }
    
    /// Connect to the FRP server
    pub fn connect(&mut self) -> Result<()> {
        let ret = unsafe { frpc_connect(self.handle) };
        if ret != 0 {
            return Err(ErrorCode::from(ret).into());
        }
        
        // Start event processing thread
        *self.running.lock().unwrap() = true;
        // Raw pointers are not Send, so pass it as usize into the thread.
        let handle = self.handle as usize;
        let running = Arc::clone(&self.running);
        
        self.event_thread = Some(thread::spawn(move || {
            while *running.lock().unwrap() {
                unsafe {
                    frpc_process_events(handle as *mut c_void);
                }
                thread::sleep(Duration::from_millis(10));
            }
        }));
        
        Ok(())
    }
    
    /// Disconnect from the FRP server
    pub fn disconnect(&mut self) -> Result<()> {
        // Stop event thread
        *self.running.lock().unwrap() = false;
        if let Some(thread) = self.event_thread.take() {
            let _ = thread.join();
        }
        
        let ret = unsafe { frpc_disconnect(self.handle) };
        if ret != 0 {
            return Err(ErrorCode::from(ret).into());
        }
        
        Ok(())
    }
    
    /// Check if connected to the FRP server
    pub fn is_connected(&self) -> bool {
        unsafe { frpc_is_connected(self.handle) }
    }
    
    /// Create a new tunnel
    pub fn create_tunnel(
        &self,
        config: TunnelConfig,
        handler: Option<Arc<dyn TunnelEventHandler>>,
    ) -> Result<FrpcTunnel> {
        FrpcTunnel::new(self.handle, config, handler)
    }
}

impl Drop for FrpcClient {
    fn drop(&mut self) {
        let _ = self.disconnect();
        unsafe {
            frpc_destroy(self.handle);
            frpc_cleanup();
        }
    }
}

/// FRPC Tunnel for data forwarding
pub struct FrpcTunnel {
    handle: *mut c_void,
    _config_strings: Vec<CString>,
    // IMPORTANT: callback user_data needs a stable address; Box<Arc<...>> keeps it stable and alive for the tunnel lifetime.
    _handler_box: Option<Box<Arc<dyn TunnelEventHandler>>>,
}

unsafe impl Send for FrpcTunnel {}
unsafe impl Sync for FrpcTunnel {}

impl FrpcTunnel {
    fn new(
        client_handle: *mut c_void,
        config: TunnelConfig,
        handler: Option<Arc<dyn TunnelEventHandler>>,
    ) -> Result<Self> {
        let mut config_strings = Vec::new();
        
        // Convert strings to CString and keep them alive
        let tunnel_name_c = CString::new(config.tunnel_name).map_err(|_| FrpcError {
            code: ErrorCode::InvalidParam,
            message: "Invalid tunnel name".to_string(),
        })?;
        config_strings.push(tunnel_name_c);
        
        let secret_key_c = config.secret_key.as_ref().map(|s| {
            CString::new(s.as_str()).map_err(|_| FrpcError {
                code: ErrorCode::InvalidParam,
                message: "Invalid secret key".to_string(),
            })
        }).transpose()?;
        if let Some(ref s) = secret_key_c {
            config_strings.push(s.clone());
        }
        
        let local_addr_c = config.local_addr.as_ref().map(|s| {
            CString::new(s.as_str()).map_err(|_| FrpcError {
                code: ErrorCode::InvalidParam,
                message: "Invalid local address".to_string(),
            })
        }).transpose()?;
        if let Some(ref s) = local_addr_c {
            config_strings.push(s.clone());
        }
        
        let remote_name_c = config.remote_name.as_ref().map(|s| {
            CString::new(s.as_str()).map_err(|_| FrpcError {
                code: ErrorCode::InvalidParam,
                message: "Invalid remote name".to_string(),
            })
        }).transpose()?;
        if let Some(ref s) = remote_name_c {
            config_strings.push(s.clone());
        }
        
        let bind_addr_c = config.bind_addr.as_ref().map(|s| {
            CString::new(s.as_str()).map_err(|_| FrpcError {
                code: ErrorCode::InvalidParam,
                message: "Invalid bind address".to_string(),
            })
        }).transpose()?;
        if let Some(ref s) = bind_addr_c {
            config_strings.push(s.clone());
        }
        
        // Put handler into a Box to get a stable pointer for C callbacks.
        let handler_box: Option<Box<Arc<dyn TunnelEventHandler>>> = handler.map(Box::new);
        let user_data_ptr = handler_box
            .as_ref()
            .map_or(ptr::null_mut(), |b| (b.as_ref() as *const Arc<dyn TunnelEventHandler>) as *mut c_void);

        // Create the C config structure
        let c_config = CTunnelConfig {
            server_addr: ptr::null(),
            server_port: 0,
            token: ptr::null(),
            use_tls: false,
            tunnel_type: config.tunnel_type as c_int,
            tunnel_name: config_strings[0].as_ptr(),
            secret_key: secret_key_c.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            local_addr: local_addr_c.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            local_port: config.local_port.unwrap_or(0),
            remote_name: remote_name_c.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            bind_addr: bind_addr_c.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            bind_port: config.bind_port.unwrap_or(0),
            options: CTunnelOptions::default(),
            log_callback: None,
            data_callback: if handler_box.is_some() { Some(data_callback_wrapper) } else { None },
            connection_callback: if handler_box.is_some() { Some(connection_callback_wrapper) } else { None },
            user_data: user_data_ptr,
        };
        
        let handle = unsafe { frpc_create_tunnel(client_handle, &c_config) };
        if handle.is_null() {
            return Err(ErrorCode::Memory.into());
        }
        
        Ok(FrpcTunnel {
            handle,
            _config_strings: config_strings,
            _handler_box: handler_box,
        })
    }
    
    /// Start the tunnel
    pub fn start(&self) -> Result<()> {
        let ret = unsafe { frpc_start_tunnel(self.handle) };
        if ret != 0 {
            return Err(ErrorCode::from(ret).into());
        }
        Ok(())
    }
    
    /// Stop the tunnel
    pub fn stop(&self) -> Result<()> {
        let ret = unsafe { frpc_stop_tunnel(self.handle) };
        if ret != 0 {
            return Err(ErrorCode::from(ret).into());
        }
        Ok(())
    }
    
    /// Send data through the tunnel
    pub fn send_data(&self, data: &[u8]) -> Result<usize> {
        let ret = unsafe {
            frpc_send_data(self.handle, data.as_ptr(), data.len())
        };
        if ret < 0 {
            return Err(ErrorCode::from(ret).into());
        }
        Ok(ret as usize)
    }

    /// Inject a "raw Yamux frame" (12-byte header + payload) into the tunnel.
    /// Mainly used for tests: trigger callbacks and cover stats fields (e.g. bytes_received).
    pub fn inject_yamux_frame(&self, frame: &[u8]) -> Result<usize> {
        if frame.is_empty() {
            return Err(ErrorCode::InvalidParam.into());
        }
        let ret = unsafe { frpc_tunnel_inject_yamux_frame(self.handle, frame.as_ptr(), frame.len()) };
        if ret < 0 {
            return Err(ErrorCode::from(ret).into());
        }
        Ok(ret as usize)
    }
    
    /// Get tunnel statistics
    pub fn get_stats(&self) -> Result<TunnelStats> {
        let mut c_stats = CTunnelStats {
            bytes_sent: 0,
            bytes_received: 0,
            connections_active: 0,
            connections_total: 0,
            last_activity_time: 0,
        };
        
        let ret = unsafe { frpc_get_tunnel_stats(self.handle, &mut c_stats) };
        if ret != 0 {
            return Err(ErrorCode::from(ret).into());
        }
        
        Ok(TunnelStats {
            bytes_sent: c_stats.bytes_sent,
            bytes_received: c_stats.bytes_received,
            connections_active: c_stats.connections_active,
            connections_total: c_stats.connections_total,
            last_activity_time: c_stats.last_activity_time,
        })
    }
    
    /// Check if tunnel is active
    pub fn is_active(&self) -> bool {
        unsafe { frpc_is_tunnel_active(self.handle) }
    }
}

impl Drop for FrpcTunnel {
    fn drop(&mut self) {
        let _ = self.stop();
        unsafe {
            frpc_destroy_tunnel(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::net::TcpListener;
    use std::io::{Read, Write};
    use std::thread;
    
    struct TestHandler {
        data_received: AtomicBool,
        connected: AtomicBool,
    }
    
    impl TunnelEventHandler for TestHandler {
        fn on_data(&self, data: &[u8]) {
            println!("Received data: {:?}", std::str::from_utf8(data));
            self.data_received.store(true, Ordering::Relaxed);
        }
        
        fn on_connection(&self, connected: bool, error_code: i32) {
            println!("Connection status: {}, error: {}", connected, error_code);
            self.connected.store(connected, Ordering::Relaxed);
        }
    }
    
    #[test]
    fn test_client_creation() {
        let client = FrpcClient::new("127.0.0.1", 7000, Some("test_token"));
        assert!(client.is_ok());
    }
    
    #[test]
    fn test_tunnel_creation() {
        let client = FrpcClient::new("127.0.0.1", 7000, Some("test_token")).unwrap();
        
        let config = TunnelConfig {
            tunnel_type: TunnelType::StcpServer,
            tunnel_name: "test_tunnel".to_string(),
            secret_key: Some("test_secret".to_string()),
            local_addr: Some("127.0.0.1".to_string()),
            local_port: Some(8080),
            remote_name: None,
            bind_addr: None,
            bind_port: None,
        };
        
        let handler = Arc::new(TestHandler {
            data_received: AtomicBool::new(false),
            connected: AtomicBool::new(false),
        });
        
        let tunnel = client.create_tunnel(config, Some(handler));
        assert!(tunnel.is_ok());
    }

    // Start a minimal mock FRPS: handles Login/LoginResp only (1-byte type + 8-byte length + JSON).
    fn start_mock_frps(resp_type: u8, resp_json: &'static str) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // Read Login
                let mut hdr = [0u8; 9];
                if s.read_exact(&mut hdr).is_err() {
                    return;
                }
                let len = i64::from_be_bytes(hdr[1..9].try_into().unwrap());
                if len < 0 || len > 1024 * 1024 {
                    return;
                }
                let mut payload = vec![0u8; len as usize];
                if len > 0 {
                    let _ = s.read_exact(&mut payload);
                }
                // Write LoginResp
                let body = resp_json.as_bytes();
                let mut out = Vec::with_capacity(1 + 8 + body.len());
                out.push(resp_type);
                out.extend_from_slice(&(body.len() as i64).to_be_bytes());
                out.extend_from_slice(body);
                let _ = s.write_all(&out);
                let _ = s.flush();
            }
        });
        (port, h)
    }

    #[test]
    fn test_connect_and_inject_yamux_frame() {
        // Positive: connect success + start visitor tunnel + inject Yamux DATA -> on_data
        let (port, jh) = start_mock_frps(b'1', "{\"version\":\"0.62.1\",\"run_id\":\"rs_test\"}");

        let mut client = FrpcClient::new("127.0.0.1", port, Some("test_token")).unwrap();
        client.connect().unwrap();

        let handler = Arc::new(TestHandler {
            data_received: AtomicBool::new(false),
            connected: AtomicBool::new(false),
        });

        let cfg = TunnelConfig {
            tunnel_type: TunnelType::StcpVisitor,
            tunnel_name: "rs_stcp_visitor".to_string(),
            secret_key: Some("rs_secret".to_string()),
            local_addr: None,
            local_port: None,
            remote_name: Some("remote_server".to_string()),
            bind_addr: Some("127.0.0.1".to_string()),
            bind_port: Some(9090),
        };

        let tunnel = client.create_tunnel(cfg, Some(handler.clone())).unwrap();
        tunnel.start().unwrap();

        // Build a Yamux DATA frame (12-byte header + payload)
        let payload = b"inbound-from-rust";
        let mut frame = Vec::with_capacity(12 + payload.len());
        frame.push(0); // version
        frame.push(0); // type=DATA
        frame.extend_from_slice(&0u16.to_be_bytes()); // flags
        frame.extend_from_slice(&1u32.to_be_bytes()); // stream_id
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()); // length
        frame.extend_from_slice(payload);

        let consumed = tunnel.inject_yamux_frame(&frame).unwrap();
        assert!(consumed > 0);

        // Callback should be triggered
        assert!(handler.data_received.load(Ordering::Relaxed));

        // Stats should be updated
        let st = tunnel.get_stats().unwrap();
        assert!(st.bytes_received > 0);

        let _ = client.disconnect();
        let _ = jh.join();
    }

    #[test]
    fn test_connect_proto_errors() {
        // Wrong response type -> PROTO
        {
            let (port, jh) = start_mock_frps(b'X', "{\"version\":\"0.62.1\",\"run_id\":\"rs_test\"}");
            let mut client = FrpcClient::new("127.0.0.1", port, Some("test_token")).unwrap();
            let r = client.connect();
            assert!(r.is_err());
            let _ = jh.join();
        }

        // Missing run_id -> PROTO
        {
            let (port, jh) = start_mock_frps(b'1', "{\"version\":\"0.62.1\"}");
            let mut client = FrpcClient::new("127.0.0.1", port, Some("test_token")).unwrap();
            let r = client.connect();
            assert!(r.is_err());
            let _ = jh.join();
        }
    }
}