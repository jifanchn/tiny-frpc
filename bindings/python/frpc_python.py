#!/usr/bin/env python3
"""
Python bindings for TINY-FRPC (ctypes-based).

Goals:
- Provide a reasonably "Pythonic" wrapper, while keeping the ABI strictly aligned with
  `tiny-frpc/include/frpc-bindings.h`.
- Avoid third-party dependencies to keep it portable across environments.
"""

import ctypes
import os
import sys
import platform
from ctypes import (
    c_void_p, c_char_p, c_uint16, c_uint32, c_uint64, c_int, c_size_t, 
    c_bool, c_uint8, POINTER, Structure, CFUNCTYPE, byref
)
from enum import IntEnum
from typing import Optional, Callable, Any
import threading
import time

def _load_library():
    """Load the FRPC shared library.

    Notes: bindings expect the shared library built from the C core (see `make bindings-shared`).
    """
    env_path = os.environ.get("FRPC_LIB_PATH")
    if env_path:
        return ctypes.CDLL(env_path)

    this_dir = os.path.dirname(os.path.abspath(__file__))

    # Convention: we build `build/libfrpc-bindings.so` on all platforms.
    # On macOS the suffix is typically .dylib, but dlopen does not care about the suffix as long
    # as the file is a valid dynamic library.
    candidate_names = [
        "libfrpc-bindings.so",
        "libfrpc-bindings.dylib",
    ]

    lib_paths = []
    for name in candidate_names:
        lib_paths.extend([
            os.path.abspath(os.path.join(this_dir, "..", "..", "build", name)),  # repo build output
            os.path.abspath(os.path.join(this_dir, name)),  # current directory
            os.path.join("/usr/local/lib", name),  # system path
        ])
    
    for path in lib_paths:
        try:
            if os.path.exists(path):
                return ctypes.CDLL(path)
        except OSError:
            continue
    
    raise RuntimeError("Could not load FRPC library. Make sure it's compiled and in the library path.")

# Load library
_lib = _load_library()

# Define callback types
LogCallback = CFUNCTYPE(None, c_int, c_char_p)
DataCallback = CFUNCTYPE(None, c_void_p, POINTER(c_uint8), c_size_t, c_void_p)
ConnectionCallback = CFUNCTYPE(None, c_void_p, c_int, c_int, c_void_p)

# Define enums
class LogLevel(IntEnum):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3

class TunnelType(IntEnum):
    STCP_SERVER = 0
    STCP_VISITOR = 1
    TCP = 2
    UDP = 3
    HTTP = 4
    HTTPS = 5

class ErrorCode(IntEnum):
    SUCCESS = 0
    INVALID_PARAM = -1
    MEMORY = -2
    NETWORK = -3
    AUTH = -4
    TIMEOUT = -5
    PROTO = -6
    INTERNAL = -7
    CONNECTION_CLOSED = -8
    CONNECTION_CLOSED_BY_REMOTE = -9
    STREAM_NOT_WRITABLE = -10

# Define structures
FRPC_MAX_CUSTOM_DOMAINS = 16

class TunnelOptions(Structure):
    """Mirror of frpc_tunnel_options_t in frpc-bindings.h (layout must match C)."""
    _fields_ = [
        # HTTP/HTTPS specific options
        ("host_header_rewrite", c_char_p),
        ("custom_domains", c_char_p * FRPC_MAX_CUSTOM_DOMAINS),
        ("custom_domain_count", c_size_t),
        ("enable_websocket", c_bool),
        ("http_user", c_char_p),
        ("http_password", c_char_p),
        ("locations", c_char_p * FRPC_MAX_CUSTOM_DOMAINS),
        ("location_count", c_size_t),

        # TCP/UDP specific options
        ("enable_multiplexing", c_bool),
        ("connection_pool_size", c_uint32),
        ("max_connections", c_uint32),
        ("bandwidth_limit_mbps", c_uint32),

        # Security options
        ("enable_tls", c_bool),
        ("tls_cert_path", c_char_p),
        ("tls_key_path", c_char_p),
        ("tls_ca_cert_path", c_char_p),
        ("tls_verify_peer", c_bool),

        # Performance options
        ("buffer_size", c_uint32),
        ("enable_compression", c_bool),
        ("compression_level", c_uint32),

        # WebSocket specific options
        ("ws_enable_compression", c_bool),
        ("ws_max_message_size", c_uint32),
        ("ws_ping_interval", c_uint32),

        # Load balancing options
        ("group_name", c_char_p),
        ("group_key", c_char_p),
        ("weight", c_uint32),
    ]

class TunnelConfig(Structure):
    _fields_ = [
        ("server_addr", c_char_p),
        ("server_port", c_uint16),
        ("token", c_char_p),
        ("use_tls", c_bool),
        ("tunnel_type", c_int),
        ("tunnel_name", c_char_p),
        ("secret_key", c_char_p),
        ("local_addr", c_char_p),
        ("local_port", c_uint16),
        ("remote_name", c_char_p),
        ("bind_addr", c_char_p),
        ("bind_port", c_uint16),
        ("options", TunnelOptions),
        ("log_callback", LogCallback),
        ("data_callback", DataCallback),
        ("connection_callback", ConnectionCallback),
        ("user_data", c_void_p),
    ]

class TunnelStats(Structure):
    _fields_ = [
        ("bytes_sent", c_uint64),
        ("bytes_received", c_uint64),
        ("connections_active", c_uint32),
        ("connections_total", c_uint32),
        ("last_activity_time", c_uint64),
    ]

# Define function prototypes
_lib.frpc_init.restype = c_int
_lib.frpc_cleanup.restype = None
_lib.frpc_set_log_callback.argtypes = [LogCallback]
_lib.frpc_set_log_callback.restype = None

_lib.frpc_create.argtypes = [c_char_p, c_uint16, c_char_p]
_lib.frpc_create.restype = c_void_p
_lib.frpc_destroy.argtypes = [c_void_p]
_lib.frpc_destroy.restype = None

_lib.frpc_connect.argtypes = [c_void_p]
_lib.frpc_connect.restype = c_int
_lib.frpc_disconnect.argtypes = [c_void_p]
_lib.frpc_disconnect.restype = c_int

_lib.frpc_create_tunnel.argtypes = [c_void_p, POINTER(TunnelConfig)]
_lib.frpc_create_tunnel.restype = c_void_p
_lib.frpc_destroy_tunnel.argtypes = [c_void_p]
_lib.frpc_destroy_tunnel.restype = None

_lib.frpc_start_tunnel.argtypes = [c_void_p]
_lib.frpc_start_tunnel.restype = c_int
_lib.frpc_stop_tunnel.argtypes = [c_void_p]
_lib.frpc_stop_tunnel.restype = c_int

_lib.frpc_send_data.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
_lib.frpc_send_data.restype = c_int

_lib.frpc_process_events.argtypes = [c_void_p]
_lib.frpc_process_events.restype = c_int

_lib.frpc_get_tunnel_stats.argtypes = [c_void_p, POINTER(TunnelStats)]
_lib.frpc_get_tunnel_stats.restype = c_int

_lib.frpc_get_error_message.argtypes = [c_int]
_lib.frpc_get_error_message.restype = c_char_p

_lib.frpc_is_connected.argtypes = [c_void_p]
_lib.frpc_is_connected.restype = c_bool
_lib.frpc_is_tunnel_active.argtypes = [c_void_p]
_lib.frpc_is_tunnel_active.restype = c_bool

_lib.frpc_tunnel_inject_yamux_frame.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
_lib.frpc_tunnel_inject_yamux_frame.restype = c_int

# Initialize library
_lib.frpc_init()

class FRPCException(Exception):
    """Exception raised by FRPC operations"""
    def __init__(self, error_code: int, message: str = None):
        self.error_code = error_code
        if message is None:
            message = _lib.frpc_get_error_message(error_code).decode('utf-8')
        super().__init__(f"FRPC Error {error_code}: {message}")

class FRPCClient:
    """FRPC Client for connecting to FRP servers"""
    
    def __init__(self, server_addr: str, server_port: int, token: str = None):
        self.server_addr = server_addr
        self.server_port = server_port
        self.token = token
        self._handle = None
        self._tunnels = {}
        self._event_thread = None
        self._running = False
        
        # Create client
        addr_bytes = server_addr.encode('utf-8')
        token_bytes = token.encode('utf-8') if token else None
        
        self._handle = _lib.frpc_create(addr_bytes, server_port, token_bytes)
        if not self._handle:
            raise FRPCException(ErrorCode.MEMORY, "Failed to create FRPC client")
    
    def __del__(self):
        self.close()
    
    def connect(self) -> None:
        """Connect to the FRP server"""
        if not self._handle:
            raise FRPCException(ErrorCode.INVALID_PARAM, "Client not initialized")
        
        ret = _lib.frpc_connect(self._handle)
        if ret != 0:
            raise FRPCException(ret)
        
        # Start event processing thread
        self._running = True
        self._event_thread = threading.Thread(target=self._event_loop, daemon=True)
        self._event_thread.start()
    
    def disconnect(self) -> None:
        """Disconnect from the FRP server"""
        if not self._handle:
            return
        
        self._running = False
        if self._event_thread:
            self._event_thread.join(timeout=1.0)
        
        _lib.frpc_disconnect(self._handle)
    
    def close(self) -> None:
        """Close the client and cleanup resources"""
        if self._handle:
            self.disconnect()
            
            # Close all tunnels
            for tunnel in list(self._tunnels.values()):
                tunnel.close()
            
            _lib.frpc_destroy(self._handle)
            self._handle = None
    
    def is_connected(self) -> bool:
        """Check if connected to the FRP server"""
        if not self._handle:
            return False
        return _lib.frpc_is_connected(self._handle)
    
    def create_tunnel(self, tunnel_type: TunnelType, tunnel_name: str, **kwargs) -> 'FRPCTunnel':
        """Create a new tunnel"""
        tunnel = FRPCTunnel(self, tunnel_type, tunnel_name, **kwargs)
        self._tunnels[tunnel_name] = tunnel
        return tunnel
    
    def _event_loop(self):
        """Event processing loop"""
        while self._running and self._handle:
            try:
                _lib.frpc_process_events(self._handle)
                time.sleep(0.01)  # 10ms polling interval
            except Exception as e:
                print(f"Event loop error: {e}")
                break

class FRPCTunnel:
    """FRPC Tunnel for data forwarding"""
    
    def __init__(self, client: FRPCClient, tunnel_type: TunnelType, tunnel_name: str, **kwargs):
        self.client = client
        self.tunnel_type = tunnel_type
        self.tunnel_name = tunnel_name
        self._handle = None
        self._config = TunnelConfig()
        
        # User callbacks (Python-side)
        self._data_callback = None
        self._connection_callback = None
        self._log_callback = None

        # ctypes callback wrappers: must keep references to avoid GC and potential crashes.
        self._data_cb_c = None
        self._conn_cb_c = None
        
        # Setup configuration
        self._setup_config(**kwargs)
        
        # Create tunnel
        self._handle = _lib.frpc_create_tunnel(client._handle, byref(self._config))
        if not self._handle:
            raise FRPCException(ErrorCode.MEMORY, "Failed to create tunnel")
    
    def _setup_config(self, **kwargs):
        """Setup tunnel configuration"""
        # Basic config
        self._config.tunnel_type = self.tunnel_type
        self._config.tunnel_name = self.tunnel_name.encode('utf-8')
        
        # Optional parameters
        if 'secret_key' in kwargs:
            self._config.secret_key = kwargs['secret_key'].encode('utf-8')
        if 'local_addr' in kwargs:
            self._config.local_addr = kwargs['local_addr'].encode('utf-8')
        if 'local_port' in kwargs:
            self._config.local_port = kwargs['local_port']
        if 'remote_name' in kwargs:
            self._config.remote_name = kwargs['remote_name'].encode('utf-8')
        if 'bind_addr' in kwargs:
            self._config.bind_addr = kwargs['bind_addr'].encode('utf-8')
        if 'bind_port' in kwargs:
            self._config.bind_port = kwargs['bind_port']
        
        # Setup callbacks
        if 'data_callback' in kwargs:
            self._data_callback = kwargs['data_callback']
            self._data_cb_c = DataCallback(self._on_data)
            self._config.data_callback = self._data_cb_c
        
        if 'connection_callback' in kwargs:
            self._connection_callback = kwargs['connection_callback']
            self._conn_cb_c = ConnectionCallback(self._on_connection)
            self._config.connection_callback = self._conn_cb_c
    
    def _on_data(self, tunnel_handle, data_ptr, length, user_data):
        """Internal data callback"""
        if self._data_callback:
            # Convert C data to Python bytes
            data = ctypes.string_at(data_ptr, length)
            self._data_callback(data)
    
    def _on_connection(self, tunnel_handle, connected, error_code, user_data):
        """Internal connection callback"""
        if self._connection_callback:
            self._connection_callback(bool(connected), error_code)
    
    def start(self) -> None:
        """Start the tunnel"""
        if not self._handle:
            raise FRPCException(ErrorCode.INVALID_PARAM, "Tunnel not initialized")
        
        ret = _lib.frpc_start_tunnel(self._handle)
        if ret != 0:
            raise FRPCException(ret)
    
    def stop(self) -> None:
        """Stop the tunnel"""
        if not self._handle:
            return
        
        _lib.frpc_stop_tunnel(self._handle)
    
    def send_data(self, data: bytes) -> int:
        """Send data through the tunnel"""
        if not self._handle:
            raise FRPCException(ErrorCode.INVALID_PARAM, "Tunnel not initialized")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Convert to C array
        data_array = (c_uint8 * len(data)).from_buffer_copy(data)
        
        ret = _lib.frpc_send_data(self._handle, data_array, len(data))
        if ret < 0:
            raise FRPCException(ret)
        
        return ret

    def inject_yamux_frame(self, frame: bytes) -> int:
        """Inject a "raw Yamux frame" (12-byte header + payload) into the tunnel.

        Mainly used for tests: trigger data_callback, cover stats fields (e.g. bytes_received), etc.
        """
        if not self._handle:
            raise FRPCException(ErrorCode.INVALID_PARAM, "Tunnel not initialized")
        if isinstance(frame, str):
            frame = frame.encode('utf-8')
        if not isinstance(frame, (bytes, bytearray)):
            raise FRPCException(ErrorCode.INVALID_PARAM, "frame must be bytes/bytearray")
        arr = (c_uint8 * len(frame)).from_buffer_copy(frame)
        ret = _lib.frpc_tunnel_inject_yamux_frame(self._handle, arr, len(frame))
        if ret < 0:
            raise FRPCException(ret)
        return ret
    
    def get_stats(self) -> dict:
        """Get tunnel statistics"""
        if not self._handle:
            return {}
        
        stats = TunnelStats()
        ret = _lib.frpc_get_tunnel_stats(self._handle, byref(stats))
        if ret != 0:
            raise FRPCException(ret)
        
        return {
            'bytes_sent': stats.bytes_sent,
            'bytes_received': stats.bytes_received,
            'connections_active': stats.connections_active,
            'connections_total': stats.connections_total,
            'last_activity_time': stats.last_activity_time,
        }
    
    def is_active(self) -> bool:
        """Check if tunnel is active"""
        if not self._handle:
            return False
        return _lib.frpc_is_tunnel_active(self._handle)
    
    def close(self) -> None:
        """Close the tunnel"""
        if self._handle:
            self.stop()
            _lib.frpc_destroy_tunnel(self._handle)
            self._handle = None
            
            # Remove from client's tunnel list
            if self.tunnel_name in self.client._tunnels:
                del self.client._tunnels[self.tunnel_name]

# Global reference to keep the log callback alive (prevent GC).
_g_log_callback_ref = None

# Convenience functions
def set_log_callback(callback: Callable[[int, str], None]) -> None:
    """Set global log callback"""
    global _g_log_callback_ref
    
    def log_wrapper(level, message):
        callback(level, message.decode('utf-8'))
    
    # Keep a reference to prevent GC from collecting the callback
    _g_log_callback_ref = LogCallback(log_wrapper)
    _lib.frpc_set_log_callback(_g_log_callback_ref)

def cleanup() -> None:
    """Cleanup FRPC library"""
    _lib.frpc_cleanup()

# Example usage
if __name__ == "__main__":
    # Set up logging
    def log_handler(level, message):
        level_names = {0: "DEBUG", 1: "INFO", 2: "WARN", 3: "ERROR"}
        print(f"[{level_names.get(level, 'UNKNOWN')}] {message}")
    
    set_log_callback(log_handler)
    
    try:
        # Create client
        client = FRPCClient("127.0.0.1", 7000, "test_token")
        
        # Create STCP server tunnel
        def on_data(data):
            print(f"Received data: {data}")
        
        def on_connection(connected, error_code):
            print(f"Connection status: {connected}, error: {error_code}")
        
        tunnel = client.create_tunnel(
            TunnelType.STCP_SERVER,
            "test_tunnel",
            secret_key="test_secret",
            local_addr="127.0.0.1",
            local_port=8080,
            data_callback=on_data,
            connection_callback=on_connection
        )
        
        # Connect and start tunnel
        client.connect()
        tunnel.start()
        
        print("Tunnel started. Press Ctrl+C to exit.")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
                if client.is_connected():
                    stats = tunnel.get_stats()
                    print(f"Stats: {stats}")
        except KeyboardInterrupt:
            print("Shutting down...")
        
    except FRPCException as e:
        print(f"FRPC Error: {e}")
    finally:
        cleanup()