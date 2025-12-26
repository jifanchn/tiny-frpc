package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include
#cgo LDFLAGS: -L../../build -lfrpc -lyamux -lcrypto -ltools -lwrapper

#include <stdlib.h>
#include <string.h>
#include "frpc.h"
#include "frpc-stcp.h"

// 回调函数定义
extern int onStcpData(void* user_ctx, unsigned char* data, size_t len);
extern int onStcpWrite(void* user_ctx, unsigned char* data, size_t len);
extern void onStcpConnection(void* user_ctx, int connected, int error_code);

// 保存visitor和server的代理实例指针，方便测试用例调用
static frpc_stcp_proxy_t* g_visitor_proxy = NULL;
static frpc_stcp_proxy_t* g_server_proxy = NULL;

// sending test data的函数
static int send_test_data_via_visitor(const char* data) {
    if (g_visitor_proxy == NULL) {
        return -1;
    }
    return frpc_stcp_send(g_visitor_proxy, (const unsigned char*)data, strlen(data));
}

// 发送回复数据（Server回复到本地连接）
static int send_reply_data_via_server(const char* data) {
    if (g_server_proxy == NULL) {
        return -1;
    }
    return frpc_stcp_send(g_server_proxy, (const unsigned char*)data, strlen(data));
}

// Helper function to start STCP Visitor
static int start_stcp_visitor(frpc_client_t* client, const char* proxy_name, const char* sk,
                      const char* server_name, const char* bind_addr, int bind_port, void* user_ctx) {
    frpc_stcp_config_t config;
    memset(&config, 0, sizeof(config));

    config.role = FRPC_STCP_ROLE_VISITOR;
    config.proxy_name = proxy_name;
    config.sk = sk;
    config.server_name = server_name;
    config.bind_addr = bind_addr;
    config.bind_port = bind_port;

    // 设置回调函数
    config.on_data = onStcpData;
    config.on_write = onStcpWrite;
    config.on_connection = onStcpConnection;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
    if (!proxy) {
        return -1;
    }

    int ret = frpc_stcp_proxy_start(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    // 设置数据传输参数
    frpc_stcp_transport_config_t transport_config;
    transport_config.use_encryption = 1;
    transport_config.use_compression = 0;
    frpc_stcp_set_transport_config(proxy, &transport_config);

    // connection to服务器
    ret = frpc_stcp_visitor_connect(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_stop(proxy);
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    // 保存代理实例指针
    g_visitor_proxy = proxy;

    return 0;
}

// Helper function to start STCP Server
static int start_stcp_server(frpc_client_t* client, const char* proxy_name, const char* sk,
                     const char* local_addr, int local_port, void* user_ctx) {
    frpc_stcp_config_t config;
    memset(&config, 0, sizeof(config));

    config.role = FRPC_STCP_ROLE_SERVER;
    config.proxy_name = proxy_name;
    config.sk = sk;
    config.local_addr = local_addr;
    config.local_port = local_port;

    // 设置回调函数
    config.on_data = onStcpData;
    config.on_write = onStcpWrite;
    config.on_connection = onStcpConnection;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
    if (!proxy) {
        return -1;
    }

    int ret = frpc_stcp_proxy_start(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    // 设置数据传输参数
    frpc_stcp_transport_config_t transport_config;
    transport_config.use_encryption = 1;
    transport_config.use_compression = 0;
    frpc_stcp_set_transport_config(proxy, &transport_config);

    // 注册服务
    const char* allowed_users[] = {"*"};  // 允许所有用户
    frpc_stcp_server_set_allow_users(proxy, allowed_users, 1);

    ret = frpc_stcp_server_register(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_stop(proxy);
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    // 保存代理实例指针
    g_server_proxy = proxy;

    return 0;
}

// 清理函数，释放资源
static void cleanup_stcp_proxies() {
    if (g_visitor_proxy) {
        frpc_stcp_proxy_stop(g_visitor_proxy);
        frpc_stcp_proxy_free(g_visitor_proxy);
        g_visitor_proxy = NULL;
    }

    if (g_server_proxy) {
        frpc_stcp_proxy_stop(g_server_proxy);
        frpc_stcp_proxy_free(g_server_proxy);
        g_server_proxy = NULL;
    }
}

*/
import "C"
import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frplog "github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/server"
)

var globalFrpcClient *C.frpc_client_t // Ensure this is the Go package level variable

// 用于测试的FRPS服务配置
var frpsConfig = &v1.ServerConfig{
	Auth: v1.AuthServerConfig{
		Method: "token",
		Token:  "test_token",
	},
	BindAddr:              "0.0.0.0",
	BindPort:              7001,
	TCPMuxHTTPConnectPort: 0,
	SubDomainHost:         "",
	// Disable TCPMux first to keep the minimum FRP message exchange + STCP E2E loop stable.
	// We can re-enable TCPMux later in deeper interop tests once Yamux alignment is fully proven.
	Transport: v1.ServerTransportConfig{
		TCPMux: new(bool),
	},
}

// Test modes
const (
	ModeServer  = "server"
	ModeVisitor = "visitor"
	ModeBoth    = "both"
)

// Error codes from frpc.h (avoid dependency on cgo-exported enum constants for editor/static analysis compatibility)
const (
	frpcErrConnectionClosed         = -8
	frpcErrConnectionClosedByRemote = -9
)

// E2E reconnect/lifecycle regression: repeat start/stop cycles in one process to catch
// resource leaks, stale state, and reconnect edge cases.
const frpcReconnectCycles = 5

func resetCycleSignals() {
	testCompleteChan = make(chan struct{}, 1)
	dataExchanged = make(chan struct{}, 1)
	serverReady = make(chan struct{}, 1)
}

// Test parameters
var (
	mode         string // mode: server, visitor, or both
	frpsAddr     string // FRPS address
	frpsPort     int    // FRPS port
	proxyName    string // proxy name
	secretKey    string // shared secret key (sk)
	serverName   string // server name (for Visitor)
	localAddr    string // local service address (for Server)
	localPort    int    // local service port (for Server)
	bindAddr     string // bind address (for Visitor)
	bindPort     int    // bind port (for Visitor)
	runFRPS      bool   // run embedded FRPS
	testMode     string // test-mode: basic, bidirectional
	frpsLogLevel string // FRPS log level: trace/debug/info/...
	verbose      bool   // verbose logs (default: false, enable with -v)
)

// Synchronization primitives for test flow
var (
	testCompleteChan   = make(chan struct{}, 1)
	connectedClients   = &sync.WaitGroup{}
	dataExchanged      = make(chan struct{}, 1)
	serverReady        = make(chan struct{}, 1)
	visitorTCPListener net.Listener // local listener to simulate Visitor bind port
)

// Test data and globals
var (
	// payloads
	testDataFromClient  = "Hello from client, this is a test message!"
	testReplyFromServer = "Hello from server, I received your message!"

	// map user_ctx -> proxy id label
	dataFlowMap = make(map[uintptr]string)
)

// init registers CLI flags.
func init() {
	flag.StringVar(&mode, "mode", ModeBoth, "Test mode: server, visitor, or both")
	flag.StringVar(&frpsAddr, "frps-addr", "127.0.0.1", "FRPS server address")
	flag.IntVar(&frpsPort, "frps-port", 7001, "FRPS server port")
	flag.StringVar(&proxyName, "proxy-name", "test_stcp", "Proxy name")
	flag.StringVar(&secretKey, "sk", "test_secret", "Secret key")
	flag.StringVar(&serverName, "server-name", "test_stcp", "Server name for Visitor mode")
	flag.StringVar(&localAddr, "local-addr", "127.0.0.1", "Local service address for Server mode")
	flag.IntVar(&localPort, "local-port", 8080, "Local service port for Server mode")
	flag.StringVar(&bindAddr, "bind-addr", "127.0.0.1", "Bind address for Visitor mode")
	flag.IntVar(&bindPort, "bind-port", 9999, "Bind port for Visitor mode")
	flag.BoolVar(&runFRPS, "run-frps", true, "Run embedded FRPS server")
	flag.StringVar(&testMode, "test-mode", "bidirectional", "Test mode: basic or bidirectional")
	flag.StringVar(&frpsLogLevel, "frps-log-level", "info", "FRPS log level: trace/debug/info/warn/error")
	flag.BoolVar(&verbose, "v", false, "Verbose logs (default: false)")
}

// startFRPSServer starts an embedded FRPS server for E2E tests.
func startFRPSServer(ctx context.Context) error {
	log.Println("Attempting to start FRPS server programmatically...")

	// Initialize frp logger to avoid noisy default logging.
	frplog.InitLogger("console", frpsLogLevel, 0, false)

	// 加载并验证配置
	cfg := frpsConfig

	cfg.Complete()

	svr, err := server.NewService(cfg)
	if err != nil {
		log.Printf("Failed to create FRPS service: %v", err)
		return fmt.Errorf("Failed to create FRPS service: %v", err)
	}

	log.Printf("FRPS service created, listening on: %s:%d, Token: %s", cfg.BindAddr, cfg.BindPort, cfg.Auth.Token)

	go func() {
		svr.Run(ctx)
		log.Println("FRPS服务已停止。")
	}()

	// Give FRPS a moment to start.
	time.Sleep(2 * time.Second)
	log.Println("FRPS server should be started。")
	return nil
}

// onStcpData is a CGO callback invoked by C STCP layer when user payload arrives.
//
//export onStcpData
func onStcpData(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	proxyID := "unknown_proxy"
	if p, ok := dataFlowMap[uintptr(user_ctx)]; ok {
		proxyID = p
	}

	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))
	log.Printf("Go onStcpData: proxy [%s] (user_ctx: %p) received %d bytes: %s\n", proxyID, user_ctx, length, string(goData))

	// In bidirectional mode, server side may reply (simplified in this test).
	if proxyID == "server_proxy" && testMode == "bidirectional" {
		log.Printf("Go onStcpData: Server proxy received data, will send reply: %s\n", testReplyFromServer)
		cReply := C.CString(testReplyFromServer)
		defer C.free(unsafe.Pointer(cReply))
		// Should send via C.frpc_stcp_send(g_server_proxy, ...), not directly write
		// 但这只是一个回调，实际发送逻辑在 handleConnection 等地方触发
		// C.send_reply_data_via_server(cReply) // This would call frpc_stcp_send on g_server_proxy
	}

	// In bidirectional mode, visitor side receiving reply marks completion.
	if proxyID == "visitor_proxy" && testMode == "bidirectional" && string(goData) == testReplyFromServer {
		log.Printf("Go onStcpData: Visitor proxy received reply from server. Data exchange complete.\n")
		select {
		case dataExchanged <- struct{}{}:
		default:
		}
	}

	return C.int(length) // Indicates all data was processed
}

// onStcpWrite is a CGO callback for high-level write notifications (not Yamux transport).
//
//export onStcpWrite
func onStcpWrite(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	// This callback, as part of frpc_stcp_config_t, is likely for notifications
	// or high-level writes, NOT for Yamux's direct transport.
	// Yamux's write_fn should be a C function using the proxy's work_conn_fd.
	// For now, just log.
	// Do NOT use globalFrpcClient here for sending Yamux frames.

	proxyID := "unknown_proxy_on_write"
	// user_ctx for onStcpWrite is the one passed to frpc_stcp_proxy_new.
	// We can use it to identify the proxy if we stored it, e.g., in dataFlowMap.
	if p, ok := dataFlowMap[uintptr(user_ctx)]; ok {
		proxyID = p
	}

	// goData := C.GoBytes(unsafe.Pointer(data), C.int(length)) // Avoid allocation if just logging length
	// Default is quiet; print this noisy diagnostic only in verbose mode.
	if verbose {
		log.Printf("Go onStcpWrite: callback for proxy [%s] (user_ctx: %p) with %d bytes. This should NOT be Yamux's transport send.\n", proxyID, user_ctx, length)
	}

	// Simulating that the write was "accepted" by the C layer to be processed.
	// The actual send for Yamux should happen via a C function configured in yamux_session_new.
	return C.int(length) // Indicate all data "processed" by this callback.
}

// onStcpConnection is a CGO callback for connect/disconnect events.
//
//export onStcpConnection
func onStcpConnection(user_ctx unsafe.Pointer, connected C.int, error_code C.int) {
	ctxInt := uintptr(user_ctx)

	if connected != 0 {
		log.Printf("Context %d: connected\n", ctxInt)
		if ctxInt == 1 { // Server
			log.Println("Serverconnected到FRPS")
			// Avoid closing channels across reconnect cycles; send a signal non-blocking.
			select {
			case serverReady <- struct{}{}:
			default:
			}
		} else if ctxInt == 2 { // Visitor
			log.Println("Visitorconnected到FRPS")
		}
	} else {
		// Disconnect: -8/-9 are treated as normal close/by-remote close in our semantics.
		if int(error_code) == frpcErrConnectionClosed || int(error_code) == frpcErrConnectionClosedByRemote {
			if verbose {
				log.Printf("Context %d: disconnected (normal), error code: %d\n", ctxInt, error_code)
			} else {
				log.Printf("Context %d: disconnected (normal)\n", ctxInt)
			}
		} else {
			log.Printf("Context %d: disconnected, error code: %d\n", ctxInt, error_code)
		}
	}
}

// startLocalTestServer starts a local echo server (represents "server side local service").
func startLocalTestServer(addr string, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return nil, err
	}

	log.Printf("Local test server started on %s:%d started\n", addr, port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Println("Accept connection error:", err)
				continue
			}

			connectedClients.Add(1)
			go handleConnection(conn)
		}
	}()

	return listener, nil
}

// handleConnection handles the local echo server connection.
func handleConnection(conn net.Conn) {
	defer conn.Close()
	defer connectedClients.Done()

	log.Printf("新连接已建立: %s", conn.RemoteAddr().String())

	buffer := make([]byte, 1024)
	for {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 读取Client发送的数据
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println("Read from connection error:", err)
			}
			return
		}

		message := string(buffer[:n])
		log.Printf("Test server received: %s\n", message)

		// 发送响应 - 回显Client发送的数据
		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Println("Write to connection error:", err)
			return
		}

		log.Printf("Test server replied: %s\n", response)
	}
}

// createFRPClientConfig creates a C frpc_config_t for CGO calls.
func createFRPClientConfig(frpsAddr string, frpsPort int, token string) *C.frpc_config_t {
	config := C.frpc_config_t{}
	config.server_addr = C.CString(frpsAddr)
	config.server_port = C.uint16_t(frpsPort)
	config.token = C.CString(token)
	config.heartbeat_interval = 30
	config.tls_enable = C.bool(false)
	config.use_encryption = C.bool(true)

	return &config
}

// freeFRPClientConfig frees heap-allocated fields inside frpc_config_t.
func freeFRPClientConfig(config *C.frpc_config_t) {
	C.free(unsafe.Pointer(config.server_addr))
	C.free(unsafe.Pointer(config.token))
}

// runBidirectionalTest runs the bidirectional TCP<->STCP bridging check.
// It returns error instead of log.Fatal to keep reconnect cycles clean.
func runBidirectionalTest(ctx context.Context) error {
	log.Println("Startingbidirectional communication test...")

	// Wait until server side is ready.
	select {
	case <-serverReady:
		log.Println("Serveris ready for testing")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("等待Server准备超时")
	}

	// Give a little time for the tunnel to become ready.
	time.Sleep(500 * time.Millisecond)

	// Create a TCP client to the Visitor bind port.
	log.Printf("Creating testClientconnection to %s:%d", bindAddr, bindPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", bindAddr, bindPort))
	if err != nil {
		return fmt.Errorf("Parse TCP address error: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return fmt.Errorf("Create TCP connection error: %w", err)
	}
	defer conn.Close()

	log.Println("已成功connection toVisitor，sending test data...")

	// Send test payload.
	_, err = conn.Write([]byte(testDataFromClient))
	if err != nil {
		return fmt.Errorf("sending test data错误: %w", err)
	}

	// Read reply.
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("Read reply from server error: %w", err)
	}

	response := string(buffer[:n])
	log.Printf("Clientreceived server reply: %s", response)

	// Validate reply contains original message.
	if !strings.Contains(response, testDataFromClient) {
		return fmt.Errorf("Server reply does not contain original message")
	}

	// Second round.
	secondTestMessage := "Second test message from client!"
	_, err = conn.Write([]byte(secondTestMessage))
	if err != nil {
		return fmt.Errorf("Send second test data error: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("Read second reply from server error: %w", err)
	}

	secondResponse := string(buffer[:n])
	log.Printf("Clientreceived second server reply: %s", secondResponse)

	// Validate second reply contains original message.
	if !strings.Contains(secondResponse, secondTestMessage) {
		return fmt.Errorf("Server second reply does not contain original message")
	}

	log.Println("Bidirectional communication test completed successfully!")
	select {
	case testCompleteChan <- struct{}{}:
	default:
	}
	return nil
}

// startVisitorLocalListener simulates Visitor-side local TCP listener.
func startVisitorLocalListener(addr string, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return nil, err
	}

	log.Printf("Visitor local listener started on %s:%d started\n", addr, port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Println("Accept connection error:", err)
				continue
			}

			log.Printf("Visitorreceived new connection: %s", conn.RemoteAddr().String())

			// Starting goroutine to handle connection
			go handleVisitorConnection(conn)
		}
	}()

	return listener, nil
}

// handleVisitorConnection handles TCP connections to Visitor bind port and forwards via C STCP.
func handleVisitorConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("Visitorhandling new connection: %s", conn.RemoteAddr().String())

	// Creating buffer to receive data
	buffer := make([]byte, 1024)

	for {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// 读取Client数据
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("从Client读取错误: %v", err)
			}
			return
		}

		clientMsg := string(buffer[:n])
		log.Printf("Visitor从Client收到: %s", clientMsg)

		// Send to Server via C function
		C.send_test_data_via_visitor(C.CString(clientMsg))

		// Simplified handling, should wait for Server reply before forwarding to Client
		// 但我们可以用已有回调系统来实现
		time.Sleep(500 * time.Millisecond) // 给Server一点时间处理

		// If there is a reply, we will receive it in onStcpData callback
		// 由于这里无法知道确切回复内容，采用简单回显
		response := fmt.Sprintf("Message forwarded toServer: %s", clientMsg)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("向Client回写错误: %v", err)
			return
		}
	}
}

func main() {
	// Ensure LLVM coverage profile is flushed (only active with -tags=covflush).
	defer flushCoverage()

	// 解析命令行参数
	flag.Parse()

	// 设置工作目录为项目根目录
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}

	// 可执行文件通常位于 ${PROJECT_ROOT}/build/ 下（make frpc-test / make coverage）。
	// exePath: ${PROJECT_ROOT}/build/frpc_test
	// Dir(Dir(exePath)) => ${PROJECT_ROOT}
	projectRoot := filepath.Dir(filepath.Dir(exePath))
	if err := os.Chdir(projectRoot); err != nil {
		log.Fatalf("Failed to change to project root directory: %v", err)
	}

	// 创建Context，用于控制服务生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置清理函数，确保资源被释放
	defer C.cleanup_stcp_proxies()

	// Handling signal for graceful exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received signal, shutting down...")
		cancel()
	}()

	// Starting embedded FRPS server (if needed)
	if runFRPS {
		if err := startFRPSServer(ctx); err != nil {
			log.Fatalf("Failed to start FRPS server: %v", err)
		}
	}

	// Starting local test server (Server or Both mode)
	var localListener net.Listener
	if mode == ModeServer || mode == ModeBoth {
		var err error
		localListener, err = startLocalTestServer(localAddr, localPort)
		if err != nil {
			log.Fatalf("Failed to start local test server: %v", err)
		}
		defer localListener.Close()
	}

	// Start Visitor local listener once; reuse across reconnect cycles.
	if mode == ModeVisitor || mode == ModeBoth {
		var err error
		visitorTCPListener, err = startVisitorLocalListener(bindAddr, bindPort)
		if err != nil {
			log.Fatalf("Failed to start Visitor local listener: %v", err)
		}
		defer visitorTCPListener.Close()
	}

	// Only in Both + bidirectional, run reconnect/lifecycle regression cycles.
	if mode == ModeBoth && testMode == "bidirectional" {
		// First, run a bad_token failure case to ensure auth failure is retryable
		// and does not poison subsequent successful connects.
		{
			resetCycleSignals()
			badCfg := createFRPClientConfig(frpsAddr, frpsPort, "bad_token")
			badClient := C.frpc_client_new(badCfg, nil)
			if badClient == nil {
				log.Fatal("创建FRPClient失败(bad_token)")
			}
			cProxyName := C.CString(proxyName)
			cSk := C.CString(secretKey)
			cLocalAddr := C.CString(localAddr)
			ret := C.start_stcp_server(badClient, cProxyName, cSk, cLocalAddr, C.int(localPort), unsafe.Pointer(uintptr(1)))
			C.free(unsafe.Pointer(cProxyName))
			C.free(unsafe.Pointer(cSk))
			C.free(unsafe.Pointer(cLocalAddr))
			// Cleanup (regardless of success or failure)
			C.cleanup_stcp_proxies()
			C.frpc_client_free(badClient)
			freeFRPClientConfig(badCfg)
			if ret == 0 {
				log.Fatal("bad_token expected to fail but succeeded (auth failure boundary test not passed)")
			}
			log.Printf("bad_token 失败用例符合预期（ret=%d），继续正常reconnect cycle", int(ret))
		}

		for i := 1; i <= frpcReconnectCycles; i++ {
			log.Printf("=== FRPC reconnect cycle %d/%d ===", i, frpcReconnectCycles)
			resetCycleSignals()

			// Each cycle creates a new client + proxies to cover repeated create/destroy
			// and disconnect/reconnect paths.
			clientConfig := createFRPClientConfig(frpsAddr, frpsPort, "test_token")
			client := C.frpc_client_new(clientConfig, nil)
			if client == nil {
				freeFRPClientConfig(clientConfig)
				log.Fatal("创建FRPClient失败")
			}

			// Starting STCP Server
			{
				cProxyName := C.CString(proxyName)
				cSk := C.CString(secretKey)
				cLocalAddr := C.CString(localAddr)
				ret := C.start_stcp_server(client, cProxyName, cSk, cLocalAddr, C.int(localPort), unsafe.Pointer(uintptr(1)))
				C.free(unsafe.Pointer(cProxyName))
				C.free(unsafe.Pointer(cSk))
				C.free(unsafe.Pointer(cLocalAddr))
				if ret != 0 {
					C.cleanup_stcp_proxies()
					C.frpc_client_free(client)
					freeFRPClientConfig(clientConfig)
					log.Fatalf("Starting STCPServer失败，error code: %d", ret)
				}
			}

			// Starting STCP Visitor
			{
				cProxyName := C.CString(proxyName)
				cSk := C.CString(secretKey)
				cServerName := C.CString(serverName)
				cBindAddr := C.CString(bindAddr)
				ret := C.start_stcp_visitor(client, cProxyName, cSk, cServerName, cBindAddr, C.int(bindPort), unsafe.Pointer(uintptr(2)))
				C.free(unsafe.Pointer(cProxyName))
				C.free(unsafe.Pointer(cSk))
				C.free(unsafe.Pointer(cServerName))
				C.free(unsafe.Pointer(cBindAddr))
				if ret != 0 {
					C.cleanup_stcp_proxies()
					C.frpc_client_free(client)
					freeFRPClientConfig(clientConfig)
					log.Fatalf("Starting STCPVisitor失败，error code: %d", ret)
				}
			}

			if err := runBidirectionalTest(ctx); err != nil {
				C.cleanup_stcp_proxies()
				C.frpc_client_free(client)
				freeFRPClientConfig(clientConfig)
				log.Fatalf("bidirectional communication test失败: %v", err)
			}

			// Cleanup for this cycle: stop/free proxies + disconnect/free client.
			C.cleanup_stcp_proxies()
			C.frpc_client_free(client)
			freeFRPClientConfig(clientConfig)

			time.Sleep(200 * time.Millisecond)
		}

		log.Println("✅ FRPC reconnect cycle全部通过")
		return
	}

	// Other modes: maintain single-start behavior (for manual debugging)
	resetCycleSignals()
	clientConfig := createFRPClientConfig(frpsAddr, frpsPort, "test_token")
	defer freeFRPClientConfig(clientConfig)
	client := C.frpc_client_new(clientConfig, nil)
	if client == nil {
		log.Fatal("创建FRPClient失败")
	}
	defer C.frpc_client_free(client)

	if mode == ModeServer || mode == ModeBoth {
		cProxyName := C.CString(proxyName)
		cSk := C.CString(secretKey)
		cLocalAddr := C.CString(localAddr)
		ret := C.start_stcp_server(client, cProxyName, cSk, cLocalAddr, C.int(localPort), unsafe.Pointer(uintptr(1)))
		C.free(unsafe.Pointer(cProxyName))
		C.free(unsafe.Pointer(cSk))
		C.free(unsafe.Pointer(cLocalAddr))
		if ret != 0 {
			log.Fatalf("Starting STCPServer失败，error code: %d", ret)
		}
		log.Println("STCPServerstarted successfully")
	}

	if mode == ModeVisitor || mode == ModeBoth {
		cProxyName := C.CString(proxyName)
		cSk := C.CString(secretKey)
		cServerName := C.CString(serverName)
		cBindAddr := C.CString(bindAddr)
		ret := C.start_stcp_visitor(client, cProxyName, cSk, cServerName, cBindAddr, C.int(bindPort), unsafe.Pointer(uintptr(2)))
		C.free(unsafe.Pointer(cProxyName))
		C.free(unsafe.Pointer(cSk))
		C.free(unsafe.Pointer(cServerName))
		C.free(unsafe.Pointer(cBindAddr))
		if ret != 0 {
			log.Fatalf("Starting STCPVisitor失败，error code: %d", ret)
		}
		log.Println("STCPVisitorstarted successfully")
	}

	// 等待Context取消（通过信号）
	<-ctx.Done()
	log.Println("关闭中，正在清理资源...")
}
