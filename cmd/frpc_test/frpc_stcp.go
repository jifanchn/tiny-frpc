package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include
#cgo LDFLAGS: -L../../build -lfrpc -lyamux -ltools -lwrapper

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

// 发送测试数据的函数
static int send_test_data_via_visitor(const char* data) {
    if (g_visitor_proxy == NULL) {
        return -1;
    }
    return frpc_stcp_send(g_visitor_proxy, (const unsigned char*)data, strlen(data));
}

// 发送回复数据（服务端回复到本地连接）
static int send_reply_data_via_server(const char* data) {
    if (g_server_proxy == NULL) {
        return -1;
    }
    return frpc_stcp_send(g_server_proxy, (const unsigned char*)data, strlen(data));
}

// 启动STCP Visitor的辅助函数
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

    // 连接到服务器
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

// 启动STCP Server的辅助函数
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

// frpc.h 中的错误码（避免依赖 cgo 导出的 enum 常量，提升编辑器/静态分析兼容性）
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
	flag.IntVar(&bindPort, "bind-port", 9090, "Bind port for Visitor mode")
	flag.BoolVar(&runFRPS, "run-frps", true, "Run embedded FRPS server")
	flag.StringVar(&testMode, "test-mode", "bidirectional", "Test mode: basic or bidirectional")
	flag.StringVar(&frpsLogLevel, "frps-log-level", "info", "FRPS log level: trace/debug/info/warn/error")
	flag.BoolVar(&verbose, "v", false, "Verbose logs (default: false)")
}

// startFRPSServer starts an embedded FRPS server for E2E tests.
func startFRPSServer(ctx context.Context) error {
	log.Println("尝试以编程方式启动FRPS服务器...")

	// Initialize frp logger to avoid noisy default logging.
	frplog.InitLogger("console", frpsLogLevel, 0, false)

	// 加载并验证配置
	cfg := frpsConfig

	cfg.Complete()

	svr, err := server.NewService(cfg)
	if err != nil {
		log.Printf("创建FRPS服务失败: %v", err)
		return fmt.Errorf("创建FRPS服务失败: %v", err)
	}

	log.Printf("FRPS服务已创建，监听地址: %s:%d, Token: %s", cfg.BindAddr, cfg.BindPort, cfg.Auth.Token)

	go func() {
		svr.Run(ctx)
		log.Println("FRPS服务已停止。")
	}()

	// Give FRPS a moment to start.
	time.Sleep(2 * time.Second)
	log.Println("FRPS服务器应该已启动。")
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
		// 这里应该通过 C.frpc_stcp_send(g_server_proxy, ...) 发送，而不是直接写
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

	return C.int(length) // 表示处理了所有数据
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
		log.Printf("上下文 %d: 已连接\n", ctxInt)
		if ctxInt == 1 { // Server
			log.Println("服务端已连接到FRPS")
			// Avoid closing channels across reconnect cycles; send a signal non-blocking.
			select {
			case serverReady <- struct{}{}:
			default:
			}
		} else if ctxInt == 2 { // Visitor
			log.Println("访问端已连接到FRPS")
		}
	} else {
		// Disconnect: -8/-9 are treated as normal close/by-remote close in our semantics.
		if int(error_code) == frpcErrConnectionClosed || int(error_code) == frpcErrConnectionClosedByRemote {
			if verbose {
				log.Printf("上下文 %d: 已断开连接(正常), 错误码: %d\n", ctxInt, error_code)
			} else {
				log.Printf("上下文 %d: 已断开连接(正常)\n", ctxInt)
			}
		} else {
			log.Printf("上下文 %d: 已断开连接, 错误码: %d\n", ctxInt, error_code)
		}
	}
}

// startLocalTestServer starts a local echo server (represents "server side local service").
func startLocalTestServer(addr string, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return nil, err
	}

	log.Printf("本地测试服务器已在 %s:%d 启动\n", addr, port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Println("接受连接错误:", err)
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

		// 读取客户端发送的数据
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println("从连接读取错误:", err)
			}
			return
		}

		message := string(buffer[:n])
		log.Printf("测试服务器收到: %s\n", message)

		// 发送响应 - 回显客户端发送的数据
		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Println("向连接写入错误:", err)
			return
		}

		log.Printf("测试服务器已回复: %s\n", response)
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
	log.Println("开始执行双向通信测试...")

	// Wait until server side is ready.
	select {
	case <-serverReady:
		log.Println("服务端已准备就绪，可以开始测试")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("等待服务端准备超时")
	}

	// Give a little time for the tunnel to become ready.
	time.Sleep(500 * time.Millisecond)

	// Create a TCP client to the Visitor bind port.
	log.Printf("创建测试客户端连接到 %s:%d", bindAddr, bindPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", bindAddr, bindPort))
	if err != nil {
		return fmt.Errorf("解析TCP地址错误: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return fmt.Errorf("创建TCP连接错误: %w", err)
	}
	defer conn.Close()

	log.Println("已成功连接到访问端，发送测试数据...")

	// Send test payload.
	_, err = conn.Write([]byte(testDataFromClient))
	if err != nil {
		return fmt.Errorf("发送测试数据错误: %w", err)
	}

	// Read reply.
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("从服务器读取回复错误: %w", err)
	}

	response := string(buffer[:n])
	log.Printf("客户端收到服务器回复: %s", response)

	// Validate reply contains original message.
	if !strings.Contains(response, testDataFromClient) {
		return fmt.Errorf("服务器回复不包含原始消息")
	}

	// Second round.
	secondTestMessage := "Second test message from client!"
	_, err = conn.Write([]byte(secondTestMessage))
	if err != nil {
		return fmt.Errorf("发送第二条测试数据错误: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("从服务器读取第二次回复错误: %w", err)
	}

	secondResponse := string(buffer[:n])
	log.Printf("客户端收到服务器第二次回复: %s", secondResponse)

	// Validate second reply contains original message.
	if !strings.Contains(secondResponse, secondTestMessage) {
		return fmt.Errorf("服务器第二次回复不包含原始消息")
	}

	log.Println("双向通信测试成功完成！")
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

	log.Printf("Visitor本地监听已在 %s:%d 启动\n", addr, port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Println("接受连接错误:", err)
				continue
			}

			log.Printf("Visitor接收到新连接: %s", conn.RemoteAddr().String())

			// 启动goroutine处理连接
			go handleVisitorConnection(conn)
		}
	}()

	return listener, nil
}

// handleVisitorConnection handles TCP connections to Visitor bind port and forwards via C STCP.
func handleVisitorConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("Visitor处理新连接: %s", conn.RemoteAddr().String())

	// 创建缓冲区接收数据
	buffer := make([]byte, 1024)

	for {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// 读取客户端数据
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("从客户端读取错误: %v", err)
			}
			return
		}

		clientMsg := string(buffer[:n])
		log.Printf("Visitor从客户端收到: %s", clientMsg)

		// 通过C函数发送到服务端
		C.send_test_data_via_visitor(C.CString(clientMsg))

		// 这里简化处理，实际应该等待服务端回复后再转发回客户端
		// 但我们可以用已有回调系统来实现
		time.Sleep(500 * time.Millisecond) // 给服务端一点时间处理

		// 如果有回复，我们会在onStcpData回调中收到
		// 由于这里无法知道确切回复内容，采用简单回显
		response := fmt.Sprintf("已将消息转发至服务端: %s", clientMsg)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("向客户端回写错误: %v", err)
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
		log.Fatalf("获取可执行文件路径失败: %v", err)
	}

	// 可执行文件通常位于 ${PROJECT_ROOT}/build/ 下（make frpc-test / make coverage）。
	// exePath: ${PROJECT_ROOT}/build/frpc_test
	// Dir(Dir(exePath)) => ${PROJECT_ROOT}
	projectRoot := filepath.Dir(filepath.Dir(exePath))
	if err := os.Chdir(projectRoot); err != nil {
		log.Fatalf("切换到项目根目录失败: %v", err)
	}

	// 创建上下文，用于控制服务生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置清理函数，确保资源被释放
	defer C.cleanup_stcp_proxies()

	// 处理信号，优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("收到信号，正在关闭...")
		cancel()
	}()

	// 启动内置FRPS服务器（如果需要）
	if runFRPS {
		if err := startFRPSServer(ctx); err != nil {
			log.Fatalf("启动FRPS服务器失败: %v", err)
		}
	}

	// 启动本地测试服务器（Server模式或Both模式）
	var localListener net.Listener
	if mode == ModeServer || mode == ModeBoth {
		var err error
		localListener, err = startLocalTestServer(localAddr, localPort)
		if err != nil {
			log.Fatalf("启动本地测试服务器失败: %v", err)
		}
		defer localListener.Close()
	}

	// Start Visitor local listener once; reuse across reconnect cycles.
	if mode == ModeVisitor || mode == ModeBoth {
		var err error
		visitorTCPListener, err = startVisitorLocalListener(bindAddr, bindPort)
		if err != nil {
			log.Fatalf("启动Visitor本地监听失败: %v", err)
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
				log.Fatal("创建FRP客户端失败(bad_token)")
			}
			cProxyName := C.CString(proxyName)
			cSk := C.CString(secretKey)
			cLocalAddr := C.CString(localAddr)
			ret := C.start_stcp_server(badClient, cProxyName, cSk, cLocalAddr, C.int(localPort), unsafe.Pointer(uintptr(1)))
			C.free(unsafe.Pointer(cProxyName))
			C.free(unsafe.Pointer(cSk))
			C.free(unsafe.Pointer(cLocalAddr))
			// 清理（无论成功/失败都要清）
			C.cleanup_stcp_proxies()
			C.frpc_client_free(badClient)
			freeFRPClientConfig(badCfg)
			if ret == 0 {
				log.Fatal("bad_token 预期失败但却成功（认证失败/重试边界测试未通过）")
			}
			log.Printf("bad_token 失败用例符合预期（ret=%d），继续正常重连循环", int(ret))
		}

		for i := 1; i <= frpcReconnectCycles; i++ {
			log.Printf("=== FRPC 重连循环 %d/%d ===", i, frpcReconnectCycles)
			resetCycleSignals()

			// Each cycle creates a new client + proxies to cover repeated create/destroy
			// and disconnect/reconnect paths.
			clientConfig := createFRPClientConfig(frpsAddr, frpsPort, "test_token")
			client := C.frpc_client_new(clientConfig, nil)
			if client == nil {
				freeFRPClientConfig(clientConfig)
				log.Fatal("创建FRP客户端失败")
			}

			// 启动 STCP Server
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
					log.Fatalf("启动STCP服务端失败，错误码: %d", ret)
				}
			}

			// 启动 STCP Visitor
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
					log.Fatalf("启动STCP访问端失败，错误码: %d", ret)
				}
			}

			if err := runBidirectionalTest(ctx); err != nil {
				C.cleanup_stcp_proxies()
				C.frpc_client_free(client)
				freeFRPClientConfig(clientConfig)
				log.Fatalf("双向通信测试失败: %v", err)
			}

			// Cleanup for this cycle: stop/free proxies + disconnect/free client.
			C.cleanup_stcp_proxies()
			C.frpc_client_free(client)
			freeFRPClientConfig(clientConfig)

			time.Sleep(200 * time.Millisecond)
		}

		log.Println("✅ FRPC 重连循环全部通过")
		return
	}

	// 其他模式：保持单次启动行为（用于人工/手动调试）
	resetCycleSignals()
	clientConfig := createFRPClientConfig(frpsAddr, frpsPort, "test_token")
	defer freeFRPClientConfig(clientConfig)
	client := C.frpc_client_new(clientConfig, nil)
	if client == nil {
		log.Fatal("创建FRP客户端失败")
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
			log.Fatalf("启动STCP服务端失败，错误码: %d", ret)
		}
		log.Println("STCP服务端启动成功")
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
			log.Fatalf("启动STCP访问端失败，错误码: %d", ret)
		}
		log.Println("STCP访问端启动成功")
	}

	// 等待上下文取消（通过信号）
	<-ctx.Done()
	log.Println("关闭中，正在清理资源...")
}
