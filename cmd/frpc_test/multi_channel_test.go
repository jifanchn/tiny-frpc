//go:build multi_channel
// +build multi_channel

package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include
#cgo LDFLAGS: -L../../build -lfrpc -lyamux -lcrypto -ltools -lwrapper

#include <stdlib.h>
#include <string.h>
#include "frpc.h"
#include "frpc-stcp.h"

// Callback function declarations
extern int onMultiChannelData(void* user_ctx, unsigned char* data, size_t len);
extern int onMultiChannelWrite(void* user_ctx, unsigned char* data, size_t len);
extern void onMultiChannelConnection(void* user_ctx, int connected, int error_code);

// Global proxy pointers for multiple channels
static frpc_stcp_proxy_t* g_multi_server_proxies[4] = {NULL, NULL, NULL, NULL};
static frpc_stcp_proxy_t* g_multi_visitor_proxies[4] = {NULL, NULL, NULL, NULL};

static int start_multi_stcp_server(frpc_client_t* client, int index, const char* proxy_name,
                                   const char* sk, const char* local_addr, int local_port, void* user_ctx) {
    if (index < 0 || index >= 4) return -1;

    frpc_stcp_config_t config;
    memset(&config, 0, sizeof(config));

    config.role = FRPC_STCP_ROLE_SERVER;
    config.proxy_name = proxy_name;
    config.sk = sk;
    config.local_addr = local_addr;
    config.local_port = local_port;
    config.on_data = onMultiChannelData;
    config.on_write = onMultiChannelWrite;
    config.on_connection = onMultiChannelConnection;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
    if (!proxy) return -1;

    int ret = frpc_stcp_proxy_start(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    frpc_stcp_transport_config_t transport_config;
    transport_config.use_encryption = 1;
    transport_config.use_compression = 0;
    frpc_stcp_set_transport_config(proxy, &transport_config);

    const char* allowed_users[] = {"*"};
    frpc_stcp_server_set_allow_users(proxy, allowed_users, 1);

    ret = frpc_stcp_server_register(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_stop(proxy);
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    g_multi_server_proxies[index] = proxy;
    return 0;
}

static int start_multi_stcp_visitor(frpc_client_t* client, int index, const char* proxy_name,
                                    const char* sk, const char* server_name,
                                    const char* bind_addr, int bind_port, void* user_ctx) {
    if (index < 0 || index >= 4) return -1;

    frpc_stcp_config_t config;
    memset(&config, 0, sizeof(config));

    config.role = FRPC_STCP_ROLE_VISITOR;
    config.proxy_name = proxy_name;
    config.sk = sk;
    config.server_name = server_name;
    config.bind_addr = bind_addr;
    config.bind_port = bind_port;
    config.on_data = onMultiChannelData;
    config.on_write = onMultiChannelWrite;
    config.on_connection = onMultiChannelConnection;

    frpc_stcp_proxy_t* proxy = frpc_stcp_proxy_new(client, &config, user_ctx);
    if (!proxy) return -1;

    int ret = frpc_stcp_proxy_start(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    frpc_stcp_transport_config_t transport_config;
    transport_config.use_encryption = 1;
    transport_config.use_compression = 0;
    frpc_stcp_set_transport_config(proxy, &transport_config);

    ret = frpc_stcp_visitor_connect(proxy);
    if (ret != 0) {
        frpc_stcp_proxy_stop(proxy);
        frpc_stcp_proxy_free(proxy);
        return ret;
    }

    g_multi_visitor_proxies[index] = proxy;
    return 0;
}

static int send_data_via_visitor(int index, const char* data) {
    if (index < 0 || index >= 4 || g_multi_visitor_proxies[index] == NULL) return -1;
    return frpc_stcp_send(g_multi_visitor_proxies[index], (const unsigned char*)data, strlen(data));
}

static void cleanup_multi_proxies() {
    for (int i = 0; i < 4; i++) {
        if (g_multi_visitor_proxies[i]) {
            frpc_stcp_proxy_stop(g_multi_visitor_proxies[i]);
            frpc_stcp_proxy_free(g_multi_visitor_proxies[i]);
            g_multi_visitor_proxies[i] = NULL;
        }
        if (g_multi_server_proxies[i]) {
            frpc_stcp_proxy_stop(g_multi_server_proxies[i]);
            frpc_stcp_proxy_free(g_multi_server_proxies[i]);
            g_multi_server_proxies[i] = NULL;
        }
    }
}

*/
import "C"
import (
	"context"
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

// Multi-channel test configuration
const (
	numChannels     = 3
	baseServerPort  = 8100
	baseVisitorPort = 9100
	multiTestCycles = 2
)

// Synchronization for multi-channel test
var (
	multiChannelReady = make([]chan struct{}, numChannels)
	multiDataReceived = make([]chan string, numChannels)
	multiChannelMutex sync.Mutex
)

func init() {
	for i := 0; i < numChannels; i++ {
		multiChannelReady[i] = make(chan struct{}, 1)
		multiDataReceived[i] = make(chan string, 10)
	}
}

//export onMultiChannelData
func onMultiChannelData(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	channelID := int(uintptr(user_ctx)) % 100 // Extract channel ID from user_ctx
	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))
	log.Printf("[Channel %d] Received %d bytes: %s", channelID, length, string(goData))

	multiChannelMutex.Lock()
	if channelID < numChannels {
		select {
		case multiDataReceived[channelID] <- string(goData):
		default:
		}
	}
	multiChannelMutex.Unlock()

	return C.int(length)
}

//export onMultiChannelWrite
func onMultiChannelWrite(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	return C.int(length)
}

//export onMultiChannelConnection
func onMultiChannelConnection(user_ctx unsafe.Pointer, connected C.int, error_code C.int) {
	channelID := int(uintptr(user_ctx)) % 100
	isServer := (int(uintptr(user_ctx)) / 100) == 1

	role := "Visitor"
	if isServer {
		role = "Server"
	}

	if connected != 0 {
		log.Printf("[Channel %d] %s connected", channelID, role)
		multiChannelMutex.Lock()
		if channelID < numChannels && isServer {
			select {
			case multiChannelReady[channelID] <- struct{}{}:
			default:
			}
		}
		multiChannelMutex.Unlock()
	} else {
		log.Printf("[Channel %d] %s disconnected, error: %d", channelID, role, error_code)
	}
}

// startMultiFRPSServer starts embedded FRPS for multi-channel test
func startMultiFRPSServer(ctx context.Context, port int) error {
	frplog.InitLogger("console", "info", 0, false)

	cfg := &v1.ServerConfig{
		Auth: v1.AuthServerConfig{
			Method: "token",
			Token:  "multi_test_token",
		},
		BindAddr: "0.0.0.0",
		BindPort: port,
		Transport: v1.ServerTransportConfig{
			TCPMux: new(bool),
		},
	}
	cfg.Complete()

	svr, err := server.NewService(cfg)
	if err != nil {
		return fmt.Errorf("failed to create FRPS service: %w", err)
	}

	go svr.Run(ctx)
	time.Sleep(2 * time.Second)
	log.Printf("Multi-channel FRPS started on port %d", port)
	return nil
}

// startMultiLocalServers starts echo servers for each channel
func startMultiLocalServers() ([]net.Listener, error) {
	listeners := make([]net.Listener, numChannels)

	for i := 0; i < numChannels; i++ {
		port := baseServerPort + i
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			// Close already started listeners
			for j := 0; j < i; j++ {
				listeners[j].Close()
			}
			return nil, fmt.Errorf("failed to start local server %d: %w", i, err)
		}
		listeners[i] = listener
		log.Printf("[Channel %d] Local echo server started on port %d", i, port)

		go func(idx int, l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}
				go handleMultiConnection(idx, conn)
			}
		}(i, listener)
	}

	return listeners, nil
}

func handleMultiConnection(channelID int, conn net.Conn) {
	defer conn.Close()
	log.Printf("[Channel %d] New connection from %s", channelID, conn.RemoteAddr())

	buffer := make([]byte, 1024)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Channel %d] Read error: %v", channelID, err)
			}
			return
		}

		msg := string(buffer[:n])
		log.Printf("[Channel %d] Echo server received: %s", channelID, msg)

		response := fmt.Sprintf("[Channel %d] Echo: %s", channelID, msg)
		conn.Write([]byte(response))
	}
}

// startMultiVisitorListeners starts TCP listeners for each visitor
func startMultiVisitorListeners() ([]net.Listener, error) {
	listeners := make([]net.Listener, numChannels)

	for i := 0; i < numChannels; i++ {
		port := baseVisitorPort + i
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			for j := 0; j < i; j++ {
				listeners[j].Close()
			}
			return nil, fmt.Errorf("failed to start visitor listener %d: %w", i, err)
		}
		listeners[i] = listener
		log.Printf("[Channel %d] Visitor listener started on port %d", i, port)

		go func(idx int, l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					continue
				}
				go handleMultiVisitorConnection(idx, conn)
			}
		}(i, listener)
	}

	return listeners, nil
}

func handleMultiVisitorConnection(channelID int, conn net.Conn) {
	defer conn.Close()
	log.Printf("[Channel %d] Visitor received connection from %s", channelID, conn.RemoteAddr())

	buffer := make([]byte, 1024)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Channel %d] Visitor read error: %v", channelID, err)
			}
			return
		}

		msg := string(buffer[:n])
		log.Printf("[Channel %d] Visitor received from client: %s", channelID, msg)

		// Forward via C STCP
		cMsg := C.CString(msg)
		C.send_data_via_visitor(C.int(channelID), cMsg)
		C.free(unsafe.Pointer(cMsg))

		time.Sleep(300 * time.Millisecond)

		response := fmt.Sprintf("[Channel %d] Forwarded: %s", channelID, msg)
		conn.Write([]byte(response))
	}
}

func runMultiChannelTest(ctx context.Context) error {
	log.Println("=== Starting multi-channel STCP test ===")

	// Wait for all servers to be ready
	for i := 0; i < numChannels; i++ {
		select {
		case <-multiChannelReady[i]:
			log.Printf("[Channel %d] Server ready", i)
		case <-time.After(10 * time.Second):
			return fmt.Errorf("timeout waiting for channel %d server to be ready", i)
		}
	}

	time.Sleep(500 * time.Millisecond)

	// Test each channel
	for i := 0; i < numChannels; i++ {
		port := baseVisitorPort + i
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return fmt.Errorf("failed to connect to visitor %d: %w", i, err)
		}

		testMsg := fmt.Sprintf("Multi-channel test message for channel %d", i)
		_, err = conn.Write([]byte(testMsg))
		if err != nil {
			conn.Close()
			return fmt.Errorf("failed to write to channel %d: %w", i, err)
		}

		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			conn.Close()
			return fmt.Errorf("failed to read from channel %d: %w", i, err)
		}

		response := string(buffer[:n])
		log.Printf("[Channel %d] Received response: %s", i, response)

		if !strings.Contains(response, fmt.Sprintf("Channel %d", i)) {
			conn.Close()
			return fmt.Errorf("channel %d: response mismatch", i)
		}

		conn.Close()
		log.Printf("[Channel %d] Test passed", i)
	}

	log.Println("=== Multi-channel STCP test completed successfully ===")
	return nil
}

func main() {
	defer flushCoverage()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	projectRoot := filepath.Dir(filepath.Dir(exePath))
	if err := os.Chdir(projectRoot); err != nil {
		log.Fatalf("Failed to change to project root: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer C.cleanup_multi_proxies()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	frpsPort := 7002
	if err := startMultiFRPSServer(ctx, frpsPort); err != nil {
		log.Fatalf("Failed to start FRPS: %v", err)
	}

	localListeners, err := startMultiLocalServers()
	if err != nil {
		log.Fatalf("Failed to start local servers: %v", err)
	}
	defer func() {
		for _, l := range localListeners {
			l.Close()
		}
	}()

	visitorListeners, err := startMultiVisitorListeners()
	if err != nil {
		log.Fatalf("Failed to start visitor listeners: %v", err)
	}
	defer func() {
		for _, l := range visitorListeners {
			l.Close()
		}
	}()

	// Run multi-channel test cycles
	for cycle := 1; cycle <= multiTestCycles; cycle++ {
		log.Printf("=== Multi-channel test cycle %d/%d ===", cycle, multiTestCycles)

		// Reset channels
		for i := 0; i < numChannels; i++ {
			multiChannelReady[i] = make(chan struct{}, 1)
			multiDataReceived[i] = make(chan string, 10)
		}

		// Create FRP client config
		cAddr := C.CString("127.0.0.1")
		cToken := C.CString("multi_test_token")
		defer C.free(unsafe.Pointer(cAddr))
		defer C.free(unsafe.Pointer(cToken))

		config := C.frpc_config_t{
			server_addr:        cAddr,
			server_port:        C.uint16_t(frpsPort),
			token:              cToken,
			heartbeat_interval: 30,
			tls_enable:         C.bool(false),
		}

		client := C.frpc_client_new(&config, nil)
		if client == nil {
			log.Fatal("Failed to create FRP client")
		}

		// Start servers for all channels
		for i := 0; i < numChannels; i++ {
			proxyName := C.CString(fmt.Sprintf("multi_stcp_%d", i))
			sk := C.CString("multi_secret")
			localAddr := C.CString("127.0.0.1")

			// user_ctx: 100 + channelID for server
			userCtx := unsafe.Pointer(uintptr(100 + i))
			ret := C.start_multi_stcp_server(client, C.int(i), proxyName, sk, localAddr,
				C.int(baseServerPort+i), userCtx)

			C.free(unsafe.Pointer(proxyName))
			C.free(unsafe.Pointer(sk))
			C.free(unsafe.Pointer(localAddr))

			if ret != 0 {
				C.cleanup_multi_proxies()
				C.frpc_client_free(client)
				log.Fatalf("Failed to start server %d: %d", i, ret)
			}
			log.Printf("[Channel %d] Server started", i)
		}

		// Start visitors for all channels
		for i := 0; i < numChannels; i++ {
			proxyName := C.CString(fmt.Sprintf("multi_stcp_visitor_%d", i))
			sk := C.CString("multi_secret")
			serverName := C.CString(fmt.Sprintf("multi_stcp_%d", i))
			bindAddr := C.CString("127.0.0.1")

			// user_ctx: channelID for visitor
			userCtx := unsafe.Pointer(uintptr(i))
			ret := C.start_multi_stcp_visitor(client, C.int(i), proxyName, sk, serverName,
				bindAddr, C.int(baseVisitorPort+i), userCtx)

			C.free(unsafe.Pointer(proxyName))
			C.free(unsafe.Pointer(sk))
			C.free(unsafe.Pointer(serverName))
			C.free(unsafe.Pointer(bindAddr))

			if ret != 0 {
				C.cleanup_multi_proxies()
				C.frpc_client_free(client)
				log.Fatalf("Failed to start visitor %d: %d", i, ret)
			}
			log.Printf("[Channel %d] Visitor started", i)
		}

		if err := runMultiChannelTest(ctx); err != nil {
			C.cleanup_multi_proxies()
			C.frpc_client_free(client)
			log.Fatalf("Multi-channel test failed: %v", err)
		}

		C.cleanup_multi_proxies()
		C.frpc_client_free(client)
		time.Sleep(300 * time.Millisecond)
	}

	log.Println("✅ Multi-channel STCP test passed!")
}
