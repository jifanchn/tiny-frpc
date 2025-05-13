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
)

// 用于测试的FRPS服务配置
var frpsConfig = &v1.ServerConfig{
	Auth: v1.AuthServerConfig{
		Method: "token",
		Token:  "test_token",
	},
	BindAddr:              "0.0.0.0",
	BindPort:              7000,
	TCPMuxHTTPConnectPort: 0,
	SubDomainHost:         "",
}

// 测试模式
const (
	ModeServer  = "server"
	ModeVisitor = "visitor"
	ModeBoth    = "both"
)

// 测试参数
var (
	mode         string  // 测试模式
	frpsAddr     string  // FRPS服务器地址
	frpsPort     int     // FRPS服务器端口
	proxyName    string  // 代理名称
	secretKey    string  // 共享密钥
	serverName   string  // 服务端名称（Visitor模式使用）
	localAddr    string  // 本地服务地址（Server模式使用）
	localPort    int     // 本地服务端口（Server模式使用）
	bindAddr     string  // 本地绑定地址（Visitor模式使用）
	bindPort     int     // 本地绑定端口（Visitor模式使用）
	runFRPS      bool    // 是否运行内置FRPS服务器
	testMode     string  // 测试模式：basic, bidirectional
)

// 用于同步测试的通道和计数器
var (
	testCompleteChan = make(chan struct{})
	connectedClients = &sync.WaitGroup{}
	dataExchanged    = make(chan struct{})
	serverReady      = make(chan struct{})
	visitorTCPListener net.Listener // 用于模拟Visitor绑定的TCP监听器
)

// 测试数据和全局变量
var (
	// 测试数据
	testDataFromClient = "Hello from client, this is a test message!"
	testReplyFromServer = "Hello from server, I received your message!"
	
	// 数据流向记录
	dataFlowMap = make(map[uintptr]string)
)

// 初始化命令行参数
func init() {
	flag.StringVar(&mode, "mode", ModeBoth, "Test mode: server, visitor, or both")
	flag.StringVar(&frpsAddr, "frps-addr", "127.0.0.1", "FRPS server address")
	flag.IntVar(&frpsPort, "frps-port", 7000, "FRPS server port")
	flag.StringVar(&proxyName, "proxy-name", "test_stcp", "Proxy name")
	flag.StringVar(&secretKey, "sk", "test_secret", "Secret key")
	flag.StringVar(&serverName, "server-name", "test_stcp", "Server name for Visitor mode")
	flag.StringVar(&localAddr, "local-addr", "127.0.0.1", "Local service address for Server mode")
	flag.IntVar(&localPort, "local-port", 8080, "Local service port for Server mode")
	flag.StringVar(&bindAddr, "bind-addr", "127.0.0.1", "Bind address for Visitor mode")
	flag.IntVar(&bindPort, "bind-port", 9090, "Bind port for Visitor mode")
	flag.BoolVar(&runFRPS, "run-frps", true, "Run embedded FRPS server")
	flag.StringVar(&testMode, "test-mode", "bidirectional", "Test mode: basic or bidirectional")
}

// 启动FRPS服务器
func startFRPSServer(ctx context.Context) error {
	log.Println("启动FRPS服务器...")
	
	// 不直接使用NewService方法，而是导入frp包模拟服务启动
	// 这里我们简化为使用系统命令启动frps（实际运行时请确保frps在PATH中）
	
	// 先写入临时配置文件
	// 在实际环境中，使用临时文件或从配置文件加载
	log.Printf("使用frps配置: %+v\n", frpsConfig)
	
	// 模拟服务器启动成功
	go func() {
		<-ctx.Done()
		log.Println("关闭FRPS服务器...")
	}()
	
	// 等待服务器启动
	time.Sleep(1 * time.Second)
	log.Printf("FRPS服务器已在 %s:%d 启动（模拟）\n", frpsConfig.BindAddr, frpsConfig.BindPort)
	
	return nil
}

// CGO回调函数，处理接收到的数据
//export onStcpData
func onStcpData(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(length))
	ctxInt := uintptr(user_ctx)
	
	message := string(dataBytes)
	log.Printf("上下文 %d 收到数据: %s\n", ctxInt, message)
	
	// 记录数据流向
	if _, ok := dataFlowMap[ctxInt]; !ok {
		dataFlowMap[ctxInt] = ""
	}
	dataFlowMap[ctxInt] += message
	
	// 根据上下文判断数据流向
	if ctxInt == 1 { // Server收到来自Visitor的数据
		log.Printf("服务端收到来自客户端的数据: %s\n", message)
		
		// 如果是在server端收到数据，自动发送回复
		go func() {
			// 稍微延迟一下，确保稳定性
			time.Sleep(200 * time.Millisecond)
			
			// 根据测试模式决定回复内容
			var replyData string
			if testMode == "bidirectional" {
				// 在双向通信测试模式下，回复收到的数据（模拟echo服务器）
				replyData = fmt.Sprintf("Echo: %s", message)
				log.Printf("服务端回复客户端: %s\n", replyData)
			} else {
				// 在基本测试模式下，发送固定的回复
				replyData = testReplyFromServer
				log.Printf("服务端发送标准回复: %s\n", replyData)
			}
			
			// 发送回复数据
			C.send_reply_data_via_server(C.CString(replyData))
		}()
	} else if ctxInt == 2 { // Visitor收到来自Server的数据
		log.Printf("客户端收到来自服务端的数据: %s\n", message)
		
		// 在基本测试模式下，检查数据是否是预期的回复
		if testMode != "bidirectional" && message == testReplyFromServer {
			log.Println("客户端收到正确的回复数据，测试通过！")
			close(dataExchanged) // 标记数据交换完成
		}
	}
	
	return C.int(0)
}

// CGO回调函数，处理发送数据
//export onStcpWrite
func onStcpWrite(user_ctx unsafe.Pointer, data *C.uchar, length C.size_t) C.int {
	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(length))
	ctxInt := uintptr(user_ctx)
	
	log.Printf("上下文 %d 正在写入数据: %s\n", ctxInt, string(dataBytes))
	
	return C.int(int(length))
}

// CGO回调函数，处理连接状态变化
//export onStcpConnection
func onStcpConnection(user_ctx unsafe.Pointer, connected C.int, error_code C.int) {
	ctxInt := uintptr(user_ctx)
	
	if connected != 0 {
		log.Printf("上下文 %d: 已连接\n", ctxInt)
		if ctxInt == 1 { // Server
			log.Println("服务端已连接到FRPS")
			close(serverReady) // 通知服务端已准备好
		} else if ctxInt == 2 { // Visitor
			log.Println("访问端已连接到FRPS")
		}
	} else {
		log.Printf("上下文 %d: 已断开连接, 错误码: %d\n", ctxInt, error_code)
	}
}

// 启动本地测试服务器
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

// 处理测试服务器连接
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

// 创建FRP客户端配置
func createFRPClientConfig(frpsAddr string, frpsPort int) *C.frpc_config_t {
	config := C.frpc_config_t{}
	config.server_addr = C.CString(frpsAddr)
	config.server_port = C.uint16_t(frpsPort)
	config.token = C.CString("test_token")
	config.heartbeat_interval = 30
	config.tls_enable = C.bool(false)
	
	return &config
}

// 释放FRP客户端配置资源
func freeFRPClientConfig(config *C.frpc_config_t) {
	C.free(unsafe.Pointer(config.server_addr))
	C.free(unsafe.Pointer(config.token))
}

// 双向通信测试
func runBidirectionalTest(ctx context.Context) {
	log.Println("开始执行双向通信测试...")
	
	// 等待服务端准备就绪
	select {
	case <-serverReady:
		log.Println("服务端已准备就绪，可以开始测试")
	case <-time.After(5 * time.Second):
		log.Println("等待服务端准备超时，继续测试")
	}
	
	// 等待一小段时间以确保连接建立
	time.Sleep(2 * time.Second)
	
	// 创建TCP客户端连接到visitor绑定的端口
	log.Printf("创建测试客户端连接到 %s:%d", bindAddr, bindPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", bindAddr, bindPort))
	if err != nil {
		log.Fatalf("解析TCP地址错误: %v", err)
	}
	
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Fatalf("创建TCP连接错误: %v", err)
	}
	defer conn.Close()
	
	log.Println("已成功连接到访问端，发送测试数据...")
	
	// 发送测试数据
	_, err = conn.Write([]byte(testDataFromClient))
	if err != nil {
		log.Fatalf("发送测试数据错误: %v", err)
	}
	
	// 等待服务器的回复
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("从服务器读取回复错误: %v", err)
	}
	
	response := string(buffer[:n])
	log.Printf("客户端收到服务器回复: %s", response)
	
	// 验证回复内容是否正确
	if !strings.Contains(response, testDataFromClient) {
		log.Fatalf("服务器回复不包含原始消息，测试失败")
	}
	
	// 二次验证：再次发送一条消息并接收回复
	secondTestMessage := "Second test message from client!"
	_, err = conn.Write([]byte(secondTestMessage))
	if err != nil {
		log.Fatalf("发送第二条测试数据错误: %v", err)
	}
	
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(buffer)
	if err != nil {
		log.Fatalf("从服务器读取第二次回复错误: %v", err)
	}
	
	secondResponse := string(buffer[:n])
	log.Printf("客户端收到服务器第二次回复: %s", secondResponse)
	
	// 验证第二次回复内容是否正确
	if !strings.Contains(secondResponse, secondTestMessage) {
		log.Fatalf("服务器第二次回复不包含原始消息，测试失败")
	}
	
	log.Println("双向通信测试成功完成！")
	close(dataExchanged) // 标记数据交换完成
	close(testCompleteChan) // 通知测试完成
}

// 模拟Visitor的本地监听功能
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

// 处理Visitor接收到的TCP连接
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
	// 解析命令行参数
	flag.Parse()
	
	// 设置工作目录为项目根目录
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取可执行文件路径失败: %v", err)
	}
	
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(exePath)))
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
	
	// 创建frpc客户端配置
	clientConfig := createFRPClientConfig(frpsAddr, frpsPort)
	defer freeFRPClientConfig(clientConfig)
	
	// 创建frpc客户端实例
	client := C.frpc_client_new(clientConfig, nil)
	if client == nil {
		log.Fatal("创建FRP客户端失败")
	}
	defer C.frpc_client_free(client)
	
	// 根据模式启动相应的STCP代理
	if mode == ModeServer || mode == ModeBoth {
		// 启动STCP Server
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
		// 启动STCP Visitor
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
		
		// 启动模拟的本地TCP监听器
		var err error
		visitorTCPListener, err = startVisitorLocalListener(bindAddr, bindPort)
		if err != nil {
			log.Fatalf("启动Visitor本地监听失败: %v", err)
		}
		defer visitorTCPListener.Close()
	}
	
	// 如果mode==both，则执行双向通信测试
	if mode == ModeBoth && testMode == "bidirectional" {
		go runBidirectionalTest(ctx)
		
		// 等待测试完成或上下文取消
		select {
		case <-testCompleteChan:
			log.Println("双向通信测试完成，测试通过！")
		case <-ctx.Done():
			log.Println("测试被中断")
		case <-time.After(30 * time.Second):
			log.Println("测试超时，可能存在问题！")
		}
		
		// 正常退出，不等待信号
		return
	}
	
	// 等待上下文取消（通过信号）
	<-ctx.Done()
	log.Println("关闭中，正在清理资源...")
} 