package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// TestStandardTcpProxy 测试标准TCP代理功能
func TestStandardTcpProxy(t Testing) {
	// 首先测试基本TCP连接
	if !testBasicTcpConnection(t) {
		t.Fatalf("%s", "基本TCP连接测试失败，网络可能有问题")
	}

	// 准备测试常量
	const (
		remotePort = 8000     // TCP代理的公共端口
	)
	
	// 使用全局配置的frps端口和令牌
	frpsPort := TestConfig.FrpsPort
	token := TestConfig.FrpsToken

	// 检查frps服务器是否运行
	frpsCleanup := StartFrpsServer(t, frpsPort, token)
	defer frpsCleanup()

	// 启动本地回显服务器
	echoAddr, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	// 解析回显服务器地址
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("解析回显服务器地址失败: %v", err)
	}

	localPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("解析端口号失败: %v", err)
	}
	
	// 记录回显服务器信息
	t.Logf("回显服务器运行在 %s:%d", host, localPort)

	// 创建frpc会话
	session, err := NewFrpcSession("127.0.0.1", frpsPort, token, true)
	if err != nil {
		t.Fatalf("创建frpc会话失败: %v", err)
	}
	defer session.Destroy()

	// 添加TCP代理
	err = session.AddTcpProxy(
		"test-tcp-proxy", // 代理名称
		host,             // 本地IP
		localPort,        // 本地端口
		remotePort,       // 远程端口
	)
	if err != nil {
		t.Fatalf("添加TCP代理失败: %v", err)
	}

	// 等待代理设置完成
	time.Sleep(1 * time.Second)

	// 测试TCP代理连接
	t.Logf("测试连接到TCP代理端口 %d", remotePort)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort), 2*time.Second)
	if err != nil {
		t.Fatalf("连接TCP代理失败: %v", err)
	}
	defer conn.Close()

	// 发送测试数据
	testData := []byte("TCP-PROXY-TEST")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("发送数据失败: %v", err)
	}

	// 读取响应
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	// 验证响应
	response := buf[:n]
	if string(response) != string(testData) {
		t.Fatalf("响应数据不匹配: 得到 '%s', 应为 '%s'", response, testData)
	}

	t.Logf("TCP代理测试成功")
}

// TestStcpServerVisitorMode 测试STCP服务器/访问者模式
func TestStcpServerVisitorMode(t Testing) {
	// 常量定义
	const (
		secretKey   = "123456" // STCP共享密钥
		numTests    = 5        // 多连接测试数量
	)
	
	// 使用更高的端口号以避免冲突
	// 注意: 对于STCP访问者，我们需要确保端口可用
	bindPort := 18000
	
	// 使用全局配置的frps服务器端口和令牌
	serverPort := TestConfig.FrpsPort
	token := TestConfig.FrpsToken

	// 启动frps服务器（或检查是否已经运行）
	frpsCleanup := StartFrpsServer(t, serverPort, token)
	defer frpsCleanup()

	// 启动echo测试服务器
	echoAddr, echoCleanup := startEchoServer(t)
	defer echoCleanup()

	// 解析echo服务器地址
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("无法解析echo服务器地址: %v", err)
	}

	localPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("无法解析端口号: %v", err)
	}

	// 记录服务器信息
	t.Logf("回显服务器运行在 %s:%d", host, localPort)

	// 创建两个frpc会话：服务器和访问者
	serverSession, err := NewFrpcSession("127.0.0.1", serverPort, token, true)
	if err != nil {
		t.Fatalf("无法创建STCP服务器会话: %v", err)
	}
	defer serverSession.Destroy()

	// 添加STCP服务器代理
	err = serverSession.AddStcpServer(
		"stcp-server",                        // 代理名称
		fmt.Sprintf("%s:%d", host, localPort), // 本地echo服务器
		secretKey,                            // 共享密钥  
	)
	if err != nil {
		t.Fatalf("无法添加STCP服务器: %v", err)
	}
	
	// 创建访问者会话
	visitorSession, err := NewFrpcSession("127.0.0.1", serverPort, token, true)
	if err != nil {
		t.Fatalf("无法创建STCP访问者会话: %v", err)
	}
	defer visitorSession.Destroy()

	// 添加STCP访问者
	// 注意：AddStcpVisitor需要bindPort为int，而不是带地址的字符串
	err = visitorSession.AddStcpVisitor(
		"stcp-visitor",  // 代理名称  
		"stcp-server",   // 服务器名称
		secretKey,       // 共享密钥
		bindPort,        // 绑定端口
	)
	if err != nil {
		t.Fatalf("无法添加STCP访问者: %v", err)
	}

	// 等待连接建立（STCP需要一些时间来交换控制消息）
	time.Sleep(2 * time.Second)
	
	// 测试单个连接
	err = testSTCPEcho(t, bindPort)
	if err != nil {
		t.Fatalf("STCP单连接测试失败: %v", err)
	}
	
	// 测试多并发连接
	err = testSTCPMultipleConnections(t, bindPort, numTests)
	if err != nil {
		t.Fatalf("STCP多连接测试失败: %v", err)
	}

	t.Logf("STCP服务器/访问者模式测试成功")
}

// TestXtcpP2PMode 测试XTCP P2P模式 - 将在后续实现
func TestXtcpP2PMode(t Testing) {
	// XTCP是另一种协议，在特定网络条件下才有效
	t.Skip(fmt.Sprintf("XTCP测试需要特殊的网络环境，暂时跳过"))
}

// testSTCPEcho 测试STCP的基本echo功能
func testSTCPEcho(t Testing, port int) error {
	// 连接到STCP访问器
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("无法连接到STCP访问器: %w", err)
	}
	defer conn.Close()

	// 准备测试数据
	testData := []byte("STCP-ECHO-TEST")

	// 发送数据
	t.Logf("发送测试数据: %s", testData)
	_, err = conn.Write(testData)
	if err != nil {
		return fmt.Errorf("发送数据失败: %w", err)
	}

	// 读取响应
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	// 验证响应
	response := buf[:n]
	t.Logf("收到响应: %s", response)
	if string(response) != string(testData) {
		return fmt.Errorf("数据不匹配: 得到 '%s', 应为 '%s'", response, testData)
	}

	t.Logf("STCP Echo测试成功")
	return nil
}

// testSTCPMultipleConnections 测试STCP的多并发连接功能
func testSTCPMultipleConnections(t Testing, port int, numConnections int) error {
	// 等待组
	var wg sync.WaitGroup
	wg.Add(numConnections)
	
	// 错误通道
	errChan := make(chan error, numConnections)
	
	// 并发测试多个连接
	for i := 0; i < numConnections; i++ {
		go func(connID int) {
			defer wg.Done()
			
			// 连接到STCP访问器
			addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errChan <- fmt.Errorf("连接 %d 无法建立: %w", connID, err)
				return
			}
			defer conn.Close()
			
			// 为每个连接生成唯一的测试数据
			testData := []byte(fmt.Sprintf("STCP-CONN-%d-TEST", connID))
			
			// 发送数据
			_, err = conn.Write(testData)
			if err != nil {
				errChan <- fmt.Errorf("连接 %d 发送数据失败: %w", connID, err)
				return
			}
			
			// 读取响应
			buf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				errChan <- fmt.Errorf("连接 %d 读取响应失败: %w", connID, err)
				return
			}
			
			// 验证响应
			response := buf[:n]
			if string(response) != string(testData) {
				errChan <- fmt.Errorf("连接 %d 数据不匹配: 得到 '%s', 应为 '%s'", connID, response, testData)
				return
			}
			
			// 这个连接测试成功
			t.Logf("并发连接 %d 测试成功", connID)
		}(i + 1)
	}
	
	// 等待所有测试完成
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	// 等待完成或超时
	select {
	case <-done:
		// 检查是否有错误
		select {
		case err := <-errChan:
			return err
		default:
			// 没有错误，所有连接测试成功
			t.Logf("多连接测试全部成功")
			return nil
		}
		
	case <-time.After(15 * time.Second):
		return fmt.Errorf("多连接测试超时")
	}
}
