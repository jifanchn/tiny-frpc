package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// TestConfig 保存全局测试配置
var TestConfig struct {
	FrpsPort int
	FrpsToken string
}

// Testing 是测试接口，包裹了testing.T的常用方法
type Testing interface {
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Helper()
	Logf(format string, args ...interface{})
	Skip(args ...interface{})
}

// mockTestingT 实现Testing接口用于独立执行测试
type mockTestingT struct {
	name    string
	failed  bool
	skipped bool
}

func (t *mockTestingT) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] %s: "+format, append([]interface{}{t.name}, args...)...)
	t.failed = true
}

func (t *mockTestingT) Fatalf(format string, args ...interface{}) {
	log.Printf("[FATAL] %s: "+format, append([]interface{}{t.name}, args...)...)
	t.failed = true
}

func (t *mockTestingT) Helper() {
	// 不需要实现的空方法
}

func (t *mockTestingT) Logf(format string, args ...interface{}) {
	log.Printf("[INFO] %s: "+format, append([]interface{}{t.name}, args...)...)
}

func (t *mockTestingT) Skip(args ...interface{}) {
	parts := []interface{}{fmt.Sprintf("[SKIP] %s:", t.name)}
	parts = append(parts, args...)
	log.Println(parts...)
	t.skipped = true
}

// isServerRunning 检查给定主机和端口上的服务器是否正在运行
func isServerRunning(host string, port int) bool {
	// 尝试连接到服务器端口
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// startEchoServer 启动一个简单的回显服务器用于测试
// 返回服务器地址和清理函数
func startEchoServer(t Testing) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动回显服务器失败: %v", err)
	}
	
	// 使用channel管理服务器生命周期
	done := make(chan struct{})
	var closed int32 = 0 // 原子标记是否已经关闭

	// 在goroutine中启动服务器
	go func() {
		defer func() {
			// 安全关闭channel，防止重复关闭
			if atomic.CompareAndSwapInt32(&closed, 0, 1) {
				close(done)
			}
		}()
		
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-done:
						// 正常关闭，不记录错误
					default:
						t.Logf("回显服务器: 接受连接错误: %v", err)
					}
					return
				}
				
				// 处理连接
				go func(c net.Conn) {
					defer c.Close()
					
					buf := make([]byte, 1024)
					for {
						c.SetReadDeadline(time.Now().Add(10 * time.Second)) // 添加超时
						n, err := c.Read(buf)
						if err != nil {
							if !errors.Is(err, io.EOF) {
								t.Logf("读取错误: %v", err)
							}
							return
						}
						
						// 回显数据
						c.SetWriteDeadline(time.Now().Add(10 * time.Second)) // 添加超时
						if _, err := c.Write(buf[:n]); err != nil {
							t.Logf("写入错误: %v", err)
							return
						}
					}
				}(conn)
			}
		}
	}()
	
	return listener.Addr().String(), func() {
		// 安全关闭channel，防止重复关闭
		if atomic.CompareAndSwapInt32(&closed, 0, 1) {
			close(done)
		}
		listener.Close()
	}
}

// isPortInUse 检查端口是否被占用
func isPortInUse(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	listener.Close()
	return false
}

// StartFrpsServer 检查frps服务器是否运行，并返回清理函数
func StartFrpsServer(t Testing, port int, token string) func() {
	if !isServerRunning("127.0.0.1", port) {
		t.Skip(fmt.Sprintf("frps server is not running on port %d, skipping test", port))
		return func() {}
	}
	return func() {}
}

// testBasicTcpConnection 测试基本TCP连接功能
func testBasicTcpConnection(t Testing) bool {
	// 尝试连接到一个已知的开放端口（如HTTP的80端口）
	conn, err := net.DialTimeout("tcp", "example.com:80", 2*time.Second)
	if err != nil {
		t.Logf("无法连接到example.com:80: %v", err)
		// 尝试另一个已知的开放端口（如HTTPS的443端口）
		conn, err = net.DialTimeout("tcp", "example.com:443", 2*time.Second)
		if err != nil {
			t.Logf("无法连接到example.com:443: %v", err)
			// 尝试本地回环地址
			conn, err = net.DialTimeout("tcp", "127.0.0.1:22", 1*time.Second) // SSH端口
			if err != nil {
				t.Logf("无法连接到本地SSH端口: %v", err)
				t.Logf("%s", "警告: 无法建立任何出站TCP连接，网络可能有问题")
				return false
			}
		}
	}
	conn.Close()
	t.Logf("%s", "基本TCP连接测试通过")
	return true
}
