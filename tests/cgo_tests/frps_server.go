package main

import (
	"context"
	"fmt"
	"net"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/types"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/server"
	"github.com/samber/lo"
)

// EmbeddedFrpsServer 是一个嵌入式的frps服务器，使用frp源代码实现
type EmbeddedFrpsServer struct {
	port    int
	token   string
	service *server.Service
	config  *v1.ServerConfig
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewEmbeddedFrpsServer 创建一个新的嵌入式frps服务器
func NewEmbeddedFrpsServer(port int, token string) *EmbeddedFrpsServer {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建基本的frps配置
	config := &v1.ServerConfig{
		BindAddr: "0.0.0.0",
		BindPort: port,
		Auth: v1.AuthServerConfig{
			Token: token,
		},
		Log: v1.LogConfig{
			Level: "debug", // 使用debug级别获取更多日志信息
			To:    "console",
		},
		Transport: v1.ServerTransportConfig{
			TCPMux: lo.ToPtr(true),
			TCPMuxKeepaliveInterval: 30,
			HeartbeatTimeout: 30,
		},
		WebServer: v1.WebServerConfig{
			Addr:    "0.0.0.0",
			Port:    0, // 禁用web管理界面
			User:    "",
			Password: "",
		},
		EnablePrometheus: false,
		MaxPortsPerClient: 0, // 0表示无限制
		AllowPorts: []types.PortsRange{
			{Start: 1, End: 65535}, // 允许所有端口
		},
		TCPMuxHTTPConnectPort: 0,
	}

	return &EmbeddedFrpsServer{
		port:   port,
		token:  token,
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动嵌入式frps服务器
func (s *EmbeddedFrpsServer) Start() error {
	// 初始化日志
	log.InitLogger(s.config.Log.To, s.config.Log.Level, int(s.config.Log.MaxDays), s.config.Log.DisablePrintColor)

	// 创建并启动frps服务
	var err error
	s.service, err = server.NewService(s.config)
	if err != nil {
		return fmt.Errorf("创建frps服务失败: %v", err)
	}

	log.Infof("嵌入式frps服务器已启动，监听端口: %d, 认证令牌: %s", s.port, s.token)

	// 在新的goroutine中运行服务
	go func() {
		s.service.Run(s.ctx)
	}()

	// 等待服务准备就绪
	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop 停止frps服务器
func (s *EmbeddedFrpsServer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	log.Infof("嵌入式frps服务器已停止")
}

// startEmbeddedFrps 启动嵌入式的frps服务并返回清理函数
func startEmbeddedFrps(port int, token string) func() {
	// 创建并启动服务器
	server := NewEmbeddedFrpsServer(port, token)
	err := server.Start()
	if err != nil {
		panic(fmt.Sprintf("启动frps服务失败: %v", err))
	}

	// 确认服务器已启动
	if !WaitForServerReady("127.0.0.1", port, 5*time.Second) {
		panic(fmt.Sprintf("无法连接到frps服务，端口: %d", port))
	}

	// 返回清理函数
	return func() {
		server.Stop()
	}
}

// FreePorts 尝试获取一组可用的网络端口
func FreePorts(count int) ([]int, error) {
	if count <= 0 {
		return nil, fmt.Errorf("端口数量必须大于0")
	}

	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, err
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, err
		}
		defer l.Close()
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// WaitForServerReady 等待服务器准备就绪
func WaitForServerReady(host string, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
