package main

/*
#cgo CFLAGS: -I../../include -I.
#cgo LDFLAGS: -L../../build -ltiny-frpc

#include <frpc_cgo_bridge.h>
#include <stdlib.h>
*/
import "C"

import (
	"flag"
	"log"
	"os"
)

// startRealFrps 使用内嵌版本的frps服务器
func startRealFrps(port int, token string) func() {
	// 调用我们的内嵌版本
	log.Printf("启动内嵌的frps服务器，端口: %d", port)
	return startEmbeddedFrps(port, token)
}

func main() {
	// 解析命令行参数
	var (
		testStandard = flag.Bool("standard", true, "运行标准TCP代理测试")
		testVisitor  = flag.Bool("visitor", true, "运行STCP服务器/访问者模式测试")
		frpsPort     = flag.Int("frps-port", 17000, "frps服务器端口")
		frpsToken    = flag.String("frps-token", "123456", "frps认证令牌")
	)
	flag.Parse()

	// 设置测试环境
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("启动tiny-frpc CGO测试...")
	
	// 初始化全局测试配置
	TestConfig.FrpsPort = *frpsPort
	TestConfig.FrpsToken = *frpsToken
	
	// 启动真实的frps服务器
	cleanupFrps := startRealFrps(TestConfig.FrpsPort, TestConfig.FrpsToken)
	defer cleanupFrps()

	// 创建测试注册表
	registry := []struct {
		name string
		fn   func(t Testing)
		run  bool
	}{
		{"StandardTcpProxy", TestStandardTcpProxy, *testStandard},
		{"StcpServerVisitorMode", TestStcpServerVisitorMode, *testVisitor},
		// XTCP功能不属于当前实现范围
		// {"XtcpP2PMode", TestXtcpP2PMode, *testVisitor},
	}

	// 运行测试
	failedTests := 0
	for _, test := range registry {
		if !test.run {
			log.Printf("跳过测试: %s", test.name)
			continue
		}

		log.Printf("运行测试: %s", test.name)
		mockT := &mockTestingT{
			name: test.name,
		}
		
		// 使用defer-recover捕获潜在的panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] %s: 测试崩溃: %v", test.name, r)
					mockT.failed = true
				}
			}()
			
			// 执行测试函数
			test.fn(mockT)
			
			// 如果测试被跳过，打印信息
			if mockT.skipped {
				log.Printf("测试'%s'被跳过", test.name)
			}
		}()
		
		if mockT.failed {
			failedTests++
		}
	}

	// 报告结果
	if failedTests > 0 {
		log.Printf("测试完成，有%d个失败", failedTests)
		os.Exit(1)
	}
	
	log.Printf("所有测试通过！")
}

// 确保mockTestingT实现了Testing接口
var _ Testing = (*mockTestingT)(nil)
