//go:build !yamux_basic && !yamux_protocol && !yamux_interop
// +build !yamux_basic,!yamux_protocol,!yamux_interop

package main

/*
#cgo CFLAGS: -I../../tiny-frpc/include
#include <stdlib.h>
*/
import "C"

import "fmt"

// 说明：
// cmd/yamux_test 目录下有多个独立的 main 程序（basic / protocol / interop）。
// 为了避免编辑器/静态分析在默认构建下报 “main redeclared”，我们用 build tags 进行区分。
//
// 正确运行方式：
// - make yamux-test
// - make test
// - 需要详细日志：make test V=1
func main() {
	fmt.Println("cmd/yamux_test: 请使用 `make yamux-test` / `make test` 运行测试；详细日志用 `make test V=1`。")
}
