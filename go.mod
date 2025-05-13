module github.com/jifanchn/tiny-frpc

go 1.23.0

toolchain go1.24.3

// 移除对 fatedier/yamux 的直接 require
// require github.com/fatedier/yamux v0.0.0-20221031155914-a8b47c1ff9c4

require github.com/fatedier/frp v0.62.1

// 添加对 hashicorp/yamux 的 require (使用一个较新的、已知的伪版本或正式版本)
// hashicorp/yamux 本身并没有很多正式的tag，所以用一个已知的commit伪版本
require github.com/hashicorp/yamux v0.1.1

// 保持 replace 指令强制使用 fatedier 的 yamux
replace github.com/hashicorp/yamux => github.com/fatedier/yamux v0.0.0-20221031155914-a8b47c1ff9c4

require (
	github.com/fatedier/golib v0.5.1 // indirect
	github.com/samber/lo v1.47.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)
