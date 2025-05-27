# tiny-frpc CGO 测试模块

## 文件结构

当前目录包含了tiny-frpc的CGO测试相关代码，用于测试C语言实现的FRP客户端与Go语言的集成。

#### C-Go 桥接层
- `frpc_cgo_bridge.h`: C与Go桥接层的头文件，定义了供Go调用的C函数接口
- `frpc_cgo_bridge.c`: C与Go桥接层的实现文件，实现了C函数接口

#### tiny-frpc CGO 测试目录

该目录包含了 tiny-frpc 的 CGO 集成测试代码。

## 目录结构（重构后）

- **frpc_cgo_bridge.h/frpc_cgo_bridge.c**: C 与 Go 的桥接层
- **frpc_bridge.go**: Go 语言封装的 frpc 客户端接口
- **frpc_bridge_test.go/frpc_test.go**: 与 frpc 相关的测试文件
- **test_common.go**: 测试通用函数和接口，包含 Testing 接口和 mockTestingT 实现
- **test_cases.go**: 所有测试用例的实现
- **frps_server.go**: 嵌入式 frps 服务器实现
- **main.go**: 测试入口点

## 测试功能

测试目录中的代码主要验证以下功能：

1. **标准 TCP 代理**: 测试 TCP 端口代理功能
2. **STCP 服务器/访问者模式**: 测试 STCP 的服务器和访问者模式

## 测试框架设计

我们实现了一个简单的测试框架：

- **Testing 接口**: 抽象了常用的测试方法，便于模拟测试环境
- **mockTestingT**: 实现了 Testing 接口，允许在非标准测试环境中运行测试
- **回显服务器**: 简单的 TCP 回显服务器用于测试连接
- **嵌入式 FRPS**: 内置 FRPS 服务器，避免依赖外部服务

## 运行测试

1.  **构建项目**:
    首先，确保你已经使用 CMake 构建了整个 `tiny-frpc` 项目，包括 C 库和 CGO 测试。从项目根目录执行：
    ```sh
    mkdir -p build
    cd build
    cmake ..
    make
    ```
    这将编译 `tiny-frpc` 库以及 CGO 测试可执行文件 `frpc_cgo_test`（位于 `build` 目录中）。

2.  **运行 CGO 测试**:
    构建完成后，可以直接从 `build` 目录运行 CGO 测试：
    ```sh
    ./frpc_cgo_test
    ```
    或者，如果你在项目的根目录，可以运行：
    ```sh
    ./build/frpc_cgo_test
    ```

可以使用命令行参数控制测试行为：

```sh
./build/frpc_cgo_test --standard=true --visitor=true --frps-port=7000 --frps-token=123456
```

## 故障排除

如果在编译或运行时遇到库链接问题，请确保：

1. `tiny-frpc` 库和 CGO 测试已经通过 CMake 正确编译（参见上面的“运行测试”部分的构建步骤）。
2. 编译后的 `tiny-frpc` 库文件（例如 `libtiny-frpc.a` 或 `libtiny-frpc.dylib/.so`）位于项目根目录下的 `build` 目录中。
3. `main.go` 文件中的 CGO 链接参数 (`LDFLAGS`) 正确指向了 `build` 目录中的 `tiny-frpc` 库。例如: `#cgo LDFLAGS: -L../../build -ltiny-frpc` (此路径相对于 `main.go` 文件，指向项目根目录下的 `build` 文件夹)。

## 测试功能模块

目前包含以下几类测试：

1. **STCP服务器/访问者模式测试** (`TestStcpServerVisitorMode`): 测试STCP的服务器-访问者模式
