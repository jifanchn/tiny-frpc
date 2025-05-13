# TINY-FRPC

这是一个使用C语言实现的轻量级FRPC客户端，主要用于嵌入式系统。项目使用POSIX接口实现，确保良好的可移植性。

## 目录结构

```
third-party/
    frp/                    # FRP源代码子模块
    yamux/                  # YAMUX源代码子模块
wrapper/
    linux/                  # POSIX API封装
        wrapper.c          # 系统调用实现
        wrapper.h          # 系统调用声明
tiny-frpc/
    include/               # 头文件目录
        frpc.h            # FRPC主要接口
        frpc-stcp.h       # STCP协议接口
        yamux.h           # YAMUX多路复用接口
        tools.h           # 工具函数接口
    source/                # 源代码目录
        frpc.c            # FRPC实现
        frpc-stcp.c       # STCP协议实现
        yamux.c           # YAMUX多路复用实现
        tools.c           # 工具函数实现
    LOGIC.md              # TINY-FRPC逻辑说明
    STAGE.md              # 开发阶段说明
    FRP-STCP.md           # FRP STCP协议分析
    YAMUX.md              # YAMUX协议分析
cmd/
    yamux_test/           # YAMUX测试目录
        yamux_basic_test.go    # 基础功能测试
        yamux_protocol_test.go # 协议特性测试
        yamux_interop_test.go  # 互操作性测试
    frpc_test/            # FRPC测试目录
        frpc_test.go      # FRPC基础测试
        frpc_cgo_test.go  # FRPC CGO测试
build/                    # 编译输出目录
go.mod                    # Go模块定义
go.sum                    # Go依赖版本
README.md                # 项目说明
Makefile                 # 构建脚本
```

## YAMUX测试用例说明

YAMUX测试套件包含三个主要测试文件，用于验证C语言实现的YAMUX协议与Go语言实现的兼容性：

### 1. yamux_basic_test.go - 基础功能测试
- 测试会话创建和释放
- 测试基本流操作（打开、关闭、数据传输）
- 测试会话配置（keepalive、窗口大小等）
- 语言：纯C实现测试

### 2. yamux_protocol_test.go - 协议特性测试
- PING/PONG测试：验证心跳机制
- 流控制测试：验证窗口更新机制
- GOAWAY测试：验证会话终止机制
- 语言：纯C实现测试

### 3. yamux_interop_test.go - 互操作性测试
- Go客户端 -> C服务端测试
  * Go创建客户端会话
  * C实现服务端接收连接
  * 验证数据传输和流控制
  
- C客户端 -> Go服务端测试
  * C创建客户端会话
  * Go实现服务端接收连接
  * 验证数据传输和流控制

## 构建和测试

```bash
# 安装依赖
make install

# 运行YAMUX测试
make yamux-test

# 运行FRPC测试
make frp-test

# 清理构建
make clean
```

## 注意事项

1. 项目使用CGO进行C和Go代码的互操作测试
2. 测试需要先编译C库（yamux和tools）
3. 所有C代码遵循Linux C标准
4. 项目依赖最小化，只使用基本的标准库 