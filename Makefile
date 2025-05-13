# 定义编译器和标志
CC = gcc
CFLAGS = -Wall -Werror -I./tiny-frpc/include

# 定义目录
BUILD_DIR = build
TINY_FRPC_DIR = tiny-frpc
SOURCE_DIR = $(TINY_FRPC_DIR)/source
INCLUDE_DIR = $(TINY_FRPC_DIR)/include
WRAPPER_DIR = wrapper/linux

# 定义库
TOOLS_LIB = $(BUILD_DIR)/libtools.a
YAMUX_LIB = $(BUILD_DIR)/libyamux.a
FRPC_LIB = $(BUILD_DIR)/libfrpc.a
WRAPPER_LIB = $(BUILD_DIR)/libwrapper.a

# 定义源文件
TOOLS_SRC = $(SOURCE_DIR)/tools.c
YAMUX_SRC = $(SOURCE_DIR)/yamux.c
FRPC_SRC = $(SOURCE_DIR)/frpc.c
FRPC_STCP_SRC = $(SOURCE_DIR)/frpc-stcp.c
WRAPPER_SRC = $(WRAPPER_DIR)/wrapper.c

# 目标文件
TOOLS_OBJ = $(BUILD_DIR)/tools.o
YAMUX_OBJ = $(BUILD_DIR)/yamux.o
FRPC_OBJ = $(BUILD_DIR)/frpc.o
FRPC_STCP_OBJ = $(BUILD_DIR)/frpc-stcp.o
WRAPPER_OBJ = $(BUILD_DIR)/wrapper.o

# Go工具
GO = go

# 默认目标
all: prepare $(TOOLS_LIB) $(YAMUX_LIB) $(FRPC_LIB) $(WRAPPER_LIB)

# 创建构建目录
prepare:
	mkdir -p $(BUILD_DIR)

# 编译工具库
$(TOOLS_OBJ): $(TOOLS_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(TOOLS_LIB): $(TOOLS_OBJ)
	ar rcs $@ $<

# 编译yamux库
$(YAMUX_OBJ): $(YAMUX_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(YAMUX_LIB): $(YAMUX_OBJ)
	ar rcs $@ $<

# 编译frpc库
$(FRPC_OBJ): $(FRPC_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(FRPC_STCP_OBJ): $(FRPC_STCP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(FRPC_LIB): $(FRPC_OBJ) $(FRPC_STCP_OBJ)
	ar rcs $@ $^ 

# 编译wrapper库
$(WRAPPER_OBJ): $(WRAPPER_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(WRAPPER_LIB): $(WRAPPER_OBJ)
	ar rcs $@ $<

# Go模块下载
install:
	$(GO) mod download

# yamux测试程序
yamux-test: all
	@echo "构建并运行yamux测试..."
	$(GO) build -o $(BUILD_DIR)/yamux_basic_test cmd/yamux_test/basic.go
	$(GO) build -o $(BUILD_DIR)/yamux_protocol_test cmd/yamux_test/protocol.go
	$(GO) build -o $(BUILD_DIR)/yamux_interop_test cmd/yamux_test/interop.go
	@echo "运行yamux基础测试..."
	$(BUILD_DIR)/yamux_basic_test || true
	@echo "运行yamux协议特性测试..."
	$(BUILD_DIR)/yamux_protocol_test || true
	@echo "运行yamux互操作性测试..."
	$(BUILD_DIR)/yamux_interop_test || true
	@echo "所有yamux测试完成"

# frpc-stcp测试程序
frpc-test: all
	cd cmd/frpc_test && $(GO) build -o ../../build/frpc_test frpc_stcp.go
	./build/frpc_test || true
	@echo "FRPC STCP测试完成"

# 清理
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaning Go test cache..."
	$(GO) clean -testcache

.PHONY: all prepare install yamux-test frpc-test frpc-test-server frpc-test-visitor clean
