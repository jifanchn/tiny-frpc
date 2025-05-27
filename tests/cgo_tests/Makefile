# Makefile for tiny-frpc CGO tests

# Compiler settings
CC = gcc
GO = go
CFLAGS = -I../../include -I../../externals/tiny-yamux/include -Wall -Werror
LDFLAGS = -L../../build -lfrpc -lyamux

# Source files
C_BRIDGE = frpc_cgo_bridge.c
GO_SOURCES = main.go frps_direct.go testing_interfaces.go

# Target executable
TARGET = frpc_test

all: $(TARGET)

$(TARGET): $(C_BRIDGE) $(GO_SOURCES)
	$(GO) build -o $(TARGET) .

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
