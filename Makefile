# tiny-frpc Makefile (simplified)
#
# Common targets:
#   make test          # Run everything: C unit tests + CGO interop tests (strict)
#   make test-bindings # Run language bindings tests (Python + Node.js + Rust)
#   make python        # Run Python bindings tests
#   make nodejs        # Run Node.js bindings tests
#   make rust          # Run Rust bindings tests
#   make demo          # Run local STCP demo (best-effort, localhost only)
#   make help          # Print this help
#   make test V=1      # Verbose logs (quiet by default)
#   make coverage      # Coverage build (>=80%) and generate build-cov/coverage.info
#   make clean         # Remove build/ and build-cov/
#
# Notes:
# - To avoid coverage instrumentation artifacts polluting normal builds (e.g. ___llvm_profile_runtime link errors),
#   normal and coverage builds use separate directories: build/ and build-cov/.

.DEFAULT_GOAL := help

CC ?= gcc
GO ?= go
NODE ?= node
NPM ?= npm

UNAME_S := $(shell uname -s)

TINY_FRPC_DIR := tiny-frpc
SOURCE_DIR := $(TINY_FRPC_DIR)/source
INCLUDE_DIR := $(TINY_FRPC_DIR)/include

# Wrapper directory: defaults to Linux, override for Windows builds:
#   make WRAPPER_DIR=wrapper/windows CC=x86_64-w64-mingw32-gcc all
WRAPPER_DIR ?= wrapper/linux

BUILD_DIR_NORMAL := build
BUILD_DIR_COV := build-cov

# Coverage switch: `make coverage` automatically sets COVERAGE=1
COVERAGE ?= 0
ifeq ($(COVERAGE),1)
  BUILD_DIR := $(BUILD_DIR_COV)
  CFLAGS_COV := -O0 -fprofile-instr-generate -fcoverage-mapping
  LDFLAGS_COV := -fprofile-instr-generate -fcoverage-mapping
  COV_GO_LDFLAGS := -fprofile-instr-generate -fcoverage-mapping
  COV_ENV := LLVM_PROFILE_FILE=$(abspath $(BUILD_DIR))/%m_%p.profraw
else
  BUILD_DIR := $(BUILD_DIR_NORMAL)
  CFLAGS_COV :=
  LDFLAGS_COV :=
  COV_GO_LDFLAGS :=
  COV_ENV :=
endif

# Verbose mode: quiet by default; use `make test V=1` for more logs.
V ?= 0
ifeq ($(V),1)
  RUN_ENV := $(COV_ENV) TINY_FRPC_VERBOSE=1
  RUN_ARGS := -v
else
  RUN_ENV := $(COV_ENV)
  RUN_ARGS :=
endif

# Compiler flags
# Note: -Wno-error=format allows format warnings (uint64_t vs %llu differs by platform)
# Note: -Wno-error=unknown-pragmas allows #pragma comment (MSVC-only) on mingw
CFLAGS := -Wall -Werror -Wno-error=format -Wno-error=unknown-pragmas -g -I$(INCLUDE_DIR) -I$(WRAPPER_DIR) $(CFLAGS_COV)
LDFLAGS := $(LDFLAGS_COV)

# Node-gyp helper (some environments don't expose `node-gyp` in PATH, but npm bundles it).
NODE_GYP_BIN := $(shell command -v node-gyp 2>/dev/null)
NODE_GYP_JS := $(shell $(NPM) root -g 2>/dev/null)/npm/node_modules/node-gyp/bin/node-gyp.js
ifeq ($(NODE_GYP_BIN),)
  NODE_GYP_RUN := $(NODE) $(NODE_GYP_JS)
else
  NODE_GYP_RUN := $(NODE_GYP_BIN)
endif

# ------------------------
# Shared library for language bindings (Python/Node.js)
# ------------------------
# Bindings currently load ../../build/libfrpc-bindings.so. We always build that path.
ifeq ($(UNAME_S),Darwin)
  SHLIB_LDFLAGS := -dynamiclib
  # Use a stable install name so consumers can locate it via rpath.
  SHLIB_ID_LDFLAGS := -Wl,-install_name,@rpath/libfrpc-bindings.so
else
  SHLIB_LDFLAGS := -shared
  SHLIB_ID_LDFLAGS :=
endif
PIC_CFLAGS := -fPIC

BINDINGS_SHLIB_DIR := $(BUILD_DIR_NORMAL)
BINDINGS_SHLIB := $(BINDINGS_SHLIB_DIR)/libfrpc-bindings.so
BINDINGS_SHLIB_DIR_STAMP := $(BINDINGS_SHLIB_DIR)/.dir

TOOLS_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/tools.pic.o
CRYPTO_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/crypto.pic.o
YAMUX_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/yamux.pic.o
FRPC_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/frpc.pic.o
FRPC_STCP_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/frpc-stcp.pic.o
WRAPPER_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/wrapper.pic.o
BINDINGS_PIC_OBJ := $(BINDINGS_SHLIB_DIR)/frpc-bindings.pic.o

# Output files
TOOLS_OBJ := $(BUILD_DIR)/tools.o
CRYPTO_OBJ := $(BUILD_DIR)/crypto.o
YAMUX_OBJ := $(BUILD_DIR)/yamux.o
FRPC_OBJ := $(BUILD_DIR)/frpc.o
FRPC_STCP_OBJ := $(BUILD_DIR)/frpc-stcp.o
WRAPPER_OBJ := $(BUILD_DIR)/wrapper.o
BINDINGS_OBJ := $(BUILD_DIR)/frpc-bindings.o

TOOLS_LIB := $(BUILD_DIR)/libtools.a
CRYPTO_LIB := $(BUILD_DIR)/libcrypto.a
YAMUX_LIB := $(BUILD_DIR)/libyamux.a
FRPC_LIB := $(BUILD_DIR)/libfrpc.a
WRAPPER_LIB := $(BUILD_DIR)/libwrapper.a
BINDINGS_LIB := $(BUILD_DIR)/libfrpc-bindings.a

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

help:
	@echo "tiny-frpc: common targets"
	@echo ""
	@echo "  make test           - Run everything (C unit tests + CGO interop tests)"
	@echo "  make bindings-test  - Run bindings tests (Python + Node.js + Rust)"
	@echo "  make e2e            - Run E2E tests with mock FRPS (Python + Node.js + Rust)"
	@echo "  make e2e-frps       - Run E2E tests with real FRPS"
	@echo "  make demo           - Run local STCP demo (best-effort, localhost only)"
	@echo ""
	@echo "  make all            - Build static libraries"
	@echo "  make clean          - Remove build outputs (build/ and build-cov/)"
	@echo "  make coverage       - Run coverage build (>=80%)"
	@echo ""
	@echo "Options:"
	@echo "  V=1                 - Verbose logs (also sets TINY_FRPC_VERBOSE=1)"
	@echo "  DEMO_STCP_RUN_CYCLES=N - How many demo cycles to run (default: 3)"
	@echo ""
	@echo "Tip: legacy target names still exist (e.g. bindings-test, python-bindings-test, demo-stcp-run)."

all: $(TOOLS_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(FRPC_LIB) $(WRAPPER_LIB) $(BINDINGS_LIB)

# ---- build: objects ----
$(TOOLS_OBJ): $(SOURCE_DIR)/tools.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CRYPTO_OBJ): $(SOURCE_DIR)/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(YAMUX_OBJ): $(SOURCE_DIR)/yamux.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(FRPC_OBJ): $(SOURCE_DIR)/frpc.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(FRPC_STCP_OBJ): $(SOURCE_DIR)/frpc-stcp.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(WRAPPER_OBJ): $(WRAPPER_DIR)/wrapper.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BINDINGS_OBJ): $(SOURCE_DIR)/frpc-bindings.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# ---- build: libraries ----
$(TOOLS_LIB): $(TOOLS_OBJ)
	ar rcs $@ $^

$(CRYPTO_LIB): $(CRYPTO_OBJ)
	ar rcs $@ $^

$(YAMUX_LIB): $(YAMUX_OBJ)
	ar rcs $@ $^

$(FRPC_LIB): $(FRPC_OBJ) $(FRPC_STCP_OBJ)
	ar rcs $@ $^

$(WRAPPER_LIB): $(WRAPPER_OBJ)
	ar rcs $@ $^

$(BINDINGS_LIB): $(BINDINGS_OBJ)
	ar rcs $@ $^

install:
	$(GO) mod download

clean:
	rm -rf $(BUILD_DIR_NORMAL) $(BUILD_DIR_COV)
	@echo "Cleaning Go test cache..."
	$(GO) clean -testcache

$(BINDINGS_SHLIB_DIR_STAMP):
	@mkdir -p $(BINDINGS_SHLIB_DIR)
	@touch $@

$(TOOLS_PIC_OBJ): $(SOURCE_DIR)/tools.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(CRYPTO_PIC_OBJ): $(SOURCE_DIR)/crypto.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(YAMUX_PIC_OBJ): $(SOURCE_DIR)/yamux.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(FRPC_PIC_OBJ): $(SOURCE_DIR)/frpc.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(FRPC_STCP_PIC_OBJ): $(SOURCE_DIR)/frpc-stcp.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(WRAPPER_PIC_OBJ): $(WRAPPER_DIR)/wrapper.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(BINDINGS_PIC_OBJ): $(SOURCE_DIR)/frpc-bindings.c | $(BINDINGS_SHLIB_DIR_STAMP)
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c $< -o $@

$(BINDINGS_SHLIB): $(TOOLS_PIC_OBJ) $(CRYPTO_PIC_OBJ) $(YAMUX_PIC_OBJ) $(FRPC_PIC_OBJ) $(FRPC_STCP_PIC_OBJ) $(WRAPPER_PIC_OBJ) $(BINDINGS_PIC_OBJ)
	$(CC) $(SHLIB_LDFLAGS) $(SHLIB_ID_LDFLAGS) -o $@ $^ -pthread $(LDFLAGS)

bindings-shared: $(BINDINGS_SHLIB)

# ------------------------
# C tests (pure C, based on wrapper/linux)
# ------------------------
$(BUILD_DIR)/test_tools: tests/test_tools.c $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(TOOLS_LIB) $(WRAPPER_LIB) $(LDFLAGS)

tools-test: $(BUILD_DIR)/test_tools
	$(RUN_ENV) $(BUILD_DIR)/test_tools

$(BUILD_DIR)/test_wrapper: tests/test_wrapper.c $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(WRAPPER_LIB) $(LDFLAGS)

wrapper-test: $(BUILD_DIR)/test_wrapper
	$(RUN_ENV) $(BUILD_DIR)/test_wrapper

$(BUILD_DIR)/test_tunnel_config: tests/test_tunnel_config.c $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

config-test: $(BUILD_DIR)/test_tunnel_config
	$(RUN_ENV) $(BUILD_DIR)/test_tunnel_config

$(BUILD_DIR)/test_error_handling: tests/test_error_handling.c $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

error-test: $(BUILD_DIR)/test_error_handling
	$(RUN_ENV) $(BUILD_DIR)/test_error_handling

$(BUILD_DIR)/test_frpc_bindings_api: tests/test_frpc_bindings_api.c $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(BINDINGS_LIB) $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(YAMUX_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

bindings-api-test: $(BUILD_DIR)/test_frpc_bindings_api
	$(RUN_ENV) $(BUILD_DIR)/test_frpc_bindings_api

$(BUILD_DIR)/test_yamux_unit: tests/test_yamux_unit.c $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) $(LDFLAGS)

yamux-unit-test: $(BUILD_DIR)/test_yamux_unit
	$(RUN_ENV) $(BUILD_DIR)/test_yamux_unit

$(BUILD_DIR)/test_frpc_stcp_unit: tests/test_frpc_stcp_unit.c $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

stcp-unit-test: $(BUILD_DIR)/test_frpc_stcp_unit
	$(RUN_ENV) $(BUILD_DIR)/test_frpc_stcp_unit

$(BUILD_DIR)/test_frpc_core_api: tests/test_frpc_core_api.c $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(FRPC_LIB) $(CRYPTO_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

frpc-core-test: $(BUILD_DIR)/test_frpc_core_api
	$(RUN_ENV) $(BUILD_DIR)/test_frpc_core_api

$(BUILD_DIR)/test_crypto: tests/test_crypto.c $(CRYPTO_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(CRYPTO_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

crypto-test: $(BUILD_DIR)/test_crypto
	$(RUN_ENV) $(BUILD_DIR)/test_crypto

c-test: all tools-test wrapper-test yamux-unit-test config-test error-test bindings-api-test stcp-unit-test frpc-core-test crypto-test

# ------------------------
# cmd/ tests (CGO: Go <-> C alignment)
# ------------------------
yamux-test: all
	$(GO) clean -cache
	$(GO) build -tags "yamux_basic" -a -o $(BUILD_DIR)/yamux_basic_test cmd/yamux_test/basic.go cmd/yamux_test/coverage_flush_stub.go
	$(GO) build -tags "yamux_protocol" -a -o $(BUILD_DIR)/yamux_protocol_test cmd/yamux_test/protocol.go cmd/yamux_test/coverage_flush_stub.go
	$(GO) build -tags "yamux_interop" -a -o $(BUILD_DIR)/yamux_interop_test cmd/yamux_test/interop.go cmd/yamux_test/coverage_flush_stub.go
	$(RUN_ENV) $(BUILD_DIR)/yamux_basic_test
	$(RUN_ENV) $(BUILD_DIR)/yamux_protocol_test
	$(RUN_ENV) $(BUILD_DIR)/yamux_interop_test

frpc-test: all
	$(GO) clean -cache
	$(GO) build -a -o $(BUILD_DIR)/frpc_test ./cmd/frpc_test
	$(RUN_ENV) $(BUILD_DIR)/frpc_test $(RUN_ARGS)

frpc-multi-channel-test: all
	$(GO) clean -cache
	$(GO) build -tags "multi_channel" -a -o $(BUILD_DIR)/frpc_multi_channel_test \
		cmd/frpc_test/multi_channel_test.go cmd/frpc_test/coverage_flush_stub.go
	$(RUN_ENV) $(BUILD_DIR)/frpc_multi_channel_test

cmd-test: yamux-test frpc-test

# Unified target: `make test`
test: c-test cmd-test

# ------------------------
# FRPS build (for E2E tests with real frps)
# ------------------------
FRPS_BIN := $(BUILD_DIR)/frps

$(FRPS_BIN): | $(BUILD_DIR)
	cd third-party/frp && $(GO) build -o ../../$(FRPS_BIN) ./cmd/frps

frps-build: $(FRPS_BIN)

# ------------------------
# E2E tests (with mock FRPS - demo_stcp_frps)
# ------------------------
python-e2e-test: bindings-shared demo-stcp
	cd bindings/python && python3 -B test_e2e.py --frps-path ../../$(DEMO_STCP_FRPS_BIN)

nodejs-e2e-test: bindings-shared demo-stcp
	cd bindings/nodejs && $(NODE_GYP_RUN) rebuild
	@mkdir -p bindings/nodejs/build
	@cp -f $(BINDINGS_SHLIB) bindings/nodejs/build/libfrpc-bindings.so
	cd bindings/nodejs && node test_e2e.js --frps-path ../../$(DEMO_STCP_FRPS_BIN)

rust-bindings-test: bindings-shared
	cd bindings/rust && cargo test --quiet

e2e-test: python-e2e-test nodejs-e2e-test rust-bindings-test
bindings-test: e2e-test

# ------------------------
# E2E tests with real FRPS (requires frps-build)
# ------------------------
python-e2e-frps: bindings-shared frps-build
	cd bindings/python && python3 -B test_e2e_frps.py --frps-path ../../$(FRPS_BIN)

e2e-frps: python-e2e-frps

# ------------------------
# High-level shortcuts (for a simpler UX)
# ------------------------
test-bindings: bindings-test
e2e: e2e-test
demo: demo-stcp-run

# ------------------------
# demo/ (Linux/POSIX demos)
# ------------------------
DEMO_STCP_DIR := demo/stcp

DEMO_STCP_CFLAGS := -I$(DEMO_STCP_DIR)

DEMO_STCP_COMMON_OBJ := $(BUILD_DIR)/demo_stcp_common.o
DEMO_STCP_FRPS_BIN := $(BUILD_DIR)/demo_stcp_frps
DEMO_STCP_SERVER_BIN := $(BUILD_DIR)/demo_stcp_server
DEMO_STCP_VISITOR_BIN := $(BUILD_DIR)/demo_stcp_visitor
DEMO_STCP_LOCAL_CLIENT_BIN := $(BUILD_DIR)/demo_stcp_local_client

# How many times to run the demo handshake in demo-stcp-run.
DEMO_STCP_RUN_CYCLES ?= 3

$(DEMO_STCP_COMMON_OBJ): $(DEMO_STCP_DIR)/common.c $(DEMO_STCP_DIR)/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEMO_STCP_CFLAGS) -c $(DEMO_STCP_DIR)/common.c -o $@

$(DEMO_STCP_FRPS_BIN): $(DEMO_STCP_DIR)/mock_frps.c $(DEMO_STCP_COMMON_OBJ) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEMO_STCP_CFLAGS) -o $@ $(DEMO_STCP_DIR)/mock_frps.c $(DEMO_STCP_COMMON_OBJ) $(WRAPPER_LIB) -pthread $(LDFLAGS)

$(DEMO_STCP_SERVER_BIN): $(DEMO_STCP_DIR)/stcp_server.c $(DEMO_STCP_COMMON_OBJ) $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEMO_STCP_CFLAGS) -o $@ $(DEMO_STCP_DIR)/stcp_server.c $(DEMO_STCP_COMMON_OBJ) $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

$(DEMO_STCP_VISITOR_BIN): $(DEMO_STCP_DIR)/stcp_visitor.c $(DEMO_STCP_COMMON_OBJ) $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEMO_STCP_CFLAGS) -o $@ $(DEMO_STCP_DIR)/stcp_visitor.c $(DEMO_STCP_COMMON_OBJ) $(FRPC_LIB) $(CRYPTO_LIB) $(YAMUX_LIB) $(TOOLS_LIB) $(WRAPPER_LIB) -pthread $(LDFLAGS)

$(DEMO_STCP_LOCAL_CLIENT_BIN): $(DEMO_STCP_DIR)/local_client.c $(DEMO_STCP_COMMON_OBJ) $(WRAPPER_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEMO_STCP_CFLAGS) -o $@ $(DEMO_STCP_DIR)/local_client.c $(DEMO_STCP_COMMON_OBJ) $(WRAPPER_LIB) -pthread $(LDFLAGS)

demo-stcp: all $(DEMO_STCP_FRPS_BIN) $(DEMO_STCP_SERVER_BIN) $(DEMO_STCP_VISITOR_BIN) $(DEMO_STCP_LOCAL_CLIENT_BIN)

# Best-effort run helper (localhost only).
demo-stcp-run: demo-stcp
	@set -e; \
	cleanup() { \
		if [ -n "$${SERVER_PID:-}" ]; then kill $$SERVER_PID >/dev/null 2>&1 || true; fi; \
		if [ -n "$${FRPS_PID:-}" ]; then kill $$FRPS_PID >/dev/null 2>&1 || true; fi; \
	}; \
	trap cleanup EXIT INT TERM; \
	$(DEMO_STCP_FRPS_BIN) --listen-addr 127.0.0.1 --listen-port 17001 --run-id demo_run > $(BUILD_DIR)/demo_stcp_frps.log 2>&1 & \
	FRPS_PID=$$!; \
	sleep 0.2; \
	i=1; \
	while [ $$i -le $(DEMO_STCP_RUN_CYCLES) ]; do \
		echo "--- demo-stcp cycle $$i/$(DEMO_STCP_RUN_CYCLES) ---"; \
		$(DEMO_STCP_SERVER_BIN) --frps-addr 127.0.0.1 --frps-port 17001 --listen-addr 127.0.0.1 --listen-port 19001 --accept-timeout-sec 5 --proxy-name demo_stcp --sk demo_secret -v > $(BUILD_DIR)/demo_stcp_server_$$i.log 2>&1 & \
		SERVER_PID=$$!; \
		sleep 0.2; \
		$(DEMO_STCP_VISITOR_BIN) --frps-addr 127.0.0.1 --frps-port 17001 --connect-addr 127.0.0.1 --connect-port 19001 --server-name demo_stcp --proxy-name demo_stcp_visitor --sk demo_secret --mode once --message "hello-$$i" -v; \
		kill $$SERVER_PID >/dev/null 2>&1 || true; \
		wait $$SERVER_PID >/dev/null 2>&1 || true; \
		SERVER_PID=; \
		i=$$((i+1)); \
	done; \
	echo "Logs: $(BUILD_DIR)/demo_stcp_frps.log (server logs: $(BUILD_DIR)/demo_stcp_server_*.log)"

# ------------------------
# Coverage (line coverage >=80%)
# ------------------------
cmd-coverage: all
	$(GO) clean -cache
	CGO_LDFLAGS="$(COV_GO_LDFLAGS) -L$(abspath $(BUILD_DIR))" $(GO) build -tags "covflush yamux_basic" -a -o $(BUILD_DIR)/yamux_basic_test cmd/yamux_test/basic.go cmd/yamux_test/coverage_flush_covflush.go
	CGO_LDFLAGS="$(COV_GO_LDFLAGS) -L$(abspath $(BUILD_DIR))" $(GO) build -tags "covflush yamux_protocol" -a -o $(BUILD_DIR)/yamux_protocol_test cmd/yamux_test/protocol.go cmd/yamux_test/coverage_flush_covflush.go
	CGO_LDFLAGS="$(COV_GO_LDFLAGS) -L$(abspath $(BUILD_DIR))" $(GO) build -tags "covflush yamux_interop" -a -o $(BUILD_DIR)/yamux_interop_test cmd/yamux_test/interop.go cmd/yamux_test/coverage_flush_covflush.go
	CGO_LDFLAGS="$(COV_GO_LDFLAGS) -L$(abspath $(BUILD_DIR))" $(GO) build -tags covflush -a -o $(BUILD_DIR)/frpc_test ./cmd/frpc_test
	$(RUN_ENV) $(BUILD_DIR)/yamux_basic_test
	$(RUN_ENV) $(BUILD_DIR)/yamux_protocol_test
	$(RUN_ENV) $(BUILD_DIR)/yamux_interop_test
	$(RUN_ENV) $(BUILD_DIR)/frpc_test

coverage: clean
	@echo "Building + running tests with coverage (>=80%)..."
	$(MAKE) COVERAGE=1 all
	# Enable V=1 in coverage runs to avoid "verbose-only" branches being counted as uncovered.
	$(MAKE) COVERAGE=1 V=1 c-test
	$(MAKE) COVERAGE=1 V=1 cmd-coverage
	@echo "Merging profraw -> profdata..."
	xcrun llvm-profdata merge -sparse $(BUILD_DIR_COV)/*.profraw -o $(BUILD_DIR_COV)/coverage.profdata
	@echo "Exporting lcov..."
	@COV_MAIN=$(BUILD_DIR_COV)/test_tools; \
	COV_OBJS="$(BUILD_DIR_COV)/test_wrapper $(BUILD_DIR_COV)/test_tunnel_config $(BUILD_DIR_COV)/test_error_handling $(BUILD_DIR_COV)/test_frpc_bindings_api $(BUILD_DIR_COV)/test_yamux_unit $(BUILD_DIR_COV)/test_frpc_stcp_unit $(BUILD_DIR_COV)/test_frpc_core_api $(BUILD_DIR_COV)/yamux_basic_test $(BUILD_DIR_COV)/yamux_protocol_test $(BUILD_DIR_COV)/yamux_interop_test $(BUILD_DIR_COV)/frpc_test"; \
	xcrun llvm-cov export $$COV_MAIN $$(for o in $$COV_OBJS; do echo --object=$$o; done) \
		-instr-profile=$(BUILD_DIR_COV)/coverage.profdata -format=lcov > $(BUILD_DIR_COV)/coverage.info
	@python3 tests/coverage_check.py $(BUILD_DIR_COV)/coverage.info 80
	@echo "Coverage OK (>=80%). Report: $(BUILD_DIR_COV)/coverage.info"

.PHONY: all install clean test c-test cmd-test \
	tools-test wrapper-test config-test error-test bindings-api-test yamux-unit-test stcp-unit-test frpc-core-test crypto-test \
	yamux-test frpc-test cmd-coverage coverage \
	bindings-shared rust-bindings-test bindings-test test-bindings \
	frps-build python-e2e-test nodejs-e2e-test e2e-test e2e \
	python-e2e-frps e2e-frps \
	demo-stcp demo-stcp-run demo \
	help
