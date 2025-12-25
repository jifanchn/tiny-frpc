# TINY-FRPC

TINY-FRPC is a lightweight, portable C implementation of the FRP client protocol, focused on STCP (Secret TCP) and designed for embedded / resource-constrained environments.

The repository uses a hybrid C/Go approach:

- C implements the portable core libraries (`tiny-frpc/`, `wrapper/`).
- Go (via CGO) provides strict alignment tests against upstream Go implementations (`cmd/`).

## Repository layout

```
third-party/
  frp/                    # Upstream FRP source code (git submodule)
  yamux/                  # Upstream Yamux source code (git submodule)

wrapper/
  linux/                  # POSIX wrapper layer for build & tests
    wrapper.c
    wrapper.h

tiny-frpc/
  include/                # Public C headers
  source/                 # C implementation
  LOGIC.md                # Implementation notes
  STAGE.md                # Project stages / milestones
  FRP-STCP.md             # STCP protocol notes (source-of-truth: third-party/frp)
  YAMUX.md                # Yamux protocol notes (source-of-truth: third-party/yamux)

tests/                    # Pure C tests
cmd/
  yamux_test/             # CGO Yamux alignment tests
    basic.go
    protocol.go
    interop.go
  frpc_test/              # CGO FRP/STCP tests (work-in-progress)
    frpc_stcp.go

build/                    # Build outputs (ignored)
build-cov/                # Coverage build outputs (ignored)
go.mod
go.sum
Makefile
```

## Prerequisites

- Go (see `go.mod` for the required toolchain)
- A C compiler (gcc/clang)
- `git` (for submodules)

## Quick start

```bash
git submodule update --init --recursive

# Recommended for China networks:
GOPROXY=https://goproxy.cn,direct make install

make all
make yamux-test
make frpc-test
```

## Build targets

- `make install`: download Go dependencies
- `make all`: build all C static libraries
- `make yamux-test`: build & run Yamux CGO alignment tests
- `make frpc-test`: build & run FRP/STCP CGO tests
- `make test`: run all C tests + CGO tests
- `make coverage`: run coverage build (requires LLVM tools on macOS)
- `make clean`: remove build outputs and clean Go test cache

## Notes

- Build outputs live under `build/` and `build-cov/` and must not be committed.
- For more logs:
  - `make test V=1` (more verbose Go build/test logs)
  - `TINY_FRPC_VERBOSE=1 make test V=1` (enable extra C-side diagnostics)
- Go module drift is avoided by pinning upstream code via `go.mod` `replace => ./third-party/*`.