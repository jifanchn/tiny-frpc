//go:build covflush

package main

/*
// LLVM profile runtime (clang -fprofile-instr-generate)
int __llvm_profile_initialize_file(void);
const char* __llvm_profile_get_filename(void);
unsigned long long __llvm_profile_get_size_for_buffer(void);
int __llvm_profile_write_buffer(char *Buffer);
int __llvm_profile_write_file(void);
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// flushCoverage forces writing the raw profile to LLVM_PROFILE_FILE.
func flushCoverage() {
	// Ensure LLVM_PROFILE_FILE is applied (some environments default to ./default.profraw unless initialized).
	initRet := int(C.__llvm_profile_initialize_file())

	// NOTE: 在某些 Go+cgo 场景下，__llvm_profile_write_file() 会返回 0 但写出 0 字节文件。
	// 这里改为：从 runtime 拿到展开后的文件名 + buffer size，然后用 write_buffer 写入内存并落盘。
	filename := C.GoString(C.__llvm_profile_get_filename())
	size := uint64(C.__llvm_profile_get_size_for_buffer())

	if filename != "" && size > 0 {
		buf := make([]byte, size)
		ret := int(C.__llvm_profile_write_buffer((*C.char)(unsafe.Pointer(&buf[0]))))
		if ret == 0 {
			// write_buffer 返回 0 表示成功；数据长度为 get_size_for_buffer().
			writeErr := os.WriteFile(filename, buf, 0o644)
			if os.Getenv("TINY_FRPC_COV_DEBUG") == "1" {
				_, _ = fmt.Fprintf(os.Stderr, "covflush(frpc_test): init=%d file=%q size=%d write_buffer=%d write_err=%v\n",
					initRet, filename, size, ret, writeErr)
			}
			return
		}
	}

	// 回退：尝试让 runtime 自己写文件（best-effort）。
	wr := int(C.__llvm_profile_write_file())
	if os.Getenv("TINY_FRPC_COV_DEBUG") == "1" {
		_, _ = fmt.Fprintf(os.Stderr, "covflush(frpc_test): init=%d file=%q size=%d write_buffer=skip write_file=%d\n",
			initRet, filename, size, wr)
	}
}
