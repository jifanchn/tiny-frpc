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
	"os"
	"unsafe"
)

// flushCoverage forces writing the raw profile to LLVM_PROFILE_FILE.
func flushCoverage() {
	_ = int(C.__llvm_profile_initialize_file())

	filename := C.GoString(C.__llvm_profile_get_filename())
	size := uint64(C.__llvm_profile_get_size_for_buffer())

	if filename != "" && size > 0 {
		buf := make([]byte, size)
		ret := int(C.__llvm_profile_write_buffer((*C.char)(unsafe.Pointer(&buf[0]))))
		if ret == 0 {
			_ = os.WriteFile(filename, buf, 0o644)
			return
		}
	}

	_ = int(C.__llvm_profile_write_file())
}
