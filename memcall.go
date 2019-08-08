package memcall

import (
	"errors"
	"runtime"
)

// Structure for typed specification of memory protection constants.

// MemoryProtectionFlag specifies some particular memory protection flag.
type MemoryProtectionFlag struct {
	// NOACCESS  := 1 (00000001)
	// READ      := 2 (00000010)
	// WRITE     := 4 (00000100) // unused
	// READWRITE := 6 (00000110)

	flag byte
}

// NoAccess specifies that the memory should be marked unreadable and immutable.
func NoAccess() MemoryProtectionFlag {
	return MemoryProtectionFlag{1}
}

// ReadOnly specifies that the memory should be marked read-only (immutable).
func ReadOnly() MemoryProtectionFlag {
	return MemoryProtectionFlag{2}
}

// ReadWrite specifies that the memory should be made readable and writable.
func ReadWrite() MemoryProtectionFlag {
	return MemoryProtectionFlag{6}
}

// ErrInvalidFlag indicates that a given memory protection flag is undefined.
var ErrInvalidFlag = errors.New("<memguard::memcall> memory protection flag is undefined")

// Wipes a given byte slice.
func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}
