package memcall

import (
	"fmt"
	"strings"
	"testing"
)

func TestCycle(t *testing.T) {
	buffer, err := Alloc(32)
	if err != nil {
		t.Error(err)
	}

	if len(buffer) != 32 || cap(buffer) != 32 {
		t.Error("allocation has invalid size")
	}
	for i := range buffer {
		if buffer[i] != 0 {
			t.Error("allocated memory not zeroed:", buffer)
		}
	}

	if err := Lock(buffer); err != nil {
		t.Error(err)
	}

	for i := range buffer {
		buffer[i] = 1
		if buffer[i] != 1 {
			t.Error("read back data different to what was written")
		}
	}

	if err := Unlock(buffer); err != nil {
		t.Error(err)
	}
	if err := Free(buffer); err != nil {
		t.Error(err)
	}
	if err := DisableCoreDumps(); err != nil {
		t.Error(err)
	}
}

func TestProtect(t *testing.T) {
	buffer, _ := Alloc(32)
	if err := Protect(buffer, ReadWrite()); err != nil {
		t.Error(err)
	}
	if err := Protect(buffer, ReadOnly()); err != nil {
		t.Error(err)
	}
	if err := Protect(buffer, NoAccess()); err != nil {
		t.Error(err)
	}
	if err := Protect(buffer, MemoryProtectionFlag{4}); err.Error() != ErrInvalidFlag {
		t.Error("expected error")
	}
	Free(buffer)
}

func TestProtFlags(t *testing.T) {
	if NoAccess().flag != 1 {
		t.Error("NoAccess value is", NoAccess().flag)
	}
	if ReadOnly().flag != 2 {
		t.Error("ReadOnly value is", ReadOnly().flag)
	}
	if ReadWrite().flag != 6 {
		t.Error("ReadWrite value is", ReadWrite().flag)
	}
}

func TestGetStartPtr(t *testing.T) {
	str := fmt.Sprintf("<memcall> could not deallocate %p", _getStartPtr(nil))
	if !strings.HasPrefix(str, "<memcall> could not deallocate") {
		t.Error("Formatted start pointer error is", str)
	}

	str = fmt.Sprintf("<memcall> could not deallocate %p", _getStartPtr([]byte{}))
	if !strings.HasPrefix(str, "<memcall> could not deallocate") {
		t.Error("Formatted start pointer error is", str)
	}

	str = fmt.Sprintf("<memcall> could not deallocate %p", _getStartPtr([]byte{1, 2, 3}))
	if !strings.HasPrefix(str, "<memcall> could not deallocate") {
		t.Error("Formatted start pointer error is", str)
	}
}
