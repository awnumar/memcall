// +build windows

package memcall

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _zero uintptr

func alloc(size int, settings ...Flag) ([]byte, error) {
	// Parse the settings, verifying any errors
	flag, lock, err := parse(settings...)
	if err != nil {
		return nil, err
	}

	// Caller is confused. Return a nil slice with no error
	if size == 0 {
		return []byte{}, nil
	}

	// Allocate the memory region
	ptr, err := windows.VirtualAlloc(_zero, uintptr(size), 0x1000|0x2000, 0x04) // PAGE_READWRITE
	if err != nil {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}
	region := _getBytes(ptr, int(size), int(size))

	// Wipe the memory region in case it has remnant data
	Wipe(region)

	// Apply the caller's settings
	if err := _apply(region, flag, lock); err != nil {
		return region, err
	}

	// Return to caller
	return region, nil
}

func apply(region []byte, settings ...Flag) error {
	flag, lock, err := parse(settings...)
	if err != nil {
		return err
	}
	return _apply(region, flag, lock)
}

func _apply(region []byte, flag int, lock bool) error {
	if cap(region) == 0 {
		return nil
	}
	if lock {
		if err := windows.VirtualLock(_getPtr(region), uintptr(len(region))); err != nil {
			return fmt.Errorf("<memcall> could not lock %p, system limit reached? [Err: %s]", &region[0], err)
		}
	} else {
		if err := windows.VirtualUnlock(_getPtr(region), uintptr(len(region))); err != nil {
			return fmt.Errorf("<memcall> could not unlock %p [Err: %s]", &region[0], err)
		}
	}
	var _ uint32
	if err := windows.VirtualProtect(_getPtr(region), uintptr(len(region)), prot, &_); err != nil {
		return fmt.Errorf("<memcall> could not set %d permissions on %p [Err: %s]", prot, &region[0], err)
	}
	return nil
}

func free(region []byte) error {
	if cap(region) == 0 {
		return nil
	}
	if err := apply(region, Readable, Writable); err != nil {
		return err
	}
	Wipe(region)
	if err := windows.VirtualFree(_getPtr(region), uintptr(0), 0x8000); err != nil {
		return fmt.Errorf("<memcall> could not deallocate %p [Err: %s]", &region[0], err)
	}
	return nil
}

func parse(settings ...Flag) (flag int, lock bool, err error) {
	var wantsRead, wantsWrite, wantsExec bool
	for _, v := range settings {
		if v == Readable {
			wantsRead = true
		} else if v == Writable {
			wantsWrite = true
		} else if v == Executable {
			wantsExec = true
		} else if v == Locked {
			lock = true
		} else {
			return 0, false, fmt.Errorf("<memcall> unknown flag %d", v)
		}
	}
	if wantsRead && wantsWrite && wantsExec {
		return 0, false, errors.New("<memcall> memory cannot be both writable and executable")
	} else if wantsRead && wantsWrite && !wantsExec {
		flag = 0x04 // PAGE_READWRITE
	} else if wantsRead && !wantsWrite && wantsExec {
		flag = 0x20 // PAGE_EXECUTE_READ
	} else if !wantsRead && wantsWrite && wantsExec {
		return 0, false, errors.New("<memcall> memory cannot be both writable and executable")
	} else if wantsRead && !wantsWrite && !wantsExec {
		flag = 0x02 // PAGE_READONLY
	} else if !wantsRead && wantsWrite && !wantsExec {
		return 0, false, errors.New("<memcall> platform does not support write-only")
	} else if !wantsRead && !wantsWrite && wantsExec {
		flag = 0x10 // PAGE_EXECUTE
	} else if !wantsRead && !wantsWrite && !wantsExec {
		if lock {
			return 0, false, errors.New("<memcall> platform does not support no-access on locked memory")
		} else {
			flag = 0x01 // PAGE_NOACCESS
		}
	} else {
		panic("unreachable")
	}
	return flag, lock, err
}

// DisableCoreDumps disables core dumps on Unix systems.
// Does nothing on windows.
func DisableCoreDumps() error {
	return nil
}

func _getPtr(b []byte) uintptr {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	return uintptr(_p0)
}

func _getBytes(ptr uintptr, len int, cap int) []byte {
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{ptr, len, cap}
	return *(*[]byte)(unsafe.Pointer(&sl))
}
