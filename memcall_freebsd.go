// +build freebsd

package memcall

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// DisableCoreDumps disables core dumps on Unix systems.
func DisableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("<memcall> could not set rlimit [Err: %s]", err)
	}
	return nil
}

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
	region, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NOCORE)
	if err != nil {
		return nil, fmt.Errorf("<memcall> could not allocate [Err: %s]", err)
	}

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
		if err := unix.Mlock(region); err != nil {
			return fmt.Errorf("<memcall> could not acquire lock on %p, limit reached? [Err: %s]", &region[0], err)
		}
	} else {
		if err := unix.Munlock(region); err != nil {
			return fmt.Errorf("<memcall> could not free lock on %p [Err: %s]", &region[0], err)
		}
	}
	if err := unix.Mprotect(region, flag); err != nil {
		return fmt.Errorf("<memcall> could not set %b on %p [Err: %s]", flag, &region[0], err)
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
	if err := unix.Munmap(region); err != nil {
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
		flag = unix.PROT_READ | unix.PROT_WRITE
	} else if wantsRead && !wantsWrite && wantsExec {
		flag = unix.PROT_READ | unix.PROT_EXEC
	} else if !wantsRead && wantsWrite && wantsExec {
		return 0, false, errors.New("<memcall> memory cannot be both writable and executable")
	} else if wantsRead && !wantsWrite && !wantsExec {
		flag = unix.PROT_READ
	} else if !wantsRead && wantsWrite && !wantsExec {
		flag = unix.PROT_WRITE
	} else if !wantsRead && !wantsWrite && wantsExec {
		flag = unix.PROT_EXEC
	} else if !wantsRead && !wantsWrite && !wantsExec {
		flag = unix.PROT_NONE
	} else {
		panic("unreachable")
	}
	return flag, lock, err
}
