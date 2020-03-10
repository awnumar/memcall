/*
Package memcall lets you allocate and manage memory outside of the Go heap.
*/
package memcall

import (
	"crypto/rand"
	"runtime"
	"unsafe"
)

// Flag indicates some particular setting.
type Flag uint8

const (
	// Readable indicates that the memory is readable.
	Readable Flag = 0 + iota

	// Writable indicates that the memory is writable.
	Writable

	// Executable indicates that the memory is executable.
	Executable

	// Locked indicates that the memory is locked into ram.
	Locked
)

// Cell holds a controlled memory region.
// Callers must handle thread-safety.
type Cell struct {
	bytes []byte
	flags []Flag
}

// Create allocates memory, applies settings, and returns the created Cell.
func Create(size int, settings ...Flag) (*Cell, error) {
	memory, err := alloc(size, settings...)
	if err != nil {
		return nil, err
	}
	c := &Cell{bytes: memory, flags: settings}
	return c, nil
}

// Size returns the number of bytes that make up the Cell's memory region.
func (c *Cell) Size() int {
	return len(c.bytes)
}

// Metadata returns all of the active settings.
func (c *Cell) Metadata() []Flag {
	return c.flags
}

// Bytes returns the contained memory region in a byte slice.
func (c *Cell) Bytes() []byte {
	return c.bytes
}

// String returns the contained memory region in a string.
func (c *Cell) String() string {
	return *(*string)(unsafe.Pointer(&c.bytes))
}

// Destroy wipes and frees the memory region associated with a cell.
func (c *Cell) Destroy() error {
	if err := free(c.bytes); err != nil {
		return err
	}
	c.bytes = []byte{}
	c.flags = []Flag{}
	// We don't remove the Cell from its Allocator's list of allocations.
	// There is no harm in this decision. It simply saves some complexity.
	// A call to Purge will clean this list out and allow the memory to be collected.
	return nil
}

// Scramble overwrites a Cell's memory region with cryptographically-safe random bytes.
func (c *Cell) Scramble() error {
	if _, err := rand.Read(c.bytes); err != nil {
		return err
	}
	return nil
}

// Wipe overwrites a Cell's memory region with null bytes.
func (c *Cell) Wipe() {
	Wipe(c.bytes)
}

// Wipe overwrites a given memory region with null bytes.
func Wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}
