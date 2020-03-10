package memcall

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestCells(t *testing.T) {
	for i := 0; i < 1024; i++ {
		c, err := Create(i, Readable, Writable, Locked)
		if err != nil {
			t.Error(err)
		}
		if len(c.bytes) != c.Size() {
			t.Error(c.Size(), c.bytes)
		}
		if c.Size() != i {
			t.Error(c.Size(), i)
		}
		m := c.Metadata()
		if len(m) != 3 {
			t.Error(m)
		}
		if err := c.Scramble(); err != nil {
			t.Error(err)
		}
		if i != 0 && bytes.Equal(c.bytes, make([]byte, len(c.bytes))) {
			t.Error(c.bytes)
		}
		if !bytes.Equal(c.Bytes(), c.bytes) {
			t.Error(c.Bytes(), c.bytes)
		}
		c.Wipe()
		if !bytes.Equal(c.Bytes(), c.bytes) {
			t.Error(c.Bytes(), c.bytes)
		}
		if err := c.Destroy(); err != nil {
			t.Error(err)
		}
	}
}

func TestString(t *testing.T) {
	c, err := Create(32, Readable, Writable)
	if err != nil {
		t.Error(err)
	}
	if c.String() != string(c.bytes) {
		t.Error(c.String(), string(c.bytes))
	}
	for i := 0; i < 32; i++ {
		c.bytes[i] = 'x'
		if c.String() != string(c.bytes) {
			t.Error(c.String(), string(c.bytes))
		}
	}
	if err := c.Destroy(); err != nil {
		t.Error(err)
	}
}

func TestCycle(t *testing.T) {
	for i := 0; i < os.Getpagesize()*2; i += 1024 {
		testCycle(t, i)
		fmt.Println(i, "passed")
	}
}

func testCycle(t *testing.T, size int) {
	b, err := alloc(size, Readable, Writable, Locked)
	if err != nil {
		t.Error(err)
	}
	if !(len(b) == size && cap(b) == size) {
		t.Error(b, len(b), cap(b))
	}
	if !bytes.Equal(b, make([]byte, size)) {
		t.Error(b)
	}
	if size > 0 {
		r := make([]byte, size)
		if _, err := rand.Read(r); err != nil {
			t.Error(err)
		}
		copy(b, r)
		if !bytes.Equal(b, r) {
			t.Error(b, r)
		}
	}
	if err := free(b); err != nil {
		t.Error(err)
	}
}

func TestApply(t *testing.T) {
	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		// todo: check for panics
	})

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
	}, Readable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < len(b); i++ {
			b[i] = 42
		}
		runtime.KeepAlive(b)
	}, Writable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		// todo
	}, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
		for i := 0; i < len(b); i++ {
			b[i] = 42
		}
		runtime.KeepAlive(b)
	}, Readable, Writable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
		// todo: exec
	}, Readable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err == nil {
			t.Error(b, err)
		}
	}, Writable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err == nil {
			t.Error(b, err)
		}
	}, Readable, Writable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		// todo
	}, Locked)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
	}, Locked, Readable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < len(b); i++ {
			b[i] = 42
		}
		runtime.KeepAlive(b)
	}, Locked, Writable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		// todo
	}, Locked, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
		for i := 0; i < len(b); i++ {
			b[i] = 42
		}
		runtime.KeepAlive(b)
	}, Locked, Readable, Writable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error(b)
		}
		// todo: exec
	}, Locked, Readable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err == nil {
			t.Error(b, err)
		}
	}, Locked, Writable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err == nil {
			t.Error(b, err)
		}
	}, Locked, Readable, Writable, Executable)

	testApply(t, func(t *testing.T, b []byte, err error) {
		if err == nil {
			t.Error(b, err)
		}
	}, 42)
}

func testApply(t *testing.T, f func(t *testing.T, b []byte, err error), flags ...Flag) {
	for i := 0; i < os.Getpagesize()*2; i += 2048 {
		b, err := alloc(i, flags...)
		f(t, b, err)
		if err := free(b); err != nil {
			t.Error(err)
		}
	}
	fmt.Println(flags, "passed")
}
