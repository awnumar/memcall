memcall
-------

[![Cirrus CI](https://api.cirrus-ci.com/github/awnumar/memcall.svg)](https://cirrus-ci.com/github/awnumar/memcall)
[![GoDoc](https://godoc.org/github.com/awnumar/memcall?status.svg)](https://godoc.org/github.com/awnumar/memcall)
[![Go Report Card](https://goreportcard.com/badge/github.com/awnumar/memcall)](https://goreportcard.com/report/github.com/awnumar/memcall)

This package provides a cross-platform wrapper allowing you to allocate memory outside of the garbage-collected Go heap.

Please report any issues that you experience.

## Usage

```go
// Allocate space for a key in a memory region locked into memory.
k, _ := memcall.Create(32, memcall.Readable, memcall.Writable, memcall.Locked)

// Get some random bytes
_ = k.Scramble()

// Use it
ciphertext := crypto.Encrypt(plaintext, k.Bytes())

// Get rid of it
_ = k.Destroy()
```

[Full documentation](https://pkg.go.dev/github.com/awnumar/memcall?tab=doc).

#### Todo:

- Realloc support.
- Improve tests.
- Allocate more efficiently.
