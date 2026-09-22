package protocol

import "runtime"

// Zero overwrites b with zeros.
//
// This is best-effort: Go's runtime gives no guarantee that a value has not
// already been copied by the garbage collector, and the compiler may in
// principle elide a dead store to memory it can prove is never read again.
// //go:noinline plus runtime.KeepAlive defeats the common optimisations, which
// is the strongest practical guarantee available in a managed runtime.
//
// The architecture does not depend on zeroisation for its core property —
// the model is never on the decryption path regardless — but it materially
// shortens the window in which a live secret exists.
//
//go:noinline
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroString overwrites the backing array of s. Strings are immutable in Go, so
// this is only safe when the caller owns the bytes outright (e.g. a string
// freshly built from a []byte that is being discarded). Prefer working with
// []byte throughout the injection path and reserving this for unavoidable
// conversions.
//
//go:noinline
func ZeroString(s string) {
	if len(s) == 0 {
		return
	}
	// Unsafe conversion of the string header to a writable slice.
	b := unsafeBytes(s)
	Zero(b)
}

// SecureBuffer holds sensitive bytes and zeroises them on Release. Use it for
// any plaintext or key material that lives longer than a single expression.
type SecureBuffer struct {
	buf   []byte
	owned bool
}

// NewSecureBuffer returns a SecureBuffer of n zeroed bytes.
func NewSecureBuffer(n int) *SecureBuffer {
	return &SecureBuffer{buf: make([]byte, n), owned: true}
}

// SecureBufferFrom takes ownership of b. The caller must not use b afterwards.
func SecureBufferFrom(b []byte) *SecureBuffer {
	return &SecureBuffer{buf: b, owned: true}
}

// Bytes returns the underlying slice. The caller must not retain it past
// Release.
func (s *SecureBuffer) Bytes() []byte { return s.buf }

// Len returns the buffer length.
func (s *SecureBuffer) Len() int {
	if s == nil {
		return 0
	}
	return len(s.buf)
}

// Release zeroises and drops the buffer. Safe to call more than once.
func (s *SecureBuffer) Release() {
	if s == nil || s.buf == nil {
		return
	}
	if s.owned {
		Zero(s.buf)
	}
	s.buf = nil
}
