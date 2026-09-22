package protocol

import "unsafe"

// unsafeBytes returns a writable view of a string's backing array.
//
// This is only used by ZeroString, for overwriting a string whose bytes the
// caller exclusively owns. Writing through the returned slice mutates the
// string in place, so the caller MUST guarantee the string is not shared,
// interned, or a constant. Go places literal strings in read-only memory;
// writing to one faults.
func unsafeBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
