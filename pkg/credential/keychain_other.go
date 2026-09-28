//go:build !darwin

package credential

import "fmt"

// FromKeychain is unavailable off macOS. On Linux the signing seed is
// delivered as a file credential or OpenBao KV; there is no keychain to
// consult, and callers must not silently fall back to a weaker source.
func FromKeychain(service, account string) (string, bool, error) {
	return "", false, fmt.Errorf("keychain: only available on macOS")
}

// ToKeychain is unavailable off macOS.
func ToKeychain(service, account, value string) error {
	return fmt.Errorf("keychain: only available on macOS")
}
