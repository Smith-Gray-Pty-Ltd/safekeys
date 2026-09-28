//go:build !darwin

package keystore

import "fmt"

// Keychain exists only on macOS. On Linux the dev KEK lives in the
// containerised OpenBao instance (see scripts/dev-up.sh and
// safekeys/dev-key-custody); there is no local binary to grant an ACL to.
type Keychain struct{}

// NewKeychain is unavailable off macOS and returns an error rather than
// silently falling back to a plaintext file — fail closed.
func NewKeychain(string, ...KeychainOption) (*Keychain, error) {
	return nil, fmt.Errorf("keychain: only available on macOS; on Linux use the dev OpenBao instance (SAFEKEYS_VAULT_ADDR)")
}

// KeychainOption tunes the (macOS-only) Keychain wrapper.
type KeychainOption func(*Keychain)

// WithKeychainAccount sets the account name (no-op off macOS).
func WithKeychainAccount(string) KeychainOption { return func(*Keychain) {} }
