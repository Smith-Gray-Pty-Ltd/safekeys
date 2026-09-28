//go:build darwin

package keystore

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Keychain is a macOS KeyWrapper that stores the KEK as a Keychain generic
// password item, so no plaintext key file exists on disk.
//
// Security property (safekeys/dev-key-custody, default-dev-no-readable-kek):
// the item's ACL is created by `security add-generic-password -T <sidecar
// binary>`, which restricts which executables may read the item without a
// user-approval prompt. A same-user agent process can still trigger that
// prompt — this raises the bar; it is NOT an OS boundary. The strong local
// boundary is the separate-user mode (deployment-packaging).
//
// The item is named by service+account so multiple sidecars on one host do
// not collide.
type Keychain struct {
	service  string
	account  string
	exePath  string // the binary whose ACL may read the item
	kek     []byte
	loaded  bool
	created bool // set when this process generated the KEK
}

// KeychainOption tunes the Keychain wrapper.
type KeychainOption func(*Keychain)

// WithKeychainAccount sets the account name (default "kek").
func WithKeychainAccount(a string) KeychainOption {
	return func(k *Keychain) { k.account = a }
}

// NewKeychain opens or creates a KEK in the user's login Keychain.
//
// service identifies the item (default "safekeys"); exePath, when non-empty,
// names the binary whose access list the item is created with. Creating the
// item requires the `security` CLI, present on every macOS install.
func NewKeychain(service string, opts ...KeychainOption) (*Keychain, error) {
	if service == "" {
		service = "safekeys"
	}
	k := &Keychain{service: service, account: "kek"}
	if exe, err := os.Executable(); err == nil {
		k.exePath = exe
	}
	for _, o := range opts {
		o(k)
	}
	secret, err := k.read()
	if err != nil {
		return nil, err
	}
	if secret == nil {
		// Generate and store. -T restricts which apps may read without a
		// prompt; the creating process is always granted.
		if err := k.create(); err != nil {
			return nil, err
		}
		secret, err = k.read()
		if err != nil {
			return nil, err
		}
		k.created = true
	}
	if len(secret) != protocol.KEKSize {
		return nil, fmt.Errorf("keychain: KEK has %d bytes, want %d", len(secret), protocol.KEKSize)
	}
	k.kek = secret
	k.loaded = true
	return k, nil
}

// Created reports whether this process generated the KEK (first run).
func (k *Keychain) Created() bool { return k.created }

// read fetches the raw key bytes, or nil when the item does not exist.
func (k *Keychain) read() ([]byte, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", k.service, "-a", k.account, "-w")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		// Exit 44 = item not found; anything else is a real failure (a
		// denied ACL prompt lands here too — fail closed).
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 44 {
			return nil, nil
		}
		return nil, fmt.Errorf("keychain: read %s/%s: %w", k.service, k.account, err)
	}
	s := strings.TrimSuffix(out.String(), "\n")
	if s == "" {
		return nil, nil
	}
	return []byte(s), nil
}

// create generates a KEK and stores it, restricted to this binary.
func (k *Keychain) create() error {
	key, err := protocol.RandomBytes(protocol.KEKSize)
	if err != nil {
		return err
	}
	defer protocol.Zero(key)
	args := []string{
		"add-generic-password",
		"-s", k.service,
		"-a", k.account,
		"-w", string(key),
		"-U", // update if it exists
	}
	// -T restricts which applications may access the item without a prompt.
	// The sidecar binary is the only grantee; `security` itself is left off
	// the list deliberately so ad-hoc reads prompt.
	if k.exePath != "" {
		args = append(args, "-T", k.exePath)
	}
	cmd := exec.Command("security", args...)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain: create %s/%s: %w: %s", k.service, k.account, err, errOut.String())
	}
	return nil
}

// Wrap implements protocol.KeyWrapper, producing "keychain:v1:<base64>".
func (k *Keychain) Wrap(kid string, dek []byte) (string, error) {
	ct, err := protocol.EncryptObject(protocol.AlgAES256GCM, k.kek, dek)
	if err != nil {
		return "", err
	}
	return "keychain:v1:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Unwrap implements protocol.KeyWrapper.
func (k *Keychain) Unwrap(kid, wrapped string) ([]byte, error) {
	raw := strings.TrimPrefix(wrapped, "keychain:v1:")
	ct, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("keychain: bad wrapped key: %w", err)
	}
	return protocol.DecryptObject(protocol.AlgAES256GCM, k.kek, ct)
}

// Healthy implements protocol.KeyWrapper.
func (k *Keychain) Healthy() error {
	if !k.loaded {
		return fmt.Errorf("keychain: not loaded")
	}
	return nil
}

// Close zeroises the in-memory KEK.
func (k *Keychain) Close() {
	protocol.Zero(k.kek)
	k.kek = nil
	k.loaded = false
}

// Compile-time interface assertion.
var _ protocol.KeyWrapper = (*Keychain)(nil)