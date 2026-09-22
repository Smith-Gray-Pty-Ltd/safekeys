package keystore_test

import (
	"os"
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// TestVaultTransitRoundTrip exercises the production key store against a real
// OpenBao/Vault Transit engine.
//
// Skipped unless SAFEKEYS_TEST_VAULT_ADDR is set, so the suite stays runnable
// without docker:
//
//	SAFEKEYS_TEST_VAULT_ADDR=http://localhost:8200 \
//	SAFEKEYS_TEST_VAULT_TOKEN=root \
//	go test ./pkg/keystore/ -run TestVault -v
//
// The property proven here: the KEK never leaves the vault. The client sends a
// DEK, receives a wrapped form, and later sends the wrapped form back — it
// never has access to the KEK.
func TestVaultTransitRoundTrip(t *testing.T) {
	addr := os.Getenv("SAFEKEYS_TEST_VAULT_ADDR")
	if addr == "" {
		t.Skip("SAFEKEYS_TEST_VAULT_ADDR not set; skipping live vault test")
	}
	token := os.Getenv("SAFEKEYS_TEST_VAULT_TOKEN")
	if token == "" {
		t.Skip("SAFEKEYS_TEST_VAULT_TOKEN not set")
	}
	kid := os.Getenv("SAFEKEYS_TEST_VAULT_KID")
	if kid == "" {
		kid = "kek-1"
	}

	v := keystore.NewVault(addr, token, "transit")
	if err := v.Healthy(); err != nil {
		t.Fatalf("vault not reachable: %v", err)
	}

	dek, err := protocol.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Zero(dek)

	wrapped, err := v.Wrap(kid, dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	// Vault returns an opaque "vault:v1:…" form — never the KEK.
	if len(wrapped) == 0 || wrapped[:6] != "vault:" {
		t.Fatalf("unexpected wrapped form %q", wrapped)
	}

	got, err := v.Unwrap(kid, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	defer protocol.Zero(got)
	if string(got) != string(dek) {
		t.Fatal("vault did not recover the DEK")
	}
}

// TestVaultUnknownKeyFailsClosed proves an unwrap against an unknown KEK is
// denied rather than silently succeeding.
func TestVaultUnknownKeyFailsClosed(t *testing.T) {
	addr := os.Getenv("SAFEKEYS_TEST_VAULT_ADDR")
	if addr == "" {
		t.Skip("SAFEKEYS_TEST_VAULT_ADDR not set")
	}
	v := keystore.NewVault(addr, os.Getenv("SAFEKEYS_TEST_VAULT_TOKEN"), "transit")
	if _, err := v.Unwrap("no-such-key", "vault:v1:AAAA"); err == nil {
		t.Fatal("unwrap with an unknown KEK was accepted")
	}
}
