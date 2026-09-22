package keystore_test

import (
	"path/filepath"
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// TestLocalRejectedWithoutOptIn proves the insecure dev store cannot be enabled
// by accident.
func TestLocalRejectedWithoutOptIn(t *testing.T) {
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "")
	if _, err := keystore.NewLocal(filepath.Join(t.TempDir(), "kek")); err == nil {
		t.Fatal("local keystore loaded without the explicit opt-in")
	}
}

// TestWrapUnwrapRoundTrip proves the envelope wrap/unwrap cycle works.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "1")
	ks, err := keystore.NewLocal(filepath.Join(t.TempDir(), "kek"))
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	dek, err := protocol.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := ks.Wrap("kek-1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) == string(dek) {
		t.Fatal("wrapped key equals the plaintext DEK")
	}
	got, err := ks.Unwrap("kek-1", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Zero(got)
	if string(got) != string(dek) {
		t.Fatal("unwrap did not recover the DEK")
	}
}

// TestWrongKeystoreCannotUnwrap proves a different KEK yields nothing —
// the property that makes a wrapped key useless to a folder's possessor.
func TestWrongKeystoreCannotUnwrap(t *testing.T) {
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "1")
	a, err := keystore.NewLocal(filepath.Join(t.TempDir(), "kekA"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := keystore.NewLocal(filepath.Join(t.TempDir(), "kekB"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	dek, _ := protocol.NewDEK()
	wrapped, err := a.Wrap("kek-1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Unwrap("kek-1", wrapped); err == nil {
		t.Fatal("a different KEK unwrapped the DEK")
	}
}

// TestKEPersistedNotRegenerated proves the KEK is stable across opens, so
// existing folders keep resolving.
func TestKEKPersisted(t *testing.T) {
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "1")
	path := filepath.Join(t.TempDir(), "kek")
	a, err := keystore.NewLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	dek, _ := protocol.NewDEK()
	wrapped, _ := a.Wrap("kek-1", dek)
	a.Close()

	b, err := keystore.NewLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Unwrap("kek-1", wrapped); err != nil {
		t.Fatalf("KEK was not persisted: %v", err)
	}
}
