package commands

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// loadLocalSigner builds the verifier for development mode.
//
// The key is read from a base64 Ed25519 seed in SAFEKEYS_DEV_SIGNING_KEY.
// Development only: production verification uses public keys fetched from the
// control plane, and the signing key lives in an HSM (ADR key-custody-hsm).
func loadLocalSigner(env Env) (*protocol.Ed25519Signer, *keystore.Local, error) {
	seedB64 := os.Getenv("SAFEKEYS_DEV_SIGNING_KEY")
	if seedB64 == "" {
		return nil, nil, fmt.Errorf("SAFEKEYS_DEV_SIGNING_KEY is not set (development mode requires a dev key)")
	}
	seed, err := base64.RawStdEncoding.DecodeString(seedB64)
	if err != nil {
		seed, err = base64.StdEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, nil, fmt.Errorf("decode dev signing key: %w", err)
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("dev signing key must be a %d-byte seed", ed25519.SeedSize)
	}
	prv := ed25519.NewKeyFromSeed(seed)
	signer, err := protocol.NewEd25519Signer("dev-key-1", prv)
	if err != nil {
		return nil, nil, err
	}
	store, err := keystore.NewLocal(env.KeystorePath)
	if err != nil {
		return nil, nil, err
	}
	return signer, store, nil
}

// folderSource opens a folder as a resolve source.
func folderSource(dir string) *folder.Source { return folder.New(dir) }

// DefaultFolderRoot returns the CLI's folder root.
func DefaultFolderRoot() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "safekeys", "folder")
	}
	return filepath.Join(h, ".safekeys", "folder")
}
