package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keysource"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// loadLocalVerifier builds the verifier for the CLI's local (no-sidecar)
// fallback path.
//
// Like the sidecar, the CLI holds PUBLIC keys only, fetched from the control
// plane. It deliberately does not read a signing key: even the development
// fallback should not demonstrate an architecture we would refuse to ship.
//
// Note this fallback exists so the CLI is usable without a running sidecar
// during single-host development. It is NOT the supported path — the sidecar is
// the only component permitted to resolve a token — and the caller warns when
// it is taken.
func loadLocalVerifier(env Env) (protocol.Verifier, *keystore.Local, error) {
	verifier, err := keysource.New(keysource.NewHTTP(env.ControlPlaneURL), 5*time.Minute)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch verification keys from %s: %w", env.ControlPlaneURL, err)
	}
	store, err := keystore.NewLocal(env.KeystorePath)
	if err != nil {
		return nil, nil, err
	}
	return verifier, store, nil
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
