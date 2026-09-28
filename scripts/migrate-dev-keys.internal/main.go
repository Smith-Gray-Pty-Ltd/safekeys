// Command migrate-dev-keys.internal re-wraps every local-wrapped object in a
// dev folder tree under a new key store, without ever exposing a plaintext
// DEK or the old KEK to the calling shell.
//
// Invoked by scripts/migrate-dev-keys.sh. Not a user-facing binary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

func main() {
	oldPath := flag.String("old-kek", "", "path of the legacy plaintext KEK file")
	devDir := flag.String("dev-dir", "", "dev dir holding folder/ trees")
	flag.Parse()
	if *oldPath == "" || *devDir == "" {
		fmt.Fprintln(os.Stderr, "both --old-kek and --dev-dir are required")
		os.Exit(2)
	}

	// The OLD keystore: a plaintext file, opened with the explicit dev opt-in
	// that NewLocal requires. (The environment opt-in is set by the wrapper
	// script; this process never persists it anywhere.)
	old, err := keystore.NewLocal(*oldPath)
	if err != nil {
		fatal("open old keystore: %v", err)
	}
	defer old.Close()

	// The NEW keystore: whatever the wrapper exported — Keychain on macOS or
	// Vault transit. Opening it AFTER the old one so a Keychain prompt has a
	// reason to exist.
	var newKS protocol.KeyWrapper
	var newKID string
	if os.Getenv("SAFEKEYS_KEYCHAIN") == "1" {
		kc, err := keystore.NewKeychain("safekeys")
		if err != nil {
			fatal("open keychain: %v", err)
		}
		defer kc.Close()
		newKS, newKID = kc, "dev-key-1"
	} else if addr := os.Getenv("SAFEKEYS_VAULT_ADDR"); addr != "" {
		v := keystore.NewVault(addr, os.Getenv("SAFEKEYS_VAULT_TOKEN"), envOr("SAFEKEYS_VAULT_MOUNT", "transit"))
		if err := v.Healthy(); err != nil {
			fatal("vault unreachable: %v", err)
		}
		newKS, newKID = v, envOr("SAFEKEYS_VAULT_KID", "kek-1")
	} else if os.Getenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE") == "1" {
		// Keep-file mode: the new key is a fresh file at the same path.
		// The old one is already open (it holds the bytes in memory); the
		// new file gets fresh random bytes and the old file is deleted by
		// the wrapper after this process exits.
		tmp := *oldPath + ".new"
		kf, err := keystore.NewLocal(tmp)
		if err != nil {
			fatal("create new key file: %v", err)
		}
		defer kf.Close()
		newKS, newKID = kf, "kek-local-1"
		defer func() {
			if err := os.Rename(tmp, *oldPath+".migrated"); err != nil {
				fatal("promote new key file: %v", err)
			}
			fmt.Println("new file key at", *oldPath+".migrated")
		}()
	} else {
		fatal("no new custody target: set SAFEKEYS_KEYCHAIN=1 or SAFEKEYS_VAULT_ADDR")
	}

	// Walk every folder tree under the dev dir and re-wrap each object whose
	// wrapped key is local-scheme.
	ctx := context.Background()
	migrated, skipped, failed := 0, 0, 0
	for _, root := range []string{
		filepath.Join(*devDir, "folder"),
		filepath.Join(*devDir, "folder-vault"),
	} {
		mans, _ := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
		for _, mf := range mans {
			objDir := filepath.Dir(mf)
			raw, err := os.ReadFile(mf)
			if err != nil {
				fatal("read %s: %v", mf, err)
			}
			var m protocol.Manifest
			if err := json.Unmarshal(raw, &m); err != nil {
				fatal("parse %s: %v", mf, err)
			}
			changed := false
			src := folder.New(objDir)
			for i, o := range m.Objects {
				if !strings.HasPrefix(o.WrappedKey, "local:v1:") {
					skipped++
					continue
				}
				_, _, err := src.Load(ctx, o.ID)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s: load: %v\n", o.ID, err)
					failed++
					continue
				}
				dek, err := old.Unwrap(o.WrappingKID, o.WrappedKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s: old KEK cannot unwrap: %v\n", o.ID, err)
					failed++
					continue
				}
				rewrapped, err := newKS.Wrap(newKID, dek)
				protocol.Zero(dek)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %s: re-wrap: %v\n", o.ID, err)
					failed++
					continue
				}
				if _, err := newKS.Unwrap(newKID, rewrapped); err != nil {
					fmt.Fprintf(os.Stderr, "  %s: verify unwrap under new key: %v\n", o.ID, err)
					failed++
					continue
				}
				m.Objects[i].WrappedKey = rewrapped
				m.Objects[i].WrappingKID = newKID
				changed = true
				migrated++
				fmt.Printf("  %s: re-wrapped (kid %s)\n", o.ID, newKID)
			}
			if changed {
				out, err := json.MarshalIndent(&m, "", "  ")
				if err != nil {
					fatal("marshal %s: %v", mf, err)
				}
				if err := os.WriteFile(mf, append(out, '\n'), 0o600); err != nil {
					fatal("write %s: %v", mf, err)
				}
			}
		}
	}
	fmt.Printf("migrated=%d skipped=%d failed=%d\n", migrated, skipped, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "migrate-dev-keys: "+f+"\n", a...)
	os.Exit(1)
}