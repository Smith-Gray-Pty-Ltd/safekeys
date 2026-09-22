// Command sidecar runs the Safekeys Sidecar / Resolver.
//
// This is the ONLY component permitted to resolve a capability token. It
// verifies the token, asks the key store to unwrap the data key, decrypts the
// object, injects the plaintext into a non-LLM consumer, and zeroises.
//
// Deployment notes (ADR separate-os-user): run this as a user distinct from any
// agent process, with no shared memory. The socket is created 0600.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/revocation"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/sidecar"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("sidecar: %v", err)
	}
}

func run() error {
	var (
		socket    = flag.String("socket", envOr("SAFEKEYS_SOCKET", "/run/safekeys/sidecar.sock"), "unix socket path")
		folderDir = flag.String("folder", envOr("SAFEKEYS_FOLDER", defaultFolderRoot()), "folder root holding ciphertext objects")
		audience  = flag.String("audience", envOr("SAFEKEYS_AUDIENCE", "env-local"), "resolver identity; tokens must match")
		keyPath   = flag.String("keystore", envOr("SAFEKEYS_KEYSTORE", defaultKeystorePath()), "local KEK path (development)")
	)
	flag.Parse()

	// ── Verifier. Development reads a seed; production loads the control
	// plane's public keys and the private key never exists here.
	signer, err := loadVerifier()
	if err != nil {
		return err
	}

	// ── Key store. The KEK never leaves it (ADR kek-never-leaves-store).
	local, err := keystore.NewLocal(*keyPath)
	if err != nil {
		return err
	}
	defer local.Close()

	// Capture so a remote caller receives the command's own output over the
	// socket. The injector still never returns the injected value.
	inj := inject.NewExecInjector()
	inj.Capture = true

	cfg := sidecar.Config{
		SocketPath: *socket,
		Audience:   *audience,
		Verifier:   signer,
		Revoked:    revocationChecker(),
		Policy:     localPolicy{},
		Source:     folder.New(*folderDir),
		Unwrap: func(ctx context.Context, kid, wrapped string) ([]byte, error) {
			return local.Unwrap(kid, wrapped)
		},
		Auditor:  logAuditor{},
		HostName: hostname(),
		Injector: inj,
	}

	srv := sidecar.New(cfg)
	srv.SetLogger(log.Printf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("sidecar: shutting down")
		cancel()
	}()

	log.Printf("sidecar: resolving for audience %q, folder %s, socket %s", *audience, *folderDir, *socket)
	log.Printf("sidecar: verifier kid=%s alg=%s", signer.KeyID(), signer.Algorithm())
	if os.Getenv("SAFEKEYS_REVOCATION_OFFLINE") == "1" {
		log.Println("sidecar: WARNING — revocation checks are OFFLINE; revoked tokens remain usable until TTL expiry")
	}
	return srv.Serve(ctx)
}

// revocationChecker builds the denylist checker.
//
// It asks the control plane on every resolve and FAILS CLOSED: if the control
// plane is unreachable the token is treated as revoked, because a resolve that
// cannot verify current authority must not proceed (ADR deny-by-default).
//
// Set SAFEKEYS_REVOCATION_OFFLINE=1 to run without a control plane. That mode
// denies nothing on revocation grounds, so only TTL bounds exposure — it is
// for isolated development and is logged loudly at startup.
func revocationChecker() resolve.RevocationChecker {
	if os.Getenv("SAFEKEYS_REVOCATION_OFFLINE") == "1" {
		return offlineRevocation{}
	}
	base := envOr("SAFEKEYS_CONTROL_PLANE_URL", "http://localhost:8080")
	key := os.Getenv("SAFEKEYS_API_KEY")
	// A short cache keeps the hot path off the network while bounding how long
	// a revocation can lag. Never cache the negative for long.
	return revocation.New(base, key, envDuration("SAFEKEYS_REVOCATION_CACHE_TTL", 2*time.Second))
}

// offlineRevocation denies nothing. Development only.
type offlineRevocation struct{}

func (offlineRevocation) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// localPolicy is the MVP local policy: allow requests the issuer already
// authorised by minting a token for them.
//
// The real implementation evaluates operator-authored rules (default deny); see
// smith-gray/policy-engine. This build performs no scope narrowing beyond what
// the token itself carries, and is documented as such.
type localPolicy struct{}

func (localPolicy) Allow(ctx context.Context, principal, sid, scope, aud, injection string) (bool, string) {
	return true, "mvp-local-allow"
}

// logAuditor writes audit records to the sidecar's log.
//
// It records identifiers and outcomes only — never a value, DEK, or KEK.
type logAuditor struct{}

func (logAuditor) Record(ctx context.Context, e resolve.AuditRecord) {
	log.Printf("audit event=%s outcome=%s sid=%s jti=%s scope=%s reason=%s host=%s",
		e.Event, e.Outcome, e.SID, e.JTI, e.Scope, e.Reason, e.Host)
}

func loadVerifier() (*protocol.Ed25519Signer, error) {
	seedB64 := os.Getenv("SAFEKEYS_DEV_SIGNING_KEY")
	if seedB64 == "" {
		return nil, errors.New(
			"SAFEKEYS_DEV_SIGNING_KEY is required in this build; " +
				"production verifies against control-plane public keys")
	}
	seed, err := base64.RawStdEncoding.DecodeString(seedB64)
	if err != nil {
		seed, err = base64.StdEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, fmt.Errorf("decode signing key: %w", err)
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key must be a %d-byte Ed25519 seed", ed25519.SeedSize)
	}
	kid := envOr("SAFEKEYS_KID", "dev-key-1")
	return protocol.NewEd25519Signer(kid, ed25519.NewKeyFromSeed(seed))
}

func defaultFolderRoot() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "safekeys", "folder")
	}
	return filepath.Join(h, ".safekeys", "folder")
}

func defaultKeystorePath() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "safekeys", "kek")
	}
	return filepath.Join(h, ".safekeys", "kek")
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
