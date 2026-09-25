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

	cpclient "github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/cpclient"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/created"
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
		socket     = flag.String("socket", envOr("SAFEKEYS_SOCKET", "/run/safekeys/sidecar.sock"), "unix socket path")
		folderDir  = flag.String("folder", envOr("SAFEKEYS_FOLDER", defaultFolderRoot()), "folder root holding ciphertext objects")
		audience   = flag.String("audience", envOr("SAFEKEYS_AUDIENCE", "env-local"), "resolver identity; tokens must match")
		keyPath    = flag.String("keystore", envOr("SAFEKEYS_KEYSTORE", defaultKeystorePath()), "local KEK path (development mode only)")
		vaultAddr  = flag.String("vault-addr", os.Getenv("SAFEKEYS_VAULT_ADDR"), "OpenBao/Vault address; when set, the KEK lives in the vault and never leaves it")
		vaultTok   = flag.String("vault-token", os.Getenv("SAFEKEYS_VAULT_TOKEN"), "OpenBao/Vault token")
		vaultMount = flag.String("vault-mount", envOr("SAFEKEYS_VAULT_MOUNT", "transit"), "OpenBao/Vault transit mount path")
		vaultKID   = flag.String("vault-kid", envOr("SAFEKEYS_VAULT_KID", "kek-1"), "transit key name (the KEK)")
	)
	flag.Parse()

	// ── Verifier. Development reads a seed; production loads the control
	// plane's public keys and the private key never exists here.
	signer, err := loadVerifier()
	if err != nil {
		return err
	}

	// ── Key store. The KEK never leaves it (ADR kek-never-leaves-store).
	//
	// Two backends:
	//   Vault  — the KEK lives inside OpenBao/Vault Transit and is never
	//            exported. This is the production path.
	//   Local  — a KEK in a 0600 file. Development only; refuses to load without
	//            an explicit opt-in.
	wrapper, kid, cleanup, err := openKeystore(*vaultAddr, *vaultTok, *vaultMount, *vaultKID, *keyPath)
	if err != nil {
		return err
	}
	defer cleanup()

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
		Unwrap: func(ctx context.Context, keyID, wrapped string) ([]byte, error) {
			return wrapper.Unwrap(keyID, wrapped)
		},
		Auditor:  logAuditor{},
		HostName: hostname(),
		Injector: inj,
		Creator:  creatorFor(wrapper, kid, *folderDir),
		Registry: registryFor(),
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
	c := revocation.New(base, key)
	// Negative caching is OFF by default: caching a not-revoked result is what
	// would let a token revoked inside the window still resolve, which the
	// `immediate-effect` contract forbids. Operators who need the throughput can
	// opt in and accept the lag.
	c.NegativeTTL = envDuration("SAFEKEYS_REVOCATION_NEGATIVE_TTL", 0)
	return c
}

// registryFor returns the control-plane client the sidecar proxies list/revoke
// through, so an agent-adjacent caller needs no credential of its own.
func registryFor() sidecar.Registry {
	base := os.Getenv("SAFEKEYS_CONTROL_PLANE_URL")
	if base == "" {
		return nil
	}
	return cpclient.New(base, os.Getenv("SAFEKEYS_API_KEY"))
}

// creatorFor builds the secret-creation path.
//
// It needs the control plane to register objects and mint tokens. Without one,
// create requests are refused rather than partially performed — a half-created
// secret (ciphertext on disk, unregistered, no token) would be worse than none.
func creatorFor(wrapper protocol.KeyWrapper, kid, folderRoot string) *created.Creator {
	base := os.Getenv("SAFEKEYS_CONTROL_PLANE_URL")
	if base == "" {
		return nil
	}
	return &created.Creator{
		Wrapper:          wrapper,
		KID:              kid,
		Registry:         cpclient.New(base, os.Getenv("SAFEKEYS_API_KEY")),
		FolderRoot:       folderRoot,
		DefaultPrincipal: envOr("SAFEKEYS_PRINCIPAL", "operator"),
		DefaultAudience:  envOr("SAFEKEYS_AUDIENCE", "env-local"),
	}
}

// openKeystore selects the key store backend.
//
// With SAFEKEYS_VAULT_ADDR set, the KEK lives in OpenBao/Vault Transit and never
// leaves it — the sidecar only ever sees wrapped, or transiently unwrapped, DEKs.
// Otherwise it falls back to the local file store, which is development-only and
// requires an explicit opt-in.
func openKeystore(vaultAddr, vaultToken, mount, vaultKID, localPath string) (protocol.KeyWrapper, string, func(), error) {
	if vaultAddr != "" {
		v := keystore.NewVault(vaultAddr, vaultToken, mount)
		if err := v.Healthy(); err != nil {
			return nil, "", nil, fmt.Errorf("vault at %s is not reachable or is sealed: %w", vaultAddr, err)
		}
		log.Printf("sidecar: keystore = vault transit (%s, key %q); the KEK never leaves the vault", vaultAddr, vaultKID)
		return v, vaultKID, func() {}, nil
	}
	local, err := keystore.NewLocal(localPath)
	if err != nil {
		return nil, "", nil, err
	}
	log.Printf("sidecar: keystore = LOCAL FILE %s (development only — set SAFEKEYS_VAULT_ADDR for production)", localPath)
	return local, envOr("SAFEKEYS_KID", "kek-local-1"), local.Close, nil
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
