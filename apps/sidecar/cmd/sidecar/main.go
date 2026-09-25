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
	"encoding/json"
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
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keysource"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/localpolicy"
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
	// ── Verifier. The sidecar holds PUBLIC keys only.
	//
	// This is the security boundary: the sidecar runs on the same host as the
	// secrets, so if it held a signing key a host compromise would let an
	// attacker mint tokens. It fetches published public keys from the control
	// plane instead, and never holds a private key at all.
	verifier, err := openVerifier()
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
		Verifier:   verifier,
		Revoked:    revocationChecker(),
		Policy:     openPolicy(),
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

// openPolicy builds the resolve-time policy checker.
//
// Resolve-time policy answers a different question from issuance-time policy:
// not "may a token for this exist" but "may THIS host inject THIS secret into
// THIS consumer, right now". A token that exists is not sufficient.
//
// Modes:
//
//	Fetched — the default. Rules come from the control plane and are cached,
//	          so an operator's rule change takes effect without a restart.
//	Static  — SAFEKEYS_POLICY_FILE names a JSON file of rules, for air-gapped
//	          or bootstrap use. Must parse; a malformed file is fatal rather
//	          than being treated as an empty (deny-all) set by accident.
//
// The default is DENY in both modes: absence of a matching allow is a denial.
func openPolicy() resolve.PolicyChecker {
	if path := os.Getenv("SAFEKEYS_POLICY_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("sidecar: read SAFEKEYS_POLICY_FILE: %v", err)
		}
		var rules []localpolicy.Rule
		if err := json.Unmarshal(raw, &rules); err != nil {
			log.Fatalf("sidecar: parse SAFEKEYS_POLICY_FILE: %v", err)
		}
		e := localpolicy.NewFromRules(rules)
		log.Printf("sidecar: policy = STATIC (%d rules); default deny", e.RuleCount())
		return e
	}

	base := envOr("SAFEKEYS_CONTROL_PLANE_URL", "http://localhost:8080")
	ttl := envDuration("SAFEKEYS_POLICY_CACHE_TTL", time.Minute)
	e, err := localpolicy.New(localpolicy.NewHTTP(base, os.Getenv("SAFEKEYS_API_KEY")), ttl)
	if err != nil {
		// Fatal, not a warning: a sidecar that cannot load policy would deny
		// everything, which looks like an outage rather than a misconfiguration.
		log.Fatalf("sidecar: load resolve-time policy from %s: %v", base, err)
	}
	log.Printf("sidecar: policy = FETCHED from %s (%d rules, cache %s); default deny", base, e.RuleCount(), ttl)
	return e
}

// logAuditor writes audit records to the sidecar's log.
//
// It records identifiers and outcomes only — never a value, DEK, or KEK.
type logAuditor struct{}

func (logAuditor) Record(ctx context.Context, e resolve.AuditRecord) {
	log.Printf("audit event=%s outcome=%s sid=%s jti=%s scope=%s reason=%s host=%s",
		e.Event, e.Outcome, e.SID, e.JTI, e.Scope, e.Reason, e.Host)
}

// openVerifier builds the token verifier from PUBLIC key material.
//
// Two modes:
//
//	Fetched  — the default. Keys come from the control plane's /v1/keys
//	           endpoint and are cached, refreshing on an unknown kid so a
//	           rotation propagates without a restart.
//	Static   — SAFEKEYS_VERIFY_KEYS names a file containing a published JWKS.
//	           For air-gapped or bootstrap use.
//
// There is deliberately NO mode that reads a private key. A compromise of the
// sidecar must not yield the ability to mint tokens.
func openVerifier() (resolve.Verifier, error) {
	if path := os.Getenv("SAFEKEYS_VERIFY_KEYS"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read SAFEKEYS_VERIFY_KEYS: %w", err)
		}
		var jwks protocol.PublicJWKS
		if err := json.Unmarshal(raw, &jwks); err != nil {
			return nil, fmt.Errorf("parse SAFEKEYS_VERIFY_KEYS: %w", err)
		}
		v, err := keysource.NewFromKeys(jwks.Keys)
		if err != nil {
			return nil, fmt.Errorf("static keys: %w", err)
		}
		log.Printf("sidecar: verifier = STATIC public keys (%d keys, kid set %v)", len(jwks.Keys), jwks.Kids())
		return v, nil
	}

	base := envOr("SAFEKEYS_CONTROL_PLANE_URL", "http://localhost:8080")
	ttl := envDuration("SAFEKEYS_KEY_CACHE_TTL", 5*time.Minute)
	v, err := keysource.New(keysource.NewHTTP(base), ttl)
	if err != nil {
		return nil, fmt.Errorf("fetch verification keys from %s: %w", base, err)
	}
	log.Printf("sidecar: verifier = FETCHED public keys from %s (%d keys, cache %s)", base, v.KeyCount(), ttl)
	return v, nil
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
