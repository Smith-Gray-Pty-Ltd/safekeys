// Command control-plane runs the Safekeys Control Plane API.
//
// It is the authority service: object registration, token issuance and
// revocation, policy, and the audit log. It NEVER accepts or returns plaintext
// — there is no endpoint with a value-bearing field.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/api"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/policy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/token"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/jackc/pgx/v5/stdlib"

	"database/sql"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("control-plane: %v", err)
	}
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("SAFEKEYS_ADDR", ":8080"), "listen address")
		dsn       = flag.String("database-url", os.Getenv("DATABASE_URL"), "Postgres DSN")
		issuerURL = flag.String("issuer", envOr("SAFEKEYS_ISSUER", "https://cp.safekeys.local"), "issuer URL embedded in tokens (must be https)")
		apiKey    = flag.String("api-key", os.Getenv("SAFEKEYS_API_KEY"), "API key clients must present")
	)
	flag.Parse()

	if *dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	if *apiKey == "" {
		return errors.New("SAFEKEYS_API_KEY is required")
	}
	if len(*issuerURL) < 8 || (*issuerURL)[:8] != "https://" {
		return fmt.Errorf("issuer must be an https URL, got %q", *issuerURL)
	}

	// ── Signing key. Development reads a seed from the environment; production
	// provisions the key into an HSM or secure element (ADR key-custody-hsm).
	signer, err := loadSigner()
	if err != nil {
		return err
	}

	// ── Database.
	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database unreachable: %w", err)
	}
	st := store.New(db)
	if err := applyMigrations(ctx, db); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	// ── Policy engine, rebuilt from the database on each evaluation so a rule
	// change takes effect without a restart.
	engine := func() *policy.Engine {
		e, err := api.LoadPolicy(context.Background(), st)
		if err != nil {
			// Fail closed: an unreadable policy denies everything.
			return policy.New(nil)
		}
		return e
	}

	// ── Bootstrap a default policy if the table is empty, so a fresh install is
	// usable. This is an explicit allow rule, not an implicit permit.
	if rules, err := st.ListPolicyRules(ctx); err == nil && len(rules) == 0 {
		_ = st.UpsertPolicyRule(ctx, store.PolicyRule{
			ID: "bootstrap-allow-operator", Effect: "allow",
			Principal: "", SID: "", Aud: "", Priority: 0,
			Scope: []string{protocol.ScopeRead, protocol.ScopeUnwrap, protocol.ScopeInjectEnv, protocol.ScopeInjectFile},
		})
		log.Println("control-plane: seeded bootstrap allow policy (review before production)")
	}

	issuer := token.New(st, signer, *issuerURL, engine)
	srv := api.New(st, issuer, *apiKey, engine)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ── Graceful shutdown.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("control-plane: shutting down")
		shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	log.Printf("control-plane: listening on %s (issuer %s, kid %s, alg %s)",
		*addr, *issuerURL, signer.KeyID(), signer.Algorithm())
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// applyMigrations runs the embedded schema.
func applyMigrations(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, store.Migrations)
	return err
}

// loadSigner builds the token signer.
//
// Development: a base64 Ed25519 seed in SAFEKEYS_DEV_SIGNING_KEY.
// Production: the key is provisioned into an HSM/secure element; only a handle
// is present here (Phase 1 — see smith-gray/hardware-root).
func loadSigner() (protocol.Signer, error) {
	seedB64 := os.Getenv("SAFEKEYS_DEV_SIGNING_KEY")
	if seedB64 == "" {
		return nil, errors.New(
			"SAFEKEYS_DEV_SIGNING_KEY is required in this build; " +
				"production provisions the signing key into an HSM or secure element")
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ensure the pgx stdlib driver is linked in.
var _ = stdlib.GetDefaultDriver
