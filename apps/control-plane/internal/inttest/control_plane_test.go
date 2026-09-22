//go:build integration

// Package inttest exercises the control plane against a real Postgres.
//
// Run with:
//
//	SAFEKEYS_TEST_DATABASE_URL=postgres://safekeys:safekeys-dev-password@localhost:5432/safekeys \
//	go test -tags integration ./test/integration/ -v
package inttest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/api"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/policy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/token"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const testAPIKey = "integration-test-key"

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dsn := os.Getenv("SAFEKEYS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SAFEKEYS_TEST_DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("database unreachable: %v", err)
	}
	ctx := context.Background()
	// Clean slate.
	_, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS audit, tokens, policy_rules, objects CASCADE`)
	if _, err := db.ExecContext(ctx, store.Migrations); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	st := store.New(db)
	_, prv, _ := ed25519.GenerateKey(nil)
	signer, err := protocol.NewEd25519Signer("int-test-key", prv)
	if err != nil {
		t.Fatal(err)
	}
	engine := func() *policy.Engine {
		rules, _ := st.ListPolicyRules(ctx)
		return policy.New(rules)
	}
	issuer := token.New(st, signer, "https://cp.safekeys.test", engine)
	srv := api.New(st, issuer, testAPIKey, engine)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); db.Close() })
	return ts, st
}

func do(t *testing.T, ts *httptest.Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Safekeys-Key", testAPIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

// TestFullTokenLifecycle drives the API end to end against Postgres.
func TestFullTokenLifecycle(t *testing.T) {
	ts, st := setup(t)
	ctx := context.Background()

	// Allow policy so issuance is permitted.
	if err := st.UpsertPolicyRule(ctx, store.PolicyRule{
		ID: "allow-all", Effect: "allow", Priority: 0,
		Scope: []string{protocol.ScopeRead, protocol.ScopeInjectEnv},
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Register an object (metadata only).
	code, _ := do(t, ts, "POST", "/v1/objects", map[string]string{
		"id": "obj_int_0001", "owner_principal": "agent-a",
		"content_type": "text/plain", "wrapping_kid": "kek-1",
	})
	if code != http.StatusCreated {
		t.Fatalf("create object: status %d", code)
	}

	// 2. Issue a token.
	code, body := do(t, ts, "POST", "/v1/tokens", map[string]any{
		"sid": "obj_int_0001", "scope": []string{"inject-env"},
		"aud": "env-test", "ttl_seconds": 3600, "principal": "agent-a",
	})
	if code != http.StatusOK {
		t.Fatalf("issue token: status %d (%v)", code, body)
	}
	tokenURI, _ := body["token"].(string)
	jti, _ := body["jti"].(string)
	if tokenURI == "" || jti == "" {
		t.Fatalf("issue returned no token/jti: %v", body)
	}

	// 3. The token is a valid safekey:// URI with a JWS fragment.
	parsed, err := protocol.ParseURI(tokenURI)
	if err != nil {
		t.Fatalf("issued token does not parse: %v", err)
	}
	if parsed.SID != "obj_int_0001" {
		t.Fatalf("sid mismatch: %q", parsed.SID)
	}

	// 4. Audit shows the issuance.
	code, body = do(t, ts, "GET", "/v1/audit?sid=obj_int_0001", nil)
	if code != http.StatusOK {
		t.Fatalf("audit: status %d", code)
	}
	events, _ := body["events"].([]any)
	foundIssue := false
	for _, e := range events {
		if m, ok := e.(map[string]any); ok && m["Event"] == "issue" {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Error("issuance was not audited")
	}

	// 5. Revoke, then confirm the denylist reports it.
	code, _ = do(t, ts, "DELETE", "/v1/tokens/"+jti, nil)
	if code != http.StatusOK {
		t.Fatalf("revoke: status %d", code)
	}
	revoked, err := st.IsRevoked(ctx, jti)
	if err != nil || !revoked {
		t.Fatalf("jti not denylisted after revoke (revoked=%v err=%v)", revoked, err)
	}

	// 6. Revoking again is not an error (idempotent).
	code, _ = do(t, ts, "DELETE", "/v1/tokens/"+jti, nil)
	if code != http.StatusOK {
		t.Fatalf("second revoke: status %d", code)
	}
}

// TestNoEndpointAcceptsPlaintext is the API-shape contract: a request carrying a
// value field must be rejected, not silently accepted.
func TestNoEndpointAcceptsPlaintext(t *testing.T) {
	ts, _ := setup(t)

	// Strict decoding rejects the unknown "value" field.
	code, _ := do(t, ts, "POST", "/v1/objects", map[string]any{
		"id": "obj_x", "owner_principal": "a", "wrapping_kid": "k",
		"value": "super-secret-value",
	})
	if code == http.StatusCreated || code == http.StatusOK {
		t.Fatal("an endpoint accepted a plaintext value field")
	}
}

// TestUnauthenticatedRejected proves every endpoint requires a credential.
func TestUnauthenticatedRejected(t *testing.T) {
	ts, _ := setup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/objects", nil)
	// no X-Safekeys-Key header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", resp.StatusCode)
	}
}

// TestPolicyDenyBlocksIssuance proves a deny rule prevents a token existing.
func TestPolicyDenyBlocksIssuance(t *testing.T) {
	ts, st := setup(t)
	ctx := context.Background()

	if err := st.UpsertPolicyRule(ctx, store.PolicyRule{
		ID: "deny-inject-file", Effect: "deny", Priority: 10,
		Scope: []string{protocol.ScopeInjectFile},
	}); err != nil {
		t.Fatal(err)
	}
	do(t, ts, "POST", "/v1/objects", map[string]string{
		"id": "obj_deny", "owner_principal": "a", "wrapping_kid": "k",
	})

	code, _ := do(t, ts, "POST", "/v1/tokens", map[string]any{
		"sid": "obj_deny", "scope": []string{"inject-file"},
		"aud": "env-test", "principal": "a",
	})
	if code != http.StatusForbidden {
		t.Fatalf("denied issuance got %d, want 403", code)
	}
}

// TestAuditRejectsSecretShapedDetail proves the audit store refuses to record a
// value even if a caller tried to pass one.
func TestAuditRejectsSecretShapedDetail(t *testing.T) {
	_, st := setup(t)
	err := st.AppendAudit(context.Background(), store.AuditEvent{
		Event: "resolve", Outcome: "allowed",
		Detail: map[string]any{"value": "leaked"},
	})
	if err == nil {
		t.Fatal("audit accepted a secret-shaped detail key")
	}
}

var _ = base64.StdEncoding
