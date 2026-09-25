package e2e_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/sidecar"
)

// TestTwoAgentDemoNoPlaintext is the blueprint's MVP acceptance criterion.
//
// Agent A creates a secret. Agent A hands Agent B a folder path and a token.
// Agent B uses the secret. NEITHER agent's transcript may contain plaintext.
func TestTwoAgentDemoNoPlaintext(t *testing.T) {
	const secretValue = "sk-live-THIS-MUST-NEVER-APPEAR-IN-A-TRANSCRIPT"

	ctx := context.Background()
	tmp := t.TempDir()

	// ── Infrastructure: keystore, signer, folder.
	store, err := withInsecureKeystore(t, filepath.Join(tmp, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// The control plane role: holds the signing key.
	_, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer("demo-key", prv)
	if err != nil {
		t.Fatal(err)
	}

	// The sidecar role: PUBLIC keys only. Derived from the signer's published
	// set, exactly as a real sidecar fetches them from /v1/keys. It never sees
	// the private key.
	publicVerifier, err := protocol.NewKeySetVerifier(signer.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}

	const audience = "env-demo"
	now := time.Now()

	// ── Agent A: create the secret.
	agentATranscript := &transcript{}

	objID := "obj_demo_agent_0001"
	dek, err := protocol.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Zero(dek)

	ciphertext, err := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte(secretValue))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := store.Wrap("kek-1", dek)
	if err != nil {
		t.Fatal(err)
	}

	folderDir := filepath.Join(tmp, "folder", objID)
	m := &protocol.Manifest{
		Safekeys: protocol.Version,
		Objects: []protocol.ManifestObject{{
			ID: objID, Path: "objects/" + objID + ".enc",
			Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
		}},
	}
	if err := protocol.WriteFolder(folderDir, m, map[string][]byte{objID: ciphertext}, "demo"); err != nil {
		t.Fatal(err)
	}

	// The token Agent A receives carries no secret material.
	claims := protocol.Claims{
		Iss: "https://cp.safekeys.local", Sub: "agent-a", SID: objID,
		Scope: []string{protocol.ScopeInjectEnv}, Aud: audience,
		Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_demo_000000000001",
	}
	jws, err := signer.Sign(protocol.Header{}, claims)
	if err != nil {
		t.Fatal(err)
	}
	tokenURI := protocol.URI(objID, jws)

	// Record what Agent A observed.
	agentATranscript.add("created secret and received token: " + tokenURI)
	agentATranscript.add("folder path: " + folderDir)

	// ── Agent A → Agent B handoff: path + token only.
	handoff := map[string]string{"folder": folderDir, "token": tokenURI}
	agentBTranscript := &transcript{}
	agentBTranscript.add("received handoff: folder=" + handoff["folder"] + " token=" + handoff["token"])

	// ── Agent B: use the secret through the sidecar.
	demoAudit := &recordingAuditor{}
	srv := sidecar.New(sidecar.Config{
		SocketPath: filepath.Join(tmp, "sidecar.sock"),
		Audience:   audience,
		Verifier:   publicVerifier,
		Source:     folder.New(filepath.Join(tmp, "folder")),
		Unwrap:     unwrapAdapter(store),
		Auditor:    demoAudit,
		HostName:   "demo-host",
		Injector:   inject.NewExecInjector(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Run the sidecar for this request.
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.Serve(serveCtx) }()
	waitForSocket(t, srv.Addr())

	// Agent B asks for the secret to be injected into a command. The command
	// asserts the value is present, and writes one line to stdout.
	outFile := filepath.Join(tmp, "command-output.txt")
	cl := &sidecar.Client{SocketPath: srv.Addr()}
	resp, err := cl.Resolve(ctx, sidecar.Request{
		Token: tokenURI,
		Scope: protocol.ScopeInjectEnv,
		Name:  "API_KEY",
		// The command proves the value arrived, then writes only a marker.
		Command: []string{"/bin/sh", "-c",
			`test "$API_KEY" = "` + secretValue + `" && echo "used-secret-ok" > ` + outFile},
		Principal: "agent-b",
	})
	if err != nil {
		t.Fatalf("Agent B resolve failed: %v", err)
	}
	if !resp.OK {
		for _, r := range demoAudit.records {
			t.Logf("audit: event=%s outcome=%s reason=%s scope=%s", r.Event, r.Outcome, r.Reason, r.Scope)
		}
		t.Fatalf("Agent B was denied: %+v", resp)
	}
	agentBTranscript.add("resolve response: ok=" + boolStr(resp.OK) + " descriptor=" + resp.Descriptor)

	// ── The assertions that matter.
	//
	// 1. The command actually saw the value (so the test is not vacuous).
	out, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("command did not run or did not see the secret: %v", err)
	}
	if !strings.Contains(string(out), "used-secret-ok") {
		t.Fatal("the wrapped command did not receive the injected secret")
	}

	// 2. Neither transcript contains plaintext.
	if err := agentATranscript.assertClean(secretValue); err != nil {
		t.Errorf("Agent A transcript: %v", err)
	}
	if err := agentBTranscript.assertClean(secretValue); err != nil {
		t.Errorf("Agent B transcript: %v", err)
	}

	// 3. The handoff payload contained no plaintext.
	for k, v := range handoff {
		if strings.Contains(v, secretValue) {
			t.Errorf("handoff field %q carried plaintext", k)
		}
	}

	// 4. The sidecar response has no field that could carry a value.
	if strings.Contains(resp.Descriptor, secretValue) {
		t.Error("sidecar descriptor carried plaintext")
	}
}

// TestFolderInertWithoutSidecar proves that holding a folder grants nothing.
func TestFolderInertWithoutSidecar(t *testing.T) {
	tmp := t.TempDir()
	store, err := withInsecureKeystore(t, filepath.Join(tmp, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const secret = "inert-test-secret"
	dek, _ := protocol.NewDEK()
	defer protocol.Zero(dek)
	ct, _ := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte(secret))
	wrapped, _ := store.Wrap("kek-1", dek)

	objID := "obj_inert_0001"
	folderDir := filepath.Join(tmp, "folder", objID)
	m := &protocol.Manifest{Safekeys: protocol.Version, Objects: []protocol.ManifestObject{{
		ID: objID, Path: "objects/" + objID + ".enc",
		Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
	}}}
	if err := protocol.WriteFolder(folderDir, m, map[string][]byte{objID: ct}, "inert"); err != nil {
		t.Fatal(err)
	}

	// Read every file. None may contain the secret.
	_ = filepath.Walk(folderDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), secret) {
			t.Fatalf("plaintext found in %s", p)
		}
		return nil
	})

	// And a client with no sidecar is refused.
	cl := &sidecar.Client{SocketPath: filepath.Join(tmp, "nonexistent.sock")}
	if _, err := cl.Resolve(context.Background(), sidecar.Request{Token: "safekey://v1/x#a.b.c"}); err == nil {
		t.Fatal("resolve without a sidecar was not refused")
	}
}

// TestPolicyDenyFailsClosed proves an explicit deny blocks a valid token.
func TestPolicyDenyFailsClosed(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	store, err := withInsecureKeystore(t, filepath.Join(tmp, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, prv, _ := ed25519.GenerateKey(nil)
	signer, _ := protocol.NewEd25519Signer("k", prv)
	publicVerifier, _ := protocol.NewKeySetVerifier(signer.PublicKeys())

	objID := "obj_deny_0001"
	dek, _ := protocol.NewDEK()
	defer protocol.Zero(dek)
	ct, _ := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte("denied-secret"))
	wrapped, _ := store.Wrap("kek-1", dek)
	folderDir := filepath.Join(tmp, "folder", objID)
	m := &protocol.Manifest{Safekeys: protocol.Version, Objects: []protocol.ManifestObject{{
		ID: objID, Path: "objects/" + objID + ".enc",
		Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
	}}}
	_ = protocol.WriteFolder(folderDir, m, map[string][]byte{objID: ct}, "deny")

	now := time.Now()
	claims := protocol.Claims{
		Iss: "https://cp.safekeys.local", SID: objID, Scope: []string{protocol.ScopeInjectEnv},
		Aud: "env-demo", Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_deny_000000000001",
	}
	jws, _ := signer.Sign(protocol.Header{}, claims)
	tokenURI := protocol.URI(objID, jws)

	audit := &recordingAuditor{}
	srv := sidecar.New(sidecar.Config{
		SocketPath: filepath.Join(tmp, "s.sock"),
		Audience:   "env-demo",
		Verifier:   publicVerifier,
		Source:     folder.New(filepath.Join(tmp, "folder")),
		Unwrap:     unwrapAdapter(store),
		Policy:     denyPolicy{},
		Auditor:    audit,
		Injector:   inject.NewExecInjector(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.Serve(serveCtx) }()
	waitForSocket(t, srv.Addr())

	cl := &sidecar.Client{SocketPath: srv.Addr()}
	resp, err := cl.Resolve(ctx, sidecar.Request{
		Token: tokenURI, Scope: protocol.ScopeInjectEnv, Name: "X",
		Command: []string{"/bin/sh", "-c", "true"},
	})
	if err == nil && resp.OK {
		t.Fatal("policy deny did not block a valid token")
	}

	// The denial must be audited, with the reason, and without a value.
	if !audit.sawDenial() {
		t.Error("denial was not audited")
	}
	for _, rec := range audit.records {
		if strings.Contains(rec.Reason+rec.SID+rec.Scope, "denied-secret") {
			t.Error("audit record contains plaintext")
		}
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

type transcript struct{ lines []string }

func (t *transcript) add(s string) { t.lines = append(t.lines, s) }

func (t *transcript) assertClean(secret string) error {
	for i, l := range t.lines {
		if strings.Contains(l, secret) {
			return &transcriptLeak{line: i, content: l}
		}
	}
	return nil
}

type transcriptLeak struct {
	line    int
	content string
}

func (e *transcriptLeak) Error() string {
	return "transcript line " + itoa(e.line) + " contains plaintext"
}

type recordingAuditor struct{ records []resolve.AuditRecord }

func (a *recordingAuditor) Record(ctx context.Context, e resolve.AuditRecord) {
	a.records = append(a.records, e)
}

func (a *recordingAuditor) sawDenial() bool {
	for _, r := range a.records {
		if r.Outcome == "denied" {
			return true
		}
	}
	return false
}

type denyPolicy struct{}

func (denyPolicy) Allow(context.Context, string, string, string, string, string) (bool, string) {
	return false, "test-explicit-deny"
}

func withInsecureKeystore(t *testing.T, path string) (*keystore.Local, error) {
	t.Helper()
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "1")
	return keystore.NewLocal(path)
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			time.Sleep(10 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("sidecar socket did not appear")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// unwrapAdapter adapts keystore.Local to the resolver's context-aware unwrap
// signature.
func unwrapAdapter(l *keystore.Local) func(context.Context, string, string) ([]byte, error) {
	return func(_ context.Context, kid, wrapped string) ([]byte, error) {
		return l.Unwrap(kid, wrapped)
	}
}
