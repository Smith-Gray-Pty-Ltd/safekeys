package sidecar_test

// Output-control integration tests, per
// .usm/features/resolution/output-control.usm. Each test maps to a spec test
// id and asserts the END-TO-END property: a prompt-injected command cannot
// read the secret back out of anything the sidecar returns.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/commandpolicy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/folder"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keystore"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/localpolicy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/sidecar"
)

// ── Harness ─────────────────────────────────────────────────────────────────

const canary = "sk-live-REDCANARY-q9X#mVt2$wZn8"

// recordingAuditor captures audit records for assertions.
type captureAuditor struct {
	mu      chan []resolve.AuditRecord
	records []resolve.AuditRecord
}

func newCaptureAuditor() *captureAuditor {
	return &captureAuditor{mu: make(chan []resolve.AuditRecord, 1)}
}

func (a *captureAuditor) Record(_ context.Context, e resolve.AuditRecord) {
	a.records = append(a.records, e)
}

func (a *captureAuditor) has(event string) bool {
	for _, r := range a.records {
		if r.Event == event {
			return true
		}
	}
	return false
}

// harness spins up a sidecar with the given policy, mints a token for the
// canary secret, and returns a client.
type harness struct {
	t       *testing.T
	client  *sidecar.Client
	audit   *captureAuditor
	token   string
	objID   string
	foldDir string
}

func newHarness(t *testing.T, checker resolve.PolicyChecker) *harness {
	t.Helper()
	ctx := context.Background()
	// Short root: macOS Unix socket paths cap around 104 bytes and the
	// default t.TempDir() nesting can exceed that.
	tmp, err := os.MkdirTemp("", "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	store, err := withInsecureKeystore(t, filepath.Join(tmp, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	_, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer("k", prv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := protocol.NewKeySetVerifier(signer.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}

	objID := fmt.Sprintf("obj_outctl_%016x", time.Now().UnixNano())
	dek, _ := protocol.NewDEK()
	t.Cleanup(func() { protocol.Zero(dek) })
	ct, _ := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte(canary))
	wrapped, _ := store.Wrap("kek-1", dek)
	foldDir := filepath.Join(tmp, "folder")
	m := &protocol.Manifest{Safekeys: protocol.Version, Objects: []protocol.ManifestObject{{
		ID: objID, Path: "objects/" + objID + ".enc",
		Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
	}}}
	if err := protocol.WriteFolder(filepath.Join(foldDir, objID), m, map[string][]byte{objID: ct}, "outctl"); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := protocol.Claims{
		Iss: "https://cp.test", SID: objID, Scope: []string{protocol.ScopeInjectEnv},
		Aud: "env-test", Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_outctl_" + objID[len(objID)-8:],
	}
	jws, _ := signer.Sign(protocol.Header{}, claims)

	audit := newCaptureAuditor()
	inj := inject.NewExecInjector()
	inj.Capture = true
	srv := sidecar.New(sidecar.Config{
		SocketPath: filepath.Join(tmp, "s.sock"),
		Audience:   "env-test",
		Verifier:   verifier,
		Source:     folder.New(foldDir),
		Unwrap: func(_ context.Context, kid, wrapped string) ([]byte, error) {
			return store.Unwrap(kid, wrapped)
		},
		Policy:   checker,
		Auditor:  audit,
		Injector: inj,
	})
	srv.SetLogger(func(format string, args ...any) {
		t.Logf("sidecar: "+format, args...)
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(sctx) }()
	waitForSocket(t, srv.Addr())

	return &harness{t: t, client: &sidecar.Client{SocketPath: srv.Addr()}, audit: audit, token: protocol.URI(objID, jws), objID: objID, foldDir: foldDir}
}

// run executes a resolve request and returns the client-visible result.
func (h *harness) run(command []string, origin string) (*sidecar.Response, error) {
	h.t.Helper()
	return h.client.Resolve(context.Background(), sidecar.Request{
		Token: h.token, Scope: protocol.ScopeInjectEnv, Name: "SAFEKEYS_SECRET",
		Command: command, Origin: origin,
	})
}

// allowAllWithoutCommands mimics an operator's broad allow rule: any scope,
// no command restriction. This is the pre-existing posture, now with the
// command dimension enforced inside.
var allowAllWithoutCommands = localpolicy.NewFromRules([]localpolicy.Rule{
	{ID: "allow-all", Effect: "allow", Scope: []string{"read", "unwrap", "inject-env", "inject-file"}, Aud: ""},
})

// allowWithSpec allows only one command shape.
func allowWithSpec(exec string, args ...string) resolve.PolicyChecker {
	return localpolicy.NewFromRules([]localpolicy.Rule{
		{ID: "allow-specific", Effect: "allow", Scope: []string{"inject-env"},
			Commands: []commandpolicy.CommandSpec{{Exec: exec, Args: argsOrNil(args)}}},
	})
}

func argsOrNil(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args
}

// ── printenv / env / echo / cat leak nothing ────────────────────────────────

func TestPrintenvEnvEchoLeakNothing(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)

	attempts := [][]string{
		{"printenv", "SAFEKEYS_SECRET"},
		{"env"},
		{"echo", "$SAFEKEYS_SECRET"},
		{"cat", h.foldDir + "/" + h.objID + "/manifest.json"}, // wrong file, but the shape
	}
	for _, argv := range attempts {
		resp, err := h.run(argv, "cli")
		if err != nil {
			// Dumpers must be REFUSED by the backstop — a denial is also a pass,
			// as long as no value appears anywhere.
			if !strings.Contains(protocol.ReasonOf(err), "") {
				t.Logf("attempt %q denied: %v", argv, err)
			}
			continue
		}
		out := string(resp.Stdout) + string(resp.Stderr)
		if strings.Contains(out, canary) {
			t.Fatalf("attempt %v leaked the value: %q", argv, out)
		}
		for _, enc := range encodedForms() {
			if strings.Contains(out, enc) {
				t.Fatalf("attempt %v leaked an encoded form: %q", argv, out)
			}
		}
		if strings.Contains(out, "[REDACTED:safekeys]") && !h.audit.has("redact") {
			t.Fatalf("redaction happened but no audit record: %q", out)
		}
	}
	if !h.audit.has("redact") {
		// At least one of the attempts must have been redacted or refused;
		// env and printenv are refused by the backstop, echo redacted if run.
		t.Log("no redaction records — attempts were refused before running (acceptable)")
	}
}

// encodedForms lists renderings of the canary the scanner must catch.
func encodedForms() []string {
	b := []byte(canary)
	return []string{
		base64.StdEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		url.QueryEscape(canary),
	}
}

// ── Encoded forms are redacted ──────────────────────────────────────────────

func TestEncodedFormsRedacted(t *testing.T) {
	// allowlist a python one-liner? No — interpreters with inline code are
	// refused. Use a helper that prints encodings via a permitted path:
	// write a script file and allow python3 script.py.
	h := newHarness(t, allowAllWithoutCommands)

	// The backstop refuses inline interpreters, so drive the encodings
	// through `cat` of a prepared file — also refused... The honest test of
	// the redaction path through the full sidecar is a command the backstop
	// allows that can emit the value. `dd` is refused. `grep` is allowed:
	// grep -o on a file containing the value. Simpler: `tr` is not in the
	// denylist, and tr can transform. But the REAL point is: any output that
	// contains an encoded form gets redacted. Use `sed` — not refused — to
	// emit the base64 of the value? sed cannot compute base64.
	//
	// The realistic allowed-command exfil: a helper binary that reads the
	// env and prints encodings. Build it as a tiny Go test helper.
	encbin := filepath.Join(t.TempDir(), "leaky")
	buildLeakyHelper(t, encbin)

	for _, mode := range []string{"b64", "hex", "pct", "json", "raw"} {
		resp, err := h.run([]string{encbin, mode}, "cli")
		if err != nil {
			t.Fatalf("helper run failed: %v", err)
		}
		out := string(resp.Stdout) + string(resp.Stderr)
		if strings.Contains(out, canary) {
			t.Fatalf("mode %s: raw value in output: %q", mode, out)
		}
		if !strings.Contains(out, "[REDACTED:safekeys]") {
			t.Fatalf("mode %s: expected redaction marker in %q", mode, out)
		}
	}
	if !h.audit.has("redact") {
		t.Fatal("no redaction audit records were written")
	}
	// The audit record must not contain the value.
	for _, r := range h.audit.records {
		blob := fmt.Sprintf("%+v", r)
		if strings.Contains(blob, canary) {
			t.Fatal("audit record contains the value")
		}
	}
}

// ── Partial leaks (cut -c1-20) are redacted ────────────────────────────────

func TestPartialLeakRedacted(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)
	encbin := filepath.Join(t.TempDir(), "leaky")
	buildLeakyHelper(t, encbin)

	for _, mode := range []string{"prefix", "suffix", "middle"} {
		resp, err := h.run([]string{encbin, mode}, "cli")
		if err != nil {
			t.Fatalf("helper run failed: %v", err)
		}
		out := string(resp.Stdout) + string(resp.Stderr)
		if strings.Contains(out, canary[:20]) || strings.Contains(out, canary[len(canary)-9:]) {
			t.Fatalf("mode %s: partial leak survived: %q", mode, out)
		}
		if !strings.Contains(out, "[REDACTED:safekeys]") {
			t.Fatalf("mode %s: expected redaction marker: %q", mode, out)
		}
	}
}

// ── Split across stdout/stderr is redacted ─────────────────────────────────

func TestSplitAcrossStreamsRedacted(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)
	encbin := filepath.Join(t.TempDir(), "leaky")
	buildLeakyHelper(t, encbin)

	resp, err := h.run([]string{encbin, "split"}, "cli")
	if err != nil {
		t.Fatalf("helper run failed: %v", err)
	}
	out := string(resp.Stdout) + string(resp.Stderr)
	if strings.Contains(out, canary) {
		t.Fatalf("split leak survived: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:safekeys]") {
		t.Fatalf("expected redaction marker: %q", out)
	}
}

// ── Disallowed command refused when a spec exists ──────────────────────────

func TestDisallowedCommandRefused(t *testing.T) {
	h := newHarness(t, allowWithSpec("/usr/bin/curl", "https://api.example.com/*", "*"))

	resp, err := h.run([]string{"/bin/cat", "/etc/passwd"}, "cli")
	if err == nil && resp.OK {
		t.Fatalf("disallowed command was allowed: %+v", resp)
	}
	// The denial is audited with the rule, and no unwrap occurred — which
	// we assert indirectly: the audit log has a deny record naming the rule.
	found := false
	for _, r := range h.audit.records {
		if r.Outcome == "denied" && strings.Contains(r.Reason, "allow-specific") {
			found = true
		}
		if strings.Contains(fmt.Sprintf("%+v", r), canary) {
			t.Fatal("audit contains the value")
		}
	}
	if !found {
		t.Fatalf("denial with rule id not audited: %+v", h.audit.records)
	}
}

// ── MCP without allowlist refused ──────────────────────────────────────────

func TestMCPWithoutAllowlistRefused(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)

	// Even a benign command is refused for MCP origin when the matching
	// rule carries no command specs.
	resp, err := h.run([]string{"/bin/true"}, "mcp")
	if err == nil && resp.OK {
		t.Fatal("MCP resolve without allowlist was allowed")
	}
	// The error is generic on the wire (ADR generic-denials); the rule id is
	// in the audit log.
	found := false
	for _, r := range h.audit.records {
		if r.Outcome == "denied" && strings.Contains(r.Reason, "mcp-command-allowlist-required") {
			found = true
		}
	}
	if !found {
		t.Fatalf("mcp denial not audited: %+v", h.audit.records)
	}
}

func TestMCPWithAllowlistAllowed(t *testing.T) {
	h := newHarness(t, allowWithSpec("/usr/bin/curl", "https://api.example.com/*"))
	resp, err := h.run([]string{"/usr/bin/curl", "https://api.example.com/health"}, "mcp")
	if err != nil {
		t.Fatalf("allowed MCP command was denied: %v", err)
	}
	if !resp.OK {
		t.Fatalf("MCP resolve failed: %+v", resp)
	}
	_ = resp // curl will fail to connect; the resolve itself succeeded
}

// ── Backstop denylist for CLI ──────────────────────────────────────────────

func TestDumperBackstopRefused(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)

	attempts := [][]string{
		{"env"}, {"printenv", "SAFEKEYS_SECRET"},
		{"base64"}, {"xxd"}, {"od"}, {"hexdump"},
		{"strings", "/dev/stdin"},
		{"sh", "-c", "printenv SAFEKEYS_SECRET"},
		{"python3", "-c", "import os;print(os.environ['SAFEKEYS_SECRET'])"},
		{"node", "-e", "console.log(process.env.SAFEKEYS_SECRET)"},
		{"awk", "BEGIN{print ENVIRON[\"SAFEKEYS_SECRET\"]}"},
		{"osascript", "-e", "system info"},
	}
	for _, argv := range attempts {
		resp, err := h.run(argv, "cli")
		if err == nil && resp.OK {
			t.Fatalf("dumper %v was allowed", argv)
		}
	}
	// Denials audited, without values.
	for _, r := range h.audit.records {
		if strings.Contains(fmt.Sprintf("%+v", r), canary) {
			t.Fatal("audit contains the value")
		}
	}
}

// ── Status-only default: 4 KiB cap ─────────────────────────────────────────

func TestOutputCappedAt4KiB(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)
	encbin := filepath.Join(t.TempDir(), "leaky")
	buildLeakyHelper(t, encbin)

	resp, err := h.run([]string{encbin, "big"}, "cli")
	if err != nil {
		t.Fatalf("helper run failed: %v", err)
	}
	if len(resp.Stdout) > 4<<10 {
		t.Fatalf("stdout = %d bytes, exceeds the 4 KiB cap", len(resp.Stdout))
	}
	if !strings.Contains(string(resp.Stdout), "[truncated by safekeys") {
		t.Fatalf("truncation marker missing: %q", string(resp.Stdout[:80]))
	}
}

// ── Write-then-read: the documented limit, demonstrated ────────────────────

// TestWriteThenReadIsNotRelayDetectable documents the honest limit: an
// allowed command can write the value to a file the agent can later read.
// Redaction covers the RELAY only. The test proves the mechanism (write
// succeeds; a later direct file read is invisible to the sidecar) so the
// README's Limits section is testable, not aspirational.
func TestWriteThenReadIsNotRelayDetectable(t *testing.T) {
	h := newHarness(t, allowAllWithoutCommands)
	encbin := filepath.Join(t.TempDir(), "leaky")
	buildLeakyHelper(t, encbin)
	out := filepath.Join(t.TempDir(), "stolen")

	// The write happens inside the consumer; the relay shows nothing.
	resp, err := h.run([]string{encbin, "write", out}, "cli")
	if err != nil {
		t.Fatalf("helper run failed: %v", err)
	}
	if strings.Contains(string(resp.Stdout)+string(resp.Stderr), canary) {
		t.Fatal("relay leaked the value")
	}
	// The file now holds the value — outside the sidecar's reach. This is
	// the limitation the README states; the mitigation is the allowlist.
	if data, err := os.ReadFile(out); err != nil || string(data) != canary {
		t.Fatalf("expected the documented limitation to hold: %v", err)
	}
}

// ── Helper binary ───────────────────────────────────────────────────────────

// buildLeakyHelper compiles a tiny program that reads SAFEKEYS_SECRET and
// emits it in a requested encoding. It is the model of an "allowed command":
// legitimate-looking, policy-permitted, and capable of exfiltration if the
// redaction layer were absent. Building at test time keeps the leak corpus
// next to the tests.
func buildLeakyHelper(t *testing.T, path string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "leaky_main.go")
	prog := `package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func main() {
	v := os.Getenv("SAFEKEYS_SECRET")
	switch os.Args[1] {
	case "raw":
		fmt.Print(v)
	case "b64":
		fmt.Print(base64.StdEncoding.EncodeToString([]byte(v)))
	case "hex":
		fmt.Print(hex.EncodeToString([]byte(v)))
	case "pct":
		fmt.Print(url.QueryEscape(v))
	case "json":
		fmt.Printf("{\"t\":%q}", v)
	case "prefix":
		if len(v) > 20 { fmt.Print(v[:20]) }
	case "suffix":
		if len(v) > 9 { fmt.Print(v[len(v)-9:]) }
	case "middle":
		if len(v) > 14 { fmt.Print(v[5:14]) }
	case "split":
		h := len(v) / 2
		fmt.Printf("%s", v[:h]); fmt.Fprintf(os.Stderr, "%s", v[h:])
	case "write":
		if err := os.WriteFile(os.Args[2], []byte(v), 0o600); err != nil { os.Exit(1) }
	case "big":
		fmt.Print(strings.Repeat("x", 8000))
	}
}
`
	if err := os.WriteFile(src, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", path, src)
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, b)
	}
}

// withInsecureKeystore mirrors the e2e harness helper.
func withInsecureKeystore(t *testing.T, path string) (*keystore.Local, error) {
	t.Helper()
	t.Setenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE", "1")
	return keystore.NewLocal(path)
}

// ── Separate-user peer-credential check ────────────────────────────────────

// TestPeerGroupDeniesOutsider proves the accept-time credential check: with
// PeerGroup set to a group this process does not belong to, the sidecar
// refuses the connection outright — even though the socket file itself would
// permit connecting (permissions are checked at the kernel credential layer,
// not only the filesystem).
func TestPeerGroupDeniesOutsider(t *testing.T) {
	// Find a group this process is NOT in. GID arithmetic on a number we do
	// not hold: os.Getgroups() lists ours; pick max+1.
	mine, err := os.Getgroups()
	if err != nil {
		t.Skipf("cannot list groups: %v", err)
	}
	outGid := os.Getgid()
	for {
		outGid++
		taken := false
		for _, g := range mine {
			if g == outGid {
				taken = true
				break
			}
		}
		if !taken {
			break
		}
	}

	ctx := context.Background()
	tmp, err := os.MkdirTemp("", "skpeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	store, err := withInsecureKeystore(t, filepath.Join(tmp, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	_, prv, _ := ed25519.GenerateKey(nil)
	signer, _ := protocol.NewEd25519Signer("k", prv)
	verifier, _ := protocol.NewKeySetVerifier(signer.PublicKeys())

	objID := fmt.Sprintf("obj_peer_%016x", time.Now().UnixNano())
	dek, _ := protocol.NewDEK()
	t.Cleanup(func() { protocol.Zero(dek) })
	ct, _ := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte("peer-secret"))
	wrapped, _ := store.Wrap("kek-1", dek)
	m := &protocol.Manifest{Safekeys: protocol.Version, Objects: []protocol.ManifestObject{{
		ID: objID, Path: "objects/" + objID + ".enc",
		Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
	}}}
	_ = protocol.WriteFolder(filepath.Join(tmp, "folder", objID), m, map[string][]byte{objID: ct}, "peer")

	now := time.Now()
	claims := protocol.Claims{
		Iss: "https://cp.test", SID: objID, Scope: []string{protocol.ScopeInjectEnv},
		Aud: "env-test", Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_peer_" + objID[len(objID)-8:],
	}
	jws, _ := signer.Sign(protocol.Header{}, claims)

	inj := inject.NewExecInjector()
	inj.Capture = true
	srv := sidecar.New(sidecar.Config{
		SocketPath: filepath.Join(tmp, "s.sock"),
		Audience:   "env-test",
		Verifier:   verifier,
		Source:     folder.New(filepath.Join(tmp, "folder")),
		Unwrap: func(_ context.Context, kid, wrapped string) ([]byte, error) {
			return store.Unwrap(kid, wrapped)
		},
		Injector:  inj,
		PeerGroup: strconv.Itoa(outGid),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	go func() { _ = srv.Serve(ctx) }()
	waitForSocket(t, srv.Addr())

	cl := &sidecar.Client{SocketPath: srv.Addr()}
	// The peer is not in the required group: the request must fail. The
	// failure shape (connection error vs denial) is deliberately not
	// asserted — a bare close is as valid as an error reply.
	token := protocol.URI(objID, jws)
	if resp, rerr := cl.Resolve(ctx, sidecar.Request{
		Token: token, Scope: protocol.ScopeInjectEnv, Name: "X",
		Command: []string{"/bin/true"}, Origin: "cli",
	}); rerr == nil && resp.OK {
		t.Fatal("peer outside PeerGroup was allowed to resolve")
	}
}
