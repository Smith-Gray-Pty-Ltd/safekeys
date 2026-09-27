package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The production profile is a security boundary, not documentation: a host that
// declares itself production must be unable to start with a development
// credential path (feature smith-gray/deployment-packaging, contract
// no-dev-credentials-in-prod). These tests exercise the real binary, because a
// unit test of the guard would not prove the wiring is present.
//
// The binary is built once into a temporary directory. Tests are skipped in
// -short mode so the fast feedback loop stays fast.

// sidecarBin builds the sidecar once for the package's tests.
func sidecarBin(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary test in -short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "safekeys-sidecar")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build sidecar: %v", err)
	}
	return bin
}

// runSidecar starts the binary with the given environment and returns its
// combined output and exit code. It never waits for a long-lived server: every
// invocation under test must fail fast, so a timeout is treated as a failure to
// enforce the contract.
func runSidecar(t *testing.T, env map[string]string, args ...string) (string, int) {
	t.Helper()
	bin := sidecarBin(t)
	cmd := exec.Command(bin, args...)
	// Start from a minimal environment so the developer's own SAFEKEYS_* do not
	// leak into the test. PATH is needed for nothing here (the binary spawns no
	// children before failing) but is harmless.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.String(), code
}

// TestProductionRefusesInsecureKeystore proves the dev-only KEK file path cannot
// be selected on a production host.
func TestProductionRefusesInsecureKeystore(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE":                 "production",
		"SAFEKEYS_ALLOW_INSECURE_KEYSTORE": "1",
		"SAFEKEYS_VAULT_ADDR":              "http://127.0.0.1:8200",
		"SAFEKEYS_VAULT_TOKEN_FILE":        "/nonexistent",
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("production accepted the insecure keystore; output:\n%s", out)
	}
	if !strings.Contains(out, "production profile refuses") {
		t.Fatalf("expected a production refusal, got:\n%s", out)
	}
}

// TestProductionRefusesEnvSuppliedKeystoreToken proves a token in the
// environment is refused, because the sidecar spawns child processes that would
// inherit it.
func TestProductionRefusesEnvSuppliedKeystoreToken(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE":           "production",
		"SAFEKEYS_VAULT_ADDR":        "http://127.0.0.1:8200",
		"SAFEKEYS_VAULT_TOKEN":       "root",
		"SAFEKEYS_API_KEY":           "k",
		"SAFEKEYS_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("production accepted an env-supplied key store token; output:\n%s", out)
	}
	if !strings.Contains(out, "SAFEKEYS_VAULT_TOKEN_FILE") {
		t.Fatalf("refusal did not name the file variable; output:\n%s", out)
	}
}

// TestProductionRefusesOfflineRevocation proves revocation cannot be disabled on
// a production host, which would let a revoked token resolve until its TTL.
func TestProductionRefusesOfflineRevocation(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE":            "production",
		"SAFEKEYS_VAULT_ADDR":         "http://127.0.0.1:8200",
		"SAFEKEYS_VAULT_TOKEN_FILE":   "/nonexistent",
		"SAFEKEYS_REVOCATION_OFFLINE": "1",
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("production accepted offline revocation; output:\n%s", out)
	}
	if !strings.Contains(out, "production profile refuses") {
		t.Fatalf("expected a production refusal, got:\n%s", out)
	}
}

// TestProductionRefusesMissingKeystore proves a production host with no key
// store configured fails rather than silently falling back to a local KEK.
func TestProductionRefusesMissingKeystore(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE": "production",
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("production started with no key store; output:\n%s", out)
	}
	if !strings.Contains(out, "SAFEKEYS_VAULT_ADDR") {
		t.Fatalf("refusal did not name the missing setting; output:\n%s", out)
	}
}

// TestProductionRefusalPrecedesNetworkWork proves the guard runs before the
// sidecar reaches out to an authority. A misconfigured host must not contact a
// control plane it should never have been talking to.
func TestProductionRefusalPrecedesNetworkWork(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE":    "production",
		"SAFEKEYS_VAULT_ADDR": "http://127.0.0.1:8200",
		// An env-supplied token triggers the refusal, so the process must stop
		// before it would fetch verification keys from the control plane below.
		"SAFEKEYS_VAULT_TOKEN": "root",
		// A control-plane URL that would fail loudly if it were dialled.
		"SAFEKEYS_CONTROL_PLANE_URL": "http://256.256.256.256:1",
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("production started despite a refused configuration; output:\n%s", out)
	}
	if strings.Contains(out, "v1/keys") {
		t.Fatalf("the guard ran after fetching verification keys; output:\n%s", out)
	}
	if !strings.Contains(out, "production profile refuses") {
		t.Fatalf("expected a production refusal, got:\n%s", out)
	}
}

// TestMissingCredentialFileFailsClosed proves a configured-but-unreadable file
// is an error rather than a silent fallback — the property that makes mounting
// a credential safe to rely on.
func TestMissingCredentialFileFailsClosed(t *testing.T) {
	out, code := runSidecar(t, map[string]string{
		"SAFEKEYS_PROFILE":          "production",
		"SAFEKEYS_VAULT_ADDR":       "http://127.0.0.1:8200",
		"SAFEKEYS_VAULT_TOKEN_FILE": filepath.Join(t.TempDir(), "absent"),
	}, "--socket", filepath.Join(t.TempDir(), "s.sock"))
	if code == 0 {
		t.Fatalf("a missing credential file did not fail the start; output:\n%s", out)
	}
	if !strings.Contains(out, "credential:") {
		t.Fatalf("expected a credential error, got:\n%s", out)
	}
}
