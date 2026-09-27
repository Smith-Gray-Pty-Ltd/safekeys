package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The control plane holds the token signing key, so the production profile must
// refuse an environment-supplied seed (feature safekeys/deployment-packaging,
// contract no-dev-credentials-in-prod). These tests exercise the real binary
// because a guard that is not wired in is no guard at all.
//
// The database is deliberately unreachable in every case: a refusal must happen
// before any connection attempt, and "database unreachable" after the guard
// would mean the guard was bypassed.

func cpBin(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary test in -short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "safekeys-cp")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build control plane: %v", err)
	}
	return bin
}

func runCP(t *testing.T, env map[string]string) (string, int) {
	t.Helper()
	bin := cpBin(t)
	cmd := exec.Command(bin)
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

// baseProdEnv is the minimum needed to reach the signing-key guard: a valid
// https issuer, an API key, and a DSN. The DSN points nowhere on purpose.
func baseProdEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"SAFEKEYS_PROFILE": "production",
		"DATABASE_URL":     "postgres://u:p@127.0.0.1:1/none",
		"SAFEKEYS_API_KEY": "test-key",
		"SAFEKEYS_ISSUER":  "https://cp.example.test",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// TestProductionRefusesEnvSigningSeed proves the seed cannot arrive as an
// environment variable on a production host. The sidecar spawns child
// processes, so any environment value would be inherited by them.
func TestProductionRefusesEnvSigningSeed(t *testing.T) {
	out, code := runCP(t, baseProdEnv(map[string]string{
		"SAFEKEYS_DEV_SIGNING_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if code == 0 {
		t.Fatalf("production accepted an env-supplied signing seed; output:\n%s", out)
	}
	if !strings.Contains(out, "SAFEKEYS_DEV_SIGNING_KEY_FILE") {
		t.Fatalf("refusal did not name the file variable; output:\n%s", out)
	}
	// The refusal must precede the database attempt.
	if strings.Contains(out, "database unreachable") {
		t.Fatalf("guard ran after the database connection; output:\n%s", out)
	}
}

// TestProductionRefusalPrecedesDatabase proves nothing is dialled before the
// configuration is validated.
func TestProductionRefusalPrecedesDatabase(t *testing.T) {
	out, code := runCP(t, baseProdEnv(map[string]string{
		"SAFEKEYS_DEV_SIGNING_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if strings.Contains(out, "database") {
		t.Fatalf("the guard did not run first; output:\n%s", out)
	}
	_ = code
}

// TestDevelopmentStillAcceptsEnvSeed proves the guard is production-only: the
// development path is unchanged, so contributors are unaffected.
func TestDevelopmentStillAcceptsEnvSeed(t *testing.T) {
	out, _ := runCP(t, baseProdEnv(map[string]string{
		"SAFEKEYS_PROFILE":         "dev",
		"SAFEKEYS_DEV_SIGNING_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if strings.Contains(out, "production profile refuses") {
		t.Fatalf("the development profile was refused: \n%s", out)
	}
	// It should now get as far as attempting the database, which is the marker
	// that the credential path was accepted.
	if !strings.Contains(out, "database unreachable") {
		t.Fatalf("expected the dev profile to proceed to the database; output:\n%s", out)
	}
}
