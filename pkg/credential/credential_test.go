package credential_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/credential"
)

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask; force the intended mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFileTakesPrecedenceOverEnv proves a mounted credential wins, so a stale
// environment variable cannot override what the orchestrator delivered.
func TestFileTakesPrecedenceOverEnv(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "tok", "from-file\n", 0o600)
	t.Setenv("SK_TOKEN", "from-env")
	t.Setenv("SK_TOKEN_FILE", path)

	got, src, err := credential.FromEnv("SK_TOKEN", "SK_TOKEN_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-file" {
		t.Fatalf("value = %q, want from-file", got)
	}
	if src != credential.SourceFile {
		t.Fatalf("source = %s, want file", src)
	}
}

// TestTrailingNewlineTrimmed covers the common `echo secret > file` case.
func TestTrailingNewlineTrimmed(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "tok", "secret\n", 0o600)
	t.Setenv("SK_TOKEN_FILE", path)

	got, _, err := credential.FromEnv("", "SK_TOKEN_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret" {
		t.Fatalf("value = %q, want secret", got)
	}
}

// TestEnvFallback keeps development ergonomic: no file, value in the env.
func TestEnvFallback(t *testing.T) {
	t.Setenv("SK_TOKEN", "env-value")
	t.Setenv("SK_TOKEN_FILE", "")

	got, src, err := credential.FromEnv("SK_TOKEN", "SK_TOKEN_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if got != "env-value" || src != credential.SourceEnv {
		t.Fatalf("got %q source %s, want env-value env", got, src)
	}
}

// TestUnsetIsNotAnError lets the caller decide whether absence is fatal.
func TestUnsetIsNotAnError(t *testing.T) {
	t.Setenv("SK_TOKEN", "")
	t.Setenv("SK_TOKEN_FILE", "")

	got, src, err := credential.FromEnv("SK_TOKEN", "SK_TOKEN_FILE")
	if err != nil {
		t.Fatalf("unset credential returned an error: %v", err)
	}
	if got != "" || src != credential.SourceNone {
		t.Fatalf("got %q source %s, want empty none", got, src)
	}
}

// TestMissingFileFailsClosed is the important one: a configured file that
// cannot be read must not silently fall back to the environment or to empty.
func TestMissingFileFailsClosed(t *testing.T) {
	t.Setenv("SK_TOKEN", "env-should-not-be-used")
	t.Setenv("SK_TOKEN_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	if _, _, err := credential.FromEnv("SK_TOKEN", "SK_TOKEN_FILE"); err == nil {
		t.Fatal("a missing credential file fell through instead of failing")
	}
}

// TestWorldReadableFileRefused proves a shared secret is not loaded silently.
func TestWorldReadableFileRefused(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "tok", "secret", 0o644)
	t.Setenv("SK_TOKEN_FILE", path)

	_, _, err := credential.FromEnv("", "SK_TOKEN_FILE")
	if err == nil {
		t.Fatal("a world-readable credential file was accepted")
	}
}

// TestEmptyFileIsAnError distinguishes "mounted but empty" from "not mounted".
func TestEmptyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "tok", "", 0o600)
	t.Setenv("SK_TOKEN_FILE", path)

	_, _, err := credential.FromEnv("", "SK_TOKEN_FILE")
	if !errors.Is(err, credential.ErrEmpty) {
		t.Fatalf("error = %v, want ErrEmpty", err)
	}
}
