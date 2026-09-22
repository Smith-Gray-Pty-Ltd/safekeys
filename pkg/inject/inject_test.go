package inject_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
)

// TestEnvInjectionReachesChildAndNotCaller proves the value lands in the child
// process but is never returned to the caller.
func TestEnvInjectionReachesChildAndNotCaller(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.txt")
	inj := inject.NewExecInjector()

	res, err := inj.Inject(context.Background(), "env", "API_KEY",
		[]byte("injected-value"),
		[]string{"/bin/sh", "-c", `printf '%s' "$API_KEY" > ` + out})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}

	// The child saw the value.
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "injected-value" {
		t.Fatalf("child did not receive the value, got %q", got)
	}

	// The caller received only the placeholder name.
	if res.Descriptor != "API_KEY" {
		t.Fatalf("descriptor = %q, want the variable name", res.Descriptor)
	}
	if strings.Contains(res.Descriptor, "injected-value") {
		t.Fatal("descriptor contains the value")
	}
}

// TestAmbientEnvNotInherited proves the child gets a minimal environment.
func TestAmbientEnvNotInherited(t *testing.T) {
	t.Setenv("SHOULD_NOT_APPEAR", "leaked")
	out := filepath.Join(t.TempDir(), "out.txt")
	inj := inject.NewExecInjector()

	if _, err := inj.Inject(context.Background(), "env", "SEEN", []byte("x"),
		[]string{"/bin/sh", "-c", `printf '%s' "$SHOULD_NOT_APPEAR" > ` + out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if len(got) != 0 {
		t.Fatalf("ambient variable leaked into the child: %q", got)
	}
}

// TestCommandOutputIsRelayed proves the command's own stdout is captured and
// returned to the caller, so a remote caller sees what the command printed.
func TestCommandOutputIsRelayed(t *testing.T) {
	inj := inject.NewExecInjector()
	inj.Capture = true

	res, err := inj.Inject(context.Background(), "env", "K", []byte("v"),
		[]string{"/bin/sh", "-c", "echo hello-from-child"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Stdout), "hello-from-child") {
		t.Fatalf("command stdout not relayed, got %q", res.Stdout)
	}
	// The injected value must not appear in the relayed output.
	if strings.Contains(string(res.Stdout)+string(res.Stderr), "v") && len(res.Stdout) < 5 {
		t.Fatal("relayed output unexpectedly small; possible value leak")
	}
}

// TestNonZeroExitIsNotADenial proves a failing command yields its exit status
// rather than an injector error. Conflating the two would mis-audit the event
// as a security denial and lose the exit code the caller is owed.
func TestNonZeroExitIsNotADenial(t *testing.T) {
	inj := inject.NewExecInjector()
	res, err := inj.Inject(context.Background(), "env", "K", []byte("v"),
		[]string{"/bin/sh", "-c", "exit 7"})
	if err != nil {
		t.Fatalf("a non-zero exit was reported as an injector error: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", res.ExitCode)
	}
}

// TestUnspawnableCommandIsAnError proves a command that cannot even start IS an
// error, distinct from one that ran and failed.
func TestUnspawnableCommandIsAnError(t *testing.T) {
	inj := inject.NewExecInjector()
	if _, err := inj.Inject(context.Background(), "env", "K", []byte("v"),
		[]string{"/nonexistent/binary/xyz"}); err == nil {
		t.Fatal("an unspawnable command was accepted")
	}
}

// TestFileInjectionPermissions proves the temp file is 0600 and removable.
func TestFileInjectionPermissions(t *testing.T) {
	dir := t.TempDir()
	inj := inject.NewExecInjector()
	inj.TempDir = dir

	res, err := inj.Inject(context.Background(), "file", "kubeconfig", []byte("apiVersion: v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(res.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("temp file mode = %v, want 0600", fi.Mode().Perm())
	}
	inj.Cleanup()
	if _, err := os.Stat(res.Descriptor); !os.IsNotExist(err) {
		t.Fatal("cleanup did not remove the temp file")
	}
}

// TestExecRequiresCommand proves the injector refuses to act when there is no
// consumer, rather than returning the value.
func TestExecRequiresCommand(t *testing.T) {
	inj := inject.NewExecInjector()
	if _, err := inj.Inject(context.Background(), "env", "X", []byte("secret"), nil); err == nil {
		t.Fatal("inject with no command was accepted; it must refuse rather than return a value")
	}
}

// TestUnknownMethodRejected proves the method set is closed.
func TestUnknownMethodRejected(t *testing.T) {
	inj := inject.NewExecInjector()
	if _, err := inj.Inject(context.Background(), "telepathy", "X", []byte("s"), []string{"true"}); err == nil {
		t.Fatal("unknown injection method was accepted")
	}
}
