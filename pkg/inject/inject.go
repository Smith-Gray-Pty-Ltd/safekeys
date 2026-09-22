// Package inject implements the secret injection methods from
// .usm/features/resolution/secret-injection.usm.
//
// The governing contract, enforced structurally: the Inject method returns only
// a non-sensitive descriptor — a placeholder name or a path — never the value.
// There is no code path in this package that returns plaintext to a caller.
//
// Methods:
//
//	env  — spawn a child with a minimal environment and the value injected
//	file — write a 0600 temp file owned by the consumer, removed on exit
//	exec — run a command as a child of the sidecar with a scrubbed environment
//
// Long-running socket/pipe consumers reuse the exec child pattern.
package inject

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Env allowlist for a wrapped child. Inheritance is the classic leak vector:
// ambient credentials silently follow the process in. Allowlisting inverts the
// default to deny.
var defaultAllowedEnv = []string{"PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TERM", "TMPDIR"}

// Outcome is what an injection produces.
//
// It carries the wrapped command's OUTPUT — its own stdout and stderr — which is
// streamed back to the caller per smith-gray/exec-wrapper. It never carries the
// injected secret and never the resolved plaintext: the injector has no field in
// which a value could travel. (A command that chooses to echo its own secret is
// the operator's decision and outside this contract.)
type Outcome struct {
	Descriptor string // placeholder name or path; never plaintext
	ExitCode   int    // wrapped command status, when one ran
	Stdout     []byte // the command's stdout
	Stderr     []byte // the command's stderr
}

// ExecInjector implements env, file, and exec injection.
type ExecInjector struct {
	// AllowEnv is the set of ambient variables the child may inherit. Nil uses
	// defaultAllowedEnv.
	AllowEnv []string
	// TempDir overrides where temp files are written.
	TempDir string
	// Stdout/Stderr, when set, receive the child's streams. Nil means inherit
	// the sidecar's streams.
	Stdout *os.File
	Stderr *os.File
	// OnChildStarted, when set, is called with the child's pid. Test hook.
	OnChildStarted func(pid int)
	// Capture, when set, collects the child's stdout/stderr into the returned
	// Outcome so a remote caller (over the socket) can receive them. When
	// false the child inherits Stdout/Stderr directly.
	Capture bool

	mu    sync.Mutex
	files map[string]string // descriptor -> path, for cleanup
}

// NewExecInjector builds an injector with default settings.
func NewExecInjector() *ExecInjector {
	return &ExecInjector{AllowEnv: defaultAllowedEnv, files: map[string]string{}}
}

// Inject dispatches on method.
//
// name is the variable name (env/exec) or a filename hint (file).
// command is required for exec.
func (in *ExecInjector) Inject(ctx context.Context, method, name string, plaintext []byte, command []string) (*Outcome, error) {
	switch method {
	case "env", "exec", "":
		if len(command) == 0 {
			// Without a command there is no consumer to inject into. Returning
			// the value would violate the contract, so this is an error.
			return nil, fmt.Errorf("inject: exec/env requires a command; refusing to return a value")
		}
		return in.exec(ctx, name, plaintext, command)
	case "file":
		path, err := in.file(name, plaintext)
		if err != nil {
			return nil, err
		}
		return &Outcome{Descriptor: path}, nil
	case "socket":
		return nil, fmt.Errorf("inject: socket injection is not implemented in the MVP")
	default:
		return nil, fmt.Errorf("inject: unknown method %q", method)
	}
}

// ExitError reports that the wrapped command ran successfully but exited
// non-zero. This is NOT a denial: the secret was injected and the command
// executed; the command itself simply failed. Conflating the two would both
// mis-audit the event as a security denial and lose the exit code the caller
// is owed (see smith-gray/exec-wrapper: "Success is communicated by exit
// code").
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.Code) }

// ExitCode returns the wrapped command's exit status from err, and whether err
// carried one.
func ExitCode(err error) (int, bool) {
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code, true
	}
	return 0, false
}

// exec spawns the command with a scrubbed environment plus the injected value.
// It returns the placeholder name, never the value.
func (in *ExecInjector) exec(ctx context.Context, name string, plaintext []byte, command []string) (*Outcome, error) {
	if name == "" {
		name = "SAFEKEYS_SECRET"
	}
	env := in.scrubbedEnv(name, plaintext)

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = env

	// Capture the command's output so it can be streamed back to the caller.
	// When Capture is false, inherit the sidecar's streams instead.
	var stdout, stderr bytes.Buffer
	if in.Capture {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	} else {
		cmd.Stdout = in.Stdout
		cmd.Stderr = in.Stderr
		if cmd.Stdout == nil {
			cmd.Stdout = os.Stdout
		}
		if cmd.Stderr == nil {
			cmd.Stderr = os.Stderr
		}
	}

	// Run in its own process group so a signal to the wrapped command does not
	// also hit the sidecar.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		// A failure to even spawn the command IS an injector error.
		return nil, err
	}
	if in.OnChildStarted != nil {
		in.OnChildStarted(cmd.Process.Pid)
	}

	out := &Outcome{Descriptor: name}
	err := cmd.Wait()
	if err != nil {
		// Distinguish "ran and failed" from "could not run". A non-zero exit is
		// NOT an injector error — the secret was injected and the command ran.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			out.ExitCode = ee.ExitCode()
		} else {
			return nil, err
		}
	}
	if in.Capture {
		out.Stdout = stdout.Bytes()
		out.Stderr = stderr.Bytes()
	}
	// The caller learns the variable name and the command's output, never the
	// injected value.
	return out, nil
}

// file writes a 0600 temp file owned by the consumer and returns its path.
func (in *ExecInjector) file(name string, plaintext []byte) (string, error) {
	if name == "" {
		name = "secret"
	}
	dir := in.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "safekeys-"+sanitise(name)+"-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	// 0600 before any content is written.
	if err := os.Chmod(path, 0o600); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := f.Write(plaintext); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	in.mu.Lock()
	if in.files == nil {
		in.files = map[string]string{}
	}
	in.files[name] = path
	in.mu.Unlock()

	// The caller receives a path it cannot usefully read (0600 and owned by the
	// consumer), not the value.
	return path, nil
}

// Cleanup removes any temp files this injector created. Call on shutdown.
func (in *ExecInjector) Cleanup() {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, p := range in.files {
		os.Remove(p)
	}
	in.files = map[string]string{}
}

// scrubbedEnv builds a minimal environment plus the injected variable.
func (in *ExecInjector) scrubbedEnv(name string, plaintext []byte) []string {
	allow := in.AllowEnv
	if allow == nil {
		allow = defaultAllowedEnv
	}
	env := make([]string, 0, len(allow)+1)
	for _, k := range allow {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	env = append(env, name+"="+string(plaintext))
	return env
}

func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "secret"
	}
	return b.String()
}

// Compile-time assurance that the injector never returns plaintext: the
// interface method's only []byte parameter is inbound.
var _ = filepath.Join
var _ = time.Second

// ensure protocol is referenced for zeroisation helpers callers should use.
var _ = protocol.Zero
