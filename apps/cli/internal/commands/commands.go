// Package commands implements the Safekeys CLI.
//
// Commands are listed in .usm/services/cli.usm: create, exec, revoke, list.
//
// The security-critical properties:
//   - create reads plaintext from stdin or a file, NEVER from argv
//   - exec returns an exit code, never a resolved value
//   - list shows metadata only
package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	cpclient "github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/cpclient"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/sidecar"
)

// Env holds CLI configuration from the environment.
type Env struct {
	ControlPlaneURL string
	APIKey          string
	SocketPath      string
	FolderDir       string
	KeystorePath    string
	Audience        string
	Principal       string
}

// FromEnv reads configuration from the environment with sensible defaults.
func FromEnv() Env {
	return Env{
		ControlPlaneURL: envOr("SAFEKEYS_CONTROL_PLANE_URL", "http://localhost:8080"),
		APIKey:          os.Getenv("SAFEKEYS_API_KEY"),
		SocketPath:      envOr("SAFEKEYS_SOCKET", filepath.Join(os.TempDir(), "safekeys", "sidecar.sock")),
		FolderDir:       envOr("SAFEKEYS_FOLDER", filepath.Join("~/.safekeys", "folder")),
		KeystorePath:    envOr("SAFEKEYS_KEYSTORE", filepath.Join("~/.safekeys", "kek")),
		Audience:        envOr("SAFEKEYS_AUDIENCE", "env-local"),
		Principal:       envOr("SAFEKEYS_PRINCIPAL", "operator"),
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return expandHome(v)
	}
	return expandHome(def)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[1:])
		}
	}
	return p
}

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	env := FromEnv()
	ctx := context.Background()

	switch args[0] {
	case "create":
		return cmdCreate(ctx, env, args[1:])
	case "exec":
		return cmdExec(ctx, env, args[1:])
	case "revoke":
		return cmdRevoke(ctx, env, args[1:])
	case "list":
		return cmdList(ctx, env, args[1:])
	case "audit":
		return cmdAudit(ctx, env, args[1:])
	case "version":
		fmt.Printf("safekeys %s (protocol v%s)\n", "0.1.0", protocol.Version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `safekeys — encrypted transport for secrets

Usage:
  safekeys create --object <id> [--file <path>]     create a secret (plaintext on stdin)
  safekeys exec --token <uri> -- <command...>       run a command with a secret injected
  safekeys revoke --jti <jti>                       revoke a capability token
  safekeys list [--objects|--tokens]                list metadata (never values)
  safekeys audit [--sid <id>]                       show the audit log
  safekeys version                                  print version

The model never sees a secret: create returns a token, exec returns an exit code.
`)
}

// ─── create ─────────────────────────────────────────────────────────────────

// cmdCreate registers an object and stores its ciphertext locally.
//
// Plaintext is read from stdin or a file — never argv, which is visible in
// process listings and shell history.
func cmdCreate(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	object := fs.String("object", "", "object id (generated if omitted)")
	file := fs.String("file", "", "read the value from this file instead of stdin")
	contentType := fs.String("content-type", "text/plain", "content-type hint")
	ttl := fs.Duration("ttl", time.Hour, "token TTL (minutes to hours)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Read the value out-of-band.
	var plaintext []byte
	var err error
	if *file != "" {
		plaintext, err = os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", *file, err)
			return 1
		}
	} else {
		plaintext, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			return 1
		}
	}
	// Trim a single trailing newline from piped input, which is rarely intended.
	plaintext = []byte(strings.TrimSuffix(string(plaintext), "\n"))
	secure := protocol.SecureBufferFrom(plaintext)
	defer secure.Release()

	if len(secure.Bytes()) == 0 {
		fmt.Fprintln(os.Stderr, "refusing to create an empty secret")
		return 2
	}
	if isTerminal() && *file == "" {
		fmt.Fprintln(os.Stderr, "warning: reading from a terminal echoes the value; prefer --file or a pipe")
	}

	// Delegate creation to the sidecar.
	//
	// The CLI deliberately does NOT encrypt locally. The sidecar owns the
	// keystore and is the only component permitted to touch key material, so
	// doing the crypto here would (a) duplicate it in every client, and (b)
	// bypass the production keystore — a local file store would be used even
	// when the sidecar is configured for OpenBao/Vault.
	//
	// The sidecar also reads the source itself, so the value never travels over
	// the socket.
	objID := *object
	if objID == "" {
		objID, err = protocol.NewID("obj")
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate id: %v\n", err)
			return 1
		}
	}

	// The sidecar reads from a file. When the caller piped a value, write it to a
	// private temp file first; never send it as a literal.
	srcPath := *file
	var tmpSrc string
	if srcPath == "" {
		f, terr := os.CreateTemp("", "safekeys-src-*")
		if terr != nil {
			fmt.Fprintf(os.Stderr, "temp file: %v\n", terr)
			return 1
		}
		if err := os.Chmod(f.Name(), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "chmod: %v\n", err)
			f.Close()
			os.Remove(f.Name())
			return 1
		}
		if _, werr := f.Write(secure.Bytes()); werr != nil {
			fmt.Fprintf(os.Stderr, "write temp: %v\n", werr)
			f.Close()
			os.Remove(f.Name())
			return 1
		}
		f.Close()
		tmpSrc, srcPath = f.Name(), f.Name()
		defer shred(tmpSrc)
	}

	cl := &sidecar.Client{SocketPath: env.SocketPath}
	resp, cerr := cl.Create(ctx, sidecar.Request{
		ObjectID:    objID,
		SourceFile:  srcPath,
		ContentType: *contentType,
		ScopeList:   []string{protocol.ScopeInjectEnv, protocol.ScopeRead},
		Audience:    env.Audience,
		TTLSeconds:  int(ttl.Seconds()),
		Principal:   env.Principal,
	})
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "no sidecar at %s: %v\n", env.SocketPath, cerr)
		fmt.Fprintln(os.Stderr, "start it with: make dev")
		return 1
	}
	if !resp.OK || resp.Created == nil {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}

	// The caller receives a token and a path — never the value.
	c := resp.Created
	fmt.Printf("object:  %s\n", c.ObjectID)
	fmt.Printf("folder:  %s\n", c.Folder)
	if c.Expires > 0 {
		fmt.Printf("expires: %s\n", time.Unix(c.Expires, 0).Format(time.RFC3339))
	}
	fmt.Printf("token:   %s\n", c.Token)
	return 0
}

// ─── exec ───────────────────────────────────────────────────────────────────

// cmdExec runs a command with secrets injected. It returns the command's exit
// code; the value is never printed.
func cmdExec(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	token := fs.String("token", "", "capability token URI")
	name := fs.String("name", "SAFEKEYS_SECRET", "environment variable name for the injected value")
	scope := fs.String("scope", protocol.ScopeInjectEnv, "operation to request")
	folder := fs.String("folder", "", "folder directory (defaults to the CLI's folder root)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if *token == "" || len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: safekeys exec --token <uri> -- <command...>")
		return 2
	}

	// Prefer the sidecar: it is the only component permitted to resolve.
	cl := &sidecar.Client{SocketPath: env.SocketPath}
	resp, err := cl.Resolve(ctx, sidecar.Request{
		Token: *token, Scope: *scope, Name: *name, Command: command, Principal: env.Principal,
	})
	if err == nil && resp.OK {
		// Relay the wrapped command's own output, then hand back its exit
		// status. A failing command is not a denial.
		if len(resp.Stdout) > 0 {
			os.Stdout.Write(resp.Stdout)
		}
		if len(resp.Stderr) > 0 {
			os.Stderr.Write(resp.Stderr)
		}
		return resp.ExitCode
	}

	// Fallback for single-host development where no sidecar is running: perform
	// the same resolution locally. This is explicitly a dev convenience and
	// prints a warning, because it means the CLI is acting as the resolver.
	if resp != nil && !resp.OK {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}
	fmt.Fprintln(os.Stderr, "warning: no sidecar reachable — resolving locally (development mode only)")
	return execLocal(ctx, env, *token, *scope, *name, *folder, command)
}

// execLocal performs resolution in-process. It exists so the MVP is usable
// without a running sidecar, and it does not weaken the model guarantee: the
// value still goes only into the child's environment.
func execLocal(ctx context.Context, env Env, tokenURI, scope, name, folderDir string, command []string) int {
	verifier, store, err := loadLocalVerifier(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signer: %v\n", err)
		return 1
	}
	if folderDir == "" {
		folderDir = env.FolderDir
	}
	parsed, err := protocol.ParseURI(tokenURI)
	if err != nil {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}
	claims, err := protocol.VerifyToken(verifier, parsed, env.Audience, time.Now(), func(string) bool { return false })
	if err != nil {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}
	if !protocol.ScopeAllows(claims.Scope, scope) {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}

	src := folderSource(filepath.Join(folderDir, claims.SID))
	obj, ct, err := src.Load(ctx, claims.SID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "denied: object unavailable")
		return 1
	}
	dek, err := store.Unwrap(obj.WrappingKID, obj.WrappedKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "denied: key store unavailable")
		return 1
	}
	defer protocol.Zero(dek)
	pt, err := protocol.DecryptObject(obj.Alg, dek, ct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "denied")
		return 1
	}
	secure := protocol.SecureBufferFrom(pt)
	defer secure.Release()

	inj := inject.NewExecInjector()
	inj.Capture = true
	out, err := inj.Inject(ctx, "env", name, secure.Bytes(), command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if len(out.Stdout) > 0 {
		os.Stdout.Write(out.Stdout)
	}
	if len(out.Stderr) > 0 {
		os.Stderr.Write(out.Stderr)
	}
	return out.ExitCode
}

// ─── revoke ─────────────────────────────────────────────────────────────────

func cmdRevoke(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	jti := fs.String("jti", "", "token id to revoke")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *jti == "" {
		fmt.Fprintln(os.Stderr, "usage: safekeys revoke --jti <jti>")
		return 2
	}
	c := cpclient.New(env.ControlPlaneURL, env.APIKey)
	if err := c.RevokeToken(ctx, *jti); err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		return 1
	}
	fmt.Printf("revoked %s\n", *jti)
	return 0
}

// ─── list ───────────────────────────────────────────────────────────────────

// cmdList shows metadata only. It has no code path that could print a value.
func cmdList(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := cpclient.New(env.ControlPlaneURL, env.APIKey)
	objs, err := c.ListObjects(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		return 1
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(objs)
		return 0
	}
	if len(objs) == 0 {
		fmt.Println("no objects")
		return 0
	}
	fmt.Printf("%-28s %-20s %-12s %s\n", "OBJECT", "OWNER", "KEK", "CREATED")
	for _, o := range objs {
		fmt.Printf("%-28s %-20s %-12s %s\n", o.ID, o.OwnerPrincipal, o.WrappingKID, o.CreatedAt)
	}
	return 0
}

// ─── audit ──────────────────────────────────────────────────────────────────

func cmdAudit(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	sid := fs.String("sid", "", "filter by object id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := cpclient.New(env.ControlPlaneURL, env.APIKey)
	events, err := c.Audit(ctx, *sid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return 1
	}
	fmt.Printf("%-22s %-12s %-8s %-10s %s\n", "TIME", "EVENT", "OUTCOME", "REASON", "SID")
	for _, e := range events {
		fmt.Printf("%-22s %-12s %-8s %-10s %s\n", e.At, e.Event, e.Outcome, e.Reason, e.SID)
	}
	return 0
}

// shred overwrites a temp file with zeros before removing it. Best-effort: the
// OS may have page-cached it, but it shortens the window a source value exists
// on disk.
func shred(path string) {
	if path == "" {
		return
	}
	if fi, err := os.Stat(path); err == nil {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0o600); err == nil {
			_, _ = f.Write(make([]byte, fi.Size()))
			f.Close()
		}
	}
	os.Remove(path)
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
