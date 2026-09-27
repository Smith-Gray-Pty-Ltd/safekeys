// Package credential resolves a secret from a file-backed source when one is
// configured, falling back to the environment.
//
// Production deploys should never place a secret in a process environment:
// environment variables are readable from /proc/<pid>/environ, are inherited
// by every child process (including the agent-spawned consumers the sidecar
// injects into), and appear in `docker inspect` and process listings. Docker
// secrets and systemd credentials both deliver material as a root-owned file
// instead, which is why the *_FILE convention exists here.
//
// Precedence is file-first when both are set: a deployment that has mounted a
// credential file means it, and the environment variable is the development
// convenience. Callers get a distinct error for a configured-but-unreadable
// file rather than a silent fallback to an empty value, because a missing
// secret must fail closed.
package credential

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Source names the two ways a credential can be supplied.
type Source int

const (
	// SourceNone means neither variable was set.
	SourceNone Source = iota
	// SourceFile means the value came from the *_FILE path.
	SourceFile
	// SourceEnv means the value came from the environment.
	SourceEnv
)

func (s Source) String() string {
	switch s {
	case SourceFile:
		return "file"
	case SourceEnv:
		return "env"
	default:
		return "none"
	}
}

// ErrEmpty is returned when a configured source exists but yields no value.
// Distinguishing this from "not configured" lets a caller treat an empty
// mounted secret as a hard failure.
var ErrEmpty = errors.New("credential: configured source is empty")

// FromEnv resolves a credential.
//
// envKey is the variable holding the value directly. fileKey names a variable
// holding a *path*; when set, the file at that path is read and its contents
// returned with a single trailing newline trimmed (editors and `echo` routinely
// add one). If both are set the file wins.
//
// It returns the value and the source used. When neither is set the value is
// empty, the source is SourceNone, and the error is nil — absence is the
// caller's decision to enforce, not an error here.
func FromEnv(envKey, fileKey string) (string, Source, error) {
	if fileKey != "" {
		if path := os.Getenv(fileKey); path != "" {
			v, err := FromFile(path)
			if err != nil {
				return "", SourceFile, err
			}
			if v == "" {
				return "", SourceFile, fmt.Errorf("%w (%s=%s)", ErrEmpty, fileKey, path)
			}
			return v, SourceFile, nil
		}
	}
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			return v, SourceEnv, nil
		}
	}
	return "", SourceNone, nil
}

// FromFile reads a credential file. It does not require the file to be 0600
// because a container orchestrator may present it with owner root and group
// read, but it does refuse a world-readable file: a credential readable by
// every user on the host is a misconfiguration worth failing on rather than
// quietly accepting.
func FromFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("credential: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("credential: %s is a directory", path)
	}
	if info.Mode().Perm()&0o004 != 0 {
		return "", fmt.Errorf("credential: %s is world-readable (mode %#o); refusing to load a shared secret", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("credential: read %s: %w", path, err)
	}
	// Trim trailing whitespace only. A credential may legitimately contain
	// interior spaces; leading/trailing whitespace is never intended.
	return strings.TrimRight(string(raw), "\r\n\t "), nil
}
