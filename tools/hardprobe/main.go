// Command hardprobe validates that the sidecar unit's systemd hardening does
// not break the operations the resolver actually performs.
//
// This exists because a hardening directive that looks strict but silently
// prevents the service from working is worse than no directive: the deployment
// appears locked down and simply fails at runtime. The probe performs the three
// operations the resolution path depends on —
//
//  1. bind and accept a Unix-domain socket (the agent-facing channel);
//  2. fork/exec a consumer with a scrubbed environment (the injection path);
//  3. read the consumer's output back (the exit-code-and-stream contract);
//
// — and exits non-zero if any of them fails. Running it under the same
// SystemCallFilter, capability, and filesystem confinement as the real unit
// turns "we set these directives" into "these directives are compatible with
// the workload".
//
// It is a verification harness for deploy/systemd/safekeys-sidecar.service, not
// a production component. See scripts/verify-hardening.sh.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hardprobe: FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("hardprobe: PASS — socket bind/accept, fork/exec, and child output all work under the unit's confinement")
}

func run() error {
	// 1. Unix socket: the sidecar's only inbound channel (AF_UNIX).
	sockPath := filepath.Join(os.TempDir(), "hardprobe.sock")
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("bind unix socket (AF_UNIX / socket syscall): %w", err)
	}
	defer ln.Close()
	if err := os.Chmod(sockPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	fmt.Printf("  socket bound: %s\n", sockPath)

	// Accept in the background so the dial below exercises the full bind →
	// listen → accept path a client would use.
	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		conn.Close()
		accepted <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 2. fork/exec a consumer with a minimal, explicit environment — exactly
	// what pkg/inject does when a token is resolved into a child process.
	// /bin/sh is used here only as a probe stand-in for the real consumer.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "echo probe-child-output")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HARDPROBE=1"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fork/exec consumer (clone/execve under SystemCallFilter): %w (stderr: %s)", err, stderr.String())
	}

	// 3. Read the child's output back — the sidecar streams this to the caller.
	if got := stdout.String(); got != "probe-child-output\n" {
		return fmt.Errorf("child output = %q, want %q", got, "probe-child-output\n")
	}
	fmt.Printf("  child forked and produced output: %q\n", stdout.String())

	// Confirm the parent can still dial its own socket after forking, which
	// proves the two halves compose rather than working only in isolation.
	c, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial own socket after fork: %w", err)
	}
	c.Close()
	if err := <-accepted; err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	fmt.Println("  socket still serves after fork")

	// 4. Confirm a temporary file can be written and removed, which the
	// file-injection method needs (PrivateTmp must still be writable).
	tmpFile := filepath.Join(os.TempDir(), "hardprobe.tmp")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		return fmt.Errorf("write temp file (file injection): %w", err)
	}
	if err := os.Remove(tmpFile); err != nil {
		return fmt.Errorf("remove temp file: %w", err)
	}
	fmt.Println("  temp-file write/remove works (file injection)")
	return nil
}
