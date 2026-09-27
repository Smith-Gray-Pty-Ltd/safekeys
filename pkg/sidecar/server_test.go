package sidecar_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/sidecar"
)

// shortSocketPath returns a socket path short enough for the platform's
// sun_path limit. macOS caps it at ~104 bytes and t.TempDir() is far longer
// than that, so tests allocate a short directory under the system temp root.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// newTestServer builds a server with the minimum wiring needed to bind a
// socket, returning it along with the socket path it will use. Nothing is
// resolved in these tests — they cover the socket's access-control properties,
// which are all decided at Listen time.
func newTestServer(t *testing.T, cfg sidecar.Config) (*sidecar.Server, string) {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = shortSocketPath(t)
	}
	srv := sidecar.New(cfg)
	t.Cleanup(srv.Stop)
	return srv, cfg.SocketPath
}

// TestDefaultSocketIsOwnerOnly pins the default: with no shared group the
// socket is 0600, so only the sidecar's own user can connect. Widening this
// default would silently expose token resolution to every local process.
func TestDefaultSocketIsOwnerOnly(t *testing.T) {
	srv, path := newTestServer(t, sidecar.Config{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("default socket mode = %#o, want 0600", got)
	}
}

// TestConfiguredGroupWidensToGroupOnly verifies a shared group yields 0660 —
// enough for agent users in the group, and still closed to everyone else.
func TestConfiguredGroupWidensToGroupOnly(t *testing.T) {
	// The current user's own primary group always exists, so this needs no
	// privilege and no fixture setup.
	gid := os.Getgid()
	cfg := sidecar.Config{SocketGroup: strconv.Itoa(gid)}
	srv, path := newTestServer(t, cfg)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("group socket mode = %#o, want 0660", got)
	}
	if got := info.Mode().Perm(); got&0o007 != 0 {
		t.Fatalf("group socket mode %#o grants world access", got)
	}
}

// TestUnknownGroupRefused proves a mistyped group fails the start rather than
// silently leaving the socket owner-only, which would look like a permission
// outage from the agent's side.
func TestUnknownGroupRefused(t *testing.T) {
	path := shortSocketPath(t)
	cfg := sidecar.Config{SocketPath: path, SocketGroup: "safekeys-no-such-group-xyz"}
	srv := sidecar.New(cfg)
	defer srv.Stop()

	if err := srv.Listen(); err == nil {
		t.Fatal("Listen accepted a group that does not exist")
	}
}

// TestWorldAccessibleModeRefused proves a misconfiguration cannot produce a
// socket any local process can reach: Listen refuses and leaves nothing behind.
func TestWorldAccessibleModeRefused(t *testing.T) {
	path := shortSocketPath(t)
	cfg := sidecar.Config{SocketPath: path, SocketMode: 0o666}
	srv := sidecar.New(cfg)
	defer srv.Stop()

	if err := srv.Listen(); err == nil {
		t.Fatal("Listen accepted a world-accessible socket mode")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a refusing Listen left a socket file behind")
	}
}

// TestClientConnectsThroughGroupSocket is the positive half of the access
// model: a client using the same socket path can reach the server. It asserts
// the channel works, not the OS permission (which needs two uids to exercise).
func TestClientConnectsThroughGroupSocket(t *testing.T) {
	path := shortSocketPath(t)
	cfg := sidecar.Config{SocketPath: path, SocketGroup: strconv.Itoa(os.Getgid())}
	srv := sidecar.New(cfg)
	defer srv.Stop()

	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	waitForSocket(t, path)

	// op=list with no registry is denied, but reaching the denial proves the
	// connection was accepted over the group socket.
	client := &sidecar.Client{SocketPath: path}
	resp, err := client.List(ctx)
	if err != nil {
		t.Fatalf("client could not reach the group socket: %v", err)
	}
	if resp.OK {
		t.Fatal("expected a denial from a server with no registry")
	}
}

// waitForSocket blocks briefly until the listener is accepting.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s never appeared", path)
}
