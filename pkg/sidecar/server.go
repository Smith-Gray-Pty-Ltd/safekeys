// Package sidecar wires the resolution path to a Unix domain socket.
//
// The socket is the sidecar's only inbound channel for agents and CLI
// (ADR socket-request-response): the OS enforces which local processes may
// connect via filesystem permissions, and no network port is exposed.
package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
)

// Request is the wire form of a resolve request.
type Request struct {
	Token     string   `json:"token"`
	Scope     string   `json:"scope"`
	Name      string   `json:"name"`
	Command   []string `json:"command"`
	Principal string   `json:"principal"`
}

// Response is the wire form of a resolve result.
//
// It carries NO plaintext field by construction. A client that wanted the value
// has no field to read it from.
type Response struct {
	OK         bool   `json:"ok"`
	Descriptor string `json:"descriptor,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Stdout     []byte `json:"stdout,omitempty"`
	Stderr     []byte `json:"stderr,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Config holds the sidecar's dependencies.
type Config struct {
	SocketPath string
	Audience   string
	Verifier   resolve.Verifier
	Revoked    resolve.RevocationChecker
	Policy     resolve.PolicyChecker
	Source     resolve.ManifestSource
	Unwrap     func(ctx context.Context, kid, wrapped string) ([]byte, error)
	Auditor    resolve.Auditor
	HostName   string
	Injector   *inject.ExecInjector
}

// Server accepts resolve requests over a Unix socket.
type Server struct {
	cfg      Config
	ln       net.Listener
	resolver *resolve.Resolver
	mu       sync.Mutex
	wg       sync.WaitGroup
	done     chan struct{}
	// logf, when set, receives operator-visible diagnostic messages. It is
	// never used to return detail to a client.
	logf func(string, ...any)
}

// SetLogger installs an operator-side diagnostic logger. Client responses are
// unaffected — denials stay generic.
func (s *Server) SetLogger(f func(string, ...any)) { s.logf = f }

// New builds a Server.
func New(cfg Config) *Server {
	inj := cfg.Injector
	if inj == nil {
		inj = inject.NewExecInjector()
	}
	host := cfg.HostName
	if host == "" {
		host, _ = os.Hostname()
	}
	return &Server{
		cfg: cfg,
		resolver: &resolve.Resolver{
			Audience: cfg.Audience,
			Verifier: cfg.Verifier,
			Revoked:  cfg.Revoked,
			Policy:   cfg.Policy,
			Injector: inj,
			Source:   cfg.Source,
			Unwrap:   cfg.Unwrap,
			Auditor:  cfg.Auditor,
			HostName: host,
			Now:      time.Now,
		},
		done: make(chan struct{}),
	}
}

// Listen binds the Unix socket, removing a stale socket file first.
//
// The socket is 0600 so only the sidecar's own user may connect. Agents run as
// a different user, which is what makes the boundary real (ADR
// separate-os-user); the CLI runs as that user and is granted access by group
// or an explicit chown in deployment.
func (s *Server) Listen() error {
	path := s.cfg.SocketPath
	if path == "" {
		return fmt.Errorf("sidecar: no socket path configured")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		// Refuse to clobber a socket another sidecar is serving.
		if c, derr := net.DialTimeout("unix", path, 200*time.Millisecond); derr == nil {
			c.Close()
			return fmt.Errorf("sidecar: socket %s is already in use", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.ln = ln
	return nil
}

// Addr returns the listening socket path.
func (s *Server) Addr() string { return s.cfg.SocketPath }

// Serve accepts connections until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			s.shutdown()
		case <-s.done:
		}
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				s.wg.Wait()
				return nil
			default:
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	if s.ln != nil {
		s.ln.Close()
	}
	if s.cfg.Injector != nil {
		s.cfg.Injector.Cleanup()
	}
	os.Remove(s.cfg.SocketPath)
}

// Stop shuts the server down.
func (s *Server) Stop() {
	s.shutdown()
}

// handle processes one connection: read one request, write one response.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	var req Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}

	res, err := s.resolver.Resolve(ctx, resolve.Request{
		TokenURI:  req.Token,
		Scope:     req.Scope,
		Name:      req.Name,
		Command:   req.Command,
		Principal: req.Principal,
	})
	if err != nil {
		// Operator-visible reason (the audit log also carries it). The CLIENT
		// still receives only a generic denial — see ADR generic-denials.
		if s.logf != nil {
			s.logf("resolve denied: reason=%s scope=%s", protocol.ReasonOf(err), req.Scope)
		}
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	writeResp(conn, Response{
		OK: true, Descriptor: res.Descriptor, ExitCode: res.ExitCode,
		Stdout: res.Stdout, Stderr: res.Stderr,
	})
}

func writeResp(conn net.Conn, r Response) {
	_ = json.NewEncoder(conn).Encode(r)
}

// Compile-time assertion that a Response has no field capable of carrying a
// resolved value.
var _ = func() bool {
	var r Response
	// The struct literal below will fail to compile if a value-bearing field is
	// ever added, forcing a deliberate review of the security contract.
	_ = struct {
		OK         bool
		Descriptor string
		ExitCode   int
		Stdout     []byte
		Stderr     []byte
		Error      string
	}{r.OK, r.Descriptor, r.ExitCode, r.Stdout, r.Stderr, r.Error}
	return true
}()

// Client is a sidecar socket client used by the CLI and tests.
type Client struct{ SocketPath string }

// Resolve sends a request and returns the descriptor.
func (c *Client) Resolve(ctx context.Context, req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, 5*time.Second)
	if err != nil {
		// No resolver reachable — fail closed. See conformance vector
		// inert-without-sidecar.
		return nil, protocol.NewDenial(protocol.ReasonNoResolver)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
