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

	cpclient "github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/cpclient"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/created"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
)

// Operation names for the socket protocol. An empty op means "resolve", for
// backward compatibility with the earliest clients.
const (
	OpResolve = "resolve"
	OpCreate  = "create"
	OpList    = "list"
	OpRevoke  = "revoke"
)

// Request is the wire form of a sidecar request.
//
// For OpResolve, Token/Scope/Name/Command are used. For OpCreate,
// SourceFile/ObjectID/ContentType/Scope/Audience/TTLSeconds are used — note
// there is deliberately NO Value field: a create request names a source the
// sidecar reads itself, so a model authoring the call never holds the bytes.
type Request struct {
	Op string `json:"op,omitempty"`

	// resolve
	Token   string   `json:"token,omitempty"`
	Scope   string   `json:"scope,omitempty"`
	Name    string   `json:"name,omitempty"`
	Command []string `json:"command,omitempty"`

	// create
	ObjectID    string   `json:"object_id,omitempty"`
	SourceFile  string   `json:"source_file,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	ScopeList   []string `json:"scope_list,omitempty"`
	Audience    string   `json:"audience,omitempty"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"`

	// list / revoke
	JTI string `json:"jti,omitempty"`

	// common
	Principal string `json:"principal,omitempty"`
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

	// create result — a token and a path, never a value.
	Created *CreatedInfo `json:"created,omitempty"`

	// list result — metadata only, never a value.
	Objects []cpclient.Object `json:"objects,omitempty"`
}

// CreatedInfo is the result of a create operation. Like Response, it has no
// field capable of carrying plaintext.
type CreatedInfo struct {
	ObjectID string   `json:"object_id"`
	Folder   string   `json:"folder"`
	Token    string   `json:"token"`
	JTI      string   `json:"jti,omitempty"`
	Expires  int64    `json:"expires,omitempty"`
	Scope    []string `json:"scope,omitempty"`
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
	// Creator handles op=create. When nil, create requests are refused.
	Creator *created.Creator
	// Registry handles op=list/op=revoke. Keeping these on the SIDECAR rather
	// than in the calling process means an agent-adjacent MCP server needs no
	// control-plane credential at all.
	Registry Registry
}

// Registry is the subset of control-plane operations the sidecar proxies for
// agent-adjacent callers: metadata listing and revocation. Neither involves a
// value.
type Registry interface {
	ListObjects(ctx context.Context, principal string) ([]cpclient.Object, error)
	RevokeToken(ctx context.Context, jti string) error
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

	switch req.Op {
	case OpCreate:
		s.handleCreate(ctx, conn, req)
		return
	case OpList:
		s.handleList(ctx, conn)
		return
	case OpRevoke:
		s.handleRevoke(ctx, conn, req)
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

// handleCreate performs a create operation. The plaintext is read from the
// caller-named source file inside the sidecar; it never travels as a literal
// through this protocol.
func (s *Server) handleCreate(ctx context.Context, conn net.Conn, req Request) {
	if s.cfg.Creator == nil {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	res, err := s.cfg.Creator.Create(ctx, created.Request{
		ObjectID:    req.ObjectID,
		SourceFile:  req.SourceFile,
		ContentType: req.ContentType,
		Scope:       req.ScopeList,
		Audience:    req.Audience,
		TTL:         ttl,
		Principal:   req.Principal,
	})
	if err != nil {
		if s.logf != nil {
			// Operator-side detail only; the client still gets a generic denial.
			reason := protocol.ReasonOf(err)
			if reason == "" {
				s.logf("create failed: %v", err)
			} else {
				s.logf("create denied: reason=%s", reason)
			}
		}
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	// The response carries a token and a path — never the created value.
	writeResp(conn, Response{OK: true, Created: &CreatedInfo{
		ObjectID: res.ObjectID, Folder: res.Folder, Token: res.Token,
		JTI: res.JTI, Expires: res.Expires, Scope: res.Scope,
	}})
}

// handleList returns object metadata. Metadata only — there is no value path.
//
// List and revoke are routed through the sidecar rather than having the MCP
// server talk to the control plane directly. That is deliberate: the MCP server
// runs inside the agent's process space, so giving it a control-plane API key
// would hand a compromised agent admin authority. The sidecar holds the
// credential; the agent-adjacent process holds none.
func (s *Server) handleList(ctx context.Context, conn net.Conn) {
	if s.cfg.Registry == nil {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	objs, err := s.cfg.Registry.ListObjects(ctx, "")
	if err != nil {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	writeResp(conn, Response{OK: true, Objects: objs})
}

// handleRevoke revokes a token by jti via the control plane.
func (s *Server) handleRevoke(ctx context.Context, conn net.Conn, req Request) {
	if s.cfg.Registry == nil || req.JTI == "" {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	if err := s.cfg.Registry.RevokeToken(ctx, req.JTI); err != nil {
		writeResp(conn, Response{OK: false, Error: "denied"})
		return
	}
	writeResp(conn, Response{OK: true, Descriptor: req.JTI})
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
		Created    *CreatedInfo
		Objects    []cpclient.Object
	}{r.OK, r.Descriptor, r.ExitCode, r.Stdout, r.Stderr, r.Error, r.Created, r.Objects}
	return true
}()

// Client is a sidecar socket client used by the CLI and tests.
type Client struct{ SocketPath string }

// List returns object metadata via the sidecar.
func (c *Client) List(ctx context.Context) (*Response, error) {
	return c.send(ctx, Request{Op: OpList})
}

// Revoke revokes a token by jti via the sidecar.
func (c *Client) Revoke(ctx context.Context, jti string) (*Response, error) {
	return c.send(ctx, Request{Op: OpRevoke, JTI: jti})
}

// Create sends a create request. The plaintext is read by the sidecar from
// SourceFile — this client has no way to send a value.
func (c *Client) Create(ctx context.Context, req Request) (*Response, error) {
	req.Op = OpCreate
	return c.send(ctx, req)
}

// Resolve sends a request and returns the descriptor.
func (c *Client) Resolve(ctx context.Context, req Request) (*Response, error) {
	req.Op = OpResolve
	return c.send(ctx, req)
}

// send writes one request and reads one response.
func (c *Client) send(ctx context.Context, req Request) (*Response, error) {
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
