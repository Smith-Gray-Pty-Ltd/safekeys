// Package resolve implements the sidecar's resolution path — the only place a
// capability token becomes plaintext.
//
// It implements .usm/features/resolution/sidecar-resolution.usm. The order is
// fixed and must not be relaxed:
//
//	verify token → local policy → unwrap DEK → decrypt → inject → zeroise → audit
//
// No key-store interaction may occur before verification succeeds.
package resolve

import (
	"context"
	"fmt"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/inject"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// RevocationChecker reports whether a jti is denylisted.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// PolicyChecker evaluates host-local policy at resolve time.
type PolicyChecker interface {
	// Allow reports whether this request may proceed. A false result must be
	// treated as denial, never as "unknown, proceed".
	Allow(ctx context.Context, principal, sid, scope, aud, injectionMethod string) (bool, string)
}

// Auditor records resolve attempts without recording secrets.
type Auditor interface {
	Record(ctx context.Context, e AuditRecord)
}

// AuditRecord is a resolve/deny event. Metadata only.
type AuditRecord struct {
	At        time.Time
	Event     string
	JTI       string
	SID       string
	Principal string
	Host      string
	Scope     string
	Outcome   string
	Reason    string
}

// Injector delivers plaintext to a non-LLM consumer.
//
// Inject MUST NOT return the value to the caller. It returns only a
// non-sensitive descriptor — a placeholder name or a path the caller cannot
// usefully read.
type Injector interface {
	Inject(ctx context.Context, method string, name string, plaintext []byte, command []string) (*inject.Outcome, error)
}

// ManifestSource loads the manifest and ciphertext for an object.
//
// In the MVP the folder is local, so this is a filesystem reader. The interface
// keeps the resolver independent of where the folder happens to live.
type ManifestSource interface {
	// Load returns the manifest object entry and the ciphertext for sid.
	Load(ctx context.Context, sid string) (*protocol.ManifestObject, []byte, error)
}

// Verifier is the capability check the resolver needs. It is the full
// protocol.Signer interface so the same implementation can both mint (control
// plane) and verify (sidecar) without a parallel type.
type Verifier interface {
	protocol.Signer
}

// Request is a resolve request from a local caller.
type Request struct {
	TokenURI  string   // safekey://v1/<sid>#<JWS>
	Scope     string   // the operation being requested: unwrap, inject-env, ...
	Name      string   // variable name or file hint for the injector
	Command   []string // for the exec method
	Principal string
	Host      string
}

// Result is what the caller receives. It intentionally cannot carry a value:
// there is no field for plaintext anywhere in this type.
type Result struct {
	Descriptor string // placeholder name or path; never plaintext
	// ExitCode is the wrapped command's status, when one ran. A failing command
	// is not a security event and is not part of any denial path.
	ExitCode int
	// Stdout/Stderr are the wrapped command's own output, relayed to the caller.
	Stdout []byte
	Stderr []byte
}

// Resolver executes the resolution path.
type Resolver struct {
	Audience string // this resolver's identity; tokens must match
	Verifier Verifier
	Revoked  RevocationChecker
	Policy   PolicyChecker
	Injector Injector
	Source   ManifestSource
	Unwrap   func(ctx context.Context, kid, wrapped string) ([]byte, error)
	Auditor  Auditor
	Now      func() time.Time
	HostName string
}

// Resolve runs the full path. On any failure it returns a *protocol.Denial and
// no plaintext has been materialised.
func (r *Resolver) Resolve(ctx context.Context, req Request) (*Result, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}

	// ── 1. Parse and verify the token. No key store interaction before this.
	parsed, err := protocol.ParseURI(req.TokenURI)
	if err != nil {
		return nil, r.deny(ctx, req, err)
	}

	revokedFn := func(jti string) bool {
		if r.Revoked == nil {
			return false
		}
		ok, err := r.Revoked.IsRevoked(ctx, jti)
		// Fail closed: a revocation-check error denies.
		return err != nil || ok
	}

	claims, err := protocol.VerifyToken(r.Verifier, parsed, r.Audience, now(), revokedFn)
	if err != nil {
		return nil, r.deny(ctx, req, err)
	}

	// The requested operation must be within the token's granted scope.
	if req.Scope != "" && !protocol.ScopeAllows(claims.Scope, req.Scope) {
		return nil, r.deny(ctx, req, protocol.NewDenial(protocol.ReasonScopeNotGranted))
	}

	// ── 2. Host-local policy. A valid token is still not sufficient.
	if r.Policy != nil {
		method := methodForScope(req.Scope)
		allowed, rule := r.Policy.Allow(ctx, claims.Sub, claims.SID, req.Scope, claims.Aud, method)
		if !allowed {
			rec := protocol.NewDenial(protocol.ReasonPolicyDenied)
			if rule != "" {
				rec = protocol.NewDenial(rule)
			}
			return nil, r.deny(ctx, req, rec)
		}
	}

	// ── 3. Load the ciphertext object.
	obj, ciphertext, err := r.Source.Load(ctx, claims.SID)
	if err != nil {
		return nil, r.deny(ctx, req, protocol.NewDenial(protocol.ReasonMalformed))
	}

	// ── 4. Unwrap the DEK. Only now do we touch the key store.
	if r.Unwrap == nil {
		return nil, r.deny(ctx, req, protocol.NewDenial(protocol.ReasonKeystoreUnreachable))
	}
	dek, err := r.Unwrap(ctx, obj.WrappingKID, obj.WrappedKey)
	if err != nil {
		return nil, r.deny(ctx, req, protocol.NewDenial(protocol.ReasonKeystoreUnreachable))
	}
	defer protocol.Zero(dek)

	// ── 5. Decrypt in memory, then zeroise.
	plaintext, err := protocol.DecryptObject(obj.Alg, dek, ciphertext)
	if err != nil {
		return nil, r.deny(ctx, req, err)
	}
	secure := protocol.SecureBufferFrom(plaintext)
	defer secure.Release()

	// ── 6. Inject into the consumer. The value never returns to the caller.
	method := methodForScope(req.Scope)
	outcome, err := r.Injector.Inject(ctx, method, req.Name, secure.Bytes(), req.Command)
	if err != nil {
		// A genuine injector failure (could not spawn, unknown method) is a
		// denial. A wrapped command exiting non-zero is NOT — see below.
		return nil, r.deny(ctx, req, protocol.NewDenial(protocol.ReasonMalformed))
	}

	// ── 7. Audit success without recording the secret. A non-zero exit is
	// recorded as a normal resolve carrying the status, not as a denial.
	rec := AuditRecord{
		At: now(), Event: "resolve", JTI: claims.JTI, SID: claims.SID,
		Principal: claims.Sub, Host: r.host(req), Scope: req.Scope, Outcome: "allowed",
	}
	if outcome.ExitCode != 0 {
		rec.Reason = fmt.Sprintf("command_exit_%d", outcome.ExitCode)
	}
	r.audit(ctx, rec)

	// The caller receives a descriptor, the command's output, and its exit
	// status — never the injected value.
	return &Result{
		Descriptor: outcome.Descriptor,
		ExitCode:   outcome.ExitCode,
		Stdout:     outcome.Stdout,
		Stderr:     outcome.Stderr,
	}, nil
}

// deny records the denial and returns a generic error. The audit reason is
// never surfaced to the caller.
func (r *Resolver) deny(ctx context.Context, req Request, err error) error {
	reason := protocol.ReasonOf(err)
	if reason == "" {
		reason = protocol.ReasonMalformed
	}
	// Best-effort: recover the jti/sid for the audit record without trusting
	// an unverified token.
	parsed, perr := protocol.ParseURI(req.TokenURI)
	var sid, jti string
	if perr == nil {
		sid = parsed.SID
		if c, cerr := protocol.DecodeClaims(parsed.JWS); cerr == nil {
			jti = c.JTI
		}
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	event := "deny"
	if reason == protocol.ReasonPolicyDenied {
		event = "policy_deny"
	}
	r.audit(ctx, AuditRecord{
		At: now(), Event: event, JTI: jti, SID: sid,
		Principal: req.Principal, Host: r.host(req), Scope: req.Scope,
		Outcome: "denied", Reason: reason,
	})
	return protocol.NewDenial(reason)
}

func (r *Resolver) audit(ctx context.Context, rec AuditRecord) {
	if r.Auditor != nil {
		r.Auditor.Record(ctx, rec)
	}
}

func (r *Resolver) host(req Request) string {
	if req.Host != "" {
		return req.Host
	}
	return r.HostName
}

// methodForScope maps a scope to an injection method.
func methodForScope(scope string) string {
	switch scope {
	case protocol.ScopeInjectEnv, protocol.ScopeUnwrap, protocol.ScopeRead:
		return "env"
	case protocol.ScopeInjectFile:
		return "file"
	default:
		return "env"
	}
}

// ErrNoToken is returned when a resolve is attempted without a token at all.
var ErrNoToken = fmt.Errorf("no token")
