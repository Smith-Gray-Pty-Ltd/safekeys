// Package token implements capability token issuance and revocation.
//
// It implements the feature spec smith-gray/capability-token and the frozen
// format in spec/capability-token/. The critical property: a minted token
// contains zero secret material.
package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/policy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// IssueRequest asks for a capability token.
type IssueRequest struct {
	SID       string
	Scope     []string
	Aud       string
	TTL       time.Duration
	Principal string
	Sub       string
}

// Issuer mints and revokes tokens.
type Issuer struct {
	store  *store.Store
	signer protocol.Signer
	issuer string
	policy func() *policy.Engine
	now    func() time.Time
}

// New builds an Issuer.
func New(s *store.Store, signer protocol.Signer, issuerURL string, engine func() *policy.Engine) *Issuer {
	return &Issuer{store: s, signer: signer, issuer: issuerURL, policy: engine, now: time.Now}
}

// SetClock overrides the clock for tests.
func (i *Issuer) SetClock(f func() time.Time) { i.now = f }

// IssuerURL returns the issuer identifier embedded in minted tokens.
func (i *Issuer) IssuerURL() string { return i.issuer }

// MaxTTL bounds token lifetime. TTLs are minutes to hours, never days.
const MaxTTL = 12 * time.Hour

// Issue validates policy and mints a token, returning the token URI.
//
// It never accepts a secret value: the request carries identifiers only.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (string, protocol.Claims, error) {
	if req.SID == "" || len(req.Scope) == 0 || req.Aud == "" {
		return "", protocol.Claims{}, protocol.NewDenial(protocol.ReasonMalformed)
	}
	for _, s := range req.Scope {
		if !protocol.IsScopeValid(s) {
			return "", protocol.Claims{}, protocol.NewDenial(protocol.ReasonMalformed)
		}
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}

	// The object must be registered; a token cannot reference an unknown object.
	obj, err := i.store.GetObject(ctx, req.SID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", protocol.Claims{}, protocol.NewDenial(protocol.ReasonMalformed)
		}
		return "", protocol.Claims{}, err
	}

	// Policy is evaluated at issuance so an unnecessary token never exists.
	for _, scope := range req.Scope {
		dec := i.policy().Evaluate(policy.Request{
			Principal: req.Principal, SID: req.SID, Scope: scope, Aud: req.Aud,
		})
		if !dec.Allow {
			_ = i.store.AppendAudit(ctx, store.AuditEvent{
				At: i.now(), Event: store.EventPolicyDeny, SID: req.SID,
				Principal: req.Principal, Scope: scope, Outcome: "denied", Reason: dec.RuleID,
			})
			return "", protocol.Claims{}, protocol.NewDenial(protocol.ReasonPolicyDenied)
		}
	}

	jti, err := protocol.NewID("jti")
	if err != nil {
		return "", protocol.Claims{}, err
	}
	now := i.now()
	claims := protocol.Claims{
		Iss:   i.issuer,
		Sub:   req.Sub,
		SID:   req.SID,
		Scope: req.Scope,
		Aud:   req.Aud,
		Exp:   now.Add(ttl).Unix(),
		Nbf:   now.Add(-30 * time.Second).Unix(), // small clock-skew allowance
		JTI:   jti,
	}

	jws, err := i.signer.Sign(protocol.Header{}, claims)
	if err != nil {
		return "", protocol.Claims{}, err
	}
	if err := i.store.CreateToken(ctx, store.Token{
		JTI: jti, SID: req.SID, Iss: claims.Iss, Sub: claims.Sub,
		Scope: claims.Scope, Aud: claims.Aud,
		Nbf: time.Unix(claims.Nbf, 0), Exp: time.Unix(claims.Exp, 0), IssuedAt: now,
	}); err != nil {
		return "", protocol.Claims{}, err
	}

	_ = i.store.AppendAudit(ctx, store.AuditEvent{
		At: now, Event: store.EventIssue, JTI: jti, SID: req.SID,
		Principal: req.Principal, Scope: fmt.Sprint(req.Scope), Outcome: "allowed",
	})

	_ = obj // the object's wrapping_kid is not needed to mint; noted for clarity
	return protocol.URI(req.SID, jws), claims, nil
}

// Revoke revokes a token by jti. Idempotent.
func (i *Issuer) Revoke(ctx context.Context, jti, principal string) error {
	if jti == "" {
		return protocol.NewDenial(protocol.ReasonMalformed)
	}
	if err := i.store.RevokeToken(ctx, jti); err != nil {
		return err
	}
	return i.store.AppendAudit(ctx, store.AuditEvent{
		At: i.now(), Event: store.EventRevoke, JTI: jti,
		Principal: principal, Outcome: "allowed",
	})
}

// Revoked reports whether a jti is denylisted. Passed to the sidecar's
// verification path.
func (i *Issuer) Revoked(ctx context.Context, jti string) bool {
	ok, err := i.store.IsRevoked(ctx, jti)
	return err == nil && ok
}
