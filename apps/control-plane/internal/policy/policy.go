// Package policy evaluates resolution policy.
//
// Policy is evaluated at TWO points, per the feature spec
// smith-gray/policy-engine:
//
//  1. at issuance, so an unnecessary token need never exist; and
//  2. locally at resolve, so a token that exists is still insufficient if
//     host-local policy forbids the specific request (e.g. inject-file on a
//     host where only inject-env is permitted).
//
// The default is DENY. Absence of a matching allow is a denial — allow-by-
// default would silently fail open as configuration drifts.
package policy

import (
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Request describes the decision being made.
type Request struct {
	Principal       string
	SID             string
	Scope           string
	Aud             string
	InjectionMethod string // "", or env|file|socket|exec
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allow  bool
	RuleID string // the rule that decided; recorded in audit
}

// Engine evaluates rules in priority order.
type Engine struct{ rules []store.PolicyRule }

// New builds an engine over the given rules. Rules are expected pre-sorted by
// descending priority.
func New(rules []store.PolicyRule) *Engine { return &Engine{rules: rules} }

// Evaluate applies the rules. The first matching rule wins; if none matches,
// the request is DENIED.
func (e *Engine) Evaluate(req Request) Decision {
	for _, r := range e.rules {
		if !matches(r, req) {
			continue
		}
		// First match wins, whatever its effect.
		return Decision{Allow: r.Effect == "allow", RuleID: r.ID}
	}
	// Deny by default.
	return Decision{Allow: false, RuleID: "default-deny"}
}

// matches reports whether a rule applies to a request. An empty field on the
// rule is a wildcard.
func matches(r store.PolicyRule, req Request) bool {
	if r.Principal != "" && r.Principal != req.Principal {
		return false
	}
	if r.SID != "" && r.SID != req.SID {
		return false
	}
	if r.Aud != "" && r.Aud != req.Aud {
		return false
	}
	if r.InjectionMethod != "" && r.InjectionMethod != req.InjectionMethod {
		return false
	}
	return protocol.ScopeAllows(r.Scope, req.Scope)
}

// Compile-time assertion that a denial carries a protocol reason.
var _ = protocol.NewDenial(protocol.ReasonPolicyDenied)
