package policy_test

import (
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/policy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// TestDefaultDeny is the contract that matters most: with no matching rule, the
// request is denied. Allow-by-default would silently fail open.
func TestDefaultDeny(t *testing.T) {
	e := policy.New(nil)
	dec := e.Evaluate(policy.Request{Principal: "a", SID: "o1", Scope: protocol.ScopeRead, Aud: "env"})
	if dec.Allow {
		t.Fatal("empty policy allowed a request; default must be deny")
	}
	if dec.RuleID != "default-deny" {
		t.Fatalf("RuleID = %q, want default-deny", dec.RuleID)
	}
}

// TestFirstMatchWinsAndPriorityOrder proves a deny rule can override an allow.
func TestDenyOverridesAllowByOrder(t *testing.T) {
	e := policy.New([]store.PolicyRule{
		{ID: "deny-inject-file", Effect: "deny", Scope: []string{protocol.ScopeInjectFile}, Priority: 10},
		{ID: "allow-all", Effect: "allow", Scope: []string{protocol.ScopeInjectFile}, Priority: 0},
	})
	dec := e.Evaluate(policy.Request{SID: "o1", Scope: protocol.ScopeInjectFile, Aud: "env"})
	if dec.Allow {
		t.Fatal("deny rule did not win")
	}
	if dec.RuleID != "deny-inject-file" {
		t.Fatalf("RuleID = %q, want the deny rule", dec.RuleID)
	}
}

// TestScopeNarrowing proves a rule only grants the scopes it names.
func TestScopeNarrowing(t *testing.T) {
	e := policy.New([]store.PolicyRule{
		{ID: "env-only", Effect: "allow", Scope: []string{protocol.ScopeInjectEnv}},
	})
	if !e.Evaluate(policy.Request{Scope: protocol.ScopeInjectEnv, Aud: "env"}).Allow {
		t.Fatal("granted scope was denied")
	}
	if e.Evaluate(policy.Request{Scope: protocol.ScopeInjectFile, Aud: "env"}).Allow {
		t.Fatal("ungranted scope was allowed")
	}
}

// TestEnvironmentBinding proves a rule bound to one audience does not satisfy a
// request from another.
func TestEnvironmentBinding(t *testing.T) {
	e := policy.New([]store.PolicyRule{
		{ID: "prod-only", Effect: "allow", Scope: []string{protocol.ScopeRead}, Aud: "env-production"},
	})
	if e.Evaluate(policy.Request{Scope: protocol.ScopeRead, Aud: "env-staging"}).Allow {
		t.Fatal("production-bound rule satisfied a staging request")
	}
	if !e.Evaluate(policy.Request{Scope: protocol.ScopeRead, Aud: "env-production"}).Allow {
		t.Fatal("production-bound rule did not satisfy a production request")
	}
}

// TestInjectionMethodRestriction proves a rule can restrict the injection
// method, which is a resolve-time-only concern.
func TestInjectionMethodRestriction(t *testing.T) {
	e := policy.New([]store.PolicyRule{
		{ID: "env-only", Effect: "allow", Scope: []string{protocol.ScopeInjectEnv}, InjectionMethod: "env"},
	})
	if !e.Evaluate(policy.Request{Scope: protocol.ScopeInjectEnv, Aud: "e", InjectionMethod: "env"}).Allow {
		t.Fatal("env injection should be allowed")
	}
	if e.Evaluate(policy.Request{Scope: protocol.ScopeInjectEnv, Aud: "e", InjectionMethod: "file"}).Allow {
		t.Fatal("file injection should be denied when the rule names env")
	}
}
