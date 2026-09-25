package localpolicy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/localpolicy"
)

func serverFor(t *testing.T, rules *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Safekeys-Key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": rules.Load().([]localpolicy.Rule)})
	}))
}

// TestDefaultDeny is the contract that matters most: with no matching rule the
// request is denied. Allow-by-default silently fails open as config drifts.
func TestDefaultDeny(t *testing.T) {
	e := localpolicy.NewFromRules(nil)
	allowed, rule := e.Allow(context.Background(), "p", "obj_1", "read", "env", "env")
	if allowed {
		t.Fatal("an empty rule set allowed a request; default must be deny")
	}
	if rule != "default-deny" {
		t.Fatalf("rule = %q, want default-deny", rule)
	}
}

// TestAllowRulePermits proves an explicit allow works.
func TestAllowRulePermits(t *testing.T) {
	e := localpolicy.NewFromRules([]localpolicy.Rule{
		{ID: "allow-read", Effect: "allow", Scope: []string{"read"}},
	})
	allowed, _ := e.Allow(context.Background(), "p", "obj_1", "read", "env", "env")
	if !allowed {
		t.Fatal("an explicit allow was denied")
	}
}

// TestDenyOverridesAllowByPriority proves ordering is honoured, so an operator
// can carve out an exception.
func TestDenyOverridesAllowByPriority(t *testing.T) {
	e := localpolicy.NewFromRules([]localpolicy.Rule{
		{ID: "allow-all-scopes", Effect: "allow", Scope: []string{"inject-file"}, Priority: 0},
		{ID: "deny-prod-inject-file", Effect: "deny", Scope: []string{"inject-file"}, Aud: "env-prod", Priority: 10},
	})
	// Production is denied: the higher-priority rule wins.
	if allowed, rule := e.Allow(context.Background(), "p", "o", "inject-file", "env-prod", "file"); allowed || rule != "deny-prod-inject-file" {
		t.Fatalf("expected the deny rule to win, got allowed=%v rule=%q", allowed, rule)
	}
	// Staging is allowed: the deny rule is audience-bound.
	if allowed, _ := e.Allow(context.Background(), "p", "o", "inject-file", "env-staging", "file"); !allowed {
		t.Fatal("staging should be allowed by the general rule")
	}
}

// TestScopeNarrowing proves a rule grants only the scopes it names.
func TestScopeNarrowing(t *testing.T) {
	e := localpolicy.NewFromRules([]localpolicy.Rule{
		{ID: "env-only", Effect: "allow", Scope: []string{"inject-env"}},
	})
	if allowed, _ := e.Allow(context.Background(), "p", "o", "inject-env", "e", "env"); !allowed {
		t.Fatal("granted scope was denied")
	}
	if allowed, _ := e.Allow(context.Background(), "p", "o", "inject-file", "e", "file"); allowed {
		t.Fatal("ungranted scope was allowed")
	}
}

// TestInjectionMethodRestriction proves a rule can restrict the injection method,
// which is a resolve-time-only concern.
func TestInjectionMethodRestriction(t *testing.T) {
	e := localpolicy.NewFromRules([]localpolicy.Rule{
		{ID: "env-injection-only", Effect: "allow", Scope: []string{"inject-env"}, InjectionMethod: "env"},
	})
	if allowed, _ := e.Allow(context.Background(), "p", "o", "inject-env", "e", "env"); !allowed {
		t.Fatal("env injection should be allowed")
	}
	if allowed, _ := e.Allow(context.Background(), "p", "o", "inject-env", "e", "exec"); allowed {
		t.Fatal("exec injection should be denied when the rule names env")
	}
}

// TestFetchesRulesAndCaches proves the HTTP path works and the cache is used.
func TestFetchesRulesAndCaches(t *testing.T) {
	var v atomic.Value
	v.Store([]localpolicy.Rule{{ID: "allow-read", Effect: "allow", Scope: []string{"read"}}})
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": v.Load().([]localpolicy.Rule)})
	}))
	defer ts.Close()

	e, err := localpolicy.New(localpolicy.NewHTTP(ts.URL, "k"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", e.RuleCount())
	}
	for i := 0; i < 3; i++ {
		if allowed, _ := e.Allow(context.Background(), "p", "o", "read", "x", "env"); !allowed {
			t.Fatal("fetched allow rule did not apply")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 fetch with a warm cache, got %d", calls.Load())
	}
}

// TestRuleChangeTakesEffectWithoutRestart proves an operator's change propagates.
func TestRuleChangeTakesEffectWithoutRestart(t *testing.T) {
	var v atomic.Value
	v.Store([]localpolicy.Rule{{ID: "allow-read", Effect: "allow", Scope: []string{"read"}}})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": v.Load().([]localpolicy.Rule)})
	}))
	defer ts.Close()

	e, err := localpolicy.New(localpolicy.NewHTTP(ts.URL, "k"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, _ := e.Allow(context.Background(), "p", "o", "read", "x", "env"); !allowed {
		t.Fatal("should start allowed")
	}

	// The operator deletes the rule.
	v.Store([]localpolicy.Rule{})
	time.Sleep(5 * time.Millisecond)

	if allowed, rule := e.Allow(context.Background(), "p", "o", "read", "x", "env"); allowed {
		t.Fatalf("a removed rule still allowed (rule=%q)", rule)
	}
}

// TestUnavailablePolicyFailsClosed is the important one: a checker that cannot
// read policy must not permit.
func TestUnavailablePolicyFailsClosed(t *testing.T) {
	e, err := localpolicy.New(localpolicy.NewHTTP("http://127.0.0.1:1", "k"), time.Minute)
	if err == nil {
		t.Fatal("expected construction to fail without a reachable control plane")
	}
	_ = e
}

// TestWarmCacheSurvivesOutage proves a blip does not take resolution down — a
// stale rule set is safer than a resolver that goes dark.
func TestWarmCacheSurvivesOutage(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": []localpolicy.Rule{
			{ID: "allow-read", Effect: "allow", Scope: []string{"read"}},
		}})
	}))
	defer ts.Close()

	e, err := localpolicy.New(localpolicy.NewHTTP(ts.URL, "k"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	up.Store(false)
	time.Sleep(5 * time.Millisecond)

	if allowed, _ := e.Allow(context.Background(), "p", "o", "read", "x", "env"); !allowed {
		t.Fatal("warm cache did not survive a control-plane outage")
	}
}
