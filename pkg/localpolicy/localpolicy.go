// Package localpolicy loads and evaluates resolve-time policy in the sidecar.
//
// This closes the gap recorded in safekeys/policy-engine: the control-plane
// engine was built and tested, but the sidecar's resolve-time check was a
// hardcoded allow, so a token that existed was sufficient regardless of what
// local policy said.
//
// The same rules are now evaluated in both places, from the same source:
//
//   - at issuance, so an unnecessary token need never exist; and
//   - locally at resolve, so a valid token is still insufficient if the host's
//     policy forbids this specific request (e.g. inject-file where only
//     inject-env is permitted).
//
// The default is DENY. If the rules cannot be loaded, the answer is deny — a
// checker that cannot see policy must not assume it is satisfied.
package localpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/commandpolicy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/resolve"
)

// Rule mirrors the control plane's policy_rules row.
type Rule struct {
	ID              string   `json:"ID"`
	Effect          string   `json:"Effect"` // "allow" | "deny"
	Principal       string   `json:"Principal"`
	SID             string   `json:"SID"`
	Scope           []string `json:"Scope"`
	Aud             string   `json:"Aud"`
	InjectionMethod string   `json:"InjectionMethod"`
	// Commands, when non-empty on an allow rule, binds the resolve to the
	// listed command specifications: a requested argv must match at least
	// one spec, or the request is denied (safekeys/output-control,
	// command-policy). Nil means "no command restriction on this rule".
	Commands []commandpolicy.CommandSpec `json:"Commands,omitempty"`
	Priority int                         `json:"Priority"`
}

// Fetcher loads the current rule set.
type Fetcher interface {
	Fetch(ctx context.Context) ([]Rule, error)
}

// HTTPFetcher loads rules from the control plane.
type HTTPFetcher struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// NewHTTP builds a fetcher.
func NewHTTP(baseURL, apiKey string) *HTTPFetcher {
	return &HTTPFetcher{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context) ([]Rule, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.BaseURL+"/v1/policies", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Safekeys-Key", f.APIKey)
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy: control plane returned %d", resp.StatusCode)
	}
	var body struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return body.Rules, nil
}

// Engine evaluates rules in priority order with a deny-by-default fallback.
type Engine struct {
	fetcher Fetcher
	ttl     time.Duration
	now     func() time.Time

	mu      sync.RWMutex
	rules   []Rule
	fetched time.Time
	lastErr error
}

// New builds an engine backed by a fetcher. A zero ttl means rules are loaded
// once and refreshed only on an explicit Refresh call.
func New(fetcher Fetcher, ttl time.Duration) (*Engine, error) {
	e := &Engine{fetcher: fetcher, ttl: ttl, now: time.Now}
	if err := e.refresh(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// NewFromRules builds an engine over a known rule set, for tests and static
// configuration.
func NewFromRules(rules []Rule) *Engine {
	return &Engine{rules: sorted(rules), now: time.Now}
}

// Allow implements resolve.PolicyChecker.
//
// It returns whether the request may proceed and, on denial, the rule id or
// policy name that denied — which is recorded in the audit log, never
// returned to the caller.
//
// The command dimension (safekeys/output-control):
//
//   - No matching rule → deny ("default-deny"), unchanged. The backstop
//     denylist presupposes an allow that got this far; it does not override
//     default deny.
//   - A matching allow rule WITHOUT Commands: CLI/SDK requests are allowed
//     unless the argv hits the backstop denylist (known dumpers); MCP
//     requests are denied ("mcp-command-allowlist-required") — the model
//     authors the command, so an explicit allowlist is mandatory.
//   - A matching allow rule WITH Commands: the argv must match one spec,
//     whatever the origin.
func (e *Engine) Allow(ctx context.Context, principal, sid, scope, aud, injection string, command []string, origin string) (bool, string) {
	rules, err := e.current(ctx)
	if err != nil {
		// Fail closed: a checker that cannot read policy must not permit.
		return false, "policy-unavailable"
	}
	origin = resolve.EffectiveOrigin(origin)
	for i := range rules {
		if !matches(rules[i], principal, sid, scope, aud, injection) {
			continue
		}
		// First match wins, whatever its effect.
		r := &rules[i]
		if r.Effect != "allow" {
			return false, r.ID
		}
		if len(r.Commands) == 0 {
			// Allow without a command restriction: MCP still requires an
			// allowlist outright; CLI/SDK pass through the backstop filter.
			if origin == resolve.OriginMCP {
				return false, "mcp-command-allowlist-required"
			}
			if commandpolicy.Refuses(command) {
				return false, "backstop-denylist"
			}
			return true, r.ID
		}
		// Rule carries command specs; the argv must match one.
		if commandpolicy.MatchesAny(r.Commands, command) {
			return true, r.ID
		}
		return false, r.ID + "-command-not-allowed"
	}
	// Deny by default. Absence of a matching allow is a denial — allow-by-
	// default silently fails open as configuration drifts.
	return false, "default-deny"
}

// matches reports whether a rule applies. An empty field is a wildcard.
func matches(r Rule, principal, sid, scope, aud, injection string) bool {
	if r.Principal != "" && r.Principal != principal {
		return false
	}
	if r.SID != "" && r.SID != sid {
		return false
	}
	if r.Aud != "" && r.Aud != aud {
		return false
	}
	if r.InjectionMethod != "" && r.InjectionMethod != injection {
		return false
	}
	for _, s := range r.Scope {
		if s == scope {
			return true
		}
	}
	return false
}

// current returns the rule set, refreshing if the TTL has lapsed.
func (e *Engine) current(ctx context.Context) ([]Rule, error) {
	e.mu.RLock()
	rules, fetched, ttl := e.rules, e.fetched, e.ttl
	e.mu.RUnlock()

	if rules != nil && (ttl <= 0 || e.now().Sub(fetched) < ttl) {
		return rules, nil
	}
	if err := e.refresh(ctx); err != nil {
		if rules != nil {
			// Serve last-known-good rather than failing a live request: a stale
			// rule set is safer than a resolver that goes dark on a blip.
			return rules, nil
		}
		return nil, err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules, nil
}

// refresh reloads the rules.
func (e *Engine) refresh(ctx context.Context) error {
	if e.fetcher == nil {
		return fmt.Errorf("policy: no fetcher configured")
	}
	rules, err := e.fetcher.Fetch(ctx)
	if err != nil {
		e.mu.Lock()
		e.lastErr = err
		e.mu.Unlock()
		return err
	}
	e.mu.Lock()
	e.rules = sorted(rules)
	e.fetched = e.now()
	e.lastErr = nil
	e.mu.Unlock()
	return nil
}

// Refresh forces a reload. For a config-reload signal.
func (e *Engine) Refresh(ctx context.Context) error { return e.refresh(ctx) }

// RuleCount reports how many rules are loaded. For a health check.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// sorted returns rules ordered for evaluation: highest priority first, then id
// for determinism.
func sorted(in []Rule) []Rule {
	out := make([]Rule, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			if out[j].Priority > out[j-1].Priority ||
				(out[j].Priority == out[j-1].Priority && out[j].ID < out[j-1].ID) {
				out[j], out[j-1] = out[j-1], out[j]
				continue
			}
			break
		}
	}
	return out
}
