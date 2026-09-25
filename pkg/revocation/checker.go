// Package revocation provides the sidecar's revocation checker.
//
// It asks the control plane's denylist on every resolve, so revocation takes
// effect immediately rather than waiting for TTL expiry, and FAILS CLOSED: if
// the control plane is unreachable the token is treated as revoked, because a
// resolve that cannot verify current authority must not proceed.
//
// Caching policy is dictated by the `immediate-effect` contract in
// .usm/features/lifecycle/token-revocation.usm: "the denylist is consulted on
// every resolve" and "no caching path can serve a revoked token".
//
//   - A POSITIVE result (revoked) is cached indefinitely. Revocation is
//     monotonic — once revoked, always revoked — so caching it can never serve
//     a live token, and it keeps the (rare) revoked case off the network.
//   - A NEGATIVE result (not revoked) is NOT cached by default. Caching it is
//     exactly what would let a token revoked inside the cache window still
//     resolve, which the contract forbids. Setting NegativeTTL explicitly opts
//     into that lag as a throughput trade-off, and weakens the guarantee.
package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ControlPlaneChecker checks a jti against the control plane denylist.
type ControlPlaneChecker struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	// NegativeTTL, when greater than zero, caches a not-revoked result for this
	// long. This trades revocation immediacy for fewer network calls and
	// therefore WEAKENS the `immediate-effect` contract: a token revoked within
	// the window will still resolve. Zero (the default) means every resolve
	// consults the control plane.
	NegativeTTL time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	revoked bool
	expires time.Time // zero means "never expires"
}

// New builds a checker with no negative caching, which is the contract-correct
// default.
func New(baseURL, apiKey string) *ControlPlaneChecker {
	return &ControlPlaneChecker{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 5 * time.Second},
		cache:   map[string]cacheEntry{},
	}
}

// IsRevoked reports whether jti is denylisted.
//
// On any error it returns true (fail closed) so the caller denies.
func (c *ControlPlaneChecker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return true, nil
	}

	// A cached revocation never expires: revoked is monotonic.
	c.mu.Lock()
	if e, ok := c.cache[jti]; ok {
		if e.expires.IsZero() || time.Now().Before(e.expires) {
			c.mu.Unlock()
			return e.revoked, nil
		}
		delete(c.cache, jti)
	}
	c.mu.Unlock()

	revoked, err := c.fetch(ctx, jti)
	if err != nil {
		// Fail closed: an unverifiable token must not resolve.
		return true, err
	}

	c.mu.Lock()
	if revoked {
		// Cache the positive forever — it can only ever be true again.
		c.cache[jti] = cacheEntry{revoked: true}
	} else if c.NegativeTTL > 0 {
		c.cache[jti] = cacheEntry{revoked: false, expires: time.Now().Add(c.NegativeTTL)}
	}
	c.mu.Unlock()

	return revoked, nil
}

// fetch asks the control plane. It uses the audit endpoint scoped to the jti,
// counting revoke events, which avoids adding a bespoke endpoint for a single
// boolean.
func (c *ControlPlaneChecker) fetch(ctx context.Context, jti string) (bool, error) {
	if c.BaseURL == "" {
		return false, fmt.Errorf("revocation: no control plane configured")
	}
	u := c.BaseURL + "/v1/audit?jti=" + url.QueryEscape(jti)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Safekeys-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("revocation: control plane returned %d", resp.StatusCode)
	}
	var body struct {
		Events []struct {
			Event   string `json:"Event"`
			Outcome string `json:"Outcome"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	for _, e := range body.Events {
		if e.Event == "revoke" {
			return true, nil
		}
	}
	return false, nil
}
