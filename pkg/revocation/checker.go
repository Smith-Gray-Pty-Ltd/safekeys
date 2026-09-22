// Package revocation provides the sidecar's revocation checker.
//
// The MVP limitation documented in apps/sidecar/cmd/sidecar/main.go — "the
// sidecar denies nothing on revocation grounds" — is closed here: the sidecar
// asks the control plane's denylist on every resolve, so revocation takes
// effect immediately rather than waiting for TTL expiry.
//
// The check FAILS CLOSED. If the control plane is unreachable, the token is
// treated as revoked, because a resolve that cannot verify current authority
// must not proceed. This is a deliberate trade: availability of the control
// plane gates resolution. Operators who need to tolerate control-plane outages
// should shorten TTLs and accept that revocation lags, rather than fail open.
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

	// CacheTTL bounds how long a negative (not-revoked) result is cached, to
	// keep the hot path off the network. A POSITIVE (revoked) result is never
	// cached as negative, and revocation is never cached away.
	CacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	revoked bool
	expires time.Time
}

// New builds a checker. cacheTTL of 0 disables caching entirely, which is the
// safest setting and the default.
func New(baseURL, apiKey string, cacheTTL time.Duration) *ControlPlaneChecker {
	return &ControlPlaneChecker{
		BaseURL:  baseURL,
		APIKey:   apiKey,
		HTTP:     &http.Client{Timeout: 5 * time.Second},
		CacheTTL: cacheTTL,
		cache:    map[string]cacheEntry{},
	}
}

// IsRevoked reports whether jti is denylisted.
//
// On any error it returns true (fail closed) so the caller denies.
func (c *ControlPlaneChecker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return true, nil
	}
	if c.CacheTTL > 0 {
		c.mu.Lock()
		if e, ok := c.cache[jti]; ok && time.Now().Before(e.expires) {
			c.mu.Unlock()
			return e.revoked, nil
		}
		c.mu.Unlock()
	}

	revoked, err := c.fetch(ctx, jti)
	if err != nil {
		// Fail closed: an unverifiable token must not resolve.
		return true, err
	}

	if c.CacheTTL > 0 {
		c.mu.Lock()
		c.cache[jti] = cacheEntry{revoked: revoked, expires: time.Now().Add(c.CacheTTL)}
		c.mu.Unlock()
	}
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
