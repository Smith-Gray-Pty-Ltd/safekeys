// Package keysource fetches and caches the control plane's published public
// keys, so the sidecar can verify tokens without holding a signing key.
//
// This is the security boundary the architecture depends on: the sidecar runs on
// the same host as the secrets and is the component most likely to be attacked.
// If it held a signing key, compromising it would let an attacker mint tokens and
// defeat the entire model. It therefore holds public keys only.
//
// Caching is required because verification sits on the resolve hot path. The
// cache REFRESHES on an unknown kid (a rotation), so a new signing key becomes
// usable without a restart, and FAILS CLOSED if the control plane is unreachable
// and the cache is cold — a verifier that cannot check a signature must not
// accept one.
package keysource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Fetcher loads the published key set.
type Fetcher interface {
	Fetch(ctx context.Context) (protocol.PublicJWKS, error)
}

// HTTPFetcher loads keys from the control plane's /v1/keys endpoint.
type HTTPFetcher struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTP builds a fetcher.
func NewHTTP(baseURL string) *HTTPFetcher {
	return &HTTPFetcher{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context) (protocol.PublicJWKS, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.BaseURL+"/v1/keys", nil)
	if err != nil {
		return protocol.PublicJWKS{}, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return protocol.PublicJWKS{}, fmt.Errorf("keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.PublicJWKS{}, fmt.Errorf("keys: control plane returned %d", resp.StatusCode)
	}
	var jwks protocol.PublicJWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return protocol.PublicJWKS{}, fmt.Errorf("keys: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return protocol.PublicJWKS{}, fmt.Errorf("keys: control plane published no keys")
	}
	return jwks, nil
}

// Verifier is a protocol.Verifier backed by a refresheable key source.
//
// It implements VerifyWith by delegating to the current key set, refreshing once
// on an unknown kid so a rotation propagates without a restart.
type Verifier struct {
	fetcher Fetcher
	ttl     time.Duration
	now     func() time.Time

	mu      sync.RWMutex
	current *protocol.KeySetVerifier
	fetched time.Time
	lastErr error
}

// New builds a Verifier. A zero ttl means keys are fetched once and only
// refreshed on an unknown kid.
func New(fetcher Fetcher, ttl time.Duration) (*Verifier, error) {
	v := &Verifier{fetcher: fetcher, ttl: ttl, now: time.Now}
	if err := v.refresh(context.Background()); err != nil {
		return nil, err
	}
	return v, nil
}

// NewFromKeys builds a Verifier over an already-known key set, for tests and for
// a sidecar configured with static keys.
func NewFromKeys(keys []protocol.PublicKey) (*Verifier, error) {
	ks, err := protocol.NewKeySetVerifier(keys)
	if err != nil {
		return nil, err
	}
	return &Verifier{current: ks, now: time.Now}, nil
}

// Verify implements protocol.Verifier. It resolves the key from the token's own
// protected header, so the caller does not need to parse the token first.
func (v *Verifier) Verify(jws string) (protocol.Header, error) {
	hdr, err := protocol.DecodeHeader(jws)
	if err != nil {
		return protocol.Header{}, err
	}
	return v.VerifyWith(hdr.Kid, hdr.Alg, jws)
}

// VerifyWith implements protocol.Verifier.
//
// An empty kid means "resolve from the token's own header". An unknown kid
// triggers ONE refresh, in case the control plane rotated its signing key since
// our last fetch; if it is still unknown, the token is denied.
func (v *Verifier) VerifyWith(kid, alg string, jws string) (protocol.Header, error) {
	ks, err := v.keySet(context.Background())
	if err != nil {
		// Cold cache and an unreachable control plane: fail closed.
		return protocol.Header{}, protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}

	hdr, verr := ks.VerifyWith(kid, alg, jws)
	if verr == nil {
		return hdr, nil
	}
	if protocol.ReasonOf(verr) != protocol.ReasonKidUnknown {
		return protocol.Header{}, verr
	}

	// Unknown kid: the control plane may have rotated. Refresh once and retry.
	if rerr := v.refresh(context.Background()); rerr != nil {
		return protocol.Header{}, verr
	}
	ks, err = v.keySet(context.Background())
	if err != nil {
		return protocol.Header{}, verr
	}
	return ks.VerifyWith(kid, alg, jws)
}

// keySet returns the current verifier, refreshing if the TTL has lapsed.
func (v *Verifier) keySet(ctx context.Context) (*protocol.KeySetVerifier, error) {
	v.mu.RLock()
	ks, fetched, ttl := v.current, v.fetched, v.ttl
	v.mu.RUnlock()

	if ks != nil && (ttl <= 0 || v.now().Sub(fetched) < ttl) {
		return ks, nil
	}
	if err := v.refresh(ctx); err != nil {
		if ks != nil {
			// Serve the last-known-good set rather than failing a live request;
			// a revoked key is handled by revocation, not by key staleness.
			return ks, nil
		}
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.current, nil
}

// refresh fetches and installs a new key set.
func (v *Verifier) refresh(ctx context.Context) error {
	if v.fetcher == nil {
		return fmt.Errorf("keys: no fetcher configured")
	}
	jwks, err := v.fetcher.Fetch(ctx)
	if err != nil {
		v.mu.Lock()
		v.lastErr = err
		v.mu.Unlock()
		return err
	}
	ks, err := protocol.NewKeySetVerifier(jwks.Keys)
	if err != nil {
		v.mu.Lock()
		v.lastErr = err
		v.mu.Unlock()
		return err
	}
	v.mu.Lock()
	v.current = ks
	v.fetched = v.now()
	v.lastErr = nil
	v.mu.Unlock()
	return nil
}

// Refresh forces a key refresh. For a config-reload signal.
func (v *Verifier) Refresh(ctx context.Context) error { return v.refresh(ctx) }

// KeyCount reports how many keys are currently held. For a health check.
func (v *Verifier) KeyCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.current == nil {
		return 0
	}
	return len(v.keysSnapshot())
}

func (v *Verifier) keysSnapshot() map[string]protocol.PublicKey {
	if v.current == nil {
		return nil
	}
	return v.current.Keys()
}
