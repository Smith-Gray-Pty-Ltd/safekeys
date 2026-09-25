package revocation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/revocation"
)

// newServer returns a test control plane. revokedJTI starts revoked; a jti in
// the returned set pointer can be toggled mid-test to simulate a revocation
// arriving between resolves.
func newServer(t *testing.T, revoked func() bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Safekeys-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		events := []map[string]string{}
		if revoked() {
			events = append(events, map[string]string{"Event": "revoke", "Outcome": "allowed"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	}))
}

func TestRevokedTokenDetected(t *testing.T) {
	ts := newServer(t, func() bool { return true })
	defer ts.Close()
	c := revocation.New(ts.URL, "test-key")

	revoked, err := c.IsRevoked(context.Background(), "jti_revoked")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revoked jti was not reported as revoked")
	}
}

func TestCleanTokenNotRevoked(t *testing.T) {
	ts := newServer(t, func() bool { return false })
	defer ts.Close()
	c := revocation.New(ts.URL, "test-key")

	revoked, err := c.IsRevoked(context.Background(), "jti_fine")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("a clean jti was reported as revoked")
	}
}

// TestRevocationIsImmediate is the contract in
// .usm/features/lifecycle/token-revocation.usm: "Effect is observable on the
// next resolve attempt" and "no caching path can serve a revoked token".
//
// This is the regression test for a real bug: the checker used to cache a
// not-revoked result for 2 seconds, so a token revoked inside that window still
// resolved. The demo script caught it.
func TestRevocationIsImmediate(t *testing.T) {
	var revoked atomic.Bool
	ts := newServer(t, revoked.Load)
	defer ts.Close()
	c := revocation.New(ts.URL, "test-key")
	ctx := context.Background()

	// First resolve: not revoked.
	got, err := c.IsRevoked(ctx, "jti_x")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("token should start unrevoked")
	}

	// Revocation arrives.
	revoked.Store(true)

	// The VERY NEXT resolve must observe it — no waiting, no cache serving a
	// stale not-revoked result.
	got, err = c.IsRevoked(ctx, "jti_x")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("revocation was not observable on the next resolve — a cache is serving a stale result")
	}
}

// TestRevokedResultIsCachedForever proves the positive case is cached (revoked
// is monotonic, so this can never serve a live token) while the negative is not.
func TestRevokedResultIsCachedForever(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]string{{"Event": "revoke", "Outcome": "allowed"}},
		})
	}))
	defer ts.Close()
	c := revocation.New(ts.URL, "k")

	for i := 0; i < 5; i++ {
		if got, _ := c.IsRevoked(context.Background(), "jti_r"); !got {
			t.Fatal("expected revoked")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected the positive result to be cached (1 call), got %d", calls.Load())
	}
}

// TestNegativeCachingIsOptInAndLags documents the throughput trade-off: setting
// NegativeTTL explicitly accepts that a revocation is not immediately visible.
func TestNegativeCachingIsOptInAndLags(t *testing.T) {
	var revoked atomic.Bool
	ts := newServer(t, revoked.Load)
	defer ts.Close()

	c := revocation.New(ts.URL, "test-key")
	c.NegativeTTL = time.Hour // explicit opt-in

	if got, _ := c.IsRevoked(context.Background(), "jti_y"); got {
		t.Fatal("should start unrevoked")
	}
	revoked.Store(true)
	if got, _ := c.IsRevoked(context.Background(), "jti_y"); got {
		t.Fatal("with NegativeTTL set the revocation should still be masked by the cache (documenting the trade-off)")
	}

	// A fresh checker, without the opt-in, sees it immediately.
	c2 := revocation.New(ts.URL, "test-key")
	if got, _ := c2.IsRevoked(context.Background(), "jti_y"); !got {
		t.Fatal("a checker without negative caching must see the revocation immediately")
	}
}

// TestFailsClosedWhenControlPlaneUnreachable is the important one: a resolve that
// cannot verify current authority must not proceed.
func TestFailsClosedWhenControlPlaneUnreachable(t *testing.T) {
	c := revocation.New("http://127.0.0.1:1", "k") // nothing listening
	revoked, err := c.IsRevoked(context.Background(), "jti_x")
	if err == nil {
		t.Fatal("expected an error when the control plane is unreachable")
	}
	if !revoked {
		t.Fatal("must fail CLOSED (revoked=true) when the control plane is unreachable")
	}
}

// TestEmptyJTIRevoked proves a malformed jti cannot bypass the check.
func TestEmptyJTIRevoked(t *testing.T) {
	c := revocation.New("", "")
	if revoked, _ := c.IsRevoked(context.Background(), ""); !revoked {
		t.Fatal("an empty jti must be treated as revoked")
	}
}
