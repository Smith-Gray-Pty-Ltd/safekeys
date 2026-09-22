package revocation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/revocation"
)

func newServer(t *testing.T, revokedJTI string) *httptest.Server {
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
		if r.URL.Query().Get("jti") == revokedJTI {
			events = append(events, map[string]string{"Event": "revoke", "Outcome": "allowed"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	}))
}

// TestRevokedTokenDetected proves a revoke event on the control plane is
// surfaced as revoked.
func TestRevokedTokenDetected(t *testing.T) {
	ts := newServer(t, "jti_revoked_1")
	defer ts.Close()
	c := revocation.New(ts.URL, "test-key", 0)

	revoked, err := c.IsRevoked(context.Background(), "jti_revoked_1")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revoked jti was not reported as revoked")
	}

	revoked, err = c.IsRevoked(context.Background(), "jti_fine_1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("a clean jti was reported as revoked")
	}
}

// TestFailsClosedWhenControlPlaneUnreachable is the important one: a resolve that
// cannot verify current authority must not proceed.
func TestFailsClosedWhenControlPlaneUnreachable(t *testing.T) {
	c := revocation.New("http://127.0.0.1:1", "k", 0) // nothing listening
	revoked, err := c.IsRevoked(context.Background(), "jti_x")
	if err == nil {
		t.Fatal("expected an error when the control plane is unreachable")
	}
	if !revoked {
		t.Fatal("must fail CLOSED (revoked=true) when the control plane is unreachable")
	}
}

// TestCacheBoundsNetworkCalls proves caching works and that a revoked result is
// never cached away.
func TestCacheBoundsNetworkCalls(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}})
	}))
	defer ts.Close()

	c := revocation.New(ts.URL, "k", 50*time.Millisecond)
	for i := 0; i < 5; i++ {
		if _, err := c.IsRevoked(context.Background(), "jti_cached"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 network call with caching, got %d", calls)
	}

	// After the TTL expires, the next check goes back to the network.
	time.Sleep(60 * time.Millisecond)
	if _, err := c.IsRevoked(context.Background(), "jti_cached"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 network calls after TTL expiry, got %d", calls)
	}
}

// TestEmptyJTIRevoked proves a malformed jti cannot bypass the check.
func TestEmptyJTIRevoked(t *testing.T) {
	c := revocation.New("", "", 0)
	if revoked, _ := c.IsRevoked(context.Background(), ""); !revoked {
		t.Fatal("an empty jti must be treated as revoked")
	}
}
