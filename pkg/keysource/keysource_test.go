package keysource_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/keysource"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// signerFor mints tokens for the tests.
func signerFor(t *testing.T, kid string) *protocol.Ed25519Signer {
	t.Helper()
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := protocol.NewEd25519Signer(kid, prv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claimsFor(t *testing.T, s *protocol.Ed25519Signer) string {
	t.Helper()
	now := time.Now()
	jws, err := s.Sign(protocol.Header{}, protocol.Claims{
		Iss: "https://cp.test", SID: "obj_1", Scope: []string{protocol.ScopeRead},
		Aud: "env-test", Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_test_000000001",
	})
	if err != nil {
		t.Fatal(err)
	}
	return jws
}

// TestVerifierAcceptsPublishedKeys is the core property: a verifier holding only
// public keys accepts a token the corresponding signer minted.
func TestVerifierAcceptsPublishedKeys(t *testing.T) {
	signer := signerFor(t, "k1")
	v, err := keysource.NewFromKeys(signer.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(claimsFor(t, signer)); err != nil {
		t.Fatalf("a valid token was rejected: %v", err)
	}
}

// TestVerifierHasNoSigningCapability is the security boundary. A verifier must
// not be able to mint a token, so a compromised sidecar cannot forge one.
//
// This is enforced by the type system: keysource.Verifier has no Sign method.
// The test asserts the structural property rather than a runtime one, because
// that is what actually protects us.
func TestVerifierHasNoSigningCapability(t *testing.T) {
	signer := signerFor(t, "k1")
	v, err := keysource.NewFromKeys(signer.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}

	// A keysource.Verifier satisfies protocol.Verifier...
	var _ protocol.Verifier = v

	// ...but must NOT satisfy protocol.Signer. If this line ever compiles, the
	// boundary has been broken and the sidecar could mint tokens.
	if _, isSigner := interface{}(v).(protocol.Signer); isSigner {
		t.Fatal("keysource.Verifier satisfies protocol.Signer — the sidecar could mint tokens")
	}
}

// TestFetchesKeysFromControlPlane proves the HTTP path works.
func TestFetchesKeysFromControlPlane(t *testing.T) {
	signer := signerFor(t, "cp-key-1")
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/keys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.PublicJWKS{
			Issuer: "https://cp.test", Keys: signer.PublicKeys(),
		})
	}))
	defer ts.Close()

	v, err := keysource.New(keysource.NewHTTP(ts.URL), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyCount() != 1 {
		t.Fatalf("expected 1 key, got %d", v.KeyCount())
	}
	if _, err := v.Verify(claimsFor(t, signer)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 fetch with a warm cache, got %d", calls.Load())
	}
}

// TestRotationPropagatesOnUnknownKid proves a new signing key becomes usable
// without restarting the sidecar — the control plane rotates, the next token
// carries the new kid, and the verifier refreshes once.
func TestRotationPropagatesOnUnknownKid(t *testing.T) {
	oldSigner := signerFor(t, "k-old")
	newSigner := signerFor(t, "k-new")

	var serving atomic.Value
	serving.Store(oldSigner.PublicKeys())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.PublicJWKS{
			Issuer: "https://cp.test", Keys: serving.Load().([]protocol.PublicKey),
		})
	}))
	defer ts.Close()

	v, err := keysource.New(keysource.NewHTTP(ts.URL), 0) // no TTL: refresh only on demand
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(claimsFor(t, oldSigner)); err != nil {
		t.Fatalf("old key should work: %v", err)
	}

	// Rotate.
	serving.Store(newSigner.PublicKeys())

	// A token from the NEW key must be accepted: the verifier refreshes on the
	// unknown kid rather than failing until a restart.
	if _, err := v.Verify(claimsFor(t, newSigner)); err != nil {
		t.Fatalf("rotation did not propagate: %v", err)
	}
}

// TestUnknownKidDenied proves an unknown key is a hard denial — never a fallback
// to a default key, which is the classic verification bypass.
func TestUnknownKidDenied(t *testing.T) {
	known := signerFor(t, "k-known")
	stranger := signerFor(t, "k-stranger")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.PublicJWKS{
			Issuer: "https://cp.test", Keys: known.PublicKeys(),
		})
	}))
	defer ts.Close()

	v, err := keysource.New(keysource.NewHTTP(ts.URL), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(claimsFor(t, stranger))
	if err == nil {
		t.Fatal("a token from an unknown key was accepted")
	}
	if got := protocol.ReasonOf(err); got != protocol.ReasonKidUnknown {
		t.Fatalf("reason = %q, want kid_unknown", got)
	}
}

// TestColdCacheUnreachableFailsClosed proves a verifier that cannot check a
// signature refuses to accept one.
func TestColdCacheUnreachableFailsClosed(t *testing.T) {
	_, err := keysource.New(keysource.NewHTTP("http://127.0.0.1:1"), time.Minute)
	if err == nil {
		t.Fatal("a verifier with a cold cache and no reachable control plane was constructed")
	}
}

// TestWarmCacheSurvivesControlPlaneOutage proves a blip does not take resolution
// down: the last-known-good keys keep working until the control plane returns.
func TestWarmCacheSurvivesControlPlaneOutage(t *testing.T) {
	signer := signerFor(t, "k1")
	var up atomic.Bool
	up.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.PublicJWKS{Keys: signer.PublicKeys()})
	}))
	defer ts.Close()

	v, err := keysource.New(keysource.NewHTTP(ts.URL), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	up.Store(false)
	time.Sleep(5 * time.Millisecond) // let the TTL lapse

	// The fetch now fails, but the cached key set serves the request.
	if _, err := v.Verify(claimsFor(t, signer)); err != nil {
		t.Fatalf("warm cache did not survive a control-plane outage: %v", err)
	}
}

// TestEmptyKeySetRejected proves a control plane that publishes nothing cannot
// produce a verifier that accepts everything.
func TestEmptyKeySetRejected(t *testing.T) {
	if _, err := keysource.NewFromKeys(nil); err == nil {
		t.Fatal("an empty key set produced a verifier")
	}
}

var _ = context.Background
