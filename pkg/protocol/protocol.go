// Package protocol implements the frozen v1 Safekeys wire formats: the
// capability token (spec/capability-token/v1.schema.json) and the encrypted
// folder (spec/encrypted-folder/v1.schema.json).
//
// Package layout:
//
//	token.go    — JWS capability tokens: claims, sign, verify, safekey:// URIs
//	folder.go   — encrypted folder manifests: read, write, validate
//	envelope.go — AEAD object encryption + envelope key wrapping
//	zeroise.go  — best-effort zeroisation of sensitive buffers
//	errors.go   — generic denials carrying an audit-only reason
//
// The central invariant, asserted by the conformance vectors in spec/: no
// plaintext, no unwrapped data encryption key (DEK), and no key-encryption key
// (KEK) may ever appear in a token or a folder manifest.
package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Version is the protocol version carried in a token URI path (safeKey://v1/…)
// and in the folder manifest "safekeys" field.
const Version = "1"

// URI scheme for a capability token.
const URIScheme = "safekey"

// TokenType is the JWS "typ" header value.
const TokenType = "safekey-token+jws"

// Algorithm allowlist. See ADR alg-allowlist: EdDSA is the modern default;
// ES256 is permitted for FIPS-oriented deployments. Symmetric algorithms are
// never permitted, and "none" is always rejected.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
)

// AllowedAlgorithms is the closed allowlist. Adding an algorithm is a new
// major format version, not a config change.
var AllowedAlgorithms = []string{AlgEdDSA, AlgES256}

// IsAlgorithmAllowed reports whether alg is on the allowlist. Anything else —
// including "none", "HS256", "HS384", "HS512" — is rejected.
func IsAlgorithmAllowed(alg string) bool {
	for _, a := range AllowedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// b64 is the base64url encoding without padding, per RFC 7515.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64decode decodes base64url, tolerating padded input.
func b64decode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("csprng: %w", err)
	}
	return b, nil
}

// NewID returns a random URL-safe identifier prefixed with prefix, e.g.
// NewID("obj") → "obj_9f3a1b2c4d5e6f70". Used for object ids and jti values.
func NewID(prefix string) (string, error) {
	b, err := RandomBytes(12)
	if err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}
