package protocol_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
)

// b64url encodes without padding, per RFC 7515.
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64decodeURL decodes base64url, tolerating padding.
func b64decodeURL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// ecdsaGenerateKey returns a fresh P-256 key for ES256 tests.
func ecdsaGenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
