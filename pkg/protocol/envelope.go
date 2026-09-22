package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD algorithm identifiers, matching the folder manifest enum.
const (
	AlgAES256GCM        = "AES-256-GCM"
	AlgChaCha20Poly1305 = "ChaCha20-Poly1305"
)

// DEKSize and KEKSize are 32 bytes (256-bit).
const (
	DEKSize = 32
	KEKSize = 32
)

// KeyWrapper wraps and unwraps data encryption keys under a key-encryption key.
//
// In production the KEK lives in a key store (OpenBao/Vault Transit) or a secure
// element, and the KEK never leaves it — see ADR kek-never-leaves-store. The
// interface exists so the sidecar never sees the KEK, only a wrapped or
// unwrapped DEK.
//
// Implementations MUST NOT persist an unwrapped DEK.
type KeyWrapper interface {
	// Wrap encrypts dek under the KEK identified by kid and returns an
	// opaque, self-describing wrapped form (e.g. Vault transit "vault:v1:…").
	Wrap(kid string, dek []byte) (string, error)

	// Unwrap recovers the DEK from wrapped, which must have been produced by
	// Wrap with the same kid.
	Unwrap(kid, wrapped string) ([]byte, error)
}

// NewDEK returns a fresh random 256-bit data encryption key.
func NewDEK() ([]byte, error) { return RandomBytes(DEKSize) }

// EncryptObject encrypts plaintext under dek using the named AEAD algorithm.
// The returned ciphertext is nonce||ciphertext.
//
// dek is not modified. The caller retains ownership of plaintext and is
// responsible for zeroising it.
func EncryptObject(alg string, dek, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(alg, dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cryptoRandReader{}, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptObject reverses EncryptObject. The returned plaintext MUST be zeroised
// by the caller once injected — use SecureBuffer.
func DecryptObject(alg string, dek, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(alg, dek)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		// AEAD failure means tampering or a wrong key. Never distinguish the
		// two to the caller.
		return nil, NewDenial(ReasonSignatureInvalid)
	}
	return pt, nil
}

func newAEAD(alg string, key []byte) (cipher.AEAD, error) {
	switch alg {
	case AlgAES256GCM:
		if len(key) != DEKSize {
			return nil, fmt.Errorf("AES-256-GCM requires a %d-byte key", DEKSize)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AlgChaCha20Poly1305:
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("ChaCha20-Poly1305 requires a %d-byte key", chacha20poly1305.KeySize)
		}
		return chacha20poly1305.New(key)
	default:
		// alg is a closed enum; an unknown value is a malformed manifest.
		return nil, NewDenial(ReasonMalformed)
	}
}

// HashObject returns the manifest "hash" value for a ciphertext blob, as
// "<algo>:<base64>", e.g. "sha256:47DEQ…". Hashes the CIPHERTEXT, never the
// plaintext.
func HashObject(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return "sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// cryptoRandReader adapts RandomBytes to an io.Reader for nonce generation.
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) {
	b, err := RandomBytes(len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, b), nil
}
