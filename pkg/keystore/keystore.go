// Package keystore provides KeyWrapper implementations for envelope key
// wrapping.
//
// The contract, from ADR kek-never-leaves-store: the long-term key-encryption
// key (KEK) must never leave the key store. Callers receive either a wrapped
// DEK or, transiently, an unwrapped one — never the KEK itself.
//
// Two implementations ship:
//
//	Vault  — production. Talks to OpenBao/Vault Transit; the KEK lives inside
//	         the vault and is never exported.
//	Local  — DEVELOPMENT ONLY. Holds a KEK in a 0600 file on disk. Explicitly
//	         insecure and refuses to run unless opted into.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// ─── Vault / OpenBao Transit ────────────────────────────────────────────────

// Vault wraps DEKs with Vault Transit. The KEK is a named transit key inside
// the vault; the vault performs wrap and unwrap, so the KEK never leaves it.
type Vault struct {
	Addr   string
	Token  string
	Mount  string
	Client *http.Client
}

// NewVault builds a Transit-backed wrapper. mount defaults to "transit".
func NewVault(addr, token, mount string) *Vault {
	if mount == "" {
		mount = "transit"
	}
	return &Vault{
		Addr:   strings.TrimRight(addr, "/"),
		Token:  token,
		Mount:  mount,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Wrap implements protocol.KeyWrapper via POST /transit/encrypt/<kid>.
func (v *Vault) Wrap(kid string, dek []byte) (string, error) {
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.do("POST", fmt.Sprintf("/v1/%s/encrypt/%s", v.Mount, kid), body, &out); err != nil {
		return "", err
	}
	if out.Data.Ciphertext == "" {
		return "", fmt.Errorf("vault: empty ciphertext")
	}
	// Vault returns "vault:v1:<base64>".
	return out.Data.Ciphertext, nil
}

// Unwrap implements protocol.KeyWrapper via POST /transit/decrypt/<kid>.
//
// A vault failure is surfaced as a generic protocol denial: the sidecar must
// fail closed without leaking whether the key existed.
func (v *Vault) Unwrap(kid, wrapped string) ([]byte, error) {
	body := map[string]string{"ciphertext": wrapped}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.do("POST", fmt.Sprintf("/v1/%s/decrypt/%s", v.Mount, kid), body, &out); err != nil {
		return nil, protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}
	return dek, nil
}

// Healthy reports whether the vault is reachable and unsealed.
func (v *Vault) Healthy() error {
	req, err := http.NewRequest("GET", v.Addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}
	return nil
}

func (v *Vault) do(method, path string, in, out any) error {
	buf, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, v.Addr+path, strings.NewReader(string(buf)))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault: %s %s -> %d", method, path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ─── Local dev key store ────────────────────────────────────────────────────

// Local is a DEVELOPMENT-ONLY KeyWrapper that keeps a KEK in a 0600 file.
//
// It exists so the MVP can run end to end without a vault, and it is loud about
// being unsafe: the KEK sits in host memory and on disk, which is precisely the
// exposure the Vault implementation and Phase 1 hardware eliminate. It refuses
// to load unless SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1 is set.
type Local struct {
	path string
	kek  []byte
}

// ErrInsecureKeystore is returned when the local store is used without an
// explicit opt-in.
var ErrInsecureKeystore = fmt.Errorf(
	"local key store is development-only and holds the KEK in plaintext; " +
		"set SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1 to opt in (never in production)")

// NewLocal opens or creates a local KEK file. It requires the explicit opt-in
// environment variable so it cannot be enabled by accident in production.
func NewLocal(path string) (*Local, error) {
	if os.Getenv("SAFEKEYS_ALLOW_INSECURE_KEYSTORE") != "1" {
		return nil, ErrInsecureKeystore
	}
	kek, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		kek, err = protocol.RandomBytes(protocol.KEKSize)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, kek, 0o600); err != nil {
			return nil, err
		}
	}
	if len(kek) != protocol.KEKSize {
		return nil, fmt.Errorf("local keystore: bad KEK size %d", len(kek))
	}
	return &Local{path: path, kek: kek}, nil
}

// Wrap implements protocol.KeyWrapper, producing "local:v1:<base64>".
func (l *Local) Wrap(kid string, dek []byte) (string, error) {
	ct, err := protocol.EncryptObject(protocol.AlgAES256GCM, l.kek, dek)
	if err != nil {
		return "", err
	}
	return "local:v1:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Unwrap implements protocol.KeyWrapper.
func (l *Local) Unwrap(kid, wrapped string) ([]byte, error) {
	raw := strings.TrimPrefix(wrapped, "local:v1:")
	ct, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}
	return protocol.DecryptObject(protocol.AlgAES256GCM, l.kek, ct)
}

// Healthy always succeeds for the local store.
func (l *Local) Healthy() error { return nil }

// Close zeroises the in-memory KEK.
func (l *Local) Close() {
	protocol.Zero(l.kek)
	l.kek = nil
}

// Compile-time interface conformance.
var (
	_ protocol.KeyWrapper = (*Vault)(nil)
	_ protocol.KeyWrapper = (*Local)(nil)
)
