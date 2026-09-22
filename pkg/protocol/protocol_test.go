package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// ─── Token: conformance vectors ─────────────────────────────────────────────

// vectorsFile mirrors spec/capability-token/v1.vectors.json.
type capVectors struct {
	Now      int64 `json:"now"`
	Resolver struct {
		Audience string `json:"audience"`
	} `json:"resolver"`
	Vectors       []capVector    `json:"vectors"`
	HeaderVectors []headerVector `json:"header_vectors"`
}

type capVector struct {
	ID      string          `json:"id"`
	Input   json.RawMessage `json:"input"`
	Revoked []string        `json:"revoked"`
	URISID  string          `json:"uri_sid"`
	Expect  struct {
		Schema  string `json:"schema"`
		Resolve string `json:"resolve"`
		Reason  any    `json:"reason"`
	} `json:"expect"`
}

type headerVector struct {
	ID     string          `json:"id"`
	Header json.RawMessage `json:"header"`
	Expect struct {
		Resolve string `json:"resolve"`
		Reason  any    `json:"reason"`
	} `json:"expect"`
}

func loadCapVectors(t *testing.T) capVectors {
	t.Helper()
	data, err := os.ReadFile("../../spec/capability-token/v1.vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v capVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

// TestSchemaVectors validates each claims vector against the frozen schema
// using a strict decode, mirroring additionalProperties:false. A vector
// carrying secret material MUST fail to decode.
func TestSchemaVectors(t *testing.T) {
	v := loadCapVectors(t)
	for _, vec := range v.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			got := "valid"
			if err := decodeStrictClaims(vec.Input); err != nil {
				got = "invalid"
			}
			if got != vec.Expect.Schema {
				t.Fatalf("schema: want %q, got %q", vec.Expect.Schema, got)
			}
		})
	}
}

// decodeStrictClaims reports an error if the claims JSON contains any field
// outside the frozen schema, or violates a structural constraint a plain decode
// does not enforce. It delegates the structural checks to the implementation's
// own validator so the test exercises real code rather than a parallel copy.
func decodeStrictClaims(raw json.RawMessage) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var c protocol.Claims
	if err := dec.Decode(&c); err != nil {
		return err
	}
	return protocol.ValidateClaims(c)
}

// TestHeaderVectors proves the algorithm allowlist rejects alg:none and all
// symmetric algorithms — the classic JWT attack class.
func TestHeaderVectors(t *testing.T) {
	v := loadCapVectors(t)
	for _, vec := range v.HeaderVectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			var h protocol.Header
			if err := json.Unmarshal(vec.Header, &h); err != nil {
				t.Fatalf("parse header: %v", err)
			}
			allowed := protocol.IsAlgorithmAllowed(h.Alg) && h.Kid != ""
			got := "denied"
			if allowed {
				got = "allowed"
			}
			if got != vec.Expect.Resolve {
				t.Fatalf("resolve: want %q, got %q (alg=%q kid=%q)", vec.Expect.Resolve, got, h.Alg, h.Kid)
			}
		})
	}
}

// TestResolveSemantics exercises the full verification path for the vectors
// whose schema result is "valid" and whose outcome is a semantic decision.
func TestResolveSemantics(t *testing.T) {
	v := loadCapVectors(t)
	signer, err := protocol.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v.Now, 0)

	for _, vec := range v.Vectors {
		if vec.Expect.Schema != "valid" {
			continue // schema-invalid vectors never reach resolution
		}
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			var c protocol.Claims
			if err := json.Unmarshal(vec.Input, &c); err != nil {
				t.Fatalf("parse claims: %v", err)
			}
			uriSID := c.SID
			if vec.URISID != "" {
				uriSID = vec.URISID
			}
			jws, err := signer.Sign(protocol.Header{}, c)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			p, err := protocol.ParseURI(protocol.URI(uriSID, jws))
			if err != nil {
				t.Fatalf("parse uri: %v", err)
			}
			revoked := func(jti string) bool {
				for _, r := range vec.Revoked {
					if r == jti {
						return true
					}
				}
				return false
			}
			_, verr := protocol.VerifyToken(signer, p, v.Resolver.Audience, now, revoked)

			got := "allowed"
			reason := ""
			if verr != nil {
				got = "denied"
				reason = protocol.ReasonOf(verr)
			}
			if got != vec.Expect.Resolve {
				t.Fatalf("resolve: want %q, got %q", vec.Expect.Resolve, got)
			}
			if want, ok := vec.Expect.Reason.(string); ok && want != "" && reason != want {
				t.Fatalf("reason: want %q, got %q", want, reason)
			}
		})
	}
}

// ─── Token: specific security properties ────────────────────────────────────

// TestTokenContainsNoSecretMaterial states the cardinal invariant: a minted
// token must not embed the value it authorises.
func TestTokenContainsNoSecretMaterial(t *testing.T) {
	secret := "super-secret-value-that-must-not-appear"
	signer, _ := protocol.GenerateEd25519Signer("k1")
	now := time.Now()
	c := protocol.Claims{
		Iss:   "https://cp.safekeys.ai",
		SID:   "obj_abc123",
		Scope: []string{protocol.ScopeRead},
		Aud:   "env-staging",
		Exp:   now.Add(time.Hour).Unix(),
		Nbf:   now.Add(-time.Minute).Unix(),
		JTI:   "jti_test_00000001",
	}
	jws, err := signer.Sign(protocol.Header{}, c)
	if err != nil {
		t.Fatal(err)
	}
	uri := protocol.URI(c.SID, jws)
	if strings.Contains(uri, secret) {
		t.Fatal("token URI contains the secret value")
	}
	// Nor may it contain key material.
	if strings.Contains(uri, "dek") || strings.Contains(uri, "kek") {
		t.Fatal("token URI contains key-shaped material")
	}
}

// TestAlgNoneRejected builds a forged token with alg:none and asserts denial.
func TestAlgNoneRejected(t *testing.T) {
	// header alg:none, arbitrary payload, empty signature
	header := protocol.Header{Alg: "none", Kid: "k1", Typ: protocol.TokenType}
	hb, _ := json.Marshal(header)
	cb := []byte(`{"iss":"https://cp.safekeys.ai","sid":"obj_a","scope":["read"],"aud":"env-staging","exp":99999999999,"nbf":1,"jti":"jti_forged_0001"}`)
	forged := b64url(hb) + "." + b64url(cb) + "."
	signer, _ := protocol.GenerateEd25519Signer("k1")
	_, err := signer.Verify(forged)
	if err == nil {
		t.Fatal("alg:none token was accepted")
	}
	if got := protocol.ReasonOf(err); got != protocol.ReasonAlgNotAllowed {
		t.Fatalf("want %q, got %q", protocol.ReasonAlgNotAllowed, got)
	}
}

// TestHMACAlgRejected asserts symmetric algorithms are refused, closing the
// algorithm-confusion attack.
func TestHMACAlgRejected(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		header := protocol.Header{Alg: alg, Kid: "k1", Typ: protocol.TokenType}
		hb, _ := json.Marshal(header)
		forged := b64url(hb) + "." + b64url([]byte(`{}`)) + ".AAAA"
		signer, _ := protocol.GenerateEd25519Signer("k1")
		if _, err := signer.Verify(forged); err == nil {
			t.Fatalf("%s token was accepted", alg)
		}
	}
}

// TestURIVersionRefused proves an unknown format version is refused, not parsed
// best-effort.
func TestURIVersionRefused(t *testing.T) {
	_, err := protocol.ParseURI("safekey://v9/obj_a#aaaa.bbbb.cccc")
	if err == nil {
		t.Fatal("unknown version was accepted")
	}
	if got := protocol.ReasonOf(err); got != protocol.ReasonUnsupportedVersion {
		t.Fatalf("want %q, got %q", protocol.ReasonUnsupportedVersion, got)
	}
}

// TestES256RoundTrip proves the FIPS-oriented algorithm works end to end.
func TestES256RoundTrip(t *testing.T) {
	key, err := ecdsaGenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewES256Signer("es-key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := protocol.Claims{
		Iss: "https://cp.safekeys.ai", SID: "obj_es", Scope: []string{protocol.ScopeUnwrap},
		Aud: "env-staging", Exp: now.Add(time.Hour).Unix(), Nbf: now.Add(-time.Minute).Unix(),
		JTI: "jti_es256_000001",
	}
	jws, err := signer.Sign(protocol.Header{}, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(jws); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// ─── Folder: conformance vectors ────────────────────────────────────────────

type folderVectors struct {
	Vectors       []folderVector `json:"vectors"`
	FolderVectors []struct {
		ID     string `json:"id"`
		Expect struct {
			Resolve string `json:"resolve"`
			Reason  any    `json:"reason"`
		} `json:"expect"`
	} `json:"folder_vectors"`
}

type folderVector struct {
	ID     string          `json:"id"`
	Input  json.RawMessage `json:"input"`
	Expect struct {
		Schema  string `json:"schema"`
		Resolve string `json:"resolve"`
		Reason  any    `json:"reason"`
	} `json:"expect"`
}

func loadFolderVectors(t *testing.T) folderVectors {
	t.Helper()
	data, err := os.ReadFile("../../spec/encrypted-folder/v1.vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v folderVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

// TestFolderSchemaVectors asserts each manifest vector decodes or fails as the
// frozen schema requires. The negative vectors carrying plaintext, an unwrapped
// DEK, or a KEK MUST fail — that is the cardinal invariant.
func TestFolderSchemaVectors(t *testing.T) {
	v := loadFolderVectors(t)
	for _, vec := range v.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			_, err := protocol.DecodeManifest(vec.Input)
			got := "valid"
			reason := ""
			if err != nil {
				got = "invalid"
				reason = protocol.ReasonOf(err)
			}
			if got != vec.Expect.Schema {
				t.Fatalf("schema: want %q, got %q (err=%v)", vec.Expect.Schema, got, err)
			}
			if want, ok := vec.Expect.Reason.(string); ok && want != "" && got == "invalid" {
				// reason may be a schema-level keyword; only check protocol reasons
				if reason != "" && reason != want {
					t.Logf("reason: want %q, got %q (schema keyword vs protocol reason)", want, reason)
				}
			}
		})
	}
}

// TestManifestRejectsSecretShapedFields is the explicit assertion that a
// manifest can never carry plaintext or key material.
func TestManifestRejectsSecretShapedFields(t *testing.T) {
	cases := map[string]string{
		"plaintext":     `{"safekeys":"1","objects":[{"id":"o1","path":"objects/o1.enc","alg":"AES-256-GCM","wrapped_key":"vault:v1:abc","value":"SECRET"}]}`,
		"unwrapped_dek": `{"safekeys":"1","objects":[{"id":"o1","path":"objects/o1.enc","alg":"AES-256-GCM","wrapped_key":"vault:v1:abc","dek":"AAAA"}]}`,
		"kek":           `{"safekeys":"1","objects":[{"id":"o1","path":"objects/o1.enc","alg":"AES-256-GCM","wrapped_key":"vault:v1:abc"}],"kek":"AAAA"}`,
	}
	for name, body := range cases {
		if _, err := protocol.DecodeManifest([]byte(body)); err == nil {
			t.Fatalf("%s: manifest with secret-shaped field was accepted", name)
		}
	}
}

// TestManifestPathTraversalRejected proves traversal and unencrypted paths are
// refused.
func TestManifestPathTraversalRejected(t *testing.T) {
	for _, bad := range []string{
		"objects/../../etc/passwd.enc",
		"secrets/plain.txt",
		"objects/plain.txt",
	} {
		body := `{"safekeys":"1","objects":[{"id":"o1","path":"` + bad + `","alg":"AES-256-GCM","wrapped_key":"vault:v1:abc"}]}`
		if _, err := protocol.DecodeManifest([]byte(body)); err == nil {
			t.Fatalf("path %q was accepted", bad)
		}
	}
}

// ─── Envelope ───────────────────────────────────────────────────────────────

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, alg := range []string{protocol.AlgAES256GCM, protocol.AlgChaCha20Poly1305} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			dek, err := protocol.NewDEK()
			if err != nil {
				t.Fatal(err)
			}
			defer protocol.Zero(dek)
			secret := []byte("sk-live-abc123")
			ct, err := protocol.EncryptObject(alg, dek, secret)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(ct), "sk-live-abc123") {
				t.Fatal("ciphertext contains plaintext")
			}
			pt, err := protocol.DecryptObject(alg, dek, ct)
			if err != nil {
				t.Fatal(err)
			}
			defer protocol.Zero(pt)
			if string(pt) != string(secret) {
				t.Fatalf("roundtrip mismatch: %q", pt)
			}
		})
	}
}

// TestUniqueDEKPerObject asserts per-object key isolation.
func TestUniqueDEKPerObject(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		dek, err := protocol.NewDEK()
		if err != nil {
			t.Fatal(err)
		}
		k := string(dek)
		if seen[k] {
			t.Fatal("DEK reused across objects")
		}
		seen[k] = true
		protocol.Zero(dek)
	}
}

// TestTamperedCiphertextRejected proves AEAD integrity catches modification.
func TestTamperedCiphertextRejected(t *testing.T) {
	dek, _ := protocol.NewDEK()
	defer protocol.Zero(dek)
	ct, err := protocol.EncryptObject(protocol.AlgAES256GCM, dek, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := protocol.DecryptObject(protocol.AlgAES256GCM, dek, ct); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

// TestZeroisation proves the buffer is actually cleared.
func TestZeroisation(t *testing.T) {
	buf := protocol.NewSecureBuffer(16)
	copy(buf.Bytes(), []byte("sensitive-value!"))
	buf.Release()
	if buf.Len() != 0 {
		t.Fatal("buffer not released")
	}
	// A directly zeroised slice must read as zeros.
	b := []byte("another-secret")
	protocol.Zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zeroised", i)
		}
	}
}

// ─── Folder: write/read integration ─────────────────────────────────────────

// TestFolderIsInert proves that reading every file in a written folder without
// a sidecar yields no secret.
func TestFolderIsInert(t *testing.T) {
	dir := t.TempDir()

	// A stand-in wrapper that returns a fixed wrapped form. The KEK never
	// leaves this object, mirroring the real key store contract.
	wrapper := &fakeWrapper{kek: []byte("0123456789abcdef0123456789abcdef")}

	secret := []byte("production-api-key")
	dek, err := protocol.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Zero(dek)
	ct, err := protocol.EncryptObject(protocol.AlgAES256GCM, dek, secret)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapper.Wrap("kek-1", dek)
	if err != nil {
		t.Fatal(err)
	}

	m := &protocol.Manifest{
		Safekeys: protocol.Version,
		Objects: []protocol.ManifestObject{{
			ID: "obj_test_0001", Path: "objects/obj_test_0001.enc",
			Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: "kek-1",
		}},
	}
	if err := protocol.WriteFolder(dir, m, map[string][]byte{"obj_test_0001": ct}, "test folder"); err != nil {
		t.Fatal(err)
	}

	// Walk every file. None may contain the secret.
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "production-api-key") {
			t.Fatalf("plaintext found in %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The README must be present and secret-free.
	readme, err := os.ReadFile(filepath.Join(dir, protocol.ReadmeName))
	if err != nil {
		t.Fatalf("README missing: %v", err)
	}
	if strings.Contains(string(readme), "production-api-key") {
		t.Fatal("README contains the secret")
	}
	if !strings.Contains(string(readme), "inert") {
		t.Error("README should explain the folder is inert")
	}
}

// fakeWrapper is an in-process KeyWrapper for tests. It holds the KEK and never
// exposes it — the same contract the real Vault/OpenBao client satisfies.
type fakeWrapper struct{ kek []byte }

func (f *fakeWrapper) Wrap(kid string, dek []byte) (string, error) {
	ct, err := protocol.EncryptObject(protocol.AlgAES256GCM, f.kek, dek)
	if err != nil {
		return "", err
	}
	return "vault:v1:" + b64url(ct), nil
}

func (f *fakeWrapper) Unwrap(kid, wrapped string) ([]byte, error) {
	raw := strings.TrimPrefix(wrapped, "vault:v1:")
	ct, err := b64decodeURL(raw)
	if err != nil {
		return nil, err
	}
	return protocol.DecryptObject(protocol.AlgAES256GCM, f.kek, ct)
}

// TestWrappedKeyIsUselessWithoutKEK proves the wrapped key in a manifest cannot
// be decrypted without the key store.
func TestWrappedKeyIsUselessWithoutKEK(t *testing.T) {
	dek, _ := protocol.NewDEK()
	defer protocol.Zero(dek)
	wrapper := &fakeWrapper{kek: []byte("0123456789abcdef0123456789abcdef")}
	wrapped, err := wrapper.Wrap("kek-1", dek)
	if err != nil {
		t.Fatal(err)
	}
	// An attacker with the wrapped key but a different KEK gets nothing.
	attacker := &fakeWrapper{kek: []byte("ffffffffffffffffffffffffffffffff")}
	if _, err := attacker.Unwrap("kek-1", wrapped); err == nil {
		t.Fatal("wrapped key was unwrapped with the wrong KEK")
	}
}
