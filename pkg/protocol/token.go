package protocol

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// newBigInt converts a fixed-width big-endian byte slice to an integer, as
// required by the JWS ES256 R||S signature form.
func newBigInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// Claims is the JWS payload of a capability token. It maps exactly to
// spec/capability-token/v1.schema.json, which sets additionalProperties:false —
// no field may carry plaintext, a DEK, or a KEK.
//
// Optional fields use omitempty so the serialised form matches the schema's
// required set.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub,omitempty"`
	SID   string   `json:"sid"`
	Scope []string `json:"scope"`
	Aud   string   `json:"aud"`
	Exp   int64    `json:"exp"`
	Nbf   int64    `json:"nbf"`
	JTI   string   `json:"jti"`
}

// Header is the JWS protected header.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Scopes are the permitted operations. Closed set — see the schema enum.
const (
	ScopeRead       = "read"
	ScopeUnwrap     = "unwrap"
	ScopeInjectEnv  = "inject-env"
	ScopeInjectFile = "inject-file"
	ScopeSign       = "sign"
)

// AllScopes is the closed scope enum.
var AllScopes = []string{ScopeRead, ScopeUnwrap, ScopeInjectEnv, ScopeInjectFile, ScopeSign}

// IsScopeValid reports whether s is a member of the closed scope enum.
func IsScopeValid(s string) bool {
	for _, a := range AllScopes {
		if a == s {
			return true
		}
	}
	return false
}

// ScopeAllows reports whether granted permits requested.
func ScopeAllows(granted []string, requested string) bool {
	for _, g := range granted {
		if g == requested {
			return true
		}
	}
	return false
}

// Verifier checks token signatures. It holds PUBLIC key material only.
//
// This is the interface the sidecar uses. Keeping it separate from Signer is a
// deliberate security boundary: the sidecar runs on the same host as the
// secrets, so it is the component most likely to be attacked. If it held a
// signing key, compromising it would let an attacker mint tokens and defeat the
// entire model. Splitting the interfaces makes that structurally impossible to
// do by accident — a Verifier simply has no Sign method to call.
type Verifier interface {
	// Verify checks the signature and returns the protected header. It must
	// reject any algorithm not on the allowlist.
	Verify(jws string) (Header, error)
	// VerifyWith checks the signature against a specific key and alg, for
	// multi-key deployments where several issuers or a rotation overlap exist.
	VerifyWith(kid, alg string, jws string) (Header, error)
}

// Signer mints tokens. Implementations hold the PRIVATE signing key; in Phase 1
// that key is HSM- or secure-element-backed — see ADR key-custody-hsm.
//
// Only the control plane needs this. The sidecar must not: see Verifier.
type Signer interface {
	Verifier
	// Sign returns the compact JWS over the given claims.
	Sign(h Header, c Claims) (string, error)
	// KeyID returns the kid this signer issues under.
	KeyID() string
	// Algorithm returns the JWS alg this signer uses.
	Algorithm() string
	// PublicKeys returns the public half of every key this signer can issue
	// under, for publication to verifiers.
	PublicKeys() []PublicKey
}

// PublicKey is published key material a verifier needs. It carries no private
// component by construction.
type PublicKey struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	// Public is the PKIX DER-encoded public key, base64 (standard) encoded.
	Public string `json:"public"`
}

// PublicJWKS is the published key set.
type PublicJWKS struct {
	Issuer string      `json:"issuer"`
	Keys   []PublicKey `json:"keys"`
}

// Kids returns the key ids in the set, for logging.
func (j PublicJWKS) Kids() []string {
	out := make([]string, 0, len(j.Keys))
	for _, k := range j.Keys {
		out = append(out, k.KID)
	}
	return out
}

// ─── Ed25519 signer ─────────────────────────────────────────────────────────

// Ed25519Signer is the default signer (alg EdDSA).
type Ed25519Signer struct {
	kid string
	prv ed25519.PrivateKey
}

// NewEd25519Signer wraps an Ed25519 private key.
func NewEd25519Signer(kid string, prv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(prv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: bad private key size %d", len(prv))
	}
	return &Ed25519Signer{kid: kid, prv: prv}, nil
}

// GenerateEd25519Signer creates a fresh signing key. Development and test use
// only — production keys are provisioned into an HSM or secure element.
func GenerateEd25519Signer(kid string) (*Ed25519Signer, error) {
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(kid, prv)
}

// KeyID implements Signer.
func (s *Ed25519Signer) KeyID() string { return s.kid }

// Algorithm implements Signer.
func (s *Ed25519Signer) Algorithm() string { return AlgEdDSA }

// Sign implements Signer.
func (s *Ed25519Signer) Sign(h Header, c Claims) (string, error) {
	return signCompact(h, c, s.kid, AlgEdDSA, func(signingInput []byte) ([]byte, error) {
		return ed25519.Sign(s.prv, signingInput), nil
	})
}

// Verify implements Verifier using this signer's own public key.
func (s *Ed25519Signer) Verify(jws string) (Header, error) {
	return verifyCompact(jws, func(h Header, signingInput, sig []byte) error {
		if h.Alg != AlgEdDSA {
			return NewDenial(ReasonAlgNotAllowed)
		}
		if h.Kid != s.kid {
			return NewDenial(ReasonKidUnknown)
		}
		pub, ok := s.prv.Public().(ed25519.PublicKey)
		if !ok {
			return NewDenial(ReasonSignatureInvalid)
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return NewDenial(ReasonSignatureInvalid)
		}
		return nil
	})
}

// VerifyWith implements Verifier. It only accepts this signer's own kid.
func (s *Ed25519Signer) VerifyWith(kid, alg string, jws string) (Header, error) {
	if kid != s.kid {
		return Header{}, NewDenial(ReasonKidUnknown)
	}
	return s.Verify(jws)
}

// PublicKeys implements Signer, publishing the public half for verifiers.
func (s *Ed25519Signer) PublicKeys() []PublicKey {
	return []PublicKey{ed25519PublicKey(s.kid, s.prv.Public().(ed25519.PublicKey))}
}

// ─── ES256 signer ───────────────────────────────────────────────────────────

// ES256Signer signs with ECDSA P-256 (alg ES256), for FIPS-oriented
// deployments.
type ES256Signer struct {
	kid string
	prv *ecdsa.PrivateKey
}

// NewES256Signer wraps an ECDSA P-256 private key.
func NewES256Signer(kid string, prv *ecdsa.PrivateKey) (*ES256Signer, error) {
	if prv == nil || prv.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("es256: requires a P-256 key")
	}
	return &ES256Signer{kid: kid, prv: prv}, nil
}

// KeyID implements Signer.
func (s *ES256Signer) KeyID() string { return s.kid }

// Algorithm implements Signer.
func (s *ES256Signer) Algorithm() string { return AlgES256 }

// Sign implements Signer.
func (s *ES256Signer) Sign(h Header, c Claims) (string, error) {
	return signCompact(h, c, s.kid, AlgES256, func(signingInput []byte) ([]byte, error) {
		digest := sha256.Sum256(signingInput)
		r, sv, err := ecdsa.Sign(rand.Reader, s.prv, digest[:])
		if err != nil {
			return nil, err
		}
		// JWS ES256 requires the fixed-width R||S form, not ASN.1 DER.
		size := (s.prv.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*size)
		r.FillBytes(sig[:size])
		sv.FillBytes(sig[size:])
		return sig, nil
	})
}

// Verify implements Verifier using this signer's own public key.
func (s *ES256Signer) Verify(jws string) (Header, error) {
	return verifyCompact(jws, func(h Header, signingInput, sig []byte) error {
		if h.Alg != AlgES256 {
			return NewDenial(ReasonAlgNotAllowed)
		}
		if h.Kid != s.kid {
			return NewDenial(ReasonKidUnknown)
		}
		size := (s.prv.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return NewDenial(ReasonSignatureInvalid)
		}
		digest := sha256.Sum256(signingInput)
		r := newBigInt(sig[:size])
		sv := newBigInt(sig[size:])
		if !ecdsa.Verify(&s.prv.PublicKey, digest[:], r, sv) {
			return NewDenial(ReasonSignatureInvalid)
		}
		return nil
	})
}

// VerifyWith implements Verifier. It only accepts this signer's own kid.
func (s *ES256Signer) VerifyWith(kid, alg string, jws string) (Header, error) {
	if kid != s.kid {
		return Header{}, NewDenial(ReasonKidUnknown)
	}
	return s.Verify(jws)
}

// PublicKeys implements Signer.
func (s *ES256Signer) PublicKeys() []PublicKey {
	return []PublicKey{ecdsaPublicKey(s.kid, &s.prv.PublicKey)}
}

// ─── Public-key verifier ────────────────────────────────────────────────────

// KeySetVerifier verifies tokens against a published set of PUBLIC keys.
//
// This is what the sidecar uses. It holds no private key and therefore cannot
// mint a token even if the host is fully compromised — the strongest property
// available to a verifier in the software-only phase.
type KeySetVerifier struct {
	keys map[string]PublicKey
	// allowMissing, when true, permits a token whose kid is unknown (development
	// only; production must be false so an unknown key is a hard denial).
	allowMissing bool
}

// NewKeySetVerifier builds a verifier from published keys.
func NewKeySetVerifier(keys []PublicKey) (*KeySetVerifier, error) {
	m := make(map[string]PublicKey, len(keys))
	for _, k := range keys {
		if k.KID == "" || k.Alg == "" || k.Public == "" {
			return nil, NewDenial(ReasonMalformed)
		}
		if !IsAlgorithmAllowed(k.Alg) {
			return nil, NewDenial(ReasonAlgNotAllowed)
		}
		m[k.KID] = k
	}
	if len(m) == 0 {
		return nil, NewDenial(ReasonKidUnknown)
	}
	return &KeySetVerifier{keys: m}, nil
}

// Keys returns the published keys this verifier holds. Public material only.
func (v *KeySetVerifier) Keys() map[string]PublicKey {
	out := make(map[string]PublicKey, len(v.keys))
	for k, val := range v.keys {
		out[k] = val
	}
	return out
}

// Verify implements Verifier, resolving the key by the token's kid.
func (v *KeySetVerifier) Verify(jws string) (Header, error) {
	// Read the header first so we know which key to use. The algorithm is still
	// allowlist-checked before any key material is touched.
	hdr, err := DecodeHeader(jws)
	if err != nil {
		return Header{}, err
	}
	return v.VerifyWith(hdr.Kid, hdr.Alg, jws)
}

// VerifyWith implements Verifier against a named key.
func (v *KeySetVerifier) VerifyWith(kid, alg string, jws string) (Header, error) {
	k, ok := v.keys[kid]
	if !ok {
		// An unknown key is a hard denial: never fall back to a default key,
		// which is the classic verification-bypass.
		return Header{}, NewDenial(ReasonKidUnknown)
	}
	if k.Alg != alg {
		return Header{}, NewDenial(ReasonAlgNotAllowed)
	}
	return verifyCompact(jws, func(h Header, signingInput, sig []byte) error {
		if h.Kid != kid {
			return NewDenial(ReasonKidUnknown)
		}
		return verifyWithPublicKey(k, signingInput, sig)
	})
}

// verifyWithPublicKey checks a signature against a published public key.
func verifyWithPublicKey(k PublicKey, signingInput, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil {
		return NewDenial(ReasonSignatureInvalid)
	}
	pub, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return NewDenial(ReasonSignatureInvalid)
	}
	switch key := pub.(type) {
	case ed25519.PublicKey:
		if k.Alg != AlgEdDSA || !ed25519.Verify(key, signingInput, sig) {
			return NewDenial(ReasonSignatureInvalid)
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Alg != AlgES256 {
			return NewDenial(ReasonSignatureInvalid)
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return NewDenial(ReasonSignatureInvalid)
		}
		digest := sha256.Sum256(signingInput)
		r := newBigInt(sig[:size])
		s := newBigInt(sig[size:])
		if !ecdsa.Verify(key, digest[:], r, s) {
			return NewDenial(ReasonSignatureInvalid)
		}
		return nil
	default:
		return NewDenial(ReasonSignatureInvalid)
	}
}

// ed25519PublicKey marshals a public key for publication.
func ed25519PublicKey(kid string, pub ed25519.PublicKey) PublicKey {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Marshalling a valid public key cannot fail; a failure here would be a
		// programming error, so publish an empty set rather than panic.
		return PublicKey{KID: kid, Alg: AlgEdDSA}
	}
	return PublicKey{KID: kid, Alg: AlgEdDSA, Public: base64.StdEncoding.EncodeToString(der)}
}

// ecdsaPublicKey marshals an ECDSA public key for publication.
func ecdsaPublicKey(kid string, pub *ecdsa.PublicKey) PublicKey {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return PublicKey{KID: kid, Alg: AlgES256}
	}
	return PublicKey{KID: kid, Alg: AlgES256, Public: base64.StdEncoding.EncodeToString(der)}
}

// DecodeHeader extracts the protected header from a compact JWS without
// verifying the signature. Callers MUST verify before trusting any claim; this
// exists so a verifier can learn which key to use, and is safe because the
// algorithm is still allowlist-checked here and the signature checked next.
func DecodeHeader(jws string) (Header, error) { return decodeHeader(jws) }

// decodeHeader extracts the protected header without verifying.
func decodeHeader(jws string) (Header, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Header{}, NewDenial(ReasonMalformed)
	}
	hb, err := b64decode(parts[0])
	if err != nil {
		return Header{}, NewDenial(ReasonMalformed)
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Header{}, NewDenial(ReasonMalformed)
	}
	if !IsAlgorithmAllowed(h.Alg) {
		return Header{}, NewDenial(ReasonAlgNotAllowed)
	}
	if h.Kid == "" {
		return Header{}, NewDenial(ReasonKidMissing)
	}
	return h, nil
}

// ─── Shared compact-JWS mechanics ───────────────────────────────────────────

// signCompact builds header.payload.signature per RFC 7515, forcing the
// caller's algorithm so a mismatched header cannot be produced.
func signCompact(h Header, c Claims, kid, alg string, sign func([]byte) ([]byte, error)) (string, error) {
	if !IsAlgorithmAllowed(alg) {
		return "", NewDenial(ReasonAlgNotAllowed)
	}
	h.Alg, h.Kid, h.Typ = alg, kid, TokenType
	if err := validateClaims(c); err != nil {
		return "", err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sig, err := sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// verifyCompact checks structure and delegates the cryptographic check. The
// algorithm MUST be on the allowlist before any key is touched.
func verifyCompact(jws string, check func(Header, []byte, []byte) error) (Header, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Header{}, NewDenial(ReasonMalformed)
	}
	hb, err := b64decode(parts[0])
	if err != nil {
		return Header{}, NewDenial(ReasonMalformed)
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Header{}, NewDenial(ReasonMalformed)
	}
	// Allowlist first — before any key is considered. Rejects alg:none and all
	// symmetric algorithms regardless of what the signer would accept.
	if !IsAlgorithmAllowed(h.Alg) {
		return Header{}, NewDenial(ReasonAlgNotAllowed)
	}
	if h.Kid == "" {
		return Header{}, NewDenial(ReasonKidMissing)
	}
	sig, err := b64decode(parts[2])
	if err != nil {
		return Header{}, NewDenial(ReasonMalformed)
	}
	if err := check(h, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return Header{}, err
	}
	return h, nil
}

// DecodeClaims extracts the claims from a compact JWS without verifying the
// signature. Callers MUST verify first; this exists so a verifier can read sid
// and exp before deciding whether to fetch a key.
func DecodeClaims(jws string) (Claims, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Claims{}, NewDenial(ReasonMalformed)
	}
	cb, err := b64decode(parts[1])
	if err != nil {
		return Claims{}, NewDenial(ReasonMalformed)
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return Claims{}, NewDenial(ReasonMalformed)
	}
	return c, nil
}

// ValidateClaims checks a decoded claims set against the frozen v1 rules: the
// closed scope enum, uniqueness, non-empty required fields, an https issuer,
// and nbf ≤ exp. It mirrors the parts of the JSON Schema that a plain decode
// does not enforce (enum, uniqueItems, minItems, pattern) and is used both at
// mint time and at verification time.
//
// Verification calls this so a token whose claims violate the schema is denied
// even if its signature is valid — a compromised or buggy issuer must not be
// able to mint a structurally invalid token that a resolver then honours.
func ValidateClaims(c Claims) error { return validateClaims(c) }

// validateClaims mirrors the schema constraints that must hold at mint time.
func validateClaims(c Claims) error {
	if c.Iss == "" || !strings.HasPrefix(c.Iss, "https://") {
		return NewDenial(ReasonMalformed)
	}
	if c.SID == "" {
		return NewDenial(ReasonMalformed)
	}
	if len(c.Scope) == 0 {
		return NewDenial(ReasonMalformed)
	}
	seen := map[string]bool{}
	for _, s := range c.Scope {
		if !IsScopeValid(s) {
			return NewDenial(ReasonMalformed)
		}
		if seen[s] {
			return NewDenial(ReasonMalformed)
		}
		seen[s] = true
	}
	if c.Aud == "" {
		return NewDenial(ReasonMalformed)
	}
	if c.Exp == 0 || c.Nbf == 0 {
		return NewDenial(ReasonMalformed)
	}
	if c.Nbf > c.Exp {
		return NewDenial(ReasonMalformed)
	}
	if c.JTI == "" {
		return NewDenial(ReasonMalformed)
	}
	return nil
}

// ─── Token URIs ─────────────────────────────────────────────────────────────

// URI builds a token URI: safekey://v1/<sid>#<jws>.
//
// The JWS lives in the FRAGMENT, not the query string, so it is never sent to a
// server and never lands in proxy or access logs. The sid is in the path so
// logs and routing can identify the object without parsing or unsealing it.
func URI(sid, jws string) string {
	return fmt.Sprintf("%s://v%s/%s#%s", URIScheme, Version, sid, jws)
}

// ParsedURI is a decomposed token URI.
type ParsedURI struct {
	SID     string
	JWS     string
	Version string
}

// ParseURI decomposes a token URI and enforces the version allowlist. A version
// this build does not implement is refused rather than parsed best-effort — see
// conformance vector unknown-format-version.
func ParseURI(raw string) (ParsedURI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ParsedURI{}, NewDenial(ReasonMalformed)
	}
	if u.Scheme != URIScheme {
		return ParsedURI{}, NewDenial(ReasonMalformed)
	}
	// url.Parse puts "v1/<sid>" in Host when it looks like an authority, or in
	// Opaque/Path depending on the form — handle both.
	rest := strings.TrimPrefix(u.Opaque, "//")
	if rest == "" {
		rest = u.Host + u.Path
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return ParsedURI{}, NewDenial(ReasonMalformed)
	}
	version, sid := strings.TrimPrefix(parts[0], "v"), parts[1]
	if version != Version {
		return ParsedURI{}, NewDenial(ReasonUnsupportedVersion)
	}
	if sid == "" || u.Fragment == "" {
		return ParsedURI{}, NewDenial(ReasonMalformed)
	}
	return ParsedURI{SID: sid, JWS: u.Fragment, Version: version}, nil
}

// VerifyToken performs the full verification sequence against a parsed URI and
// returns the claims.
//
// Order matters and mirrors the contracts in smith-gray/capability-token and
// smith-gray/sidecar-resolution: signature and algorithm first, then time
// bounds, then audience, then sid/path agreement, then scope. No key-store
// interaction may occur before this returns nil — that is enforced by the
// caller performing the unwrap only after VerifyToken succeeds.
func VerifyToken(v Verifier, p ParsedURI, audience string, now time.Time, revoked func(jti string) bool) (Claims, error) {
	// 1. Signature and algorithm (Verify rejects a disallowed alg internally).
	if _, err := v.Verify(p.JWS); err != nil {
		return Claims{}, err
	}

	// 2. Claims.
	c, err := DecodeClaims(p.JWS)
	if err != nil {
		return Claims{}, err
	}
	// Structurally invalid claims are denied even with a valid signature.
	if err := validateClaims(c); err != nil {
		return Claims{}, err
	}

	// 3. Time bounds. Use Unix seconds to match NumericDate semantics.
	nowSec := now.Unix()
	if nowSec >= c.Exp {
		return Claims{}, NewDenial(ReasonExpired)
	}
	if nowSec < c.Nbf {
		return Claims{}, NewDenial(ReasonNotYetValid)
	}

	// 4. Audience — binds authority to one resolver/environment.
	if c.Aud != audience {
		return Claims{}, NewDenial(ReasonAudienceMismatch)
	}

	// 5. sid must equal the URI path id. A mismatch is a confused-deputy
	// attempt: a valid token for object A presented as a handle for object B.
	if c.SID != p.SID {
		return Claims{}, NewDenial(ReasonSIDPathMismatch)
	}

	// 6. Revocation — enforced independently of TTL.
	if revoked != nil && revoked(c.JTI) {
		return Claims{}, NewDenial(ReasonRevoked)
	}

	return c, nil
}

// PublicKeyFromDER parses a PKIX DER public key into a crypto.PublicKey.
func PublicKeyFromDER(der []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(der)
}
