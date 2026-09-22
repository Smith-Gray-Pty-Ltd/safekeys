# Capability Token v1

The only secret-bearing artefact an agent reasons about — and it bears no secret.

```
safekey://v1/<sid>#<JWS>
```

| Part | Meaning |
|------|---------|
| `safekey://v1/` | Scheme, format version. A resolver **must** refuse a version it does not implement. |
| `<sid>` | Object identifier. Must match the `sid` claim — a mismatch is denied. |
| `#<JWS>` | RFC 7515 compact JWS. Kept in the fragment so it is not sent to servers or written to proxy logs. |

## Why JWS instead of query-string claims

The technical blueprint sketched `safekey://v1/<id>?scope=…&aud=…&exp=…&kid=…` with a separate `sig` claim. We deliberately deviate, and this is the reasoning.

**The blueprint's form is a bespoke signed-URL scheme.** Nothing in it is defined by a standard: not the canonicalisation of the bytes to be signed, not the parameter ordering or escaping, not how the signature is appended or recovered. Every implementation — the Go sidecar, the Python SDK, a customer's third-party resolver — would have to reproduce our rules byte-for-byte. A subtle mismatch in one language is a silent authorisation bypass.

**JWS moves that risk into reviewed libraries.** Signature, canonicalisation, and verification are standardised and implemented everywhere. We stop owning crypto-critical parsing.

The decisive point for this product: **standardisation is what makes government-grade assurance reachable, not what dilutes it.**

| Requirement | JWS | Bespoke query-string |
|---|---|---|
| FIPS 140-3 validated crypto module | ✅ EdDSA / ES256 available in validated modules | ❌ no such thing exists for a private format |
| Independent audit | "does it conform to RFC 7515 and reject `alg: none`?" — quick | must audit novel canonicalisation — slow, uncertain |
| Third-party interop (resolver, HSM, partner runtime) | ✅ day one | ❌ reimplement our rules |
| Longevity past the team | ✅ | ❌ usually dies with its authors |

The semantics the blueprint specified — `sid`, `scope`, `aud`, `exp`, `nbf`, `jti` — are preserved exactly. We changed only *how the bytes are signed*.

## Header rules (enforced by the verifier, not the schema)

A verifier **must**:

- Accept **only** `alg` ∈ `{EdDSA, ES256}`.
- **Reject** `alg: none` — the classic JWT attack.
- **Reject** all symmetric algorithms (`HS256`, `HS384`, `HS512`, …). Accepting these lets a verifier be tricked into treating a published verification key as a shared secret.
- Require `kid` and resolve it to a known verification key.
- Reject any `kid` it does not know, rather than falling back to a default key.

`EdDSA` is the modern default. `ES256` is permitted for FIPS-oriented deployments. The allowlist is closed: adding an algorithm is a new major format version.

## Claims

| Claim | Required | Notes |
|-------|----------|-------|
| `iss` | yes | Issuer control plane. Must be `https`. |
| `sub` | no | Principal the token was issued to. Recommended for attribution. |
| `sid` | yes | Object id. Must equal the `<sid>` in the URI path. |
| `scope` | yes | Non-empty subset of `read`, `unwrap`, `inject-env`, `inject-file`, `sign`. |
| `aud` | yes | Resolver identity / environment. Binds the token to one place. |
| `exp` | yes | NumericDate. TTL is minutes to hours, never days. |
| `nbf` | yes | NumericDate. Must be ≤ `exp`. |
| `jti` | yes | Unique id, recorded at mint, checked against the denylist on every resolve. |

## Key custody

`kid` resolves to a verification key. In the MVP both signing and verification keys are held by the control plane and distributed to sidecars. In Phase 1 the signing key **must** be HSM- or secure-element-backed and never a bare file. The token format does not change when that happens — only where the key lives.

## Conformance

[`v1.schema.json`](v1.schema.json) validates the decoded claims set.
[`v1.vectors.json`](v1.vectors.json) holds 15 claims vectors and 6 header vectors.

```bash
python3 -c "
import json, jsonschema
V = jsonschema.Draft202012Validator(json.load(open('v1.schema.json')))
vec = json.load(open('v1.vectors.json'))
for v in vec['vectors']:
    got = 'valid' if not list(V.iter_errors(v['input'])) else 'invalid'
    assert got == v['expect']['schema'], v['id']
print('all claims vectors pass')"
```

Note the two negative vectors that carry a `value` and a `dek` field: because the schema sets `additionalProperties: false`, both **must** fail validation. If either ever validates, the format has been broken and no token can be trusted.
