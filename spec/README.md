# Safekeys Protocol Specifications

Frozen wire-format artefacts for the open Safekeys protocol. These are the
contracts that independent implementations (Go sidecar, control plane, Python and
TypeScript SDKs, third-party resolvers) must agree on byte-for-byte.

Specification text lives in [`.usm/`](../.usm); this directory holds the
**machine-checkable** artefacts — JSON Schemas and conformance vectors.

| Format | Schema | Vectors | Governed by |
|--------|--------|---------|-------------|
| Capability token v1 | [`capability-token/v1.schema.json`](capability-token/v1.schema.json) | [`capability-token/v1.vectors.json`](capability-token/v1.vectors.json) | `smith-gray/capability-token` |
| Encrypted folder manifest v1 | [`encrypted-folder/v1.schema.json`](encrypted-folder/v1.schema.json) | [`encrypted-folder/v1.vectors.json`](encrypted-folder/v1.vectors.json) | `smith-gray/encrypted-folder` |

## Versioning

Each format is versioned independently and immutably. A `v1` artefact, once
published, is never modified in a breaking way — additive changes only, and only
where the schema already permits them.

Version identifiers appear in the wire format itself:

- A token URI path is `safekey://v1/…`.
- A folder manifest carries `"safekeys": "1"`.

A resolver **must** reject a version it does not implement rather than attempting
best-effort parsing.

## The one invariant

Both formats exist so that **no secret material can appear in either**. This is
enforced structurally:

- Both schemas set `additionalProperties: false`, so a field cannot be smuggled
  in.
- Neither schema has any field capable of holding plaintext, an unwrapped data
  key (DEK), or a key-encryption key (KEK).
- Conformance vectors include explicit negative cases asserting that a token
  containing a secret, and a manifest containing a wrapped key, are rejected.

If a proposed change requires adding a field that can carry key material, it is
not a `v1` change — it is a new major version with a new threat-model review.

## Conformance

Vectors are language-neutral JSON. Each vector has an `id`, an `input`, and an
`expect` object. Implementations should run them as a table-driven test.

```jsonc
{
  "id": "expired-token-rejected",
  "input": { /* the artefact under test */ },
  "expect": {
    "schema": "invalid",      // "valid" | "invalid"
    "resolve": "denied",      // "allowed" | "denied" | "n/a"
    "reason": "exp"           // short machine-readable reason, or null
  }
}
```

`expect.schema` is a pure JSON Schema validation result and can be checked with
any validator. `expect.resolve` is a **semantic** result — TTL bounds, audience
matching, revocation — and requires an implementation. Both are recorded in the
vector so a partial implementation cannot silently pass.

## Relationship to the blueprint

These artefacts implement the "Protocols and data formats" section of the
Safekeys Technical Blueprint (2026-09-22), with one deliberate deviation: the
token is carried as a signed JWS rather than as query-string claims. The rationale
is recorded as an ADR in
[`.usm/features/protocol/capability-token.usm`](../.usm/features/protocol/capability-token.usm)
and summarised in [`capability-token/README.md`](capability-token/README.md).
