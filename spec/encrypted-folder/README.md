# Encrypted Folder v1

The transport unit. An ordinary directory (or object prefix) that can be copied,
synced, committed, or handed between agents — with no cryptographic exposure from
the copying.

```
my-secret/
├── objects/
│   ├── obj_7f3a91c2.enc        # AEAD ciphertext blobs
│   └── obj_cert.enc
├── manifest.json               # metadata only — see v1.schema.json
└── README.safekeys             # secret-free, model-readable
```

## Why an ordinary directory

No container format, no custom tooling. Any filesystem, object store, or artefact
system carries it unchanged, and `git`, `tar`, `rsync`, and `diff` all work as-is.
The security comes from the *contents being ciphertext*, not from the container.
A folder is **inert**: holding it grants nothing.

Resolution requires all three of:

1. a valid, unexpired, in-audience, unrevoked token,
2. a running sidecar on the same host,
3. a reachable key authority holding the KEK.

Remove any one and the folder yields nothing. That is the property conformance
vector `inert-without-token`, `inert-without-sidecar`, and
`inert-without-keystore` assert.

## What may appear in a manifest

Metadata only. Permitted per object:

| Field | Notes |
|-------|-------|
| `id` | Referenced by a token's `sid`. |
| `path` | Must be `objects/*.enc` — never an unencrypted file. |
| `alg` | `AES-256-GCM` (FIPS-oriented) or `ChaCha20-Poly1305` (fast in software). |
| `wrapped_key` | **Envelope-wrapped** DEK. Useless without the KEK. |
| `wrapping_kid` | Which KEK wrapped it — enables rotation and multi-authority resolution. |
| `content_type` | Hint only; never used to decide whether to decrypt. |
| `hash` | Optional ciphertext integrity hash for sync/dedup. |
| `size` | Optional transport hint. |
| `token_references` | `safekey://` handles for discovery — **references, not authority**. |

## What may never appear

- **Plaintext.** Enforced structurally: `additionalProperties: false`.
- **An unwrapped DEK.** Only `wrapped_key` is permitted. An implementation that
  finds an unwrapped DEK in a manifest **must** refuse to proceed and **must** log
  a security event — this would indicate a compromised writer.
- **A KEK.** Long-term key material lives in the key store or a secure element and
  never travels in a folder.

Two conformance vectors (`plaintext-in-manifest`, `unwrapped-dek-in-manifest`,
`kek-in-manifest`) assert these fail validation. If they ever pass, the format is
broken.

## README.safekeys

Every folder carries a README written for both humans and models, containing no
secrets. Agents will encounter folders; a clear explanation stops one from trying
to extract values and keeps the folder self-describing across a handoff. Its
presence is required by the implementation even though it is not a manifest field.

## Conformance

[`v1.schema.json`](v1.schema.json) validates `manifest.json`.
[`v1.vectors.json`](v1.vectors.json) holds 13 manifest vectors and 4 semantic
folder vectors.

```bash
python3 -c "
import json, jsonschema
V = jsonschema.Draft202012Validator(json.load(open('v1.schema.json')))
vec = json.load(open('v1.vectors.json'))
for v in vec['vectors']:
    got = 'valid' if not list(V.iter_errors(v['input'])) else 'invalid'
    assert got == v['expect']['schema'], v['id']
print('all manifest vectors pass')"
```

The `folder_vectors` array covers results that need an implementation: no token,
unreachable key store, no sidecar, and a full read of a copied folder.

## Versioning

`safekeys` is `const: "1"`. A resolver **must** refuse a version it does not
implement rather than attempting best-effort parsing — vector
`unknown-format-version`. Additive changes only within `v1`; anything requiring a
new key-bearing field is a new major version with a fresh threat-model review.
