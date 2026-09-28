# Security Policy

Safekeys is designed so that language models never receive secret values
through Safekeys itself. Agents handle capability tokens only; the sidecar
injects plaintext outside the model and redacts anything it relays back.

## Reporting a vulnerability

Email **james@smith-gray.com**. Please do not open a public issue for a
vulnerability. Include a reproduction; we will acknowledge within 3 business
days and coordinate a fix and disclosure timeline with you.

Please do not report the documented limitations as vulnerabilities — they are
stated openly in the README ("Security guarantees and limits"): exfiltration
by an *allowed* command, rooted hosts, and humans pasting secrets into chats.

## Official package names

Impersonation is a supply-chain risk. The **only** official distribution
channels are:

| Registry | Official name |
|---|---|
| npm | `@smithgray/safekeys-mcp`, `@smithgray/safekeys-sdk`, `@smithgray/safekeys-cli` (+ `@smithgray/safekeys-cli-<platform>`) |
| PyPI | `safekeys` |
| Docker | `safekeys/sidecar`, `safekeys/control-plane` (mirror) and `ghcr.io/smith-gray-pty-ltd/safekeys-*` (canonical) |
| Go | `github.com/Smith-Gray-Pty-Ltd/safekeys` |
| crates.io | `safekeys` (placeholder only, until the Rust client ships) |

**Not official:**

- The unscoped npm package `safekeys` — owned by an unrelated third party.
  Never install or depend on it; documentation must always say
  `npm i @smithgray/...`.
- `github.com/safekeys` — not our repository.

Any other name, org, or registry is not ours. If you find one claiming to be
Safekeys, please report it as a vulnerability.

## Verify your install

Every artefact is verifiable. The commands below fail loudly when the
identity or checksum does not match.

### Container images (GHCR and Docker Hub)

Keyless cosign verification, pinned to this repository's release workflow:

```bash
cosign verify \
  ghcr.io/smith-gray-pty-ltd/safekeys-sidecar@sha256:<digest> \
  --certificate-identity-regexp \
    '^https://github.com/Smith-Gray-Pty-Ltd/safekeys/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For the Docker Hub mirror, substitute the image
`docker.io/safekeys/safekeys-sidecar@sha256:<digest>` — the signature and
identity requirements are identical. The SBOM is attested alongside the
signature; to inspect it:

```bash
cosign verify-attestation --type cyclonedx \
  ghcr.io/smith-gray-pty-ltd/safekeys-sidecar@sha256:<digest> \
  --certificate-identity-regexp \
    '^https://github.com/Smith-Gray-Pty-Ltd/safekeys/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### npm packages (provenance)

Every `@smithgray/*` package is published with npm provenance from GitHub
Actions. Verify with:

```bash
npm audit signatures
```

in any project that installed our packages. It confirms the package was
built by this repository's `release.yml` workflow, not somewhere else.

### Release binaries (sha256)

Every GitHub Release carries `SHA256SUMS`. After downloading:

```bash
# Download SHA256SUMS from the release page, then:
sha256sum --check --ignore-missing SHA256SUMS
```

A mismatch — or a release without a checksum file — means do not run it.

## Package hygiene

- No npm package in this repository declares a postinstall or any lifecycle
  script; the CLI resolves prebuilt binaries shipped inside per-platform npm
  packages (the esbuild pattern), never downloaded at install time.
- Runtime dependencies are minimal in every real package; the placeholders
  (`npm safekeys-mcp`/`safekeys-cli`, PyPI `safekeys-mcp`/`safe-keys`,
  crates.io `safekeys`) contain no code and no dependencies.
- Publishing requires 2FA on the npm `smithgray` org and on the PyPI accounts.
- PyPI publishing uses Trusted Publishing (OIDC) with no stored tokens; npm
  uses provenance (OIDC). The only registry without an OIDC option, Docker
  Hub, uses an access token scoped to push on the `safekeys` org only, held
  in the `release` environment — nowhere else.

## Version status

0.1.0 is an **early preview**. The architecture and the agent-facing token
interface are stable; the packaging surface may still change before 1.0.