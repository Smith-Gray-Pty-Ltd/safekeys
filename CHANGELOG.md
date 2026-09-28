# Changelog

All notable changes to Safekeys. Versions follow semver; 0.x is early preview
and the API surface may change.

## [0.1.0] — 2026-09-28

First preview release. The agent-facing interface is stable; packaging is new.

### Output control (`safekeys/output-control`) — closes the relay leak

The first release's core claim — *models never see secret values* — now holds
against the channel it was weakest on: command output relayed back to the
model.

- **Output redaction in the sidecar**: anything the sidecar relays is scanned
  for the resolved value — and substrings of 8+ characters — in raw, base64,
  base64url, hex, percent-encoded, and JSON-escaped form, including values
  split across output boundaries; matches become `[REDACTED:safekeys]`.
- **Status-only by default**: `resolve_for_tool` returns the exit code plus
  redacted output capped at 4 KiB; uncapped output requires an explicit
  policy allowance and is still redacted.
- **Command policy**: policy rules can bind allowed commands (executable
  path + argument globs) per object and scope. **MCP-initiated resolves are
  denied unless an allowlist exists**; CLI and SDK resolves fall back to a
  documented backstop denylist (env, printenv, cat, base64, xxd, strings,
  inline-code interpreters, and more) that is documented as a backstop, not
  the control.
- **Secrets never travel on argv** (env or 0600 temp file only), asserted by
  tests.
- A red-team script (`scripts/redteam-mcp.sh`, in CI on every PR) drives the
  known leak corpus through a real MCP connection and proves none return the
  secret; it found and fixed a folded-base64 redaction bug and a glob
  semantics bug on the way.

### Dev key custody (`safekeys/dev-key-custody`) — closes the dev-KEK gap

- The default dev flow leaves **no plaintext key material** the agent's OS
  user can read: the KEK lives in the macOS Keychain or the containerised
  OpenBao dev instance on Linux; the token signing seed follows the same
  ladder. Plaintext files exist only behind
  `SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1` with a loud warning and a permission
  check (group/world-readable files refuse to start).
- `dev-up.sh` refuses to start on stale plaintext key files and prints the
  one-line migration command (`scripts/migrate-dev-keys.sh`, which re-wraps
  objects and securely deletes the files).
- A documented separate-user local mode runs the sidecar as a dedicated OS
  user with **peer-credential checks on the socket** — the strong same-host
  boundary (the Keychain is a storage improvement, not an access boundary;
  measured and documented).
- The sidecar is honest about what remains: an allowed command can
  exfiltrate over the network or write a file the agent can read; redaction
  covers the relay only. See the README's *Security guarantees and limits*.

### Distribution (`safekeys/distribution`)

- Official packages: npm `@smithgray/safekeys-mcp`, `@smithgray/safekeys-sdk`
  (TypeScript, preview), `@smithgray/safekeys-cli` (esbuild-pattern installer
  with per-platform binary packages), PyPI `safekeys`, Docker
  `safekeys/sidecar` + `safekeys/control-plane` (GHCR canonical), crates.io
  `safekeys` placeholder.
- Gated release pipeline: build + tests + red-team before any publish; every
  publish job behind the `release` environment (required reviewer); npm
  provenance, PyPI Trusted Publishing, cosign-signed multi-arch images with
  SBOM attestations, sha256 checksums on release binaries.
- Defensive placeholders reserve the unscoped names (npm `safekeys-mcp`,
  `safekeys-cli`; PyPI `safekeys-mcp`, `safe-keys`; crates.io `safekeys`).
  The npm package `safekeys` is owned by an unrelated third party — never
  install it.

### Earlier

MVP architecture: capability tokens + ciphertext folders + sidecar-only
resolution, MCP server, Python/TypeScript token-only SDKs, control plane
(policy, audit), hardened deployment packaging. See `.usm/` for the specs.

[0.1.0]: https://github.com/Smith-Gray-Pty-Ltd/safekeys/releases/tag/v0.1.0