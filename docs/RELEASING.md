# Releasing

The name reservation surface and the release pipeline for Safekeys 0.1.0.
Spec: `.usm/features/deployment/distribution.usm`.

**No agent publishes anything.** Every first publish and every account/org
creation below is a human act, performed by James. The release workflow is
gated on the `release` environment with James as the required reviewer, so
per-release publishing also needs his click.

## The name table

Every reserved name. Status is `real` (the actual artefact), `placeholder`
(defensive, points at the real one), or `hold` (reserved, publishes nothing).

| Registry | Name | Status | Owner account | Who publishes |
|---|---|---|---|---|
| npm | `@smithgray/safekeys-mcp` | real | npm org `smithgray` | release env (James approves) |
| npm | `@smithgray/safekeys-sdk` | real (preview) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli` | real (installer, esbuild pattern) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli-darwin-arm64` | real (binary pkg) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli-darwin-x64` | real (binary pkg) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli-linux-x64` | real (binary pkg) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli-linux-arm64` | real (binary pkg) | npm org `smithgray` | release env |
| npm | `@smithgray/safekeys-cli-win32-x64` | real (binary pkg) | npm org `smithgray` | release env |
| npm | `safekeys-mcp` | placeholder 0.0.1 | James's npm account | James (first), release env after |
| npm | `safekeys-cli` | placeholder 0.0.1 | James's npm account | James (first), release env after |
| npm org | `safekeys` | **hold** — empty org, publish nothing | James creates | — |
| PyPI | `safekeys` | real (the Python SDK) | Trusted Publishing | release env |
| PyPI | `safekeys-mcp` | placeholder 0.0.1 | Trusted Publishing | release env |
| PyPI | `safe-keys` | placeholder 0.0.1 (covers `safe_keys`) | Trusted Publishing | release env |
| Docker Hub | `safekeys/sidecar` | real (mirror) | Docker org `safekeys` | release env |
| Docker Hub | `safekeys/control-plane` | real (mirror) | Docker org `safekeys` | release env |
| GHCR | `ghcr.io/smith-gray-pty-ltd/safekeys-sidecar` | real (canonical) | this repo | release env |
| GHCR | `ghcr.io/smith-gray-pty-ltd/safekeys-control-plane` | real (canonical) | this repo | release env |
| crates.io | `safekeys` | placeholder 0.0.1 | James's crates.io account (GitHub login) | **James, manual** |
| Homebrew | `smith-gray-pty-ltd/tap/safekeys` | planned | `Smith-Gray-Pty-Ltd/homebrew-tap` | release env (once the tap exists) |
| Go | `github.com/Smith-Gray-Pty-Ltd/safekeys` | real module path | this repo | `go install` from a tag |
| GitHub | `github.com/safekeys` | taken by a third party — **do not use or reference** | — | — |
| npm | `safekeys` (unscoped) | taken by a third party (`maxa_mm`) — **never install or depend on it** | — | — |

Docs must always say `npm i @smithgray/...` and `pip install safekeys`.

## James's one-time steps (in order)

1. **npm org hold** — create an empty npm org named `safekeys`
   (https://www.npmjs.com/org/create). Publish **nothing** to it, ever: it
   exists so nobody can impersonate `@safekeys/*`.
2. **npm 2FA** — confirm 2FA is enforced for the `smithgray` org
   (org settings → "Require two-factor authentication"), and that your
   personal account has 2FA with a hardware key or TOTP.
3. **npm trusted publishing** — on npmjs.com, org settings → "Publishing
   permissions" → configure a trusted publisher for
   `Smith-Gray-Pty-Ltd/safekeys` + workflow `release.yml`, environment
   `release`. Repeat per package on first publish (npm asks once per name).
4. **PyPI Trusted Publishers** — on pypi.org, add a **pending publisher** for
   each of `safekeys`, `safekeys-mcp`, `safe-keys` under your account:
   owner `Smith-Gray-Pty-Ltd`, repo `safekeys`, workflow `release.yml`,
   environment `release`. Enable 2FA.
5. **Docker Hub** — create the org `safekeys`; create an **access token
   scoped to push on the safekeys org only**; put it in this repo as
   environment secret `DOCKERHUB_TOKEN` under the `release` environment
   (with `DOCKERHUB_USERNAME` as an environment variable).
6. **crates.io** — log in with GitHub, then from `dist/crates/safekeys`:
   `cargo publish --dry-run && cargo publish`.
7. **GitHub `release` environment** — repo Settings → Environments → create
   `release` → required reviewers: James → add the environment secrets
   (`DOCKERHUB_TOKEN`, `DOCKERHUB_USERNAME`) and environment variables.
   Every publish job targets this environment, so nothing ships without your
   approval.
8. **Homebrew tap** — create the repo `Smith-Gray-Pty-Ltd/homebrew-tap`
   (empty is fine; the release job generates the formula for it).
9. **Optional GitHub org hold** — create org `safekeys-ai` as a defensive
   hold for future naming.
10. **First publishes** — push tag `v0.1.0`. The release workflow runs; when
    it reaches the `release` environment, approve it. npm, PyPI, GHCR and
    Docker Hub artefacts publish with provenance/signatures. crates.io is
    manual (step 6).

## Per-release steps (after the one-time setup)

1. Update `CHANGELOG.md` and bump versions (they must agree across Go
   `main.go`? — no, Go versions are set at link time; npm `package.json`s and
   PyPI `pyproject.toml`).
2. Commit, then tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. Watch the **Release** workflow: `gate` must pass, then approve the
   `release` environment when the publish jobs request it.
4. Verify what shipped (see SECURITY.md "Verify your install"): cosign on the
   images, `npm audit signatures`, sha256 against `SHA256SUMS`.
5. If anything is wrong: the images are re-deployable from the previous
   digest; npm/PyPI artefacts are immutable — yank or deprecate as needed and
   fix forward.

## Dry-run mode

Run the whole pipeline without publishing:
`gh workflow run release.yml -f dry_run=true`. Builds, tests, red-team,
checksums and SBOM all run; nothing is pushed or published. This is how
pipeline changes are tested (test `pipeline-dry-run-green`).

## Where things live in this repo

| Artefact | Path |
|---|---|
| npm MCP server | `packages/mcp-server/` |
| npm TS SDK | `packages/sdk/` |
| npm CLI installer + platform packages | `packages/cli/` |
| PyPI SDK | `packages/sdk-python/` |
| npm placeholders | `dist/npm/safekeys-{mcp,cli}/` |
| PyPI placeholders | `dist/pypi/{safekeys-mcp,safe-keys}/` |
| crates.io placeholder | `dist/crates/safekeys/` |
| Release pipeline | `.github/workflows/release.yml` |
| Official names statement | `SECURITY.md` |

## TODO (not switched now)

- Vanity Go module path `safekeys.ai/go` via a go-import meta tag on the
  marketing site — recorded in `safekeys/site`; do not switch until the site
  is live and serving that path.