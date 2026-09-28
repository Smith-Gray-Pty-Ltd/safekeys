# Safekeys

> **Secrets move. Models don't see.**

Safekeys is designed so that language models never receive secret values
through Safekeys itself. Agents handle capability tokens only; the sidecar
injects plaintext outside the model and redacts anything it relays back.

Encrypted transport for secrets through environments, agentic flows, and LLM
systems. Safekeys treats secrets as **movable encrypted objects** (ciphertext
folders) plus **opaque capability tokens**. A privileged local sidecar resolves
them outside the LLM process. The agent-facing interface is stable as the
backend hardens from software isolation to hardware and threshold cryptography.

## Security guarantees and limits

Safekeys guarantees that language models never receive secret values through
Safekeys itself.

**Guarantees**

- Agents see only capability tokens, folder paths, and status. Tokens contain
  zero secret material and are short-lived, scoped, and audience-bound.
- Plaintext exists only inside the sidecar's injection path, for the consuming
  process, and is zeroised immediately after use.
- Output relayed through the sidecar's API is redacted: the resolved value
  cannot be read back out of command stdout/stderr in raw, base64, base64url,
  hex, percent-encoded, or JSON-escaped form — including partial echoes of 8+
  characters and values split across output boundaries. Matches are replaced
  with `[REDACTED:safekeys]`.
- Secret values never travel on a command line; injection is environment-variable
  or 0600-file only.
- Default development storage keeps key material — the key-encryption key and
  the token signing seed — out of plaintext files the agent's OS user can read
  (macOS Keychain, or a containerised OpenBao on Linux). A plaintext dev key
  file exists only behind an explicit opt-in that refuses loose file
  permissions. The Keychain is a storage improvement, not an access boundary;
  for a same-host access boundary, run the sidecar as a dedicated user
  (`scripts/separate-user-mode.sh`).
- Policy is deny by default and can bind which commands a token may run;
  MCP-initiated resolves require a command allowlist outright, and known
  secret-dumping commands are refused for CLI and SDK resolves when no
  allowlist exists.
- Every resolve, denial, and redaction is appended to an audit log containing
  identifiers and outcomes only — stealing the whole log yields no secrets.

**Limits**

- Redaction covers the relay channel only. An allowed command can still
  exfiltrate data over the network under its own protocols, or write the
  secret to a file the agent can later read; neither passes back through the
  relay. Use tight command allowlists for high-value secrets.
- A rooted host can observe anything its processes can, including the sidecar.
  Phase 1 moves long-term key custody into hardware; plaintext materialised
  for a running consumer is observable to root regardless of phase.
- A human who pastes a secret into a chat has defeated the purpose; no tool
  can detect that.

## The Problem

Agentic systems now create, route, and consume credentials across machines,
clouds, and multi-agent protocols. Today those secrets typically land in
environment variables, config files, tool-call arguments, or model context.

Once an LLM has seen a value, that session — and often the logs, traces, and
memory around it — is compromised.

## The Model

| Object | What it is | Who sees it |
|--------|-----------|-------------|
| **Capability token** | A short-lived, scoped, audience-bound handle containing **zero** secret material | Agents, prompts, memory, tool calls |
| **Encrypted folder** | Ciphertext blobs + a manifest + a secret-free README | Anywhere — git, object stores, agent handoffs |
| **Sidecar / Resolver** | The only component permitted to resolve a token | A separate OS user, isolated from agents |

Agents may **define, create, transport, and request use of** secrets. They never
receive plaintext or long-term keys.

### Core principles

- **The LLM is never on the decryption path.** No model holds, receives, or can derive plaintext secret material or long-term keys.
- **Agents see only opaque capability tokens.** The only secret-bearing artefact an agent reasons about contains nothing sensitive.
- **The agent-facing interface is stable.** Tokens plus folders stay constant as the backend hardens.
- **Plaintext is materialised only for the consumer, then zeroised.** It exists transiently inside the sidecar's injection path and nowhere else.
- **Open protocol, commercial authority.** The protocol, sidecar, CLI, and core SDKs are open; the hosted authority, hardware, and enterprise controls are commercial.

## Status

**Pre-alpha, but running.** The Phase 0 software MVP is implemented and tested
end to end: a capability token, an encrypted folder, a privileged sidecar that
resolves it, a control plane that issues, revokes and audits, a CLI, and the
two-agent demo asserting no transcript contains plaintext.

Hardware, threshold crypto, and post-quantum ratchets land later without
changing the agent-facing API.

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 0** | Software sidecar, control plane, folder format, CLI | **Implemented** |
| **Phase 0** | MCP server, Python SDK | **Implemented** |
| **Phase 1** | Hardware root of trust (TPM 2.0, enclave, USB token, secure element) | Planned |
| **Phase 2** | Threshold key splitting + hybrid post-quantum ratchet | Planned |
| **Phase 3** | Certified tokens, PUF binding, formally verified critical path | Planned |

## Quick start

Requires Go 1.24+ and Docker.

```bash
# 1. Start Postgres + OpenBao (the key store)
docker compose up -d

# 2. Generate a development signing key (production uses an HSM — see ADR key-custody-hsm)
export SAFEKEYS_DEV_SIGNING_KEY=$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1        # development-only local KEK

# 3. Build
go build -o bin/safekeys        ./apps/cli/cmd/safekeys
go build -o bin/safekeys-cp     ./apps/control-plane/cmd/server
go build -o bin/safekeys-sidecar ./apps/sidecar/cmd/sidecar

# 4. Run the control plane and the sidecar
DATABASE_URL='postgres://safekeys:safekeys-dev-password@localhost:5432/safekeys?sslmode=disable' \
  SAFEKEYS_API_KEY=dev-key ./bin/safekeys-cp &
./bin/safekeys-sidecar &

# 5. Create a secret — the value goes via stdin, never argv
echo -n 'sk-live-abc123' | ./bin/safekeys create --object obj_demo

# 6. Use it. The command sees the value; you receive an exit code.
./bin/safekeys exec --token 'safekey://v1/obj_demo#…' -- /bin/sh -c 'test -n "$SAFEKEYS_SECRET"'
```

The full walkthrough, including the revoke → denied lifecycle, is in
[`docs/quickstart.md`](docs/quickstart.md).

## Deploying to a real host

`make dev` is the development stack. It runs OpenBao in dev mode and keeps the
KEK in a local file — fine on a laptop, not acceptable on a host holding real
secrets. Deployment is a separate, hardened path in [`deploy/`](deploy/):

```bash
make images            # build the production container images
make deploy-check      # validate the production Compose file
make verify-hardening  # prove the systemd confinement still permits the workload
```

The reference topology is **systemd on the host**, because the sidecar's job is
to inject a secret into a consumer process it spawns itself — a containerised
sidecar cannot reach a host process. `deploy/` ships:

| Artefact | Purpose |
|----------|---------|
| `Dockerfile.control-plane`, `Dockerfile.sidecar` | Static, non-root, shell-free images (~17–22MB) |
| `deploy/systemd/` | Units carrying the OS isolation (seccomp filter, Protect\*, no capabilities) |
| `deploy/openbao/openbao.hcl` | Persistent, TLS, sealed-at-rest key store — never `-dev` |
| `deploy/apparmor/` | Optional mandatory-access-control profile for the sidecar |
| `deploy/compose.prod.yml` | Production Compose, with digest-pinned images |

Two safeguards make the hardened path hard to get wrong:

- **The production profile refuses every development shortcut.** Set
  `SAFEKEYS_PROFILE=production` and the binaries refuse an env-var signing seed,
  a dev key-store token, the insecure local keystore, and offline revocation —
  before they contact anything.
- **No credential goes through the environment.** Every secret is mounted as a
  file (`*_FILE` variables), so values never appear in `/proc/<pid>/environ`,
  `docker inspect`, or the environment of the consumer processes the sidecar
  spawns. The credential loader refuses a world-readable file outright.

Full operator instructions, in provisioning order, are in
[`deploy/README.md`](deploy/README.md).

## Testing it in opencode

Safekeys ships an MCP server, so opencode (or Claude, Cursor, Codex, Gemini) can
create and use secrets without ever seeing a value.

```bash
make build          # Go binaries
make dev            # Postgres + OpenBao + control plane + sidecar (background)
```

Then the project already has it wired in `opencode.json`:

```jsonc
{
  "mcp": {
    "safekeys": {
      "type": "local",
      "command": ["node", "packages/mcp-server/dist/index.js"],
      "enabled": true
    }
  }
}
```

Verify opencode sees it:

```bash
opencode mcp list        # → ✓ safekeys connected
```

Then in an opencode session:

> Write a secret to /tmp/api-key.txt, then use `safekeys` create_secret on it,
> and use resolve_for_tool to run `gh api /user` with it.

The model gets a token and a path. It never gets the value — there is no
parameter on `create_secret` that could carry one.

**No environment configuration is needed.** The Go, TypeScript and Python
clients all default to the same socket path (`$TMPDIR/safekeys/sidecar.sock`),
which is where `make dev` puts it.

```bash
make demo           # end-to-end: create → use → revoke, asserting no leak
make mcp-smoke      # drive the MCP server against the live stack
```

## MCP server — use Safekeys from any agent runtime

One MCP server covers Claude, Cursor, Codex, Gemini, and anything else that
speaks MCP. No per-vendor SDK.

```bash
cd packages/mcp-server && npm install && npm run build
```

Register it with your runtime (the shape is the same everywhere):

```jsonc
{
  "mcpServers": {
    "safekeys": {
      "command": "node",
      "args": ["/path/to/safekeys/packages/mcp-server/dist/index.js"],
      "env": { "SAFEKEYS_SOCKET": "/run/safekeys/sidecar.sock" }
    }
  }
}
```

Four tools, all token-only:

| Tool | Takes | Returns |
|------|-------|---------|
| `create_secret` | a **file path** containing the secret | a capability token + folder path |
| `resolve_for_tool` | a token + a command | the command's output and exit status |
| `list_objects` | — | object metadata |
| `revoke_token` | a `jti` | confirmation |

**`create_secret` has no value parameter.** The sidecar reads the file itself, so
a model cannot pass a secret even if a prompt injection tells it to. That is a
structural guarantee, not a behavioural rule.

**The MCP server holds no control-plane credential and no keys.** It runs inside
the agent's process space, so `list` and `revoke` are proxied through the sidecar
— otherwise a compromised agent would inherit admin authority just by hosting the
server.

```bash
# Smoke test the full flow against a running control plane + sidecar
cd packages/mcp-server && node scripts/mcp-smoke.mjs
```

## Tests

```bash
go test ./...                                    # unit + two-agent demo
(cd packages/mcp-server && npm test)             # MCP tool contracts

# against real infrastructure
SAFEKEYS_TEST_DATABASE_URL='postgres://safekeys:safekeys-dev-password@localhost:5432/safekeys?sslmode=disable' \
  go test -tags integration ./apps/control-plane/internal/inttest/
SAFEKEYS_TEST_VAULT_ADDR=http://localhost:8200 SAFEKEYS_TEST_VAULT_TOKEN=root \
  go test ./pkg/keystore/ -run TestVault
```

## Repository layout

```
apps/
  control-plane/   Go — authority: objects, tokens, policy, audit, Postgres
  sidecar/         Go — the only component permitted to resolve a token
  cli/             Go — create, exec, revoke, list, audit
  safekeys/        Next.js — safekeys.ai (not yet built)
packages/
  mcp-server/      TypeScript — one MCP server for every agent runtime
pkg/
  protocol/        Go — frozen v1 token + folder formats, AEAD, zeroisation
  resolve/         Go — the resolution path (verify → unwrap → inject → wipe)
  inject/          Go — env, file, exec injection adapters
  created/         Go — the secret-creation path (plaintext never leaves it)
  keystore/        Go — Vault/OpenBao Transit + a development-only local store
  credential/      Go — file-first credential loading (*_FILE), env fallback
  profile/         Go — the production profile that refuses dev-only settings
  revocation/      Go — denylist checks against the control plane
  sidecar/         Go — the Unix socket server and client
  folder/          Go — ciphertext folder source
  cpclient/        Go — control-plane HTTP client (used by the sidecar only)
deploy/            Hardened production packaging: units, Compose, OpenBao, AppArmor
spec/              Frozen JSON Schemas + language-neutral conformance vectors
test/e2e/          The two-agent demo
```

## Architecture

```
   ┌──────────────┐  token only   ┌──────────────────────────────────┐
   │  LLM / Agent │ ────────────► │  Sidecar / Resolver              │
   │   process    │               │  verify → unwrap → inject → wipe │
   └──────────────┘               └────────────┬─────────────────────┘
          │ tokens, paths,                    │ unwrap request
          │ ciphertext, status                ▼
          │                          ┌──────────────────┐
          │                          │  Key Store       │
          │                          │  (OpenBao/Vault) │
          │                          └──────────────────┘
          │                          ┌──────────────────┐
          └────────────────────────► │  Control Plane   │
                                     │  issue / revoke  │
                                     │  policy / audit  │
                                     └──────────────────┘
```

## Documentation

This repository is **spec-first**. The `.usm/` directory is the source of truth:
a structured system map of services, features, flows, contracts, and decisions,
validated against a JSON Schema and consumed by both humans and AI agents.

- [`AGENTS.md`](AGENTS.md) — agent workflow and conventions
- [`.usm/system.usm`](.usm/system.usm) — system identity, principles, threat model
- [`.usm/features/`](.usm/features) — feature specs with contracts and tests

Read the specs **before** the code. Code and specs are not allowed to drift.

```bash
usm docs serve --watch     # render the system map locally
usm generate --check       # verify generated docs are up to date
usm query "features where status = planned"
```

## Contributing

The core protocol and reference implementation are open source (Apache-2.0) so
they can be audited and adopted broadly. Please open an issue before starting
significant work — specs are drafted and reviewed before implementation.

## License

[Apache-2.0](LICENSE) © 2026 Smith & Gray Pty Ltd
