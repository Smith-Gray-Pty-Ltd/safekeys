# Safekeys

> **Secrets move. Models don't see.**

Encrypted transport for secrets through environments, agentic flows, and LLM
systems — designed so plaintext is never exposed to any model.

Safekeys treats secrets as **movable encrypted objects** (ciphertext folders)
plus **opaque capability tokens**. A privileged local sidecar resolves them
outside the LLM process. The agent-facing interface is stable as the backend
hardens from software isolation to hardware and threshold cryptography.

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
| Phase 0 | Python SDK, MCP server | Planned |
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

## Tests

```bash
go test ./...                                    # unit + two-agent demo

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
pkg/
  protocol/        Go — frozen v1 token + folder formats, AEAD, zeroisation
  resolve/         Go — the resolution path (verify → unwrap → inject → wipe)
  inject/          Go — env, file, exec injection adapters
  keystore/        Go — Vault/OpenBao Transit + a development-only local store
  revocation/      Go — denylist checks against the control plane
  sidecar/         Go — the Unix socket server and client
  folder/          Go — ciphertext folder source
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
