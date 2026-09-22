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

**Pre-alpha.** The MVP is software-only and already meets the product promise:
models never see secrets. Hardware, threshold crypto, and post-quantum ratchets
land later without changing the agent-facing API.

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 0** | Software sidecar, control plane, folder format, CLI, Python SDK | Planned |
| **Phase 1** | Hardware root of trust (TPM 2.0, enclave, USB token, secure element) | Planned |
| **Phase 2** | Threshold key splitting + hybrid post-quantum ratchet | Planned |
| **Phase 3** | Certified tokens, PUF binding, formally verified critical path | Planned |

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

**MVP components**

| Component | Directory | Language |
|-----------|-----------|----------|
| Sidecar / Resolver | `apps/sidecar` | Go |
| Control Plane API | `apps/control-plane` | Go |
| Safekeys CLI | `apps/cli` | Go |
| Safekeys.ai Site | `apps/safekeys` | Next.js |
| MCP Server | `packages/mcp-server` | TypeScript |
| Python SDK | `packages/sdk-python` | Python |
| TypeScript SDK | `packages/sdk-typescript` | TypeScript |

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
