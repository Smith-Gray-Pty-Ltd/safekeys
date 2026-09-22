<!-- USM:START -->
# Sidecar / Resolver

> Auto-generated from `.usm/services/sidecar.usm`. Hand-edit sections below; they'll be preserved on regeneration.

## Project Overview

Sidecar / Resolver — the only component permitted to resolve a capability token. It validates tokens, requests data-key unwrap from the key store, injects plaintext into a non-LLM consumer, and zeroises. Written in Go, it runs as a separate user from agents with seccomp/AppArmor confinement and no shared memory.


## Tech Stack

| Layer | Technology |
|-------|-----------|
| Type | worker |
| Framework | go |

## Commands

```bash
# Development
cd apps/sidecar && npm run dev
cd apps/sidecar && npm run build
cd apps/sidecar && npm start
# Validation
cd apps/sidecar && npm run lint
cd apps/sidecar && npm run typecheck
```

## Directory Structure

- `apps/sidecar` — source code
- `apps/sidecar/.usm/` — USM source files

## Key Rules

- **go-sidecar**: Implement the sidecar in Go rather than Rust. (accepted)
- **separate-os-user**: The sidecar runs as a different OS user from any agent process, with no shared memory. (accepted)
- **deny-by-default**: If the key store or control plane is unreachable, resolution fails closed. (accepted)
- **Auth**: Local authenticated channel; control-plane API key; device identity via mTLS later
- **Secrets**: docs/help/security-model.md
- **Never commit without passing lint AND typecheck**
- **Read this file and project docs before writing any code**

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SAFEKEYS_SOCKET` | /run/safekeys/sidecar.sock | Yes |
| `CONTROL_PLANE_URL` | http://localhost:8080 | Yes |
| `CONTROL_PLANE_API_KEY` | dev-only-api-key | Yes |

## Architecture

See [Architecture Overview](docs/architecture/overview.md) for system context.

## Conventions

- Read this file and project docs before writing any code
- Follow patterns in shared packages (`packages/`)
- Use lint and typecheck commands before committing

<!-- USM:END -->




