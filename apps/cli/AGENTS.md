<!-- USM:START -->
# Safekeys CLI

> Auto-generated from `.usm/services/cli.usm`. Hand-edit sections below; they'll be preserved on regeneration.

## Project Overview

Safekeys CLI — the operator and agent-facing command line (safekeys create, exec, revoke, list). It talks to the local sidecar over the Unix socket and to the control plane for token lifecycle, never handling plaintext except on the create path where it writes directly to the sidecar.


## Tech Stack

| Layer | Technology |
|-------|-----------|
| Type | api |
| Framework | go |

## Commands

```bash
# Development
cd apps/cli && npm run dev
cd apps/cli && npm run build
cd apps/cli && npm start
# Validation
cd apps/cli && npm run lint
cd apps/cli && npm run typecheck
```

## Directory Structure

- `apps/cli` — source code
- `apps/cli/.usm/` — USM source files

## Key Rules

- **exec-is-primary-injection**: The exec wrapper is the preferred injection mechanism over returning values on stdout. (accepted)
- **Auth**: Local sidecar socket plus control-plane API key
- **Secrets**: docs/help/security-model.md
- **Never commit without passing lint AND typecheck**
- **Read this file and project docs before writing any code**

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SAFEKEYS_SOCKET` | /run/safekeys/sidecar.sock | Yes |
| `CONTROL_PLANE_URL` | http://localhost:8080 | Yes |

## Architecture

See [Architecture Overview](docs/architecture/overview.md) for system context.

## Conventions

- Read this file and project docs before writing any code
- Follow patterns in shared packages (`packages/`)
- Use lint and typecheck commands before committing

<!-- USM:END -->




