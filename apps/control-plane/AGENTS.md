<!-- USM:START -->
# Control Plane API

> Auto-generated from `.usm/services/control-plane.usm`. Hand-edit sections below; they'll be preserved on regeneration.

## Project Overview

Control Plane API — issues and revokes capability tokens, manages policy, and exposes the audit log. It never receives plaintext secrets. Built in Go on Postgres, authenticating sidecars and CLIs via API key in the MVP and mTLS later.


## Tech Stack

| Layer | Technology |
|-------|-----------|
| Type | api |
| Framework | go |
| Port | 8080 |

## Commands

```bash
# Development
cd apps/control-plane && npm run dev
cd apps/control-plane && npm run build
cd apps/control-plane && npm start
# Validation
cd apps/control-plane && npm run lint
cd apps/control-plane && npm run typecheck
```

## Directory Structure

- `apps/control-plane` — source code
- `apps/control-plane/.usm/` — USM source files

## Key Rules

- **go-and-postgres**: Implement the control plane in Go backed by Postgres. (accepted)
- **no-plaintext-at-control-plane**: The control plane must never accept or store plaintext secret material. (accepted)
- **Auth**: API key (MVP), mutual TLS for sidecars (later)
- **Secrets**: docs/help/control-plane-auth.md
- **Never commit without passing lint AND typecheck**
- **Read this file and project docs before writing any code**

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | postgres://localhost:5432/safekeys | Yes |
| `KEYSTORE_ADDR` | http://localhost:8200 | Yes |
| `KEYSTORE_TOKEN` | dev-only-token | Yes |
| `CONTROL_PLANE_API_KEY` | dev-only-api-key | Yes |

## Architecture

See [Architecture Overview](docs/architecture/overview.md) for system context.

## Conventions

- Read this file and project docs before writing any code
- Follow patterns in shared packages (`packages/`)
- Use lint and typecheck commands before committing

<!-- USM:END -->




