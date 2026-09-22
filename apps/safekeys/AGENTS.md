<!-- USM:START -->
# Safekeys.ai Site

> Auto-generated from `.usm/services/safekeys.usm`. Hand-edit sections below; they'll be preserved on regeneration.

## Project Overview

Safekeys.ai Site — the public marketing and documentation presence at safekeys.ai, explaining the encrypted transport model, the open protocol, and the "Secrets move. Models don't see." positioning. It is the adoption front door for the open core.


## Tech Stack

| Layer | Technology |
|-------|-----------|
| Type | web-app |
| Framework | nextjs |
| Port | 3000 |

## Commands

```bash
# Development
cd apps/safekeys && npm run dev
cd apps/safekeys && npm run build
cd apps/safekeys && npm start
# Validation
cd apps/safekeys && npm run lint
cd apps/safekeys && npm run typecheck
```

## Directory Structure

- `apps/safekeys` — source code
- `apps/safekeys/.usm/` — USM source files

## Key Rules

- **open-protocol-wedge**: Position the site around the open protocol as the adoption wedge, with hardware and hosted authority as the commercial layer. (accepted)
- **Auth**: none (public marketing site)
- **Never commit without passing lint AND typecheck**
- **Read this file and project docs before writing any code**

## Architecture

See [Architecture Overview](docs/architecture/overview.md) for system context.

## Conventions

- Read this file and project docs before writing any code
- Follow patterns in shared packages (`packages/`)
- Use lint and typecheck commands before committing

<!-- USM:END -->




