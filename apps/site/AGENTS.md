<!-- USM:START -->
# Safekeys.ai Site

> Auto-generated from `.usm/services/site.usm`. Hand-edit sections below; they'll be preserved on regeneration.

## Project Overview

Safekeys.ai Site — the public marketing and documentation presence at safekeys.ai, explaining the encrypted transport model, the open protocol, and the "Secrets move. Models don't see." positioning. It is the adoption front door for the open core.

TODO (post-0.1.0, vanity Go module path): serve a go-import meta tag at
safekeys.ai/go so Go installs can read `go install safekeys.ai/go/cmd/safekeys`.
Do NOT switch the module path until the site is live and serving that path;
the module remains github.com/Smith-Gray-Pty-Ltd/safekeys for 0.1.0.


## Tech Stack

| Layer | Technology |
|-------|-----------|
| Type | web-app |
| Framework | nextjs |
| Port | 3000 |

## Commands

```bash
# Development
cd apps/site && npm run dev
cd apps/site && npm run build
cd apps/site && npm start
# Validation
cd apps/site && npm run lint
cd apps/site && npm run typecheck
```

## Directory Structure

- `apps/site` — source code
- `apps/site/.usm/` — USM source files

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
