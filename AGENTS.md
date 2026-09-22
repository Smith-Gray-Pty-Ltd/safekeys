<!-- USM:START -->
# Safekeys — Agent Context

> Auto-generated from `.usm/system.usm`. Hand-edit sections below; they'll be preserved on regeneration.

Safekeys.ai — encrypted transport for secrets through environments, agentic flows, and LLM systems, designed so plaintext is never exposed to any model. Secrets are treated as movable encrypted objects (ciphertext folders) plus opaque capability tokens; a privileged local sidecar resolves them outside the LLM process. The agent-facing interface is stable as the backend hardens from software isolation to hardware and threshold cryptography.


## The 4 Apps

| App | Directory | Port | Role |
|-----|-----------|------|------|
| Safekeys CLI | `apps/cli` | — | Safekeys CLI — the operator and agent-facing command line (safekeys create, exec, revoke, list) |
| Control Plane API | `apps/control-plane` | 8080 | Control Plane API — issues and revokes capability tokens, manages policy, and exposes the audit log |
| Safekeys.ai Site | `apps/safekeys` | 3000 | Safekeys |
| Sidecar / Resolver | `apps/sidecar` | — | Sidecar / Resolver — the only component permitted to resolve a capability token |

## Shared Packages

| Package | Purpose |
|---------|---------|
| `mcp-server` | the highest-leverage MVP integration. One MCP server exposes Safekeys tools to every MCP-capable agent runtime (Claude, Cursor, Codex, Gemini), so agents can create and use secrets without per-vendor SDK work. Agents receive only tokens, paths, and status. |
| `python-sdk` | a token-only client for agents building secret workflows (LangChain and LangGraph tools first). It exposes create_secret and resolve_for_tool, and by construction cannot return plaintext to the caller: it only ever returns capability tokens and folder paths. |
| `typescript-sdk` | the Node-side counterpart to the Python SDK, targeting Mastra, Vercel AI SDK, and OpenAI Agents SDK customers. Identical token-only API surface: accept and return capability tokens and folder paths, never plaintext. |

## Key Principles

- **The LLM is never on the decryption path**: No language model ever holds, receives, or can derive plaintext secret material or long-term keys.
- **Agents see only opaque capability tokens**: The only secret-bearing artefact an agent reasons about is a short-lived, scoped, audience-bound capability token containing zero secret material.
- **Stable agent-facing interface**: The public interface (tokens plus folders) stays constant as backends harden from software isolation to hardware to threshold crypto.
- **Plaintext is materialised only for the consumer, then zeroised**: Plaintext exists only transiently inside the sidecar's injection path for the consuming non-LLM process, and is zeroised immediately after use.
- **Open protocol, commercial authority**: Token and folder specifications, the sidecar reference implementation, CLI, and core SDKs are open source; the hosted authority, hardware, and enterprise controls are commercial.

## Rules for Agents

1. **Read the relevant .usm files before modifying any code.** Use MCP tools (`usm_list`, `usm_read`, `usm_search`) to understand the system map.
2. **Follow patterns established in shared packages.** Do not invent new auth patterns.
3. **Conventional commits**: `feat(scope): description`, `fix(scope): description`.
4. **Never stop a running dev server.**
5. **Never commit without passing lint AND typecheck.**

## USM Spec-First Workflow

This project uses USM for structured system documentation. Follow this workflow:

### Before Starting Work
0. **Confirm the docs watch server is running** (`usm docs serve --watch`).
   If not running, start it. The human reviews specs in the browser, not just chat.
1. Use MCP tools to read the system map:
   - `usm_list` — list all .usm files
   - `usm_read` — read a specific feature or service
   - `usm_search` — find features by keyword
   - `usm_summary` — quick overview of a file

### When Implementing a New Feature
1. Discuss the feature with the human
2. Call `usm_draft_feature` with structured fields (summary, intent, flows, contracts, tests)
3. Show the human the generated markdown preview for review
4. If approved, call `usm_write_feature` to persist the .usm file
5. **Return the live docs link** (e.g. `http://localhost:5173/features/...`) so the human can review the rendered spec in the browser
6. Wait for human confirmation that the spec is correct before implementing
7. Implement the feature in code
8. Call `usm_update_feature_status` to mark as built (with implementation path)

### When Updating an Existing Feature
1. Read the existing .usm spec first (`usm_read`)
2. Make code changes
3. Call `usm_update_feature` if the spec needs updating
4. Call `usm_update_feature_status` if status changed
5. **Return the live docs link** so the human can verify the updated spec renders correctly

### Generating and Reviewing Docs
- `usm docs serve --watch` — serve docs locally with VitePress, watch .usm/ for changes
- `usm docs serve --audience help` — serve filtered public docs
- `usm generate` — produce markdown, OpenAPI, Mermaid, test specs from .usm files

### Key Rules
- **NEVER** create .usm files by hand — use the MCP write tools (they validate)
- **ALWAYS** show the human the markdown before writing to disk
- **ALWAYS** return the live docs link after writing a spec — the human reviews in the browser
- **ALWAYS** wait for human confirmation before implementing
- **ALWAYS** update feature status after implementation
- The .usm file IS the documentation — if it's wrong, the docs are wrong

## Agent Feedback Protocol

> **If you are an AI agent, read this.** When you discover a bug, inconsistency, or improvement, first classify WHERE it lives (below), then follow this project's configured policy — do NOT improvise or invent your own tracking files.

### Step 1 — Where does the bug live?

| Scope | Covers | Where it goes |
|-------|--------|---------------|
| **This project** | App code, infra, this repo's own `.usm` specs | Step 2 below — this project's policy |
| **The USM tool itself** | `@smithgray/usm` CLI commands, MCP tool behaviour, generator output, schema validation | Upstream: <https://github.com/Smith-Gray-Pty-Ltd/usm/issues> |

USM tool bugs are NOT this project's bugs. Include the `@smithgray/usm` version (`npm ls @smithgray/usm`), the command or MCP tool invoked, reproduction steps, and expected vs actual.
For a USM tool bug: describe it to the human and **ask** whether to file it upstream (they may prefer to file it themselves).
**Never** file USM tool bugs in this project's tracker (<https://github.com/Smith-Gray-Pty-Ltd/safekeys/issues>) or in `.usm/feedback/` — they will not be seen by anyone who can fix them.

### Step 2 — This project's policy (for project-scope issues)

**Active policy:** `human-gate`

- Surface the issue to the human in conversation. Describe what you found and **ask** whether to record or file it.
- Do **NOT** write any feedback file, create an issue, or commit a fix without explicit human approval.

**Hard rules (all policies):**
- **NEVER** create ad-hoc tracking files at the repo root (`bugs.md`, `ISSUES.md`, `TODO-agent.md`, etc.).
- The **only** canonical location for structured project feedback is `.usm/feedback/`.
- Real bugs in this project live in the issue tracker: <https://github.com/Smith-Gray-Pty-Ltd/safekeys/issues>.
- Real bugs in the **USM tool itself** live upstream: <https://github.com/Smith-Gray-Pty-Ltd/usm/issues> — never in this repo.
- If ever unsure, default to asking the human.

<!-- USM:END -->

