---
applyTo: "**"
---

# USM Iron Rules (self-check every message)

1. Before ANY code change: does a .usm spec govern this? Find it (`usm_search`/`usm_read`/`usm_query`) and read its contracts BEFORE editing. No spec for new work → draft one (`usm_draft_feature`), show the human the markdown, get approval (`usm_write_feature`) — BEFORE writing code.
2. NEVER hand-write .usm files — use the MCP write tools (they validate). Use `usm_write_system`/`usm_write_service` for system and service files, not just feature tools. NEVER write a spec without showing the human the markdown preview first.
3. After implementing: update the spec (`usm_update_feature` / `usm_update_feature_status`) in the same session. Code and spec must not drift.
4. Found a bug? Classify scope first: this project → feedback policy in AGENTS.md; the USM tool itself (CLI/MCP/generators/schema) → https://github.com/Smith-Gray-Pty-Ltd/usm/issues — never this repo's tracker. NEVER create ad-hoc tracking files (bugs.md, ISSUES.md).
5. Drifted? If you've been editing code without consulting specs: STOP, read the governing spec, reconcile, continue.
