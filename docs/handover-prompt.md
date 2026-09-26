# Safekeys — session handover prompt

Paste this into a new session to continue the work.

---

## The prompt

```
Continue work on the Safekeys repository at /Users/jamesgray/Code/safekeys.

Read AGENTS.md and .usm/system.usm FIRST — this project is spec-first and the
.usm/ directory is the source of truth, not the code. Use the usm MCP tools
(usm_list, usm_read, usm_search, usm_query) before changing anything.

## What Safekeys is

Encrypted transport for secrets through agentic/LLM flows, so plaintext never
reaches a model. A secret is a ciphertext folder plus an opaque capability token.
A privileged local sidecar resolves the token outside the LLM process. The
agent-facing interface (tokens + folders) is stable as the backend hardens from
software isolation to hardware to threshold crypto.

Tagline: "Secrets move. Models don't see."

## Current state (as of commit fd0de5d)

Phase 0 MVP is BUILT and working end to end. Public repo:
https://github.com/Smith-Gray-Pty-Ltd/safekeys

Implemented and tested:
- pkg/protocol      token (RFC 7515 JWS, alg allowlist) + folder + AEAD + zeroise
- pkg/sidecar       Unix socket server; the ONLY component that resolves a token
- pkg/resolve       the fixed order: verify → policy → unwrap → decrypt → inject → zeroise → audit
- pkg/inject        env / 0600-file / exec injection; scrubbed minimal environment
- pkg/keysource     fetches+caches the control plane's PUBLIC keys (no private key)
- pkg/localpolicy   resolve-time policy, default-deny, cached
- pkg/revocation    checks the denylist on every resolve, fails closed
- pkg/keystore      OpenBao/Vault Transit (KEK never leaves) + dev-only local store
- apps/control-plane  objects, tokens, policy, append-only audit on Postgres
- apps/sidecar        the resolver binary
- apps/cli            create, exec, revoke, list, audit
- packages/mcp-server 4 token-only tools for every MCP runtime
- packages/sdk-python token-only client + LangChain/LangGraph tools
- spec/               frozen v1 JSON Schemas + 28 conformance vectors, all passing
- test/e2e/           the two-agent demo (neither transcript contains plaintext)

12 features built, 2 in-progress, 2 planned. usm check: 25 valid, 0 warnings.
CI is in .github/workflows/ci.yml — 4 jobs (Go, MCP, Python, USM).

## Test it

    make build      # Go binaries
    make dev        # Postgres + OpenBao + control plane + sidecar (background)
    make demo       # create → use → revoke, asserting no leak at each step
    opencode mcp list    # → ✓ safekeys connected

    make test-all   # Go + MCP + Python
    usm check && usm generate --check

The stack is currently STOPPED; postgres and openbao containers are still up
from earlier (docker compose ps).

## What's left, in priority order

Tier 3 — deployment (the last blocker before a VPS):
  - No Dockerfile, no systemd units, no deploy/ directory
  - docker-compose.yml runs OpenBao in -dev mode with a hardcoded root token
  - Signing key is an env-var seed; Phase 1 wants HSM/secure-element custody
  - apps/safekeys (the Next.js marketing site) has no code

Tier 2 — completeness:
  - Socket/pipe injection (currently errors by design)
  - TypeScript SDK (packages/sdk-typescript missing; largely redundant given MCP)
  - Sidecar OS isolation: the ADR describes a separate user + seccomp/AppArmor;
    the code does not implement it

Tier 4 — Phase 1/2 hardening:
  - Hardware root of trust (TPM 2.0, cloud enclave, USB token, secure element)
  - Threshold key splitting + hybrid post-quantum ratchet

## Rules that are non-negotiable

1. The LLM is never on the decryption path. No exception, including tests and demos.
2. Never log plaintext, a DEK, or a KEK. The audit log is metadata only.
3. The sidecar holds PUBLIC keys only — never a signing key. A test asserts
   keysource.Verifier does not satisfy protocol.Signer. Do not weaken this.
4. create_secret takes a FILE PATH, never a value parameter. opencode does not
   declare MCP elicitation (verified empirically), and MCP forbids requesting
   secrets via form-mode elicitation. Do not add a value parameter.
5. Specs and code must not drift. Update the .usm file when behaviour changes,
   and use usm_update_feature_status when the status changes.
6. Conventional commits. Never commit without lint AND typecheck passing.
7. Never stop a running dev server.

## Working agreements

- This project's feedback policy is `human-gate`: surface a bug to the human and
  ASK before filing. Bugs in the USM tool itself go upstream to
  https://github.com/Smith-Gray-Pty-Ltd/usm/issues, never in this repo.
  (Issues #32–#37 were filed there and are now fixed in usm 0.8.1.)
- USM's usm_update_feature MCP tool re-serialises the whole file, which refolds
  block scalars (| becomes >) and drops blank lines. Verify with a parsed-YAML
  diff afterwards, then restore the formatting if it matters.
- Show the human the spec markdown and the live docs link before implementing.

Start by asking which of the remaining items to take, or propose one.
```

---

## Notes for you (not part of the prompt)

**Repo state at handover:** `fd0de5d` on `main`, clean, in sync with origin.

**Two environment things worth knowing:**

- `make dev` uses `SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1` (dev-only). For the Vault
  path, set `SAFEKEYS_VAULT_ADDR` — the sidecar then never touches a KEK file.
- `opencode` has `safekeys` **project-scoped only**, not globally. A backup of
  your global config is at `~/.config/opencode/opencode.jsonc.bak-20260926-000739`.
  The global-config question is still open.

**Docker containers** `safekeys-postgres-1` and `safekeys-openbao-1` have been up
3 days. `docker compose down` when you're done with them.
