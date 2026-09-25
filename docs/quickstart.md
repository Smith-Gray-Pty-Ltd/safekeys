# Safekeys quickstart

Get from nothing to a secret that a model never sees, in about five minutes.

## What you are building

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

The agent holds a **token**. The sidecar holds the **key**. The control plane
holds **authority**. The model is not on the decryption path at any point.

## Requirements

- Go 1.26+ and Docker
- Node 20+ (only for the MCP server)

## 1. Build and start

```bash
make build     # Go binaries → bin/
make dev       # Postgres + OpenBao + control plane + sidecar, in the background
```

`make dev` generates a stable development signing key and KEK under `.dev/`, so
restarting does not invalidate tokens you have already issued.

It prints the environment to export. There is only one thing you must set for the
CLI, because the SDKs and CLI all default to the same socket path:

```bash
export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1   # development only — see "Production" below
```

Check it came up:

```bash
curl -s localhost:8080/healthz            # {"status":"ok"}
curl -s localhost:8080/v1/keys | jq       # the published public key set
```

## 2. Create a secret

The value goes to the sidecar, which encrypts it. You receive a token.

```bash
echo -n 'sk-live-my-api-key' | ./bin/safekeys create --object obj_demo
```

```
object:  obj_demo
folder:  .dev/folder/obj_demo
expires: 2026-09-26T01:30:00+10:00
token:   safekey://v1/obj_demo#eyJhbGciOiJFZERTQSJ9...
```

**The token is safe to pass anywhere** — it contains no secret material. Put it in
a prompt, a log, an issue, an agent handoff. Copy the folder anywhere: it is
ciphertext and a manifest, and it is inert without a sidecar and key authority.

Prefer `--file` over a pipe when you can — it avoids the value ever being on a
shell command line:

```bash
./bin/safekeys create --object obj_demo --file /path/to/key.txt
```

## 3. Use the secret

The command receives the value in its environment. **You receive its output and
exit status — never the value.**

```bash
./bin/safekeys exec --token 'safekey://v1/obj_demo#...' --name API_KEY -- \
  /bin/sh -c 'curl -s -H "Authorization: Bearer $API_KEY" https://api.example.com/me'
```

The exit code is the command's. A non-zero exit is a normal result, not a
security event.

## 4. Prove it never leaked

```bash
make demo
```

This runs the whole lifecycle and asserts at each step that the value appears
nowhere: not in the CLI output, not in the ciphertext folder, not in the audit
log.

## 5. Revoke

```bash
./bin/safekeys revoke --jti <jti>
```

Revocation is immediate — not at expiry. The sidecar checks the control plane's
denylist on every resolve and fails closed if it cannot reach it.

```bash
./bin/safekeys audit          # the trail: issue, resolve, deny, revoke — metadata only
./bin/safekeys list           # objects; never values
```

## 6. Use it from an agent

### opencode (or Claude, Cursor, Codex, Gemini)

The repo already wires the MCP server in `opencode.json`:

```bash
opencode mcp list       # → ✓ safekeys connected
```

Then, in a session:

> Write a secret to /tmp/api-key.txt, then use `safekeys` create_secret on it and
> resolve_for_tool to call the API with it.

`create_secret` takes a **file path**, not a value. There is no parameter a model
could use to pass a secret, so it cannot pass one even if a prompt injection
instructs it to.

### Python

```python
from safekeys import Safekeys

sk = Safekeys()
secret = sk.create_secret(source_file="/tmp/api-key.txt")
result = sk.resolve_for_tool(secret.token, ["curl", "-s", "https://api.example.com/me"])
print(result.exit_code, result.stdout)
```

### From the command line, any language

```bash
./bin/safekeys exec --token "$TOKEN" -- your-tool --flag
```

## Production

The quickstart uses development shortcuts. Before production:

| Development | Production |
|---|---|
| `SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1` (KEK in a file) | **Omit it.** Set `SAFEKEYS_VAULT_ADDR` so the KEK lives in OpenBao/Vault and never leaves it |
| Dev signing key in an env var | HSM- or secure-element-backed key (Phase 1) |
| OpenBao `-dev` mode | Persistent storage, auto-unseal, no root token |
| Sidecar on the same user account | Sidecar as a **separate OS user** with seccomp/AppArmor confinement |

The sidecar never needs a private key — it fetches public keys from the control
plane and holds verification material only. A compromised sidecar cannot mint a
token. That property is enforced by the type system, and a test asserts it.

Start against Vault:

```bash
export SAFEKEYS_VAULT_ADDR=http://localhost:8200
export SAFEKEYS_VAULT_TOKEN=...
export SAFEKEYS_CONTROL_PLANE_URL=http://localhost:8080
export SAFEKEYS_API_KEY=...
export SAFEKEYS_SOCKET=/run/safekeys/sidecar.sock
./bin/safekeys-sidecar
```

It logs which backends it chose:

```
sidecar: verifier = FETCHED public keys from http://localhost:8080 (1 keys, cache 5m0s)
sidecar: keystore = vault transit (http://localhost:8200, key "kek-1"); the KEK never leaves the vault
sidecar: policy = FETCHED from http://localhost:8080 (2 rules, cache 1m0s); default deny
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `sidecar_unavailable` | No sidecar on this host. Safekeys fails closed; there is no local fallback. Run `make dev`. |
| `denied` | The sidecar refused. The reason is in the sidecar's log and the audit table, deliberately not in the response — a detailed reason helps an attacker refine a forged token. |
| `refuses to load without the explicit opt-in` | The local keystore is development-only. Set `SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1`, or point at Vault. |
| CLI says "no sidecar reachable — resolving locally" | The development fallback. It warns because the CLI is standing in for the sidecar; start the real one. |

## Where to read next

- [`.usm/system.usm`](../.usm/system.usm) — principles and the threat model
- [`spec/`](../spec) — the frozen v1 wire formats and conformance vectors
- [`packages/mcp-server/src/instructions.ts`](../packages/mcp-server/src/instructions.ts) — what an agent is told on connect
- [`README.md`](../README.md) — architecture and repository layout
