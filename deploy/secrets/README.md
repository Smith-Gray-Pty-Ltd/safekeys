# Deployment secrets

Every file in this directory is a credential. **None of them are committed** —
`.gitignore` excludes the contents. Only `README.md` and `.gitkeep` are tracked.

The Compose file mounts these as files (contract `no-dev-credentials-in-prod`),
and the systemd units deliver them through `LoadCredential` so their values never
enter a process environment.

## Files

| File | Mode | Owner | How to produce |
|------|------|-------|----------------|
| `postgres-password` | 0600 | root | Any high-entropy string |
| `database-url` | 0600 | root | DSN containing that password |
| `signing-key` | 0600 | root | base64 Ed25519 seed (interim — see below) |
| `control-plane-api-key` | 0600 | root | Any high-entropy string |
| `vault-token` | 0600 | root | Scoped OpenBao token, transit-only |

All files must be **world-unreadable**. The credential loader refuses a file with
the world-read bit set rather than loading a shared secret silently.

## Generating them

```bash
cd deploy/secrets
umask 077

# High-entropy strings.
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > control-plane-api-key
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > postgres-password

DB_PASS="$(cat postgres-password)"
printf 'postgres://safekeys:%s@postgres:5432/safekeys?sslmode=disable' "$DB_PASS" > database-url

# The token signing seed. This is the most sensitive value here: whoever holds
# it can mint capability tokens. Generate it on the authority host only.
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())' > signing-key

# The OpenBao token is created by `bao token create` (see ../README.md) and
# written here afterwards — do not invent one by hand.
```

Then tighten everything:

```bash
chmod 0600 *
chown root:root *
```

## The signing key is an interim measure

Whoever holds `signing-key` can mint tokens for any object. It is a bare key on
disk today because HSM custody is Phase 1
([`smith-gray/hardware-root`](../../.usm/features/hardening/hardware-root.usm)).
The mitigations in place now:

- It lives only on the authority host — never on a host running agent workloads.
- The sidecar never receives it; the sidecar holds **public keys only**, so a
  secrets-host compromise cannot mint tokens.
- It is delivered as a credential file, so it is absent from the environment and
  from `docker inspect`.
- The production profile refuses an environment-supplied seed outright.

When Phase 1 lands, this file is replaced by a device handle and the value stops
existing on disk.

## Rotating

Rotation differs per credential:

1. **control-plane-api-key** — set the new value on the control plane, then the
   sidecar, then the CLI. Both accept a single active key in the MVP, so there is
   a brief window of mismatch; stagger accordingly.
2. **signing-key** — the control plane publishes public keys at `/v1/keys` and
   the sidecar refreshes on an unknown `kid`. Start the control plane with the
   **new** key under a **new** `SAFEKEYS_KID` while retaining the old key's
   public half, let sidecars pick it up, then retire the old entry once all
   issued tokens have expired.
3. **vault-token** — create a replacement token, update the file, restart the
   sidecar, then revoke the old token.
