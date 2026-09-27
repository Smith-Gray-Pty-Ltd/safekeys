# Deploying Safekeys

This directory contains everything needed to run Safekeys on a real host.
The development stack (`docker-compose.yml`, `make dev`) is unchanged and
unaffected — this is a separate, hardened path.

> **Read this before running anything.** The deployment decisions are recorded in
> the spec at [`.usm/features/deployment/deployment-packaging.usm`](../../.usm/features/deployment/deployment-packaging.usm),
> which is the source of truth. This README is the operator's companion to it.

## What is here

| Path | Purpose |
|------|---------|
| `compose.prod.yml` | Production Compose: Postgres, OpenBao, control plane, optional sidecar |
| `systemd/` | systemd units carrying the OS-isolation hardening (the reference topology) |
| `openbao/openbao.hcl` | OpenBao server config — persistent storage, TLS, no dev mode |
| `apparmor/safekeys-sidecar` | Mandatory-access-control profile for the sidecar |
| `secrets/` | Where credentials are mounted from (never committed) |
| `.env.example` | The variables Compose expects, including image digests |

## Two topologies — choose deliberately

The sidecar's MVP job is to inject a resolved secret into a **consumer process
it spawns itself** (`pkg/inject` runs the command as a child with a scrubbed
environment). A container has its own process namespace, so a containerised
sidecar can only inject into consumers inside that same container.

### 1. Host sidecar with systemd — the reference topology

```
   authority host                         secrets host
  ┌────────────────┐                   ┌──────────────────────────┐
  │ control plane  │◄──── HTTPS ───────│ sidecar (systemd,        │
  │ + Postgres     │                   │   non-root, confined)    │
  │ + OpenBao      │◄──── HTTPS ───────│   │                      │
  └────────────────┘                   │   │ spawns               │
                                       │   ▼                      │
                                       │ consumer process         │
                                       │ (agent tool, CLI)        │
                                       └──────────────────────────┘
```

Use this when the processes that consume secrets run on the host. It is the only
topology in which the sidecar can inject into them.

### 2. All-container with Compose

Valid **only** when each consumer runs in the same container as the sidecar
(or shares its namespace). The `sidecar` service is behind a Compose profile and
is off by default:

```bash
docker compose -f deploy/compose.prod.yml --profile sidecar up -d
```

If you run this expecting host processes to resolve through it, resolution will
succeed and injection will fail. That is the constraint, not a bug.

## Provisioning order

### 1. Host users and groups

The sidecar must run as a user distinct from any agent user, and the socket is
shared with agents through a dedicated group.

```bash
# The resolver's own account — no login shell, no home.
useradd --system --no-create-home --shell /usr/sbin/nologin safekeys-sidecar

# The control plane's account.
useradd --system --no-create-home --shell /usr/sbin/nologin safekeys-control-plane

# The shared group. Its only purpose is socket access: members may ask the
# sidecar to resolve, and nothing else. Add agent users to it.
groupadd --system safekeys-socket
usermod -aG safekeys-socket safekeys-agent
```

The socket group matters because the default socket mode is `0600` — reachable
only by the sidecar's own user. Naming a group widens it to `0660`, owned by the
sidecar user and that group, and nothing else on the host can connect. A
world-accessible socket is refused outright at startup.

### 2. Directories

```bash
install -d -o safekeys-sidecar  -g safekeys-sidecar  -m 0700 /var/lib/safekeys/folder
install -d -o root              -g root              -m 0700 /etc/safekeys/secrets
install -d -o openbao           -g openbao           -m 0700 /var/lib/openbao/data
```

### 3. Credentials

Every credential is delivered as a root-owned `0600` file, never as an
environment variable. Environment variables are readable from `/proc/<pid>/environ`,
inherited by every child process the sidecar spawns, and visible in
`docker inspect`.

See [`secrets/README.md`](secrets/README.md) for how to generate each one.

| File | Consumed by | Notes |
|------|-------------|-------|
| `signing-key` | control plane | base64 Ed25519 seed; **until Phase 1 HSM custody** |
| `control-plane-api-key` | control plane + sidecar | client credential |
| `database-url` | control plane | contains the Postgres password |
| `vault-token` | sidecar | scoped OpenBao token, transit-only |
| `postgres-password` | Postgres container | |

### 4. Key store

OpenBao must be initialised once and unsealed after every restart. It is never
run in dev mode.

```bash
# First run only: produces unseal shares and an initial root token.
bao operator init -key-shares=5 -key-threshold=3

# Store the unseal shares somewhere that is NOT this host. If the host's disk
# image is stolen, the shares are what prevent the KEK from being unwrapped.

# After each restart:
bao operator unseal   # repeat key-threshold times, from the off-host shares

# Then, once, as root:
bao secrets enable transit
bao write -f transit/keys/kek-1
```

Create a **scoped** token for the sidecar rather than using the root token. The
sidecar only needs to wrap and unwrap with one transit key:

```bash
cat > sidecar-policy.hcl <<'EOF'
path "transit/encrypt/kek-1" { capabilities = ["update"] }
path "transit/decrypt/kek-1" { capabilities = ["update"] }
EOF
bao policy write safekeys-sidecar sidecar-policy.hcl
bao token create -policy=safekeys-sidecar -period=24h -orphan
# Write the token to /etc/safekeys/secrets/vault-token as root:root 0600.
```

The KEK never leaves OpenBao. The sidecar sees only wrapped, or transiently
unwrapped, data keys — never the KEK itself.

### 5. Signing key (interim, until Phase 1)

```bash
# On the authority host, as root. Generate into a file, never into a shell
# variable, so it cannot land in history or a process listing.
umask 077
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())' \
  > /etc/safekeys/secrets/signing-key
chown root:root /etc/safekeys/secrets/signing-key
chmod 0600 /etc/safekeys/secrets/signing-key
```

Whoever holds this key can mint tokens. It is the most sensitive material in the
system, it lives only on the authority host, and the sidecar never receives it —
the sidecar holds public keys only. HSM or secure-element custody is the Phase 1
target ([`safekeys/hardware-root`](../../.usm/features/hardening/hardware-root.usm));
this file is the explicit, auditable interim.

### 6. Start

```bash
# Authority host
install -m 0644 deploy/systemd/openbao.service            /etc/systemd/system/
install -m 0644 deploy/systemd/safekeys-control-plane.service /etc/systemd/system/
install -m 0641 deploy/openbao/openbao.hcl /etc/openbao/openbao.hcl
systemctl daemon-reload
systemctl enable --now openbao
systemctl enable --now safekeys-control-plane

# Secrets host
install -m 0644 deploy/systemd/safekeys-sidecar.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now safekeys-sidecar
```

## Verification

```bash
# The hardening assertion (contract sidecar-host-isolation). The exposure level
# should be at or below the threshold the spec pins.
systemd-analyze security safekeys-sidecar

# The socket access model. A user in safekeys-socket can resolve; anyone else
# is refused by the OS before the sidecar even sees the request.
sudo -u safekeys-agent /usr/local/bin/safekeys list
sudo -u nobody          /usr/local/bin/safekeys list   # must fail to connect

# Fail-closed behaviour: stop OpenBao and confirm the sidecar does not serve.
systemctl stop openbao
journalctl -u safekeys-sidecar -n 20    # expect a refusal, not a fallback
```

## Updating

Images are referenced by **digest**, not tag, so a running host executes exactly
the artefact that was tested. To update, change the digest in `.env`, then:

```bash
docker compose -f deploy/compose.prod.yml pull
docker compose -f deploy/compose.prod.yml up -d
```

To roll back, restore the previous digest — no rebuild is required.

## What is deliberately not here

- **Kubernetes manifests.** The reference target is a single hardened VM. The
  images and configuration are orchestrator-agnostic, so a cluster can be added
  later behind the same digests. The reasoning is recorded as the
  `systemd-single-vm-first` decision in the spec.
- **A hosted registry push from this repository's default flow.** CI publishes
  images for release tags; local builds need no registry. See
  `.github/workflows/release.yml`.
- **HSM-backed signing.** Phase 1. See `safekeys/hardware-root`.
