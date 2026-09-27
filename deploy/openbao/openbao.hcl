# OpenBao production server configuration.
#
# This is the file the production systemd unit points at. It is deliberately
# NOT `bao server -dev`:
#
#   - dev mode holds all state in memory, so a restart destroys every KEK and
#     every wrapped DEK becomes permanently undecryptable;
#   - dev mode uses a fixed root token ("root"), so anyone who can reach the
#     port is the administrator;
#   - dev mode is not supported for production by the OpenBao project.
#
# Install to /etc/openbao/openbao.hcl, owned root:openbao, mode 0640.
#
# Before first start:
#   1. Choose a storage backend below (file is the single-VM default).
#   2. Provision a TLS certificate for the listener. The API carries the
#      unseal flow and transit operations; plaintext HTTP would expose the
#      unseal key to the network.
#   3. Run `bao operator init` and record the unseal shares somewhere that is
#      not this host. OpenBao starts sealed; it cannot unseal itself.

ui = false

# ── Storage ─────────────────────────────────────────────────────────────────
# The file backend is appropriate for a single-VM install. Replace with
# "postgresql" or a cloud backend for a highly available deployment.
storage "file" {
  path = "/var/lib/openbao/data"
}

# ── Listener ────────────────────────────────────────────────────────────────
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/openbao/tls/server.crt"
  tls_key_file  = "/etc/openbao/tls/server.key"

  # Reject plaintext clients outright rather than accepting and upgrading.
  tls_disable = false
}

# ── Seal ────────────────────────────────────────────────────────────────────
# Without auto-unseal, an operator supplies unseal shares after every restart.
# That is the correct default for a single-VM install: the shares exist
# off-host, so a stolen disk image cannot be unsealed by an attacker.
#
# For hands-off restarts, configure an auto-unseal stanza pointing at a cloud
# KMS *that the model provider does not control*. Do not use a multi-tenant
# AI-cloud KMS: it would re-introduce model-side exposure of the root of trust,
# which is the risk provider-kms-exposure in .usm/system.usm.
#
# seal "awskms" {
#   region     = "ap-southeast-2"
#   kms_key_id = "REPLACE"
# }

api_addr     = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

# TLS is terminated by the listener, so this must be true to allow the
# self-signed certificate the install generates.
disable_mlock = false
