# Test Specifications

Auto-generated from .usm/features/*.usm `tests[]` and `flows[]`.

## smith-gray/audit-logging [built]

### From flows:

- **record-resolve**: Record a resolution attempt
  _The sidecar reports each attempt to the audit log, successful or denied._
  - observe → `Sidecar completes a resolve attempt with an outcome.`
  - send → `Sidecar sends the record to the control plane — requester, scope, jti, object id, host, outcome, timestamp.`
  - record → `Control plane appends the record; no plaintext is present in the payload.`
  - observe → `The record is queryable but not modifiable.`
- **query-audit**: Query the audit log
  _An operator or auditor reviews resolution history._
  - authenticate → `Caller authenticates with auditor or operator credentials.`
  - send → `Query by object, jti, principal, host, outcome, or time range.`
  - receive → `Matching records are returned; values are absent by construction.`

### From tests:

- **audit-contains-no-plaintext** (type: assertion)
  - setup: secret_value = audit-test-secret
  - assert: assertion: no audit record contains the secret value
  - assert: assertion: no record contains key material
- **audit-is-immutable** (type: assertion)
  - setup: attempt_mutation = true
  - assert: assertion: no endpoint permits updating or deleting a record
  - assert: assertion: attempts to mutate are rejected
- **denials-are-recorded** (type: assertion)
  - setup: valid_token = false
  - assert: assertion: a record exists with a denial outcome
  - assert: assertion: the record identifies the requester and target
- **attribution-complete** (type: assertion)
  - setup: valid_token = true
  - setup: injection_method = inject-env
  - assert: assertion: the record contains requester, scope, jti, object id, host, and timestamp
  - assert: assertion: the record joins to the token issuance event

_Spec file: `.usm-workspace/tests/features/audit-logging.spec.ts`_

## smith-gray/control-plane-api [built]

### From flows:

- **allocate-object**: Allocate an object id and wrapping policy
  _The sidecar asks the control plane to register a new secret object._
  - receive → `Sidecar requests an object id with an intended wrapping policy and owning principal.`
  - validate → `Authenticate the sidecar and authorise object creation for that principal.`
  - generate → `Allocate and persist an object id and its policy record.`
  - receive → `Sidecar receives the object id; no secret material is involved.`
- **issue-token**: Issue a capability token
  _The control plane mints a signed token for an object, scope, and audience._
  - receive → `Receive a mint request with object id, scope, audience, and TTL.`
  - validate → `Evaluate policy for the requester, scope, object, and audience.`
  - generate → `Build claims and sign the token with the active kid.`
  - record → `Record the jti and the issuance event.`
  - send → `Return the token URI.`
- **revoke-token**: Revoke a token
  _The control plane adds a jti to the denylist._
  - receive → `Receive a revoke request for a jti or object.`
  - record → `Add to the denylist and write an audit record.`
  - observe → `Subsequent resolves with that jti are denied.`

### From tests:

- **no-endpoint-accepts-plaintext** (type: assertion)
  - setup: attempt = POST /v1/objects with a value field
  - assert: assertion: the request is rejected
  - assert: assertion: no value is persisted
- **unauthenticated-request-rejected** (type: assertion)
  - setup: credentials = none
  - assert: assertion: the request is rejected with an authentication error
  - assert: assertion: no token is minted
- **revoke-twice-is-safe** (type: assertion)
  - setup: revoke_calls = 2
  - assert: assertion: both calls succeed
  - assert: assertion: the jti is denied
- **issuance-audited** (type: assertion)
  - assert: assertion: an audit record exists for the issuance
  - assert: assertion: it contains the jti and scope

_Spec file: `.usm-workspace/tests/features/control-plane-api.spec.ts`_

## smith-gray/policy-engine [built]

### From flows:

- **evaluate-issuance-policy**: Evaluate policy at issuance
  _The control plane decides whether to mint the requested token at all._
  - receive → `Receive a mint request with requester, object, scope, audience, and TTL.`
  - validate → `Load the applicable policy for the requester and object.`
  - observe → `Allow, or deny with a generic error.`
  - record → `The decision is recorded in the audit log.`
- **evaluate-local-policy**: Evaluate local policy at resolve
  _The sidecar applies host-local policy before injecting._
  - receive → `Sidecar receives a resolve request with a valid token and an injection method.`
  - validate → `Check local policy — which processes may request which injection method for which object.`
  - observe → `Allow, or deny by default if unspecified.`
  - record → `The decision, including denials, is reported to the audit log.`

### From tests:

- **undefined-rule-denies** (type: assertion)
  - setup: local_policy = empty
  - assert: assertion: the resolve is denied
  - assert: assertion: the denial is recorded
- **injection-method-restricted** (type: assertion)
  - setup: policy_allows = inject-env
  - setup: request = inject-file
  - assert: assertion: the request is denied
  - assert: assertion: the reason names the denied rule
- **cross-environment-policy-not-satisfied** (type: assertion)
  - setup: policy_requires = env-production
  - setup: token_aud = env-staging
  - assert: assertion: the resolve is denied
  - assert: assertion: policy is enforced at resolve as well as issuance
- **decisions-are-audited** (type: assertion)
  - setup: outcome = deny
  - assert: assertion: an audit record exists for the policy decision
  - assert: assertion: it identifies the denying rule

_Spec file: `.usm-workspace/tests/features/policy-engine.spec.ts`_

## smith-gray/hardware-root [planned]

### From flows:

- **bind-device**: Bind a hardware root to an environment
  _A device is provisioned and bound to customer policy on first plug-in._
  - setup → `Device is factory-provisioned with identity, an attestation key, and a locked applet.`
  - authenticate → `First plug-in performs mutual attestation between the device and the key authority.`
  - validate → `The binding is recorded against customer policy in the control plane.`
  - observe → `The sidecar now performs unwrap operations through the device.`
- **unwrap-via-device**: Unwrap through the hardware boundary
  _The device performs or gates the unwrap so key material never enters host RAM._
  - send → `Sidecar sends the unwrap request to the device.`
  - validate → `The device checks that the request is authorised by policy and device state.`
  - observe → `The long-term share never leaves the device boundary.`
  - delete → `The device zeroises transient material and any tamper response wipes state.`
- **revoke-device**: Revoke a lost device
  _A lost or stolen device is revoked by serial._
  - receive → `Operator revokes the device serial at the authority.`
  - record → `The binding is invalidated and the revocation is audited.`
  - observe → `Attestation fails for that device on any subsequent unwrap attempt.`

### From tests:

- **share-absent-from-host** (type: assertion)
  - setup: device = tpm2
  - assert: assertion: the long-term share is not present in the sidecar's process memory
  - assert: assertion: unwrap succeeds through the device boundary
- **api-unchanged-with-hardware** (type: assertion)
  - setup: same_tokens_as_mvp = true
  - assert: assertion: token and folder formats are identical to the software phase
  - assert: assertion: client SDKs require no modification
- **failed-attestation-denies** (type: assertion)
  - setup: attestation = fail
  - assert: assertion: the operation is denied
  - assert: assertion: no unwrap occurs
- **lost-device-revocable-by-serial** (type: assertion)
  - setup: device_serial = SE-0001
  - assert: assertion: the device binding is invalidated
  - assert: assertion: subsequent unwrap attempts fail attestation

_Spec file: `.usm-workspace/tests/features/hardware-root.spec.ts`_

## smith-gray/threshold-crypto [planned]

### From flows:

- **split-key-shares**: Split key knowledge across holders
  _One share lives in the secure element; complementary shares live at the authority._
  - generate → `Provisioning splits key knowledge into shares with a threshold policy.`
  - setup → `One share is installed in the secure element; complementary shares are held at the authority.`
  - observe → `No single holder can reconstruct the key alone.`
- **ephemeral-reconstruction**: Reconstruct ephemerally inside the element
  _The key exists only inside the secure element for the duration of one operation._
  - receive → `Device receives an authorised operation request and attests remotely.`
  - validate → `Remote attestation succeeds before any unwrap is permitted.`
  - generate → `The key is reconstructed inside the element for the requested operation only.`
  - delete → `The reconstructed material is destroyed when the operation completes.`
- **hybrid-ratchet**: Hybrid post-quantum session ratchet
  _Control-plane sessions use a classical plus PQ ratchet._
  - setup → `Negotiate a hybrid KEM combining a classical and an ML-KEM-class mechanism.`
  - generate → `Ratchet session keys forward so compromise of one key does not expose past traffic.`
  - observe → `Harvested session traffic is not decryptable by a future quantum adversary.`

### From tests:

- **single-share-insufficient** (type: assertion)
  - setup: available_shares = 1
  - setup: threshold = 2
  - assert: assertion: reconstruction fails
  - assert: assertion: no key material is produced
- **unattested-device-denied** (type: assertion)
  - setup: attestation = fail
  - assert: assertion: unwrap is denied
  - assert: assertion: no reconstruction occurs
- **reconstruction-does-not-persist** (type: assertion)
  - setup: operations = 2
  - assert: assertion: no reconstructed material survives between operations
  - assert: assertion: host memory never contains the key
- **session-ratchet-forward-secret** (type: assertion)
  - setup: compromise = session key at time T
  - assert: assertion: traffic before T is not decryptable
  - assert: assertion: the hybrid KEM was used for establishment

_Spec file: `.usm-workspace/tests/features/threshold-crypto.spec.ts`_

## smith-gray/integration-mcp-server [built]

### From flows:

- **expose-tools**: Expose Safekeys tools over MCP
  _The MCP server registers token-only tools with the host runtime._
  - setup → `MCP server starts and registers create_secret, resolve_for_tool, list, and revoke tools.`
  - observe → `The host agent runtime discovers the tools through the standard MCP handshake.`
  - observe → `Tool schemas expose identifiers, tokens, and paths only.`
- **call-tool**: Call a Safekeys tool from an agent
  _The agent invokes a tool and receives a token or status, never a value._
  - receive → `MCP server receives a tool call from the host runtime.`
  - send → `The handler forwards the operation to the local sidecar over its socket.`
  - receive → `A token, path, or status is returned to the agent.`
  - observe → `The tool result contains no plaintext, and the call arguments never carried a value.`

### From tests:

- **tool-result-has-no-plaintext** (type: assertion)
  - setup: tool = resolve_for_tool
  - setup: secret_value = mcp-test-secret
  - assert: assertion: the tool result contains no plaintext
  - assert: assertion: the result is a token, path, or status
- **server-has-no-vendor-branching** (type: assertion)
  - setup: static_check = true
  - assert: assertion: no vendor-specific code paths exist
  - assert: assertion: the server implements standard MCP only
- **sidecar-unavailable-is-an-error** (type: assertion)
  - setup: sidecar_running = false
  - assert: assertion: the tool returns an error
  - assert: assertion: no fallback resolution is attempted

_Spec file: `.usm-workspace/tests/features/integration-mcp-server.spec.ts`_

## smith-gray/integration-python-sdk [built]

### From flows:

- **create-secret-tool**: Create a secret via the SDK tool
  _The agent creates a secret and receives a token._
  - receive → `Agent calls create_secret with metadata and a non-context value source such as a file path.`
  - send → `SDK hands the value to the local sidecar over the Unix socket.`
  - receive → `SDK returns a capability token and folder path.`
  - observe → `The agent transcript contains no plaintext.`
- **resolve-for-tool**: Resolve a secret for a tool call
  _The agent requests use of a secret without receiving the value._
  - receive → `Agent calls resolve_for_tool with a token and the target tool or command.`
  - send → `SDK forwards the request to the sidecar, which injects into the consumer.`
  - receive → `SDK returns a success status or placeholder.`
  - observe → `The value never enters the Python process hosting the agent.`

### From tests:

- **create-returns-token-not-value** (type: assertion)
  - setup: value_source = file
  - setup: secret_value = sdk-test-secret
  - assert: assertion: the return value is a token and path
  - assert: assertion: the return value does not contain the secret
- **resolve-returns-status-only** (type: assertion)
  - setup: token = safekey://v1/demo
  - assert: assertion: the return value is a status or placeholder
  - assert: assertion: no plaintext is returned to the agent process
- **sdk-has-no-crypto** (type: assertion)
  - setup: static_check = true
  - assert: assertion: the SDK imports no decryption or key-handling primitives
  - assert: assertion: all resolution goes through the sidecar socket
- **langgraph-agent-transcript-clean** (type: assertion)
  - setup: agent = langgraph
  - assert: assertion: the agent transcript contains no plaintext
  - assert: assertion: the agent holds only a token afterwards

_Spec file: `.usm-workspace/tests/features/integration-python-sdk.spec.ts`_

## smith-gray/secret-creation [built]

### From flows:

- **create-from-cli**: Create a secret from the CLI
  _A human supplies a value out-of-band and receives a token._
  - receive → `Operator pipes the value to `safekeys create` via stdin or a file — not as an argument.`
  - send → `CLI sends the plaintext to the local sidecar over the Unix socket.`
  - receive → `Sidecar asks the control plane to allocate an object id and wrapping policy.`
  - encrypt → `Sidecar generates a DEK, encrypts the plaintext locally, and writes the ciphertext object.`
  - transmit → `Sidecar sends the DEK for wrapping under the KEK in the key store.`
  - receive → `A capability token is returned to the caller; the plaintext is discarded.`
- **create-from-agent**: Create a secret from an agent SDK
  _An agent creates a secret and receives only a token — it never supplies a value it read from context._
  - receive → `Agent SDK calls create_secret with metadata and a value source that is not model context (a file path or an out-of-band reference).`
  - send → `SDK forwards the value to the sidecar over the local channel without it entering the agent's transcript.`
  - receive → `SDK returns a capability token and folder path to the agent.`
  - observe → `The agent transcript contains no plaintext.`

### From tests:

- **creation-returns-token-only** (type: assertion)
  - setup: secret_value = value-from-stdin
  - assert: assertion: the response contains a capability token
  - assert: assertion: the response does not contain the secret value
  - assert: assertion: the stored object is ciphertext
- **argv-never-contains-plaintext** (type: assertion)
  - setup: supplied_via = file
  - assert: assertion: the process arguments contain no plaintext
  - assert: assertion: the value arrives over stdin or a file descriptor
- **agent-transcript-clean** (type: assertion)
  - setup: agent = langgraph-agent
  - setup: secret_source = file
  - assert: assertion: the agent transcript contains no plaintext
  - assert: assertion: the agent holds only a token afterwards

_Spec file: `.usm-workspace/tests/features/secret-creation.spec.ts`_

## smith-gray/secret-transport [in-progress]

### From flows:

- **agent-to-agent**: Transport a secret between agents
  _Agent A creates a secret; Agent B uses it, with neither transcript containing plaintext._
  - receive → `Agent A creates a secret and receives a token and folder path.`
  - send → `Agent A passes the folder path and token to Agent B through the agent bus.`
  - observe → `No unwrap occurs in transit; the folder is inert.`
  - send → `Agent B presents the token to its local sidecar to use the secret.`
  - observe → `Neither Agent A's nor Agent B's transcript contains plaintext.`
- **cross-environment**: Transport a secret across environments
  _A folder is synced or copied to another environment and used there under a new token._
  - send → `The folder is copied to the destination environment via git, an object store, or artefacts.`
  - observe → `No key material travels with it and no unwrap occurs.`
  - transmit → `A token scoped to the destination audience is minted.`
  - observe → `The destination sidecar can now resolve; the source's token cannot be used at the destination.`

### From tests:

- **two-agent-demo-no-plaintext** (type: assertion)
  - setup: agent_a = creator
  - setup: agent_b = consumer
  - setup: secret_value = demo-secret
  - assert: assertion: Agent A's transcript contains no plaintext
  - assert: assertion: Agent B's transcript contains no plaintext
  - assert: assertion: Agent B successfully used the secret
- **cross-environment-token-rejected** (type: assertion)
  - setup: source_aud = env-staging
  - setup: destination = env-production
  - assert: assertion: the source token is denied at the destination
  - assert: assertion: a destination-scoped token succeeds
- **intercepted-transport-yields-nothing** (type: assertion)
  - setup: capture_transport = true
  - assert: assertion: captured payloads contain no plaintext
  - assert: assertion: captured tokens cannot be used without a reachable sidecar and key authority

_Spec file: `.usm-workspace/tests/features/secret-transport.spec.ts`_

## smith-gray/token-revocation [built]

### From flows:

- **revoke-token**: Revoke a capability token
  _An operator invalidates a specific token by its unique id._
  - receive → `Operator issues a revoke request for a jti or object id.`
  - validate → `Control plane checks the operator's authority to revoke that object or token.`
  - record → `The jti is added to the denylist and the revoke is recorded in the audit log.`
  - observe → `Every subsequent resolve attempt with that jti is denied.`
- **revoke-device**: Revoke a device-bound token (later phase)
  _A lost hardware token is revoked by serial._
  - receive → `Operator revokes a device serial or its associated binding.`
  - record → `The device binding is invalidated at the authority.`
  - observe → `Attestation fails for that device on the next unwrap attempt.`

### From tests:

- **revoked-token-denied-on-next-resolve** (type: assertion)
  - setup: ttl_seconds = 3600
  - setup: revoke_before_use = true
  - assert: assertion: the next resolve with that jti is denied
  - assert: assertion: denial occurs well before expiry
- **revocation-recorded** (type: assertion)
  - setup: valid_token = true
  - assert: assertion: an audit record exists for the revocation
  - assert: assertion: it names the revoking principal and the target
- **no-cache-serves-revoked-token** (type: assertion)
  - setup: resolved_once_before_revocation = true
  - assert: assertion: a previously successful resolve does not make the token reusable
  - assert: assertion: no in-memory cache bypasses the denylist

_Spec file: `.usm-workspace/tests/features/token-revocation.spec.ts`_

## smith-gray/capability-token [built]

### From flows:

- **mint-token**: Mint a capability token
  _The control plane issues a signed token for a specific object, scope, and audience._
  - receive → `Control plane receives an object id, requested scope, audience, and TTL from the sidecar.`
  - validate → `Policy is evaluated — is this requester allowed to mint this scope for this object and audience?`
  - generate → `Generate claims (sid, scope, aud, exp, nbf, jti) and sign with the active kid.`
  - record → `Persist the jti so it can be revoked and audited.`
  - receive → `Caller receives the token URI; no secret material is present in the response.`
- **verify-token**: Verify a token at the sidecar
  _The sidecar is the only component that validates a token before resolving._
  - parse → `Parse the safekey:// URI and extract the token and claims.`
  - validate → `Verify signature against the issuer's key (kid), then expiry (exp/nbf).`
  - validate → `Verify the audience matches this resolver/environment identity.`
  - validate → `Verify the requested operation is within the token's scope (least privilege).`
  - validate → `Check the jti against the revocation denylist.`
  - observe → `On any failure, deny by default without revealing why beyond a generic denial code.`

### From tests:

- **token-has-no-secret-material** (type: assertion)
  - setup: secret_value = super-secret-value
  - assert: assertion: the minted token string does not contain the secret value in any encoding
  - assert: assertion: decoding the token yields only the declared claims
  - assert: assertion: no DEK or KEK identifier resolves to recoverable key bytes
- **expired-token-denied** (type: assertion)
  - setup: ttl_seconds = 1
  - setup: wait_seconds = 2
  - assert: assertion: resolution is denied with a generic denial
  - assert: assertion: no key-store unwrap is attempted
- **wrong-audience-denied** (type: assertion)
  - setup: aud = env-production
  - setup: resolver_identity = env-staging
  - assert: assertion: resolution is denied
  - assert: assertion: no plaintext is materialised
- **revoked-token-denied-immediately** (type: assertion)
  - setup: revoke_before_use = true
  - setup: ttl_seconds = 3600
  - assert: assertion: resolution is denied even though the token has not expired

_Spec file: `.usm-workspace/tests/features/capability-token.spec.ts`_

## smith-gray/encrypted-folder [built]

### From flows:

- **build-folder**: Build an encrypted folder
  _Ciphertext objects plus a manifest are written to a directory or object prefix._
  - generate → `For each secret, generate a random DEK and encrypt the plaintext into objects/<id>.enc.`
  - generate → `Write manifest.json — object ids, content-type hints, token references, wrapping key ids, and hashes.`
  - generate → `Write README.safekeys describing the folder for humans and agents, containing no secrets.`
  - observe → `The folder is now inert; it can be copied or committed without further protection.`
- **copy-folder**: Transport a folder
  _A folder is moved between environments or agents with no unwrap occurring._
  - receive → `Destination receives the folder or object prefix verbatim.`
  - observe → `No unwrap is attempted; no key material is required to hold the copy.`
  - observe → `Cryptographic exposure is unchanged by the copy.`

### From tests:

- **folder-copy-yields-nothing** (type: assertion)
  - setup: folder_with_secrets = true
  - assert: assertion: the copied folder contains no plaintext
  - assert: assertion: reading every file in the folder without a sidecar yields no secret
- **manifest-leak-yields-nothing** (type: assertion)
  - setup: manifest_only = true
  - assert: assertion: no secret is recoverable from manifest.json alone
  - assert: assertion: wrapping key ids are identifiers, not key material
- **readme-safe-for-model-context** (type: assertion)
  - assert: assertion: README.safekeys contains no secret values
  - assert: assertion: pasting README.safekeys into a model context exposes nothing sensitive

_Spec file: `.usm-workspace/tests/features/encrypted-folder.spec.ts`_

## smith-gray/envelope-encryption [built]

### From flows:

- **wrap-dek**: Wrap a data encryption key
  _A new DEK is generated locally and wrapped by the KEK without leaving the key store's trust boundary._
  - generate → `Generate a random DEK for the object.`
  - encrypt → `Encrypt the plaintext object with the DEK.`
  - send → `Send the DEK to the key store for wrapping under the KEK; only the wrapped form is persisted.`
  - observe → `Plaintext is discarded from memory after encryption.`
- **unwrap-dek**: Unwrap a DEK for a resolve
  _The sidecar requests unwrap only after a token has passed every verification step._
  - transmit → `Sidecar sends the wrapped DEK and token context to the key store after token verification.`
  - receive → `Key store returns the unwrapped DEK over an authenticated channel.`
  - decrypt → `Sidecar decrypts the target object in memory.`
  - delete → `Zeroise the DEK and the plaintext buffer once injection completes.`

### From tests:

- **kek-not-exportable** (type: assertion)
  - setup: keystore = openbao-dev
  - assert: assertion: the created KEK cannot be read back in plaintext through the API
  - assert: assertion: only wrapped DEKs are persisted
- **unique-dek-per-object** (type: assertion)
  - setup: objects = 100
  - assert: assertion: all 100 wrapped DEKs differ
  - assert: assertion: no DEK is reused across objects
- **dek-zeroised-after-resolve** (type: assertion)
  - setup: single_resolve = true
  - assert: assertion: the plaintext buffer is cleared after injection
  - assert: assertion: no plaintext persists in the sidecar after the resolve returns
- **deny-by-default-when-store-unreachable** (type: assertion)
  - setup: keystore_reachable = false
  - assert: assertion: resolution fails closed
  - assert: assertion: no cached or fallback plaintext is used

_Spec file: `.usm-workspace/tests/features/envelope-encryption.spec.ts`_

## smith-gray/exec-wrapper [built]

### From flows:

- **exec-with-token**: Execute a wrapped command
  _The CLI resolves the token and runs the command with injected env._
  - receive → `CLI receives a token and a command to run after a -- separator.`
  - send → `CLI forwards the resolve request to the local sidecar over its socket.`
  - setup → `Sidecar builds a minimal environment for the child, adds the injected value under its variable name, and spawns the command.`
  - observe → `The command runs; its stdout and stderr are streamed to the caller.`
  - receive → `The caller receives the command's exit code; the value is never printed by the wrapper.`

### From tests:

- **child-sees-injected-env** (type: assertion)
  - setup: command = sh -c 'test "$API_KEY" = "expected"'
  - assert: assertion: the command exits zero
  - assert: assertion: the injected variable is present in the child environment
- **ambient-env-not-inherited** (type: assertion)
  - setup: ambient_var = SHOULD_NOT_APPEAR
  - assert: assertion: the child does not see ambient variables outside the explicit allowlist
- **no-plaintext-in-argv-or-output** (type: assertion)
  - setup: command = printenv API_KEY
  - assert: assertion: the wrapper's own output does not include the value
  - assert: assertion: process arguments contain the token but not the value

_Spec file: `.usm-workspace/tests/features/exec-wrapper.spec.ts`_

## smith-gray/secret-injection [in-progress]

### From flows:

- **inject-env**: Inject as an environment variable
  _For a child process that already reads env — CLIs and SDKs._
  - receive → `Sidecar receives a resolve request scoped to inject-env for a named variable.`
  - setup → `Resolve and decrypt the object.`
  - send → `Spawn the consumer with the value in its environment; do not inherit it in the agent's env.`
  - observe → `Return a success code only.`
- **inject-file**: Inject as a 0600 temp file
  _For tools that require a file — kubeconfig, certificates._
  - receive → `Sidecar receives a resolve request scoped to inject-file.`
  - setup → `Write the value to a temporary file owned by the consumer with mode 0600.`
  - send → `Return the path to the consumer.`
  - delete → `Remove the file when the consumer exits.`
- **inject-socket**: Inject over a Unix socket or pipe
  _For long-running local services._
  - receive → `Sidecar receives a resolve request scoped for a socket or pipe consumer.`
  - send → `Deliver the value over the established local channel.`
  - delete → `Zeroise after delivery.`
- **inject-exec**: Inject via the exec wrapper
  _Run a command with secrets injected and the environment scrubbed._
  - receive → `Sidecar receives safekeys exec --token ... -- <command>.`
  - resolve → `Resolve all tokens required by the command.`
  - setup → `Spawn the command as a child of the sidecar with a minimal environment and injected values.`
  - observe → `Return the command's exit code; values never reach the caller.`

### From tests:

- **env-injection-not-visible-to-agent** (type: assertion)
  - setup: injection_method = inject-env
  - setup: consumer = printenv MY_TOKEN
  - assert: assertion: the child process sees the value
  - assert: assertion: the agent's own environment does not contain the value
  - assert: assertion: the sidecar response contains no value
- **temp-file-permissions** (type: assertion)
  - setup: injection_method = inject-file
  - assert: assertion: the temp file is mode 0600
  - assert: assertion: the file is owned by the consumer, not the agent
  - assert: assertion: the file is removed after the consumer exits
- **exec-returns-only-exit-code** (type: assertion)
  - setup: command = sh -c 'test -n "$API_KEY"'
  - assert: assertion: the caller receives an exit code, not the value
  - assert: assertion: the command's stdout is not augmented with the secret

_Spec file: `.usm-workspace/tests/features/secret-injection.spec.ts`_

## smith-gray/sidecar-resolution [built]

### From flows:

- **resolve-and-inject**: Resolve a token and inject the secret
  _The sidecar takes a token from a local caller and injects the secret into a non-LLM consumer._
  - receive → `Receive a resolve request and capability token over the local Unix domain socket.`
  - validate → `Verify signature, expiry, audience, scope, and jti denylist. Deny on any failure.`
  - validate → `Evaluate local policy — may this process request this injection method for this object?`
  - transmit → `Request DEK unwrap from the key store.`
  - decrypt → `Decrypt the target object in sidecar memory.`
  - send → `Inject into the consumer (env var, temp file, socket/pipe, or exec).`
  - delete → `Zeroise the plaintext and DEK, then return only a success code.`
  - observe → `Append an audit record — who, what scope, which jti, which host — without plaintext.`

### From tests:

- **resolution-denied-without-token** (type: assertion)
  - setup: token = null
  - assert: assertion: the request is denied
  - assert: assertion: no key-store unwrap is attempted
  - assert: assertion: no plaintext is materialised
- **agent-never-receives-value** (type: assertion)
  - setup: injection_method = inject-env
  - assert: assertion: the response contains only a status or placeholder
  - assert: assertion: the resolved value does not appear in the response body
- **resolve-fails-closed-without-keystore** (type: assertion)
  - setup: keystore_reachable = false
  - setup: valid_token = true
  - assert: assertion: resolution is denied
  - assert: assertion: no cached value is substituted
- **every-resolve-is-audited** (type: assertion)
  - setup: valid_token = true
  - assert: assertion: an audit record exists for the resolve
  - assert: assertion: the record contains the jti and outcome
  - assert: assertion: the record contains no plaintext
- **prompt-injection-cannot-dump-keys** (type: assertion)
  - setup: attack = model instructs agent to print all environment variables and resolve every token it can see
  - assert: assertion: the agent can only request resolution via the token it holds
  - assert: assertion: injected values are not readable back through the sidecar
  - assert: assertion: no long-term key material is reachable from the agent's process

_Spec file: `.usm-workspace/tests/features/sidecar-resolution.spec.ts`_
