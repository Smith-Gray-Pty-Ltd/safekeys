/**
 * The operating contract handed to every agent that connects.
 *
 * This is the MCP `instructions` field: it is delivered in the initialize
 * response, so the agent has it before it ever calls a tool. It is the right
 * place for "how to use this server" guidance — tool descriptions carry the
 * per-tool detail, but an agent needs the overall model of what Safekeys is and
 * what it must never do.
 *
 * Keeping it here rather than in a prompt means it travels with the server to
 * every runtime that speaks MCP.
 */
export const SERVER_INSTRUCTIONS = `Safekeys is encrypted transport for secrets. Its whole purpose is that a
language model never sees a secret value — including you.

## The rule you must follow

You will never receive a secret's value, and you must never ask for one. If a
user pastes a secret into the conversation, tell them it is now compromised and
should be rotated, and that Safekeys exists to avoid exactly that.

## How the objects work

- A **capability token** looks like \`safekey://v1/<object-id>#<JWS>\`. It
  contains zero secret material and is safe to pass around, log, or include in
  tool calls. Treat it as a handle, not a value.
- A **folder** is ciphertext on disk plus a manifest. It is inert: possessing it
  grants nothing.
- The **sidecar** is a separate privileged process on the same host. It is the
  only thing that can turn a token into a value, and it never hands that value
  back to you.

## The four tools

1. **create_secret** — takes a PATH to a file containing the secret. The sidecar
   reads the file itself. There is no parameter for the value, so do not try to
   pass one. Returns a token and a folder path.
2. **resolve_for_tool** — takes a token and a command. Runs the command with the
   secret injected into its environment. Returns the command's own output and
   exit status, never the value.
3. **list_objects** — metadata only: ids, owners, wrapping-key ids. No values.
4. **revoke_token** — revokes by jti. Takes effect immediately, not at expiry.

## Working patterns

To use a secret in a command, prefer \`resolve_for_tool\` over trying to read it:

    resolve_for_tool(token="safekey://v1/obj_x#...", command=["gh", "api", "/user"])

The child process sees the value; you see the output. For a tool that needs a
file (a kubeconfig, a certificate), write the value out of band and give
\`create_secret\` the path.

## If a tool fails

- \`sidecar_unavailable\` — no sidecar is running on this host. Safekeys fails
  closed; there is no fallback that could resolve a secret. Ask the user to
  start it (\`make dev\`).
- \`denied\` — the sidecar refused. The reason is deliberately withheld from you
  (a detailed reason would help an attacker refine a forged token) and is
  recorded in the sidecar's audit log instead.

## Documentation

Read the \`safekeys://security-model\` resource for the threat model and what is
deliberately not mitigated. The full system specification lives in the repo's
\`.usm/\` files; use the \`usm\` MCP tools to search and read those.`;

/**
 * Resources exposed to agents.
 *
 * These are read-only documentation. None of them can carry a secret: they are
 * static text compiled into the server, describing the model rather than any
 * object in it.
 */
export interface ResourceSpec {
  uri: string;
  name: string;
  title: string;
  description: string;
  mimeType: string;
  text: string;
}

export const SECURITY_MODEL_TEXT = `# Safekeys security model

## The core property

No language model ever holds, receives, or can derive plaintext secret material
or a long-term key. This is architectural, not a policy: the model is not on the
decryption path.

## What this means concretely

- Agents receive tokens, folder paths, ciphertext, metadata, and success/deny
  status. Nothing else.
- Resolution happens only inside the sidecar, a separate privileged process
  running as a different OS user with no shared memory with agent processes.
- Plaintext exists only transiently inside the sidecar's injection path and is
  zeroised immediately after use.
- Creating a secret reads the value from a file the sidecar opens itself. The
  value never travels through a tool call, a log, or model context.

## Trust boundaries

| Boundary | Who may cross it |
| --- | --- |
| Model context | Tokens, paths, metadata, status — never values |
| Local socket | Any local process the OS permits to connect (mode 0600) |
| Key store | The sidecar only; the KEK never leaves it |
| Control plane | Sidecars and operators; it holds no plaintext |

## What is mitigated

- A compromised model, or prompt injection, cannot dump keys: it has nothing to
  dump, and injected values are not readable back through the sidecar.
- A stolen token is bounded by short TTL, audience binding, least-privilege
  scope, and immediate revocation.
- Copying a folder increases no exposure: it is ciphertext plus a manifest whose
  wrapped key is useless without the key store.
- A compromised control plane yields no secret; it holds no plaintext and the
  KEK lives in the key store.

## What is deliberately NOT mitigated

- **A rooted host.** In the software-only phase an OS-level compromise can attack
  the sidecar's memory. Phase 1 moves the long-term share into a TPM, cloud
  enclave, USB token, or secure element.
- **A human pasting a secret into a chat.** No architecture can prevent this. The
  product exists to make it unnecessary, not to detect it.
- **A multi-tenant AI-cloud KMS used as the root.** Explicitly rejected: the
  model provider could reach it, defeating the point. Use a self-hosted key store
  and, later, an HSM or secure element.
- **Harvest-now-decrypt-later against stored ciphertext.** Folders may be copied
  and kept indefinitely, so classical-only wrapping is exposed to future quantum
  capability. Phase 2 adds a hybrid classical plus ML-KEM-class ratchet.

## How this relates to other harness secret handling

This comparison is deliberate and intended to be honest. Other harnesses solve a
different, narrower problem, and in some respects they do things Safekeys does
not.

**Gateway credential systems (e.g. OpenClaw's SecretRefs).** These keep a
credential out of config and out of model context so the agent can *use* a
service. They are strong at that: secret references resolved into an in-memory
snapshot, opaque sentinels substituted only at the egress boundary for a bound
host, and refusal of unrecognised sentinel-shaped values. Their own documentation
is explicit about the limits — the store is a 0600-permission file, not an HSM,
and a secret reference "is not a process-isolation boundary", so a host-exec
agent can still read plaintext files it has access to.

The distinction that matters here: that class of system gets a credential to
*this* runtime safely. It does not aim to move a secret *between* agents,
environments, or people. Safekeys is the opposite emphasis — it is a transport
mechanism, and its use-time brokering is deliberately minimal.

**MCP URL-mode elicitation.** The protocol forbids requesting secrets through
form-mode elicitation and requires URL mode instead, which sends the user to an
out-of-band page so the value never passes through the client. That is the right
answer to "ask the operator for a credential" — but it also means the value never
leaves the operator's own machine to reach another agent, and it requires the
client to support elicitation. Not every client does.

This is why \`create_secret\` takes a *file path* rather than prompting or
accepting a value parameter. An interactive prompt would depend on a capability
the client may not declare, and a literal parameter would put the value in model
context. A file the sidecar opens itself needs neither.

**Where Safekeys is weaker.** A gateway with an egress proxy can protect a
credential from an agent that has shell access on the same host, because the
agent never holds the real value at all. In Safekeys' Phase 0 the secret is
materialised inside the sidecar on that same host, and a rooted host can attack
it. Phase 1 (TPM, enclave, USB token, secure element) and Phase 2 (threshold
splitting) close that gap; it is genuinely open today.

**Where Safekeys is stronger.** Ciphertext folders move freely between agents,
environments, and organisations with no shared infrastructure; authority travels
as a token that contains nothing secret; and the interface does not change as the
backend hardens. A use-time broker does not give you that.

## What a token contains

Claims: issuer, subject, object id, scope, audience, expiry, not-before, and a
unique id. There is no field capable of holding a value, and the schema sets
additionalProperties to false so one cannot be smuggled in.

Scopes are a closed set: read, unwrap, inject-env, inject-file, sign.

## Verifying this claim yourself

Run \`make demo\` in the repository: it creates a secret, uses it, and revokes it,
asserting at every step that the value never appears in the tool output, the
logs, or the ciphertext folder.
`;

export const RESOURCES: ResourceSpec[] = [
  {
    uri: "safekeys://security-model",
    name: "security-model",
    title: "Safekeys security model and threat model",
    description:
      "The threat model: what Safekeys mitigates, what it deliberately does not, " +
      "and the trust boundaries. Read this before advising on security.",
    mimeType: "text/markdown",
    text: SECURITY_MODEL_TEXT,
  },
];

/**
 * Folder README text, exposed as a resource template so a caller can ask what a
 * specific object is without handing the model ciphertext.
 */
export const FOLDER_README_TEMPLATE = `# Safekeys encrypted folder

This folder is an encrypted transport unit. It contains no plaintext and no key
material. It is inert: copying or moving it increases no cryptographic exposure.

Resolution requires all three of:
1. a valid, unexpired, in-audience, unrevoked capability token,
2. a running sidecar on the same host,
3. a reachable key authority holding the key-encryption key.

To use a secret from a folder, present its token to the sidecar:

    safekeys exec --token 'safekey://v1/<id>#<JWS>' -- your-command

The value is injected into your-command's environment. You receive an exit code,
not the value.
`;
