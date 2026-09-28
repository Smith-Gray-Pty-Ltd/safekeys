/**
 * Safekeys TypeScript SDK — token-only client for agents.
 *
 * Contract (safekeys/python-sdk, mirrored): the API accepts and returns only
 * capability tokens and folder paths. It performs no cryptography and holds
 * no credentials: every resolution is delegated to the local sidecar over a
 * Unix socket. There is no method that can return a resolved value.
 *
 * EARLY PREVIEW — the API surface may change before 1.0.
 *
 * Create: takes a PATH, never a value. The sidecar reads the file itself, so
 * a model authoring the call cannot pass a value even under prompt injection.
 * Use: the command receives the value in its environment; you receive its
 * redacted, size-capped output and exit status.
 */

import * as net from "node:net";

/** A Unix-domain-socket client for the local sidecar. Zero dependencies. */
class SidecarClient {
  constructor(private readonly socketPath: string) {}

  request(req: Record<string, unknown>): Promise<Record<string, unknown>> {
    // Vendored minimal NDJSON-over-UDS client: connect, newline-delimited
    // JSON, read one response, close — the sidecar's wire protocol.
    return new Promise((resolve, reject) => {
      const sock = net.connect(this.socketPath);
      let buf = "";
      // The sidecar answers one JSON value per request (json.Encoder.Encode
      // emits a trailing newline) and may keep the socket open; resolve on
      // the first complete value rather than on connection close.
      const tryParse = () => {
        const idx = buf.indexOf("\n");
        if (idx < 0) return;
        const line = buf.slice(0, idx);
        try {
          resolve(JSON.parse(line));
        } catch (e) {
          reject(e);
        }
        sock.destroy();
      };
      sock.on("connect", () => sock.write(JSON.stringify(req) + "\n"));
      sock.on("data", (d: Buffer) => {
        buf += d.toString("utf8");
        tryParse();
      });
      sock.on("error", reject);
      sock.on("end", () => {
        // Server closed without a full line: a protocol failure.
        tryParse();
      });
    });
  }
}

/** Result of a resolve: token-only by construction. */
export interface ResolveResult {
  descriptor: string;
  exitCode: number;
  stdout: string; // redacted and size-capped by the sidecar
  stderr: string;
}

/** Result of a create: a token and a folder path, never a value. */
export interface CreatedSecret {
  objectId: string;
  folder: string;
  token: string; // safekey://v1/...#<JWS> — zero secret material
  jti?: string;
  expires?: number;
  scope?: string[];
}

export class Safekeys {
  private client: SidecarClient;

  constructor(opts: { socketPath?: string } = {}) {
    const socketPath =
      opts.socketPath ??
      process.env.SAFEKEYS_SOCKET ??
      `${(process.env.TMPDIR ?? "/tmp").replace(/\/$/, "")}/safekeys/sidecar.sock`;
    this.client = new SidecarClient(socketPath);
  }

  /** Create a secret from a file path. The value never passes through this SDK. */
  async createSecret(sourceFile: string, opts: { scope?: string[]; ttlSeconds?: number; audience?: string } = {}): Promise<CreatedSecret> {
    const res = await this.client.request({
      op: "create",
      source_file: sourceFile,
      scope_list: opts.scope ?? ["inject-env", "read"],
      ttl_seconds: opts.ttlSeconds ?? 900,
      audience: opts.audience,
      principal: process.env.SAFEKEYS_PRINCIPAL ?? "operator",
    });
    if (!res.ok) throw new Error(`safekeys: create denied by the sidecar (fails closed)`);
    const c = res.created as { object_id: string; folder: string; token: string; jti?: string; expires?: number; scope?: string[] };
    return { objectId: c.object_id, folder: c.folder, token: c.token, jti: c.jti, expires: c.expires, scope: c.scope };
  }

  /**
   * Run a command with the secret injected into its environment. Returns the
   * command's redacted, size-capped output and exit status — never the value.
   * Commands are policy-limited: an operator-authored allowlist is required
   * for MCP-style flows, and known dumpers are refused (safekeys/output-control).
   */
  async resolveForTool(token: string, command: string[], opts: { name?: string } = {}): Promise<ResolveResult> {
    const res = await this.client.request({
      op: "resolve",
      token,
      scope: "inject-env",
      name: opts.name ?? "SAFEKEYS_SECRET",
      command,
      origin: "sdk",
    });
    if (!res.ok) throw new Error(`safekeys: resolve denied by the sidecar (fails closed)`);
    return {
      descriptor: (res.descriptor as string) ?? "",
      exitCode: (res.exit_code as number) ?? 0,
      // The wire format carries []byte as base64 (Go's encoding/json).
      stdout: decodeMaybeB64(res.stdout),
      stderr: decodeMaybeB64(res.stderr),
    };
  }

  /** Revoke a token by jti. Takes effect immediately, not at expiry. */
  async revoke(jti: string): Promise<void> {
    const res = await this.client.request({ op: "revoke", jti });
    if (!res.ok) throw new Error("safekeys: revoke denied by the sidecar");
  }
}

export default Safekeys;

// Go marshals []byte as base64; plain strings pass through untouched.
function decodeMaybeB64(v: unknown): string {
  if (v == null) return "";
  if (Buffer.isBuffer(v)) return v.toString("utf8");
  if (typeof v === "string") {
    try {
      return Buffer.from(v, "base64").toString("utf8");
    } catch {
      return v;
    }
  }
  return String(v);
}
