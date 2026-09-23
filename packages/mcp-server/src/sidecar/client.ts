/**
 * Sidecar client.
 *
 * The MCP server talks ONLY to the local sidecar over its Unix domain socket.
 * It holds no control-plane credential, no keys, and performs no crypto — see
 * contract `delegate-to-sidecar` in
 * .usm/features/integration/mcp-server.usm.
 *
 * That separation matters because the MCP server runs inside the agent's process
 * space: a compromised agent must not inherit admin authority just by hosting
 * this server.
 */
import net from "node:net";
import os from "node:os";
import path from "node:path";

/** A sidecar request. Mirrors pkg/sidecar/server.go Request. */
export interface SidecarRequest {
  op?: "resolve" | "create" | "list" | "revoke";
  token?: string;
  scope?: string;
  name?: string;
  command?: string[];
  object_id?: string;
  source_file?: string;
  content_type?: string;
  scope_list?: string[];
  audience?: string;
  ttl_seconds?: number;
  jti?: string;
  principal?: string;
}

/** Object metadata. Never a value. */
export interface ObjectMetadata {
  id: string;
  folder_id?: string;
  owner_principal?: string;
  content_type?: string;
  wrapping_kid?: string;
  created_at?: string;
}

/** A create result: a token and a path, never a value. */
export interface CreatedInfo {
  object_id: string;
  folder: string;
  token: string;
  jti?: string;
  expires?: number;
  scope?: string[];
}

/** A sidecar response. Mirrors pkg/sidecar/server.go Response. */
export interface SidecarResponse {
  ok: boolean;
  descriptor?: string;
  exit_code?: number;
  stdout?: string;
  stderr?: string;
  error?: string;
  created?: CreatedInfo;
  objects?: ObjectMetadata[];
}

export class SidecarUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SidecarUnavailableError";
  }
}

export class SidecarDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SidecarDeniedError";
  }
}

/**
 * Default socket path. Matches SAFEKEYS_SOCKET in the Go components.
 *
 * It is a Unix socket rather than a TCP port so the OS enforces which local
 * processes may connect, via filesystem permissions.
 */
export function defaultSocketPath(): string {
  if (process.env.SAFEKEYS_SOCKET) return process.env.SAFEKEYS_SOCKET;
  return path.join(os.tmpdir(), "safekeys", "sidecar.sock");
}

export class SidecarClient {
  private readonly socketPath: string;
  private readonly timeoutMs: number;

  constructor(socketPath?: string, timeoutMs = 60_000) {
    this.socketPath = socketPath ?? defaultSocketPath();
    this.timeoutMs = timeoutMs;
  }

  /**
   * Send one request and read one response.
   *
   * There is deliberately no fallback path. If the sidecar is unreachable the
   * call fails — see contract `delegate-to-sidecar` and conformance vector
   * `sidecar-unavailable-is-an-error`. Silently resolving locally would defeat
   * the entire design.
   */
  async send(req: SidecarRequest): Promise<SidecarResponse> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = "";
      let settled = false;

      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        fn();
      };

      socket.setTimeout(this.timeoutMs);

      socket.on("connect", () => {
        socket.write(JSON.stringify(req));
        // Signal end-of-request so the sidecar's decoder sees a complete message.
        socket.end();
      });

      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
      });

      socket.on("end", () => {
        finish(() => {
          try {
            resolve(JSON.parse(buffer) as SidecarResponse);
          } catch {
            reject(new SidecarUnavailableError("malformed response from sidecar"));
          }
        });
      });

      socket.on("timeout", () => {
        finish(() => reject(new SidecarUnavailableError("sidecar timed out")));
      });

      socket.on("error", (err: NodeJS.ErrnoException) => {
        finish(() => {
          if (err.code === "ENOENT" || err.code === "ECONNREFUSED") {
            reject(
              new SidecarUnavailableError(
                `no sidecar listening at ${this.socketPath}; Safekeys fails closed rather than resolving locally`,
              ),
            );
          } else {
            reject(new SidecarUnavailableError(err.message));
          }
        });
      });
    });
  }

  /** Resolve a token into a consumer. Returns status, never a value. */
  async resolve(req: SidecarRequest): Promise<SidecarResponse> {
    return this.send({ ...req, op: "resolve" });
  }

  /** Create a secret from a source file. This client cannot send a value. */
  async create(req: SidecarRequest): Promise<SidecarResponse> {
    return this.send({ ...req, op: "create" });
  }

  /** List object metadata. */
  async list(): Promise<SidecarResponse> {
    return this.send({ op: "list" });
  }

  /** Revoke a token by jti. */
  async revoke(jti: string): Promise<SidecarResponse> {
    return this.send({ op: "revoke", jti });
  }
}
