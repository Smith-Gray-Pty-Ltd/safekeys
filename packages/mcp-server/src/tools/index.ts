/**
 * Safekeys MCP tools.
 *
 * Four tools, and every one of them is token-only. The governing contract is
 * `token-only-tool-results` in .usm/features/integration/mcp-server.usm:
 *
 *   - results carry tokens, folder paths, or status codes
 *   - no tool returns a resolved value
 *   - tool arguments carry tokens, not values
 *
 * The type signatures below are part of the enforcement. A tool's output type
 * has no field capable of holding plaintext, so a handler cannot return one even
 * by mistake.
 */
import { z } from "zod";
import type { SidecarClient, ObjectMetadata } from "../sidecar/client.js";
import { SidecarDeniedError, SidecarUnavailableError } from "../sidecar/client.js";

/**
 * The scopes a caller may request. Closed set, mirroring the token schema.
 */
export const SCOPES = ["read", "unwrap", "inject-env", "inject-file", "sign"] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * A tool result.
 *
 * Note what is absent: no `value`, no `secret`, no `content` field. This is the
 * structural guarantee — there is nowhere for plaintext to travel.
 */
export interface ToolResult {
  ok: boolean;
  /** A short human/model-readable summary containing no secret material. */
  message: string;
  /** Present on create_secret: a capability token and where the folder lives. */
  object_id?: string;
  folder?: string;
  token?: string;
  jti?: string;
  expires?: number;
  scope?: string[];
  /** Present on list_objects: metadata only. */
  objects?: Array<{
    id: string;
    owner?: string;
    content_type?: string;
    wrapping_kid?: string;
    created_at?: string;
  }>;
  /** On resolve_for_tool: the consumer's exit status, when one ran. */
  exit_code?: number;
  /** The consumer's own stdout, when the caller asked for it. */
  stdout?: string;
}

// ─── Input schemas ──────────────────────────────────────────────────────────

/**
 * create_secret takes a SOURCE FILE, not a value.
 *
 * This is the whole point. A model authoring this call can name a path it knows
 * exists on the host, but it never has the bytes — the sidecar reads the file
 * itself. There is no `value` parameter, so a model cannot pass one even if
 * instructed to.
 */
export const CreateSecretInput = z.object({
  source_file: z
    .string()
    .min(1)
    .describe(
      "Absolute path to a file on the local host containing the secret value. " +
        "The sidecar reads this file itself; the value is never passed through " +
        "the tool call. Write the secret to the file out-of-band before calling.",
    ),
  object_id: z
    .string()
    .optional()
    .describe("Optional object id. Generated when omitted."),
  content_type: z
    .string()
    .optional()
    .describe("Optional media-type hint, e.g. text/plain or application/x-pem-file."),
  scope: z
    .array(z.enum(SCOPES))
    .optional()
    .describe("Scopes to grant the returned token. Defaults to ['inject-env','read']."),
  audience: z
    .string()
    .optional()
    .describe("Audience/environment the token is bound to. Defaults to the sidecar's own."),
  ttl_seconds: z
    .number()
    .int()
    .positive()
    .max(43_200)
    .optional()
    .describe("Token lifetime in seconds. Bounded to 12 hours; tokens are short-lived by design."),
});

/** resolve_for_tool consumes a token and runs a command with the secret injected. */
export const ResolveForToolInput = z.object({
  token: z
    .string()
    .min(1)
    .describe(
      "A capability token URI, e.g. safekey://v1/<id>#<JWS>. This contains no " +
        "secret material and is safe to pass. The sidecar resolves it; the value " +
        "is injected into the command, never returned here.",
    ),
  command: z
    .array(z.string())
    .min(1)
    .describe(
      "The command to run with the secret injected into its environment, as an " +
        "argv array. The secret appears only in the child's environment.",
    ),
  name: z
    .string()
    .optional()
    .describe("Environment variable name for the injected value. Defaults to SAFEKEYS_SECRET."),
  scope: z
    .enum(SCOPES)
    .optional()
    .describe("Operation to request. Defaults to inject-env."),
});

export const ListObjectsInput = z.object({});

export const RevokeTokenInput = z.object({
  jti: z
    .string()
    .min(1)
    .describe("The token id to revoke. Revocation takes effect immediately, not at expiry."),
});

// ─── Handlers ───────────────────────────────────────────────────────────────

export interface Handlers {
  createSecret(input: z.infer<typeof CreateSecretInput>): Promise<ToolResult>;
  resolveForTool(input: z.infer<typeof ResolveForToolInput>): Promise<ToolResult>;
  listObjects(): Promise<ToolResult>;
  revokeToken(input: z.infer<typeof RevokeTokenInput>): Promise<ToolResult>;
}

/** Build the tool handlers over a sidecar client. */
export function makeHandlers(client: SidecarClient): Handlers {
  return {
    async createSecret(input): Promise<ToolResult> {
      const res = await client.create({
        source_file: input.source_file,
        object_id: input.object_id,
        content_type: input.content_type,
        scope_list: input.scope as string[] | undefined,
        audience: input.audience,
        ttl_seconds: input.ttl_seconds,
      });
      if (!res.ok || !res.created) {
        throw new SidecarDeniedError(res.error ?? "denied");
      }
      const c = res.created;
      // A token and a path leave this function — never the value.
      return {
        ok: true,
        message: `Created secret ${c.object_id}. A token was issued and the ciphertext folder is at ${c.folder}. The value was read by the sidecar and never passed through this call.`,
        object_id: c.object_id,
        folder: c.folder,
        token: c.token,
        jti: c.jti,
        expires: c.expires,
        scope: c.scope,
      };
    },

    async resolveForTool(input): Promise<ToolResult> {
      const res = await client.resolve({
        token: input.token,
        command: input.command,
        name: input.name,
        scope: input.scope ?? "inject-env",
      });
      if (!res.ok) {
        throw new SidecarDeniedError(res.error ?? "denied");
      }
      // The command's own output is relayed; the injected value is not.
      return {
        ok: true,
        message: `Command ran with the secret injected. Exit status ${res.exit_code ?? 0}. The value was never returned to this caller.`,
        exit_code: res.exit_code ?? 0,
        stdout: decodeMaybeB64(res.stdout),
      };
    },

    async listObjects(): Promise<ToolResult> {
      const res = await client.list();
      if (!res.ok) {
        throw new SidecarDeniedError(res.error ?? "denied");
      }
      const objects = (res.objects ?? []).map(projectMetadata);
      return {
        ok: true,
        message: `${objects.length} object(s). Metadata only — values are never listed.`,
        objects,
      };
    },

    async revokeToken(input): Promise<ToolResult> {
      const res = await client.revoke(input.jti);
      if (!res.ok) {
        throw new SidecarDeniedError(res.error ?? "denied");
      }
      return { ok: true, message: `Revoked ${input.jti}. This takes effect immediately.`, jti: input.jti };
    },
  };
}

/**
 * Project an object record down to display fields.
 *
 * Written explicitly rather than spreading the input, so a new field on the
 * wire cannot leak into a tool result by default.
 */
function projectMetadata(o: ObjectMetadata): NonNullable<ToolResult["objects"]>[number] {
  return {
    id: o.id,
    owner: o.owner_principal,
    content_type: o.content_type,
    wrapping_kid: o.wrapping_kid,
    created_at: o.created_at,
  };
}

/**
 * The Go sidecar base64-encodes byte fields. Decode for display; on failure
 * return the empty string rather than guessing.
 */
function decodeMaybeB64(s: string | undefined): string | undefined {
  if (!s) return undefined;
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return undefined;
  }
}

export { SidecarDeniedError, SidecarUnavailableError };
