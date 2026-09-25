/**
 * Safekeys MCP server entrypoint.
 *
 * One MCP server exposes Safekeys tools to every MCP-capable agent runtime —
 * Claude, Cursor, Codex, Gemini — over standard stdio transport. There is no
 * vendor-specific branching anywhere in this package, by design: see contract
 * `single-server-many-runtimes`.
 *
 * Security posture:
 *   - the server holds NO control-plane credential and NO key material
 *   - every operation is delegated to the local sidecar over a Unix socket
 *   - if the sidecar is unavailable the call fails; there is no fallback
 *   - no tool result type has a field capable of carrying plaintext
 *
 * NOTE: stdout is the MCP transport. All diagnostics go to stderr.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

import { SidecarClient, SidecarUnavailableError, SidecarDeniedError } from "./sidecar/client.js";
import {
  makeHandlers,
  CreateSecretInput,
  ResolveForToolInput,
  ListObjectsInput,
  RevokeTokenInput,
} from "./tools/index.js";
import type { ToolResult } from "./tools/index.js";
import { SERVER_INSTRUCTIONS, RESOURCES, FOLDER_README_TEMPLATE } from "./instructions.js";

/** Version reported to the host runtime. */
export const VERSION = "0.1.0";

/** The MCP content shape a tool returns. */
type ToolContent = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

/** Turn a thrown error into a generic, non-leaking tool response. */
export function renderError(err: unknown): ToolContent {
  // Denials are deliberately generic — a detailed reason is a probing oracle
  // (ADR generic-denials). The real reason is in the sidecar's audit log.
  let body: Record<string, unknown>;
  if (err instanceof SidecarUnavailableError) {
    body = {
      ok: false,
      error: "sidecar_unavailable",
      message: `${err.message} Safekeys fails closed: no secret can be created or resolved without the local sidecar.`,
    };
  } else if (err instanceof SidecarDeniedError) {
    body = { ok: false, error: "denied", message: "Denied." };
  } else {
    body = { ok: false, error: "error", message: "Internal error." };
  }
  return { content: [{ type: "text", text: JSON.stringify(body, null, 2) }], isError: true };
}

/** Render a successful result as JSON text. Contains no secret material. */
export function renderResult(r: ToolResult): ToolContent {
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
}

/**
 * Build the MCP server with all four tools registered.
 *
 * Exported so tests can drive it in-process without spawning a child.
 */
export function buildServer(client: SidecarClient): McpServer {
  // The instructions field is delivered in the initialize response, so an agent
  // has the operating contract before it calls anything. It carries the "never
  // ask for a value" rule, which no per-tool description can express.
  const server = new McpServer(
    { name: "safekeys", version: VERSION },
    { instructions: SERVER_INSTRUCTIONS },
  );
  const handlers = makeHandlers(client);

  // Documentation resources. Static text compiled into the server — none of
  // these can carry a secret, because none of them describe an object.
  for (const r of RESOURCES) {
    server.registerResource(
      r.name,
      r.uri,
      { title: r.title, description: r.description, mimeType: r.mimeType },
      async (uri) => ({
        contents: [{ uri: uri.href, mimeType: r.mimeType, text: r.text }],
      }),
    );
  }

  // A template for any folder's README, so a caller can ask what an object is
  // without being handed ciphertext.
  server.registerResource(
    "folder-readme",
    new ResourceTemplate("safekeys://folder/{id}/readme", { list: undefined }),
    {
      title: "Encrypted folder README",
      description: "Explains what a Safekeys folder is and how it is used. Contains no secrets.",
      mimeType: "text/markdown",
    },
    async (uri, vars) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: `# Safekeys folder: ${String(vars.id ?? "unknown")}\n\n${FOLDER_README_TEMPLATE}`,
        },
      ],
    }),
  );

  server.registerTool(
    "create_secret",
    {
      title: "Create a secret",
      description:
        "Create a secret without ever handling its value. Takes a path to a file " +
        "containing the secret; the sidecar reads and encrypts it, and this tool " +
        "returns only a capability token and the ciphertext folder path. There is " +
        "deliberately no parameter for the value itself, so the secret never passes " +
        "through the model.",
      inputSchema: CreateSecretInput.shape,
    },
    async (args) => {
      try {
        return renderResult(await handlers.createSecret(args));
      } catch (err) {
        return renderError(err);
      }
    },
  );

  server.registerTool(
    "resolve_for_tool",
    {
      title: "Run a command with a secret injected",
      description:
        "Resolve a capability token and run a command with the secret injected into " +
        "its environment. The command sees the value; this tool returns only the " +
        "command's own output and exit status. The value is never returned here.",
      inputSchema: ResolveForToolInput.shape,
    },
    async (args) => {
      try {
        return renderResult(await handlers.resolveForTool(args));
      } catch (err) {
        return renderError(err);
      }
    },
  );

  server.registerTool(
    "list_objects",
    {
      title: "List secret objects",
      description:
        "List registered secret objects. Returns metadata only — object ids, owners, " +
        "and wrapping-key ids. Values are never listed and cannot be retrieved here.",
      inputSchema: ListObjectsInput.shape,
    },
    async () => {
      try {
        return renderResult(await handlers.listObjects());
      } catch (err) {
        return renderError(err);
      }
    },
  );

  server.registerTool(
    "revoke_token",
    {
      title: "Revoke a capability token",
      description:
        "Revoke a capability token by its id. Revocation takes effect immediately " +
        "rather than at expiry, so this is the kill switch for a token believed leaked.",
      inputSchema: RevokeTokenInput.shape,
    },
    async (args) => {
      try {
        return renderResult(await handlers.revokeToken(args));
      } catch (err) {
        return renderError(err);
      }
    },
  );

  return server;
}

async function main(): Promise<void> {
  const client = new SidecarClient();
  const server = buildServer(client);
  await server.connect(new StdioServerTransport());
}

// Start only when executed directly, so tests can import this module safely.
const invokedDirectly =
  process.argv[1] !== undefined && /(?:^|[\\/])index\.(?:js|ts)$/.test(process.argv[1]);

if (invokedDirectly) {
  main().catch((err: unknown) => {
    process.stderr.write(`safekeys-mcp: ${String(err)}\n`);
    process.exit(1);
  });
}
