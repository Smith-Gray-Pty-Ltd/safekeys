/**
 * A real MCP client driving the Safekeys server over stdio.
 *
 * This is the acceptance test the spec asks for: an agent creates a secret and
 * uses it, and neither the tool results nor the transcripts contain plaintext.
 *
 * Run against a live control plane + sidecar:
 *   node scripts/mcp-smoke.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SECRET = "sk-live-MCP-SMOKE-MUST-NOT-LEAK-" + Math.random().toString(36).slice(2, 8);

function fail(msg) {
  console.error("FAIL:", msg);
  process.exit(1);
}

function ok(msg) {
  console.log("  ok —", msg);
}

// ── Set up a source file OUT OF BAND. The model never sees its contents; the
// sidecar reads the path itself.
const dir = mkdtempSync(join(tmpdir(), "safekeys-mcp-"));
const sourceFile = join(dir, "secret.txt");
writeFileSync(sourceFile, SECRET, { mode: 0o600 });

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(process.cwd(), "dist/index.js")],
  env: { ...process.env },
});

const client = new Client({ name: "smoke", version: "0.0.0" }, { capabilities: {} });

/** Everything the model would ever see. */
const transcript = [];
const record = (label, value) => transcript.push(`${label}: ${value}`);

try {
  await client.connect(transport);
  console.log("connected to safekeys MCP server\n");

  // ── 1. Tools are discoverable.
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name).sort();
  console.log("tools:", names.join(", "));
  for (const want of ["create_secret", "list_objects", "resolve_for_tool", "revoke_token"]) {
    if (!names.includes(want)) fail(`missing tool ${want}`);
  }
  ok("all four tools registered");

  // ── 2. create_secret must expose no value-bearing parameter.
  const createTool = tools.tools.find((t) => t.name === "create_secret");
  const props = Object.keys(createTool.inputSchema.properties ?? {});
  record("create_secret params", props.join(","));
  for (const forbidden of ["value", "secret", "plaintext", "content", "password"]) {
    if (props.includes(forbidden)) fail(`create_secret exposes a "${forbidden}" parameter`);
  }
  ok(`create_secret takes ${props.join(", ")} — no value parameter`);

  // ── 3. Create a secret. The result should carry a token, not the value.
  const created = await client.callTool({
    name: "create_secret",
    arguments: { source_file: sourceFile, scope: ["inject-env", "read"], ttl_seconds: 900 },
  });
  const createdText = created.content.map((c) => c.text).join("");
  record("create_secret result", createdText);
  if (createdText.includes(SECRET)) fail("create_secret result contains the plaintext");
  const createdJson = JSON.parse(createdText);
  if (!createdJson.token?.startsWith("safekey://v1/")) fail("no token returned");
  ok(`created ${createdJson.object_id}, token issued`);

  // ── 4. list_objects returns metadata only.
  const listed = await client.callTool({ name: "list_objects", arguments: {} });
  const listedText = listed.content.map((c) => c.text).join("");
  record("list_objects result", listedText);
  if (listedText.includes(SECRET)) fail("list_objects leaked the plaintext");
  ok("list_objects returned metadata only");

  // ── 5. resolve_for_tool runs a command with the secret injected. The command
  // proves it received the value; the tool result must not contain it.
  const markerFile = join(dir, "child-saw-it.txt");
  const resolved = await client.callTool({
    name: "resolve_for_tool",
    arguments: {
      token: createdJson.token,
      command: [
        "/bin/sh",
        "-c",
        `test -n "$SAFEKEYS_SECRET" && printf 'child-received-secret' > ${markerFile} && echo child-ran`,
      ],
    },
  });
  const resolvedText = resolved.content.map((c) => c.text).join("");
  record("resolve_for_tool result", resolvedText);
  if (resolvedText.includes(SECRET)) fail("resolve_for_tool leaked the plaintext");
  ok("resolve_for_tool returned status without the value");

  // The command actually saw it (so the test is not vacuous).
  const { readFileSync } = await import("node:fs");
  if (readFileSync(markerFile, "utf8") !== "child-received-secret") {
    fail("the wrapped command did not receive the injected secret");
  }
  ok("the wrapped command received the secret");

  // ── 6. Revoke, then confirm the token is refused.
  const jti = createdJson.jti;
  if (jti) {
    const revoked = await client.callTool({ name: "revoke_token", arguments: { jti } });
    record("revoke_token result", revoked.content.map((c) => c.text).join(""));
    ok(`revoked ${jti}`);

    await new Promise((r) => setTimeout(r, 2500)); // allow the revocation cache to lapse
    const after = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token: createdJson.token, command: ["/bin/sh", "-c", "echo SHOULD-NOT-RUN"] },
    });
    const afterText = after.content.map((c) => c.text).join("");
    record("post-revoke resolve", afterText);
    if (afterText.includes("SHOULD-NOT-RUN")) fail("a revoked token still resolved");
    ok("revoked token is refused");
  }

  // ── 7. The whole transcript must be clean.
  const full = transcript.join("\n");
  if (full.includes(SECRET)) {
    fail("the model-visible transcript contains the plaintext");
  }
  ok("no plaintext anywhere in the model-visible transcript");

  console.log("\nPASS — the MCP server never exposed the secret.");
  await client.close();
  process.exit(0);
} catch (err) {
  console.error("FAIL:", err);
  process.exit(1);
}
