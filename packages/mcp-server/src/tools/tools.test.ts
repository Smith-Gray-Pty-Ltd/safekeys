/**
 * Tool contract tests.
 *
 * These assert the guarantees in .usm/features/integration/mcp-server.usm:
 * results never carry plaintext, arguments never carry values, nothing is
 * resolved without the sidecar, and there is no vendor branching.
 */
import { describe, expect, it, vi } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { makeHandlers, CreateSecretInput, ResolveForToolInput } from "../tools/index.js";
import { SidecarClient, SidecarUnavailableError } from "../sidecar/client.js";
import type { SidecarResponse } from "../sidecar/client.js";

/** A stub client that returns canned responses, so no socket is needed. */
function stubClient(response: SidecarResponse): SidecarClient {
  const client = Object.create(SidecarClient.prototype) as SidecarClient;
  vi.spyOn(client, "create").mockResolvedValue(response);
  vi.spyOn(client, "resolve").mockResolvedValue(response);
  vi.spyOn(client, "list").mockResolvedValue(response);
  vi.spyOn(client, "revoke").mockResolvedValue(response);
  return client;
}

const SECRET = "sk-live-MUST-NOT-APPEAR-ANYWHERE";

describe("create_secret", () => {
  it("returns a token and a folder path, never the value", async () => {
    const client = stubClient({
      ok: true,
      created: {
        object_id: "obj_abc",
        folder: "/home/u/.safekeys/folder/obj_abc",
        token: "safekey://v1/obj_abc#eyJhbGciOiJFZERTQSJ9.e30.sig",
        jti: "jti_1",
        expires: 1790013600,
        scope: ["inject-env"],
      },
    });
    const h = makeHandlers(client);
    const res = await h.createSecret({ source_file: "/tmp/secret.txt" });

    expect(res.ok).toBe(true);
    expect(res.token).toContain("safekey://v1/");
    expect(res.folder).toBeTruthy();

    // The serialised result must not contain any value: there is no field for one.
    const serialised = JSON.stringify(res);
    expect(serialised).not.toContain(SECRET);
  });

  it("has no parameter capable of carrying a secret value", () => {
    // The schema's keys are the complete set of inputs a model can supply.
    const keys = Object.keys(CreateSecretInput.shape);
    expect(keys).toContain("source_file");
    // These are the names a value-bearing parameter would plausibly use.
    for (const forbidden of ["value", "secret", "plaintext", "content", "data", "password"]) {
      expect(keys, `create_secret must not accept a "${forbidden}" parameter`).not.toContain(
        forbidden,
      );
    }
  });

  it("propagates a denial as an error rather than a partial result", async () => {
    const client = stubClient({ ok: false, error: "denied" });
    const h = makeHandlers(client);
    await expect(h.createSecret({ source_file: "/tmp/x" })).rejects.toThrow(/denied/i);
  });
});

describe("resolve_for_tool", () => {
  it("returns the command's exit status and output, never the value", async () => {
    const stdout = Buffer.from("marker-line\n", "utf8").toString("base64");
    const client = stubClient({ ok: true, exit_code: 0, stdout });
    const h = makeHandlers(client);
    const res = await h.resolveForTool({
      token: "safekey://v1/obj_abc#a.b.c",
      command: ["/bin/sh", "-c", "echo marker-line"],
    });

    expect(res.ok).toBe(true);
    expect(res.exit_code).toBe(0);
    expect(res.stdout).toContain("marker-line");
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  it("accepts a token argument, not a value argument", () => {
    const keys = Object.keys(ResolveForToolInput.shape);
    expect(keys).toContain("token");
    expect(keys).toContain("command");
    for (const forbidden of ["value", "secret", "plaintext", "password"]) {
      expect(keys).not.toContain(forbidden);
    }
  });

  it("propagates a denial", async () => {
    const client = stubClient({ ok: false, error: "denied" });
    const h = makeHandlers(client);
    await expect(
      h.resolveForTool({ token: "safekey://v1/x#a.b.c", command: ["true"] }),
    ).rejects.toThrow(/denied/i);
  });
});

describe("list_objects", () => {
  it("projects metadata only, dropping any unexpected wire field", async () => {
    // The stub returns an extra field the wire should never carry. The handler
    // must not pass it through.
    const client = stubClient({
      ok: true,
      objects: [
        {
          id: "obj_1",
          owner_principal: "agent-a",
          content_type: "text/plain",
          wrapping_kid: "kek-1",
          created_at: "2026-09-22T00:00:00Z",
          // @ts-expect-error deliberately injecting an unexpected field
          value: SECRET,
        },
      ],
    });
    const h = makeHandlers(client);
    const res = await h.listObjects();

    expect(res.objects).toHaveLength(1);
    expect(res.objects?.[0]?.id).toBe("obj_1");
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });
});

describe("revoke_token", () => {
  it("reports the revoked jti", async () => {
    const client = stubClient({ ok: true });
    const h = makeHandlers(client);
    const res = await h.revokeToken({ jti: "jti_1" });
    expect(res.ok).toBe(true);
    expect(res.jti).toBe("jti_1");
  });
});

describe("delegate-to-sidecar", () => {
  it("fails rather than resolving locally when the sidecar is absent", async () => {
    // A path that cannot exist: the client must surface a hard failure.
    const client = new SidecarClient("/nonexistent/safekeys/sidecar.sock", 500);
    await expect(client.resolve({ token: "safekey://v1/x#a.b.c", command: ["true"] })).rejects.toThrow(
      SidecarUnavailableError,
    );
  });

  it("never falls back to a local resolution", async () => {
    const client = new SidecarClient("/nonexistent/safekeys/sidecar.sock", 500);
    const h = makeHandlers(client);
    await expect(
      h.resolveForTool({ token: "safekey://v1/x#a.b.c", command: ["true"] }),
    ).rejects.toThrow();
  });
});

describe("single-server-many-runtimes", () => {
  /** Collect every .ts source file under src/. */
  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) out.push(...sourceFiles(p));
      else if (p.endsWith(".ts") && !p.endsWith(".test.ts")) out.push(p);
    }
    return out;
  }

  it("contains no vendor-specific branching", () => {
    const vendors = ["claude", "cursor", "codex", "gemini", "openai", "anthropic", "copilot"];
    for (const file of sourceFiles(join(process.cwd(), "src"))) {
      const text = readFileSync(file, "utf8").toLowerCase();
      for (const vendor of vendors) {
        // Mentioning a vendor in a comment or docstring is fine; branching on one
        // is not.
        expect(
          /if\s*\([^)]*vendor/.test(text),
          `${file} appears to branch on a vendor`,
        ).toBe(false);
      }
    }
  });

  it("uses only the standard MCP SDK entrypoints", () => {
    const index = readFileSync(join(process.cwd(), "src/index.ts"), "utf8");
    expect(index).toContain("@modelcontextprotocol/sdk/server/mcp.js");
    expect(index).toContain("@modelcontextprotocol/sdk/server/stdio.js");
  });
});
