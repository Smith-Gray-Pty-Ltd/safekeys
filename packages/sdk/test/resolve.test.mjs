// Token-only contract tests for the TS SDK, driven against a fake sidecar
// socket that speaks the real NDJSON wire protocol (mirrors pkg/sidecar).
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import net from "node:net";
import os from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { Safekeys } from "../dist/index.js";

const tmp = mkdtempSync(join(os.tmpdir(), "sk-sdk-"));
const sockPath = join(tmp, "s.sock");

let server;
const scripted = new Map();

beforeAll(async () => {
  server = net.createServer((conn) => {
    let buf = "";
    conn.on("data", (d) => {
      buf += d.toString("utf8");
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line);
        const resp = scripted.get(req.op);
        conn.end(JSON.stringify(resp) + "\n");
      }
    });
  });
  await new Promise((r) => server.listen(sockPath, r));
});

afterAll(() => {
  server?.close();
  rmSync(tmp, { recursive: true, force: true });
});

describe("Safekeys SDK (token-only contract)", () => {
  it("createSecret returns a token and folder, never a value", async () => {
    scripted.set("create", {
      ok: true,
      created: { object_id: "obj_t1", folder: "/folders/obj_t1", token: "safekey://v1/obj_t1#jws", jti: "jti_1", expires: 1, scope: ["inject-env"] },
    });
    const sk = new Safekeys({ socketPath: sockPath });
    const c = await sk.createSecret("/tmp/secret.txt");
    expect(c.token).toBe("safekey://v1/obj_t1#jws");
    expect(JSON.stringify(c)).not.toContain("the-actual-value");
  });

  it("resolveForTool returns redacted output and status — never the value", async () => {
    scripted.set("resolve", {
      ok: true,
      descriptor: "env:SAFEKEYS_SECRET",
      exit_code: 0,
      stdout: Buffer.from("[REDACTED:safekeys]\n").toString("base64"),
      stderr: "",
    });
    const sk = new Safekeys({ socketPath: sockPath });
    const r = await sk.resolveForTool("safekey://v1/obj_t1#jws", ["gh", "api", "/user"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("[REDACTED:safekeys]");
    expect(JSON.stringify(r)).not.toContain("sk-live");
  });

  it("denials throw and carry no detail beyond the denial", async () => {
    scripted.set("resolve", { ok: false, error: "denied" });
    const sk = new Safekeys({ socketPath: sockPath });
    await expect(sk.resolveForTool("safekey://v1/x#y", ["/bin/true"])).rejects.toThrow(/fails closed/);
  });

  it("sends origin=sdk so the sidecar applies the SDK command policy", async () => {
    let seen;
    const server2 = net.createServer((conn) => {
      conn.on("data", (d) => {
        seen = JSON.parse(d.toString().split("\n")[0]);
        conn.end(JSON.stringify({ ok: true, descriptor: "", exit_code: 0 }) + "\n");
      });
    });
    await new Promise((r) => server2.listen(join(tmp, "echo.sock"), r));
    const sk2 = new Safekeys({ socketPath: join(tmp, "echo.sock") });
    await sk2.resolveForTool("safekey://v1/x#y", ["/bin/true"]);
    expect(seen.origin).toBe("sdk");
    expect(seen.command).toEqual(["/bin/true"]);
    server2.close();
  });
});
