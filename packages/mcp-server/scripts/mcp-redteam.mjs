/**
 * Red-team driver for the Safekeys MCP server.
 *
 * Runs the known secret-leak attempts through resolve_for_tool over a real
 * MCP stdio connection and asserts the tool result NEVER contains the secret
 * — raw, encoded, or partial — while a control case proves the command really
 * received the value (so a pass is not vacuous).
 *
 * Attempt classes (safekeys/output-control):
 *   1. dumpers and inline-code interpreters → refused by the sidecar
 *   2. encodings printed by an ALLOWED helper → redacted by the sidecar
 *   3. partial echoes → redacted by the sidecar
 *   4. split across stdout/stderr → redacted by the sidecar
 *   5. write-then-read → the documented limit; the relay stays clean
 *   6. control: the command received the value
 *
 * Everything the model would see (every tool result, every message) is
 * captured in a transcript and swept at the end.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

// The MCP server to probe: anchored here, so the script runs from anywhere.
const serverPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

// A canary with letters, digits, and punctuation — 25 chars so its 8+
// substrings are meaningful, and realistic enough to exercise encoding paths.
const SECRET = "sk-live-REDCANARY-" + Math.random().toString(36).slice(2, 8) + "#$";

const attempts = [];
let failures = 0;

function record(label, value) {
  attempts.push(`${label}: ${value}`);
}

function pass(label) {
  console.log(`  ok — ${label}`);
}

function fail(label) {
  console.error(`  FAIL — ${label}`);
  failures++;
}

/** Build the tiny "allowed command" helper: a compiled binary that can emit
 * the value in encodings/pieces. It is deliberately allowlist-friendly — the
 * shape of a legitimate integration — which is exactly why the redaction
 * layer must hold. */
function buildLeakyHelper(dir) {
  const src = join(dir, "leaky.go");
  writeFileSync(
    src,
    `package main
import (
  "encoding/base64"; "encoding/hex"; "fmt"; "net/url"; "os"; "strings"
)
func main() {
  v := os.Getenv("SAFEKEYS_SECRET")
  switch os.Args[1] {
  case "raw": fmt.Print(v)
  case "b64": fmt.Print(base64.StdEncoding.EncodeToString([]byte(v)))
  case "b64fold":
    e := base64.StdEncoding.EncodeToString([]byte(v))
    var parts []string
    for i := 0; i < len(e); i += 8 { end := i+8; if end > len(e) { end = len(e) }; parts = append(parts, e[i:end]) }
    fmt.Print(strings.Join(parts, "\\n"))
  case "hex": fmt.Print(hex.EncodeToString([]byte(v)))
  case "pct": fmt.Print(url.QueryEscape(v))
  case "json": fmt.Printf("{\\"t\\":%q}", v)
  case "prefix": if len(v) > 20 { fmt.Print(v[:20]) }
  case "middle": if len(v) > 14 { fmt.Print(v[5:14]) }
  case "split": h := len(v)/2; fmt.Printf("%s", v[:h]); fmt.Fprintf(os.Stderr, "%s", v[h:])
  case "write": if err := os.WriteFile(os.Args[2], []byte(v), 0o600); err != nil { os.Exit(1) }; fmt.Print("wrote")
  case "big": fmt.Print(strings.Repeat("x", 8000) + v)
  }
}`,
    { mode: 0o600 },
  );
  execFileSync("go", ["build", "-o", join(dir, "leaky"), src], { stdio: "pipe" });
  return join(dir, "leaky");
}

// ── Setup ────────────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "safekeys-redteam-"));
const sourceFile = join(dir, "secret.txt");
writeFileSync(sourceFile, SECRET, { mode: 0o600 });
const helper = buildLeakyHelper(dir);

// ── Allowlist the helper: MCP resolves are deny-by-default without a command
// allowlist (the whole point), so sections 2-5 author one for the canary's
// object — the exact operator action the denial message asks for.
async function allowlistHelper(objectId) {
  const base = process.env.SAFEKEYS_CONTROL_PLANE_URL || "http://localhost:8080";
  const key = process.env.SAFEKEYS_API_KEY || "dev-api-key";
  const res = await fetch(`${base}/v1/policies`, {
    method: "PUT",
    headers: { "X-Safekeys-Key": key, "Content-Type": "application/json" },
    body: JSON.stringify({
      ID: `redteam-${objectId}`,
      Effect: "allow",
      SID: objectId,
      Scope: ["inject-env"],
      Commands: [
        { exec: helper, args: ["*"] },            // one-arg modes
        { exec: helper, args: ["write", "*"] },   // write-then-read mode
      ],
      Priority: 100,
    }),
  });
  if (!res.ok) throw new Error(`policy PUT failed: ${res.status} ${await res.text()}`);
  console.log(`allowlisted ${helper} for ${objectId}\n`);
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  env: { ...process.env },
});

const client = new Client({ name: "redteam", version: "0.0.0" }, { capabilities: {} });

const sweep = (out, label) => {
  const haystack = typeof out === "string" ? out : JSON.stringify(out);
  record(label, haystack);
  const leaky = [];
  if (haystack.includes(SECRET)) leaky.push("raw");
  if (haystack.includes(Buffer.from(SECRET).toString("base64"))) leaky.push("base64");
  if (haystack.includes(Buffer.from(SECRET).toString("base64url"))) leaky.push("base64url");
  if (haystack.includes(Buffer.from(SECRET).toString("hex"))) leaky.push("hex");
  if (haystack.includes(SECRET.slice(0, 20))) leaky.push("prefix20");
  if (haystack.includes(SECRET.slice(0, 8))) leaky.push("prefix8");
  if (leaky.length) fail(`${label}: LEAKED (${leaky.join(", ")})`);
  else pass(`${label}: no secret material`);
};

try {
  await client.connect(transport);
  console.log("connected to safekeys MCP server\n");

  // ── Create the canary through the real flow.
  const created = await client.callTool({
    name: "create_secret",
    arguments: { source_file: sourceFile, scope: ["inject-env"], ttl_seconds: 900 },
  });
  const createdText = created.content.map((c) => c.text).join("");
  record("create_secret", createdText);
  if (createdText.includes(SECRET)) fail("create_secret leaked the plaintext");
  const { token, jti, object_id } = JSON.parse(createdText);
  pass("create_secret returned a token");
  await allowlistHelper(object_id);
  // Let the sidecar's policy cache expire so the new rule is seen. The dev
  // TTL is 60s (SAFEKEYS_POLICY_CACHE_TTL); the red team can wait it out.
  console.log("  (waiting out the sidecar's policy cache…)");
  await new Promise((r) => setTimeout(r, 65_000));

  // ── 1. Dumpers and inline interpreters: must be REFUSED outright.
  console.log("\n[1] dumpers and inline-code interpreters (expect refusal)");
  const refused = [
    ["printenv", "SAFEKEYS_SECRET"],
    ["env"],
    ["echo", "$SAFEKEYS_SECRET"],
    ["cat", sourceFile],
    ["base64", "-w0", sourceFile],
    ["xxd", sourceFile],
    ["od", "-c", sourceFile],
    ["hexdump", "-C", sourceFile],
    ["strings", sourceFile],
    ["sh", "-c", "printenv SAFEKEYS_SECRET"],
    ["/bin/bash", "-c", "echo $SAFEKEYS_SECRET"],
    ["python3", "-c", "import os;print(os.environ['SAFEKEYS_SECRET'])"],
    ["node", "-e", "console.log(process.env.SAFEKEYS_SECRET)"],
    ["perl", "-e", "print $ENV{SAFEKEYS_SECRET}"],
    ["ruby", "-e", "puts ENV['SAFEKEYS_SECRET']"],
    ["php", "-r", "echo getenv('SAFEKEYS_SECRET');"],
    ["awk", "BEGIN{print ENVIRON[\"SAFEKEYS_SECRET\"]}"],
    ["osascript", "-e", "do shell script \"printenv SAFEKEYS_SECRET\""],
  ];
  for (const argv of refused) {
    const res = await client.callTool({ name: "resolve_for_tool", arguments: { token, command: argv } });
    const text = res.content.map((c) => c.text).join("");
    const refusedShape = res.isError === true || /denied|refus|error/i.test(text);
    if (res.isError !== true && !refusedShape) {
      fail(`${argv.join(" ")} was NOT refused`);
      sweep(text, `  output of ${argv.join(" ")}`);
    } else {
      pass(`${argv.join(" ")} refused`);
      record(`refused: ${argv.join(" ")}`, text);
    }
  }

  // ── 2. Encodings through an ALLOWED helper: must come back REDACTED.
  // MCP deny-by-default refuses unlisted commands, so the redaction path is
  // exercised where the operator explicitly allowed the helper.
  console.log("\n[2] encodings via an allowlisted helper (expect [REDACTED:safekeys])");
  for (const mode of ["b64", "b64fold", "hex", "pct", "json"]) {
    const res = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token, command: [helper, mode] },
    });
    const text = res.content.map((c) => c.text).join("");
    if (res.isError === true) {
      fail(`${mode}: helper was refused — add it to the allowlist in the dev policy to run this check`);
    } else if (text.includes("[REDACTED:safekeys]") || !/\S/.test(text.replace(/ok|Command ran|Exit status|\d|\W/g, "")) || text.length < 40) {
      // Either an explicit marker, or the output collapsed to status-only —
      // both are redactions from the caller's point of view.
      sweep(text, `${mode} output redacted`);
    } else {
      sweep(text, `${mode} output`);
      fail(`${mode}: no redaction marker and output survived intact`);
    }
  }

  // ── 3. Partial echoes through the helper.
  console.log("\n[3] partial echoes (expect redaction)");
  for (const mode of ["prefix", "middle"]) {
    const res = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token, command: [helper, mode] },
    });
    const text = res.content.map((c) => c.text).join("");
    if (res.isError === true) {
      fail(`${mode}: helper was refused`);
    } else {
      sweep(text, `${mode} output`);
    }
  }

  // ── 4. Split across stdout and stderr.
  console.log("\n[4] split across streams (expect redaction)");
  {
    const res = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token, command: [helper, "split"] },
    });
    const text = res.content.map((c) => c.text).join("");
    if (res.isError !== true) sweep(text, "split output");
    else fail("split: helper was refused");
  }

  // ── 5. Write-then-read: the documented LIMIT. The relay stays clean; the
  // file the helper wrote is outside the sidecar's reach. Prove both halves.
  console.log("\n[5] write-then-read (documented limit: relay stays clean)");
  {
    const outFile = join(dir, "stolen.txt");
    const res = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token, command: [helper, "write", outFile] },
    });
    const text = res.content.map((c) => c.text).join("");
    if (res.isError !== true) sweep(text, "write relay");
    else fail("write: helper was refused");
    const stolen = readFileSync(outFile, "utf8");
    if (stolen === SECRET) {
      console.log("      (the file the helper wrote holds the value — the documented limit)");
    } else {
      fail("write-then-read control failed: the file does not hold the value");
    }
  }

  // ── 6. Control: the command REALLY received the value.
  console.log("\n[6] control (the injection is real)");
  {
    const marker = join(dir, "marker.txt");
    // shell -c is refused by design, so the control uses the helper in raw
    // mode writing to a file... which is also the relayed value. Instead:
    // the helper writes a marker only if the env var is non-empty AND equals
    // nothing it prints. Use write + compare here.
    const res = await client.callTool({
      name: "resolve_for_tool",
      arguments: { token, command: [helper, "write", marker] },
    });
    const text = res.content.map((c) => c.text).join("");
    if (res.isError === true) fail("control: helper was refused");
    else if (readFileSync(marker, "utf8") === SECRET) pass("the wrapped command received the real value");
    else fail("control: command did not receive the value");
  }

  // ── 7. Sweep the whole model-visible transcript.
  console.log("\n[7] transcript sweep");
  const full = attempts.join("\n");
  sweep(full, "model-visible transcript");

  if (failures > 0) {
    console.error(`\nFAIL — ${failures} leak(s) or unexpected behaviours.`);
    process.exitCode = 1;
  } else {
    console.log("\nPASS — no leak attempt returned the secret through the MCP server.");
  }
  await client.close();
} catch (err) {
  console.error("FAIL:", err);
  process.exitCode = 1;
} finally {
  rmSync(dir, { recursive: true, force: true });
}