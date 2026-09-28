// safekeys/distribution, test cli-meta-resolves-platform-binary: the meta
// package must resolve the right binary package per platform, and fail loudly
// on an unsupported platform — never a download fallback.
import { test } from "node:test";
import assert from "node:assert/strict";
import { platformPackage, platformPkgs } from "../src/resolve.js";

test("resolves the correct platform package for each supported host", () => {
  const cases = [
    ["darwin", "arm64", "@smithgray/safekeys-cli-darwin-arm64"],
    ["darwin", "x64", "@smithgray/safekeys-cli-darwin-x64"],
    ["linux", "x64", "@smithgray/safekeys-cli-linux-x64"],
    ["linux", "arm64", "@smithgray/safekeys-cli-linux-arm64"],
    ["win32", "x64", "@smithgray/safekeys-cli-win32-x64"],
  ];
  for (const [p, a, want] of cases) {
    assert.equal(platformPackage(p, a), want);
  }
  // The table carries exactly the five advertised platforms.
  assert.deepEqual(Object.keys(platformPkgs).sort(), [
    "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64",
  ]);
});

test("unsupported platforms fail loudly with no fallback", () => {
  for (const [p, a] of [["sunos", "x64"], ["freebsd", "arm64"], ["linux", "riscv64"]]) {
    assert.throws(() => platformPackage(p, a), /no prebuilt Safekeys CLI/);
  }
});

test("the meta package declares the five platform packages as optionalDependencies at the same version", async () => {
  const meta = JSON.parse(await import("node:fs").then((m) => m.readFileSync(new URL("../package.json", import.meta.url), "utf8")));
  for (const pkg of Object.values(platformPkgs)) {
    assert.equal(meta.optionalDependencies[pkg], "0.1.0");
  }
  assert.equal(meta.name, "@smithgray/safekeys-cli");
});

test("no lifecycle scripts anywhere in the CLI package", async () => {
  const meta = JSON.parse(await import("node:fs").then((m) => m.readFileSync(new URL("../package.json", import.meta.url), "utf8")));
  const forbidden = ["preinstall", "install", "postinstall", "prepublish"];
  for (const s of forbidden) {
    assert.ok(!(s in (meta.scripts ?? {})), `forbidden lifecycle script: ${s}`);
  }
});
