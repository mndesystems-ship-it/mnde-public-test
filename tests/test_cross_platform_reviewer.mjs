#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, renameSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactsRoot = join(repoRoot, "reviewer-kit", "artifacts");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// Dedicated port: 8787 is the sidecar's real default, so a developer's live
// sidecar may legitimately own it while tests run.
const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8814";

function run(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, MNDE_SIDECAR_URL: sidecarUrl }
  });
}

const reviewer = process.platform === "win32"
  ? run(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", "npm run reviewer-kit"])
  : run("npm", ["run", "reviewer-kit"]);
if (reviewer.status !== 0) {
  process.stdout.write(reviewer.stdout ?? "");
  process.stderr.write(reviewer.stderr ?? "");
  if (reviewer.error) process.stderr.write(`${reviewer.error.message}\n`);
  process.exit(reviewer.status ?? 1);
}
assert((reviewer.stdout ?? "").includes("FINAL VERDICT: PASS"), "reviewer kit did not print final PASS");

const allowPath = join(artifactsRoot, "receipts", "allow-receipt.json");
const refusePath = join(artifactsRoot, "receipts", "refuse-receipt.json");
assert(verificationPassed(verifyReceiptFile(allowPath)), "ALLOW receipt did not verify");
assert(verificationPassed(verifyReceiptFile(refusePath)), "REFUSE receipt did not verify");

let sidecarClosed = false;
for (let attempt = 0; attempt < 20; attempt += 1) {
  try {
    await fetch(`${sidecarUrl}/healthz`);
  } catch {
    sidecarClosed = true;
    break;
  }
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
}
assert(sidecarClosed, "sidecar still reachable after reviewer kit");

const demoReceiptPath = join(repoRoot, "examples", "receipts", "valid-receipt.json");
const demoManifestPath = join(repoRoot, "authority", "authority-manifest.json");
const localManifestPath = join(repoRoot, ".mnde-test", "authority", "authority-manifest.json");

function withManifestRemoved(manifestPath, label, fn) {
  const backupPath = `${manifestPath}.cross-platform-test-backup`;
  try {
    if (existsSync(backupPath)) throw new Error(`stale ${label} authority manifest backup exists`);
    assert(existsSync(manifestPath), `${label} authority manifest is missing before test`);
    renameSync(manifestPath, backupPath);
    fn();
  } finally {
    if (!existsSync(manifestPath) && existsSync(backupPath)) renameSync(backupPath, manifestPath);
  }
}

assert(verificationPassed(verifyReceiptFile(demoReceiptPath)), "demo receipt did not verify before authority isolation tests");
assert(verificationPassed(verifyReceiptFile(allowPath)), "live reviewer-kit receipt did not verify before authority isolation tests");

withManifestRemoved(demoManifestPath, "demo", () => {
  assert(!verificationPassed(verifyReceiptFile(demoReceiptPath)), "removing demo authority should break demo fixture verification");
  assert(verificationPassed(verifyReceiptFile(allowPath)), "removing demo authority should not break live reviewer-kit receipt verification");
});

withManifestRemoved(localManifestPath, "local tester", () => {
  assert(!verificationPassed(verifyReceiptFile(allowPath)), "removing local tester authority should break live reviewer-kit receipt verification");
  assert(verificationPassed(verifyReceiptFile(demoReceiptPath)), "removing local tester authority should not break demo fixture verification");
});

console.log("PASS cross-platform reviewer tests");
