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

function run(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8"
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
    await fetch("http://127.0.0.1:8787/healthz");
  } catch {
    sidecarClosed = true;
    break;
  }
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
}
assert(sidecarClosed, "sidecar still reachable after reviewer kit");

const manifestPath = join(repoRoot, "authority", "authority-manifest.json");
const backupPath = `${manifestPath}.cross-platform-test-backup`;
try {
  if (existsSync(backupPath)) throw new Error("stale authority manifest backup exists");
  renameSync(manifestPath, backupPath);
  assert(!verificationPassed(verifyReceiptFile(allowPath)), "missing authority bundle should fail verification");
} finally {
  if (!existsSync(manifestPath) && existsSync(backupPath)) renameSync(backupPath, manifestPath);
}

console.log("PASS cross-platform reviewer tests");
