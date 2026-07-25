#!/usr/bin/env node
// Installed-artifact conformance test.
//
// Proves the packaged CLI (init -> doctor -> smoke) works after a REAL `npm
// install` of the packed tarball into a clean, ordinary Node project — not by
// extracting the tarball with `tar` (which skips npm's own bin-symlinking,
// dependency resolution, and files-allowlist enforcement, and so cannot catch
// bugs in any of those). This is the exact gate the Phase 2 packaging spec
// requires: "test installation from the packed artifact, not only from the
// source checkout" and "test on a clean temporary directory."
//
// Runs `npm pack` fresh (which triggers the real `prepack` -> build-package.mjs
// step), installs the resulting tarball into a throwaway temp project, and
// exercises the CLI exactly as an end user would via the installed bin.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// npm ships as a .cmd shim on Windows; spawnSync cannot exec a .cmd directly
// without a shell. Resolve the real npm-cli.js next to the running node
// binary instead, so npm can be invoked as `node npm-cli.js ...` with a plain
// argv array on every platform — no shell, no escaping concerns.
function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}
const npmCliJs = resolveNpmCli();

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (result.error) throw result.error;
  return result;
}

function runNpm(args, opts = {}) {
  return npmCliJs ? run(process.execPath, [npmCliJs, ...args], opts) : run(npmCmd, args, { shell: true, ...opts });
}

function assertOk(label, result) {
  assert.equal(
    result.status,
    0,
    `${label} failed (exit ${result.status}):\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`
  );
  return result;
}

const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
const nodeCmd = process.execPath;

let packDir;
let projectDir;
try {
  // 1. Pack the real tarball (triggers prepack -> build-package.mjs).
  packDir = mkdtempSync(join(tmpdir(), "mnde-pack-"));
  const packResult = assertOk("npm pack", runNpm(["pack", "--json", "--pack-destination", packDir], { cwd: repoRoot }));
  // The prepack hook (build-package.mjs) writes its own progress line to
  // stdout before npm's --json array, so the JSON payload isn't the whole
  // stream — slice from the first "[" to isolate it.
  const jsonStart = packResult.stdout.indexOf("[");
  assert.ok(jsonStart >= 0, `npm pack --json produced no JSON array:\n${packResult.stdout}`);
  const packInfo = JSON.parse(packResult.stdout.slice(jsonStart))[0];
  const tarballPath = join(packDir, packInfo.filename);
  assert.ok(existsSync(tarballPath), `packed tarball missing: ${tarballPath}`);

  // Defense in depth: the build already refuses to emit private key material
  // (assertNoPrivateKeyMaterial in build-package.mjs) — re-check the actual
  // shipped file list here too, independently, against the published contract.
  assert.ok(Array.isArray(packInfo.files), "npm pack --json must report a file list");
  const shippedPaths = packInfo.files.map((f) => f.path.replace(/\\/g, "/"));
  for (const forbidden of ["shared/receipt_keys/", "authority/root_authority_private.pem", ".mnde-test/"]) {
    assert.ok(
      !shippedPaths.some((p) => p.includes(forbidden)),
      `packed artifact must never ship ${forbidden}, found in: ${shippedPaths.join(", ")}`
    );
  }

  // 2. Install the tarball into a genuinely clean temp project via a real
  //    `npm install` — not tar extraction.
  projectDir = mkdtempSync(join(tmpdir(), "mnde-install-"));
  assertOk("npm init", runNpm(["init", "-y"], { cwd: projectDir }));
  assertOk("npm install (tarball)", runNpm(["install", tarballPath], { cwd: projectDir }));

  const binDir = join(projectDir, "node_modules", ".bin");
  for (const bin of ["mnde-sidecar", "sidecar", "mnde"]) {
    const binPath = process.platform === "win32" ? join(binDir, `${bin}.cmd`) : join(binDir, bin);
    assert.ok(existsSync(binPath), `expected bin not installed: ${binPath}`);
  }

  const cliEntry = join(projectDir, "node_modules", "mnde-public-test", "dist", "bin", "mnde-sidecar.mjs");
  assert.ok(existsSync(cliEntry), `installed CLI entry point missing: ${cliEntry}`);

  const homeDir = join(projectDir, ".mnde");
  const runCli = (args) => run(nodeCmd, [cliEntry, ...args], { cwd: projectDir, env: { ...process.env, MNDE_HOME: homeDir } });

  // 3. init -> doctor -> smoke, exactly as an end user would run it.
  const initResult = runCli(["init"]);
  assert.equal(initResult.status, 0, `init failed:\n${initResult.stdout}\n${initResult.stderr}`);

  const doctorResult = runCli(["doctor"]);
  assert.equal(doctorResult.status, 0, `doctor failed after init:\n${doctorResult.stdout}\n${doctorResult.stderr}`);

  const smokeResult = runCli(["smoke"]);
  assert.equal(smokeResult.status, 0, `smoke failed:\n${smokeResult.stdout}\n${smokeResult.stderr}`);
  assert.match(smokeResult.stdout, /VERIFIED/, "smoke must report an offline-verified receipt");
  assert.match(smokeResult.stdout, /First verifiable receipt in/, "smoke must report success timing");

  const firstReceiptPath = join(homeDir, "first-receipt.json");
  assert.ok(existsSync(firstReceiptPath), "smoke must persist first-receipt.json under MNDE_HOME");
  const firstReceipt = JSON.parse(readFileSync(firstReceiptPath, "utf8"));
  assert.equal(firstReceipt.verifiable_signature?.algorithm, "ED25519");

  // 4. init must be idempotent: re-running against the same MNDE_HOME must not
  //    fail or regenerate keys.
  const privateKeyPath = join(homeDir, "shared", "receipt_keys", "receipt_signing_private.pem");
  const keyBefore = readFileSync(privateKeyPath, "utf8");
  const reinitResult = runCli(["init"]);
  assert.equal(reinitResult.status, 0, "re-running init must be idempotent");
  const keyAfter = readFileSync(privateKeyPath, "utf8");
  assert.equal(keyAfter, keyBefore, "init must never overwrite an existing signing key");

  console.log("PASS installed-artifact conformance (real npm pack + npm install)");
} finally {
  if (projectDir) rmSync(projectDir, { recursive: true, force: true });
  if (packDir) rmSync(packDir, { recursive: true, force: true });
}
