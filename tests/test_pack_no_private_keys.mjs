#!/usr/bin/env node
// Verifies the actual npm-pack boundary — not the build script's own idea of
// what it copied, but the literal file list npm reports and the literal
// bytes inside the resulting tarball once extracted. This is deliberately
// independent of build/lib/private-key-scan.mjs's use inside the build step:
// it re-runs the same content-based scan against genuinely extracted tarball
// contents, so a bug that only manifested between "what the build wrote" and
// "what npm actually packed" would still be caught here.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { scanForPrivateKeyMaterial } from "../build/lib/private-key-scan.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}
const npmCliJs = resolveNpmCli();
const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (result.error) throw result.error;
  return result;
}
function runNpm(args, opts = {}) {
  return npmCliJs ? run(process.execPath, [npmCliJs, ...args], opts) : run(npmCmd, args, { shell: true, ...opts });
}
function assertOk(label, result) {
  assert.equal(result.status, 0, `${label} failed (exit ${result.status}):\n${result.stdout}\n${result.stderr}`);
  return result;
}

let packDir;
let extractDir;
try {
  packDir = mkdtempSync(join(tmpdir(), "mnde-pack-security-"));
  const packResult = assertOk("npm pack", runNpm(["pack", "--json", "--pack-destination", packDir], { cwd: repoRoot }));
  const jsonStart = packResult.stdout.indexOf("[");
  assert.ok(jsonStart >= 0, `npm pack --json produced no JSON array:\n${packResult.stdout}`);
  const packInfo = JSON.parse(packResult.stdout.slice(jsonStart))[0];
  const tarballPath = join(packDir, packInfo.filename);
  assert.ok(existsSync(tarballPath), `packed tarball missing: ${tarballPath}`);

  // Path-based sanity check against npm's own reported file list — cheap,
  // catches the obvious case even before touching the actual tarball bytes.
  const shippedPaths = packInfo.files.map((f) => f.path.replace(/\\/g, "/"));
  for (const forbidden of ["shared/receipt_keys/", "authority/root_authority_private.pem", ".mnde-test/", "build/"]) {
    assert.ok(
      !shippedPaths.some((p) => p.includes(forbidden)),
      `npm pack must never report ${forbidden} in its file list, found in: ${shippedPaths.join(", ")}`
    );
  }

  // Authoritative check: extract the REAL tarball and content-scan what's
  // actually inside it — not the pre-pack dist/ directory, not npm's file
  // list, the literal packed bytes.
  extractDir = mkdtempSync(join(tmpdir(), "mnde-pack-extract-"));
  // Keep the archive argument relative: GNU tar otherwise parses a Windows
  // drive letter as "host:path", while bsdtar does not support --force-local.
  const relativeTarballPath = relative(extractDir, tarballPath).replace(/\\/g, "/");
  assertOk("tar extract", run("tar", ["-xzf", relativeTarballPath], { cwd: extractDir }));

  const offenders = scanForPrivateKeyMaterial(extractDir);
  assert.deepEqual(offenders, [], `private key marker found inside the packed tarball: ${JSON.stringify(offenders)}`);

  console.log(`PASS pack boundary contains no private-key material (${packInfo.entryCount} files, ${extractDir})`);
} finally {
  if (extractDir) rmSync(extractDir, { recursive: true, force: true });
  if (packDir) rmSync(packDir, { recursive: true, force: true });
}
