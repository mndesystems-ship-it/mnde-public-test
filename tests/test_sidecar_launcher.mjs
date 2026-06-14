// MNDe sidecar launcher tests.
//
//   npm run test:sidecar
//
// Verifies one-command design-partner startup: missing authority bootstraps,
// missing receipt directory bootstraps, startup reaches READY, invalid config
// fails closed, and shutdown exits cleanly. Node APIs only; cross-platform
// (graceful stop is triggered with a "stop" line on stdin, the same path Ctrl+C
// drives, so the test does not depend on POSIX signal delivery).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { authorityPaths } from "../shared/authority-manifest.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function runLauncher(env) {
  const child = spawn(process.execPath, ["scripts/start-sidecar.mjs"], {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
  child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
  return { child, out: () => stdout, err: () => stderr };
}

function waitForOutput(getter, substring, timeoutMs = 25_000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const timer = setInterval(() => {
      if (getter().includes(substring)) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() > deadline) {
        clearInterval(timer);
        reject(new Error(`timed out waiting for "${substring}"`));
      }
    }, 100);
  });
}

function waitForExit(child, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    const timer = setTimeout(() => reject(new Error("process did not exit in time")), timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

async function stopLauncher(handle) {
  handle.child.stdin.write("stop\n");
  return waitForExit(handle.child);
}

async function main() {
  console.log("MNDe sidecar launcher tests\n");

  await test("1. missing authority bootstraps correctly", async () => {
    const manifestPath = authorityPaths(repoRoot, { kind: "local" }).manifestPath;
    rmSync(manifestPath, { force: true });
    assert.equal(existsSync(manifestPath), false, "precondition: manifest removed");

    const handle = runLauncher({ MNDE_BIND_PORT: "8811" });
    try {
      await waitForOutput(handle.out, "Status: READY");
      assert.equal(existsSync(manifestPath), true, "launcher must recreate the authority manifest");
    } finally {
      await stopLauncher(handle);
    }
  });

  await test("2. missing receipt directory bootstraps correctly", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-launcher-"));
    const receiptsDir = join(dir, "receipts-does-not-exist-yet");
    assert.equal(existsSync(receiptsDir), false, "precondition: receipt dir absent");

    const handle = runLauncher({ MNDE_BIND_PORT: "8812", MNDE_RECEIPTS_DIR: receiptsDir });
    try {
      await waitForOutput(handle.out, "Status: READY");
      assert.equal(existsSync(receiptsDir), true, "launcher must create the receipt directory");
    } finally {
      await stopLauncher(handle);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await test("3. receipt directory writable check fails closed", async () => {
    // Put a FILE where the receipts parent dir must be, so the dir cannot be
    // created or written. Cross-platform: mkdir/write under a file throws.
    const dir = mkdtempSync(join(tmpdir(), "mnde-launcher-"));
    const blockingFile = join(dir, "not-a-dir");
    writeFileSync(blockingFile, "x");
    const receiptsDir = join(blockingFile, "receipts");
    const handle = runLauncher({ MNDE_BIND_PORT: "8815", MNDE_RECEIPTS_DIR: receiptsDir });
    try {
      const code = await waitForExit(handle.child);
      assert.notEqual(code, 0, "an unwritable receipt directory must exit non-zero");
      assert.match(handle.err(), /Receipt directory not writable\./);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await test("4. startup succeeds and prints the READY banner", async () => {
    const handle = runLauncher({ MNDE_BIND_PORT: "8813" });
    try {
      await waitForOutput(handle.out, "Status: READY");
      assert.match(handle.out(), /URL: http:\/\/127\.0\.0\.1:8813/);
      assert.match(handle.out(), /Authority: LOCAL READY/);
    } finally {
      await stopLauncher(handle);
    }
  });

  await test("5. invalid configuration fails closed", async () => {
    const handle = runLauncher({ MNDE_BIND_PORT: "not-a-port" });
    const code = await waitForExit(handle.child);
    assert.notEqual(code, 0, "invalid config must exit non-zero");
    assert.match(handle.err(), /ERROR:/);
    assert.match(handle.err(), /Invalid bind port/);
  });

  await test("6. shutdown exits cleanly", async () => {
    const handle = runLauncher({ MNDE_BIND_PORT: "8814" });
    await waitForOutput(handle.out, "Status: READY");
    const code = await stopLauncher(handle);
    assert.equal(code, 0, "clean shutdown must exit zero");
    assert.match(handle.out(), /Stopping MNDe Sidecar\.\.\./);
    assert.match(handle.out(), /Stopped\./);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL sidecar launcher tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS sidecar launcher tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
