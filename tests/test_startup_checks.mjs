// Startup security checks: directory permissions + harness identity.
//
//   npm run test:startup-checks
//
// Proves that world-writable directories are detected and rejected at startup.
// A world-writable nonce or execution-ID directory lets a local attacker
// pre-create files to block legitimate operations or inject fake reservations.
// Also proves the test harness refuses to adopt a foreign process that already
// answers /readyz on the target port (e.g. a stale or live dev sidecar): every
// decision would silently run against the wrong server otherwise.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { checkDirectoryPermissions } from "../sidecar/startup_checks.mjs";

const IS_POSIX = process.platform !== "win32";

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    process.stdout.write(`  [PASS] ${name}\n`);
  } catch (error) {
    results.push(false);
    process.stdout.write(`  [FAIL] ${name}: ${error.message}\n`);
  }
}

async function main() {
  process.stdout.write("MNDe startup directory permission checks\n\n");

  const baseDir = mkdtempSync(join(tmpdir(), "mnde-startup-checks-"));
  try {

    await test("non-existent directory is created and accepted", () => {
      const dir = join(baseDir, "auto-created");
      const result = checkDirectoryPermissions(dir);
      assert.equal(result.ok, true, `expected ok, got: ${result.reason}`);
    });

    if (IS_POSIX) {
      await test("world-writable directory is rejected (POSIX)", () => {
        const dir = join(baseDir, "world-writable");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o777); // world-writable
        const mode = statSync(dir).mode & 0o777;
        assert.ok(mode & 0o002, "test setup: directory must be world-writable");
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, false,
          "world-writable directory must be rejected");
        assert.ok(result.reason.includes("world-writable"),
          `reason must mention world-writable, got: ${result.reason}`);
      });

      await test("owner-only directory is accepted (POSIX)", () => {
        const dir = join(baseDir, "owner-only");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o700); // rwx------
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, true,
          `owner-only directory must be accepted, got: ${result.reason}`);
      });

      await test("group-readable but not world-writable is accepted (POSIX)", () => {
        const dir = join(baseDir, "group-read");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o750); // rwxr-x---
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, true,
          `group-readable directory must be accepted, got: ${result.reason}`);
      });

      await test("removing world-write bit fixes a previously rejected directory", () => {
        const dir = join(baseDir, "fixed");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o777);
        const before = checkDirectoryPermissions(dir);
        assert.equal(before.ok, false, "pre-fix: must be rejected");

        chmodSync(dir, 0o755); // remove world-write
        const after = checkDirectoryPermissions(dir);
        assert.equal(after.ok, true, "post-fix: must be accepted");
      });
    } else {
      // Windows: the check is skipped; verify it doesn't throw and returns ok.
      await test("Windows: permission check is skipped (no Unix mode bits)", () => {
        const dir = join(baseDir, "windows-dir");
        mkdirSync(dir, { recursive: true });
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, true,
          "Windows permission check must always return ok (ACLs are not checked via stat.mode)");
      });
    }

  } finally {
    rmSync(baseDir, { recursive: true, force: true });
  }

  await test("harness refuses to adopt a foreign server already answering /readyz", async () => {
    // Impostor: answers ok:true on /readyz but cannot echo the per-start
    // harness nonce, exactly like a stale or live dev sidecar on the port.
    const decoy = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise((ready, failed) => {
      decoy.once("error", failed);
      decoy.listen(8813, "127.0.0.1", ready);
    });
    try {
      let started = null;
      let caught = null;
      try {
        started = await startMndeSidecar({ url: "http://127.0.0.1:8813" });
      } catch (error) {
        caught = error;
      } finally {
        if (started) await started.stop();
      }
      assert.equal(started, null, "harness must not return a handle for a foreign server");
      assert.ok(caught, "startup against an occupied port must fail");
      assert.match(String(caught.message), /already serving|exited early/);
    } finally {
      await new Promise((done) => decoy.close(done));
    }
  });

  const failed = results.filter((ok) => !ok).length;
  process.stdout.write("\n");
  if (failed > 0) {
    process.stdout.write(`FAIL startup checks tests (${results.length - failed}/${results.length})\n`);
    process.exit(1);
  }
  process.stdout.write(`PASS startup checks tests (${results.length}/${results.length})\n`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
