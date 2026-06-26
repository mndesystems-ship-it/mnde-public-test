// Startup directory security checks.
//
//   npm run test:startup-checks
//
// Proves that world-writable directories are detected and rejected at startup.
// A world-writable nonce or execution-ID directory lets a local attacker
// pre-create files to block legitimate operations or inject fake reservations.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { checkDirectoryPermissions } from "../sidecar/startup_checks.mjs";

const IS_POSIX = process.platform !== "win32";

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    process.stdout.write(`  [PASS] ${name}\n`);
  } catch (error) {
    results.push(false);
    process.stdout.write(`  [FAIL] ${name}: ${error.message}\n`);
  }
}

function main() {
  process.stdout.write("MNDe startup directory permission checks\n\n");

  const baseDir = mkdtempSync(join(tmpdir(), "mnde-startup-checks-"));
  try {

    test("non-existent directory is created and accepted", () => {
      const dir = join(baseDir, "auto-created");
      const result = checkDirectoryPermissions(dir);
      assert.equal(result.ok, true, `expected ok, got: ${result.reason}`);
    });

    if (IS_POSIX) {
      test("world-writable directory is rejected (POSIX)", () => {
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

      test("owner-only directory is accepted (POSIX)", () => {
        const dir = join(baseDir, "owner-only");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o700); // rwx------
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, true,
          `owner-only directory must be accepted, got: ${result.reason}`);
      });

      test("group-readable but not world-writable is accepted (POSIX)", () => {
        const dir = join(baseDir, "group-read");
        mkdirSync(dir, { recursive: true });
        chmodSync(dir, 0o750); // rwxr-x---
        const result = checkDirectoryPermissions(dir);
        assert.equal(result.ok, true,
          `group-readable directory must be accepted, got: ${result.reason}`);
      });

      test("removing world-write bit fixes a previously rejected directory", () => {
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
      test("Windows: permission check is skipped (no Unix mode bits)", () => {
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

  const failed = results.filter((ok) => !ok).length;
  process.stdout.write("\n");
  if (failed > 0) {
    process.stdout.write(`FAIL startup checks tests (${results.length - failed}/${results.length})\n`);
    process.exit(1);
  }
  process.stdout.write(`PASS startup checks tests (${results.length}/${results.length})\n`);
}

main();
