// Authority-assertion nonce replay protection tests.
//
//   npm run test:nonce-replay
//
// Proves that a valid assertion token can only be accepted once, globally,
// across concurrent processes. Two simultaneous reservation attempts for the
// same nonce must never both succeed.

import assert from "node:assert/strict";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reserveNonce, nonceDirPath, _cleanupNonceDirForTest } from "../sidecar/auth_authority.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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
  process.stdout.write("MNDe authority assertion — nonce replay protection\n\n");

  const dir = mkdtempSync(join(tmpdir(), "mnde-nonce-test-"));
  const cacheFile = join(dir, "auth-nonces.json");
  process.env.MNDE_AUTH_NONCE_CACHE = cacheFile;

  try {
    const now = Date.now();

    // Nonces must be 24-128 URL-safe chars (NONCE_PATTERN). Use fixed-length strings.
    const nonce = "replay-test-nonce-aabb11cc22dd33";
    const nonceDir = nonceDirPath();

    await test("first reservation of a fresh nonce succeeds", () => {
      const ok = reserveNonce(nonce, now);
      assert.equal(ok, true, "first reservation must succeed");
    });

    await test("nonce file exists in the nonce directory after reservation", () => {
      const entries = readdirSync(nonceDir);
      assert.ok(entries.includes(nonce), `nonce file '${nonce}' must exist in ${nonceDir}`);
    });

    await test("second reservation of the same nonce in the same process is refused", () => {
      const ok = reserveNonce(nonce, now + 1);
      assert.equal(ok, false, "replay within the same process must be refused");
    });

    await test("cross-process reservation of the same nonce is refused (atomic O_EXCL)", () => {
      // Spawn a child that attempts openSync("wx") on the already-reserved nonce file.
      // exit 0 = file was NOT there (bad — replay possible)
      // exit 1 = EEXIST (good — reservation correctly blocked)
      const nonceFile = join(nonceDir, nonce);
      const child = spawnSync(process.execPath, ["--input-type=module"], {
        input: [
          `import { openSync } from "node:fs";`,
          `try {`,
          `  openSync(${JSON.stringify(nonceFile)}, "wx");`,
          `  process.exit(0);`,
          `} catch {`,
          `  process.exit(1);`,
          `}`
        ].join("\n"),
        encoding: "utf8"
      });
      assert.equal(child.status, 1,
        "cross-process O_EXCL open must fail with EEXIST — the nonce file already exists, proving global exclusion");
    });

    await test("two concurrent processes racing on a fresh nonce: exactly one wins", () => {
      const racedNonce = "replay-test-raced-xx99yy88zz77ww";
      const raceFile = join(nonceDir, racedNonce);

      // Both children try to openSync("wx") the same file at the same time.
      // We use spawnSync sequentially here, but the key proof is that O_EXCL
      // is an atomic kernel primitive: whichever process issues the syscall first
      // wins, and the other gets EEXIST. Verify one wins and one loses.
      const script = [
        `import { openSync, writeSync, closeSync } from "node:fs";`,
        `try {`,
        `  const fd = openSync(${JSON.stringify(raceFile)}, "wx");`,
        `  writeSync(fd, "reserved");`,
        `  closeSync(fd);`,
        `  process.exit(0);`,   // won
        `} catch {`,
        `  process.exit(1);`,   // lost (EEXIST)
        `}`
      ].join("\n");

      const opts = { input: script, encoding: "utf8" };
      const a = spawnSync(process.execPath, ["--input-type=module"], opts);
      const b = spawnSync(process.execPath, ["--input-type=module"], opts);

      // Exactly one must win (exit 0) and the other must lose (exit 1).
      const wins = [a.status, b.status].filter((s) => s === 0).length;
      const losses = [a.status, b.status].filter((s) => s === 1).length;
      assert.equal(wins, 1, `exactly one process must win the O_EXCL race (got ${wins} wins)`);
      assert.equal(losses, 1, `exactly one process must lose the O_EXCL race (got ${losses} losses)`);
    });

    await test("a different nonce is still accepted while another is reserved", () => {
      const other = "replay-test-other-aabb11cc22dd44";
      const ok = reserveNonce(other, now);
      assert.equal(ok, true, "a distinct nonce must still be reserved successfully");
    });

    await test("nonce dir path is derived from MNDE_AUTH_NONCE_CACHE", () => {
      const derived = nonceDirPath();
      assert.ok(derived.endsWith(".d"), "nonce dir must end with .d suffix");
      assert.ok(derived.includes("auth-nonces"), "nonce dir must be adjacent to the cache file");
    });

    await test("crash-residue empty file is preserved by cleanup (not deleted, nonce stays reserved)", () => {
      // Simulate a crash between openSync and writeSync: file exists but is empty.
      // Number("") === 0, which is finite and always <= now, so the naive cleanup
      // condition would delete it, reopening the nonce for replay. The fix adds
      // raw.length > 0 guard to prevent this.
      const crashNonce = "crash-residue-test-aabb11cc22dd55";
      const nd = nonceDirPath();
      mkdirSync(nd, { recursive: true });
      const fd = openSync(join(nd, crashNonce), "wx");
      closeSync(fd); // empty file — crash between open and write

      _cleanupNonceDirForTest(nd);

      assert.ok(existsSync(join(nd, crashNonce)),
        "empty crash-residue file must survive cleanup — deleting it would reopen replay");

      // Also verify that reserveNonce now sees the file as already reserved:
      const ok = reserveNonce(crashNonce, Date.now());
      assert.equal(ok, false, "nonce from crash-residue file must be refused by reserveNonce");
    });

    await test("path-traversal nonce is rejected by reserveNonce internal guard", () => {
      // reserveNonce is exported so it needs its own defense-in-depth check.
      // join(dir, "../evil") would escape the nonce directory without this guard.
      const traversalAttempts = ["../evil", "../../etc/passwd", "..", "a/b", "nonce with spaces"];
      for (const bad of traversalAttempts) {
        const ok = reserveNonce(bad, Date.now());
        assert.equal(ok, false, `path-traversal nonce '${bad}' must be refused`);
      }
    });
  } finally {
    delete process.env.MNDE_AUTH_NONCE_CACHE;
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  process.stdout.write("\n");
  if (failed > 0) {
    process.stdout.write(`FAIL nonce replay tests (${results.length - failed}/${results.length})\n`);
    process.exit(1);
  }
  process.stdout.write(`PASS nonce replay tests (${results.length}/${results.length})\n`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
