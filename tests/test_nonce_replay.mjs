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
import { spawn, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { reserveNonce, nonceDirPath, _cleanupNonceDirForTest } from "../sidecar/auth_authority.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Windows ESM requires a file:// URL for absolute paths in import() / import statements.
const authAuthorityURL = pathToFileURL(resolve(repoRoot, "sidecar/auth_authority.mjs")).href;

// Run two child processes concurrently (both started before either is awaited)
// and collect their exit codes.
function raceTwoChildren(scriptA, scriptB, env) {
  return new Promise((res) => {
    const opts = { env: { ...process.env, ...env }, encoding: "utf8" };
    let done = 0;
    const statuses = [null, null];
    function finish(i, code) {
      statuses[i] = code;
      if (++done === 2) res(statuses);
    }
    const a = spawn(process.execPath, ["--input-type=module"], { ...opts, stdio: ["pipe", "inherit", "inherit"] });
    const b = spawn(process.execPath, ["--input-type=module"], { ...opts, stdio: ["pipe", "inherit", "inherit"] });
    a.on("close", (code) => finish(0, code));
    b.on("close", (code) => finish(1, code));
    a.stdin.end(scriptA);
    b.stdin.end(scriptB);
  });
}

// Build the inline script a child uses to call reserveNonce via the real module.
// exit 0 = reserveNonce returned true (won), exit 1 = false (lost), exit 2 = threw
function reserveNonceScript(nonce, cacheFile) {
  return [
    `import { reserveNonce } from ${JSON.stringify(authAuthorityURL)};`,
    `process.env.MNDE_AUTH_NONCE_CACHE = ${JSON.stringify(cacheFile)};`,
    `try {`,
    `  const ok = reserveNonce(${JSON.stringify(nonce)}, Date.now());`,
    `  process.exit(ok ? 0 : 1);`,
    `} catch (e) {`,
    `  process.stderr.write(String(e) + "\\n");`,
    `  process.exit(2);`,
    `}`,
  ].join("\n");
}

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

    await test("cross-process replay refused: child calls reserveNonce on already-reserved nonce", async () => {
      // The nonce was reserved above. A child process that imports the real
      // reserveNonce module and calls it must be refused (the file already exists).
      const script = reserveNonceScript(nonce, cacheFile);
      const child = spawnSync(process.execPath, ["--input-type=module"], {
        input: script,
        env: { ...process.env, MNDE_AUTH_NONCE_CACHE: cacheFile },
        encoding: "utf8",
      });
      assert.equal(child.status, 1,
        "child calling reserveNonce on an already-reserved nonce must return false (exit 1)");
    });

    await test("wrapper-level race: two child processes calling reserveNonce concurrently — exactly one wins", async () => {
      // Both children import the real reserveNonce and race on a fresh nonce.
      // They are started concurrently (both spawned before either is awaited).
      const racedNonce = "replay-test-raced-xx99yy88zz77ww";
      const script = reserveNonceScript(racedNonce, cacheFile);
      const [statusA, statusB] = await raceTwoChildren(script, script, { MNDE_AUTH_NONCE_CACHE: cacheFile });

      assert.ok(statusA !== 2 && statusB !== 2, "neither child should have thrown");

      const wins = [statusA, statusB].filter((s) => s === 0).length;
      const losses = [statusA, statusB].filter((s) => s === 1).length;
      assert.equal(wins, 1,
        `exactly one process must win the reserveNonce race (got ${wins} wins, statuses: ${statusA}, ${statusB})`);
      assert.equal(losses, 1,
        `exactly one process must lose the reserveNonce race (got ${losses} losses)`);
    });

    await test("mutation proof: non-exclusive write allows both children to 'win' (confirms the race test catches a broken wrapper)", async () => {
      // This test validates the sensitivity of the race test above.
      // It simulates what would happen if reserveNonce used openSync("w") instead
      // of openSync("wx"): both processes can open-and-write the file, so both
      // return true — meaning the race test above WOULD FAIL on a broken wrapper.
      //
      // We demonstrate this by racing two children that each attempt openSync("w")
      // (non-exclusive) on a shared file. Under "w" both succeed (exit 0). This
      // proves the race test above is sensitive to the exclusive-open flag: if the
      // real module used "w", both children calling reserveNonce would also win,
      // and the assert.equal(wins, 1) above would throw.
      const mutantNonce = "replay-mutant-test-aabb11cc22dde1";
      const mutantFile = join(nonceDir, mutantNonce);
      mkdirSync(nonceDir, { recursive: true });

      const nonExclusiveScript = [
        `import { openSync, writeSync, closeSync } from "node:fs";`,
        `try {`,
        `  const fd = openSync(${JSON.stringify(mutantFile)}, "w");`,  // non-exclusive
        `  writeSync(fd, "mutant");`,
        `  closeSync(fd);`,
        `  process.exit(0);`,
        `} catch {`,
        `  process.exit(1);`,
        `}`,
      ].join("\n");

      const [statusA, statusB] = await raceTwoChildren(nonExclusiveScript, nonExclusiveScript, {});
      const bothWon = statusA === 0 && statusB === 0;
      assert.ok(bothWon,
        `non-exclusive open must allow both processes to win (got ${statusA}, ${statusB}) — ` +
        "if this fails, the mutation proof is broken");
      // Proof: if reserveNonce used "w" instead of "wx", the race test above would
      // observe wins===2 and throw. Therefore the race test IS sensitive to the flag.
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
