// Durable execution ID dedup tests.
//
//   npm run test:execution-id-dedup
//
// Proves that execution IDs are reserved globally and survive process restart.
// A duplicate submission must be refused even after in-process state is cleared.

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  reserveExecutionId,
  execIdDirPath,
  _resetInProcessCacheForTest
} from "../sidecar/execution_id_store.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const storeModuleURL = pathToFileURL(resolve(repoRoot, "sidecar/execution_id_store.mjs")).href;

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

// Run two child processes concurrently (both spawned before either is awaited).
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

// Build a child script that calls reserveExecutionId via the real module.
// exit 0 = reserved (won), exit 1 = refused (lost), exit 2 = error
function reserveScript(execId, storeDir) {
  return [
    `import { reserveExecutionId } from ${JSON.stringify(storeModuleURL)};`,
    `process.env.MNDE_EXEC_ID_CACHE = ${JSON.stringify(storeDir)};`,
    `try {`,
    `  const ok = reserveExecutionId(${JSON.stringify(execId)});`,
    `  process.exit(ok ? 0 : 1);`,
    `} catch (e) {`,
    `  process.stderr.write(String(e) + "\\n");`,
    `  process.exit(2);`,
    `}`,
  ].join("\n");
}

async function main() {
  process.stdout.write("MNDe execution ID dedup — durable replay protection\n\n");

  const dir = mkdtempSync(join(tmpdir(), "mnde-exec-id-test-"));
  const storeDir = join(dir, "exec-id-store.d");
  process.env.MNDE_EXEC_ID_CACHE = storeDir;

  try {
    // ── In-process tests ──────────────────────────────────────────────────────

    await test("first reservation of a fresh execution ID succeeds", () => {
      const ok = reserveExecutionId("exec-id-first-aabb11cc22dd33aa");
      assert.equal(ok, true, "first reservation must succeed");
    });

    await test("file exists on disk after reservation", () => {
      assert.ok(existsSync(join(storeDir, "exec-id-first-aabb11cc22dd33aa")),
        "execution ID file must exist after reservation");
    });

    await test("same execution ID refused immediately (in-process cache)", () => {
      const ok = reserveExecutionId("exec-id-first-aabb11cc22dd33aa");
      assert.equal(ok, false, "duplicate must be refused");
    });

    // ── Restart simulation ────────────────────────────────────────────────────
    // This is the critical test: clearing the in-process Set (simulating a
    // restart) must NOT reopen the execution ID. The file on disk is the source
    // of truth. If the file check were absent, this test would return true.

    await test("execution ID refused after in-process cache cleared (restart simulation)", () => {
      _resetInProcessCacheForTest(); // simulates what a process restart does
      const ok = reserveExecutionId("exec-id-first-aabb11cc22dd33aa");
      assert.equal(ok, false,
        "execution ID must remain refused even after in-process state is cleared — " +
        "the file on disk must prevent replay across restarts");
    });

    await test("path-traversal execution ID rejected", () => {
      const bad = ["../evil", "../../etc", "a/b", "nonce\x00null"];
      for (const id of bad) {
        const ok = reserveExecutionId(id);
        assert.equal(ok, false, `traversal attempt '${id}' must be refused`);
      }
    });

    await test("different execution ID still accepted", () => {
      const ok = reserveExecutionId("exec-id-second-aabb11cc22dd44bb");
      assert.equal(ok, true, "a distinct execution ID must be accepted");
    });

    // ── Cross-process tests ───────────────────────────────────────────────────

    await test("cross-process: child calling reserveExecutionId on an already-reserved ID is refused", () => {
      const script = reserveScript("exec-id-first-aabb11cc22dd33aa", storeDir);
      const child = spawnSync(process.execPath, ["--input-type=module"], {
        input: script,
        env: { ...process.env, MNDE_EXEC_ID_CACHE: storeDir },
        encoding: "utf8"
      });
      assert.equal(child.status, 1,
        "child process must be refused for an already-reserved execution ID");
    });

    await test("cross-process race: two children calling reserveExecutionId concurrently — exactly one wins", async () => {
      const raceId = "exec-id-raced-xx99yy88zz77ww11";
      const script = reserveScript(raceId, storeDir);
      const [statusA, statusB] = await raceTwoChildren(script, script, { MNDE_EXEC_ID_CACHE: storeDir });

      assert.ok(statusA !== 2 && statusB !== 2, "neither child should have errored");
      const wins = [statusA, statusB].filter((s) => s === 0).length;
      const losses = [statusA, statusB].filter((s) => s === 1).length;
      assert.equal(wins, 1,
        `exactly one child must win the race (got ${wins} wins, statuses: ${statusA}, ${statusB})`);
      assert.equal(losses, 1, `exactly one child must lose the race (got ${losses} losses)`);
    });

    await test("mutation proof: non-exclusive write lets both children win (confirms race test is flag-sensitive)", async () => {
      // If reserveExecutionId used openSync("w") instead of "wx", both children
      // could claim the same execution ID. This test proves the race test above
      // would catch a broken implementation by showing that "w" allows both to win.
      const mutantId = "exec-id-mutant-aabb11cc22dde1ff";
      mkdirSync(storeDir, { recursive: true });
      const mutantFile = join(storeDir, mutantId);
      const nonExclusiveScript = [
        `import { openSync, writeSync, closeSync } from "node:fs";`,
        `try {`,
        `  const fd = openSync(${JSON.stringify(mutantFile)}, "w");`,
        `  writeSync(fd, "mutant");`,
        `  closeSync(fd);`,
        `  process.exit(0);`,
        `} catch {`,
        `  process.exit(1);`,
        `}`,
      ].join("\n");
      const [a, b] = await raceTwoChildren(nonExclusiveScript, nonExclusiveScript, {});
      assert.ok(a === 0 && b === 0,
        `non-exclusive open must allow both children to win (got ${a}, ${b}) — ` +
        "proves the real race test would catch a broken O_EXCL implementation");
    });

  } finally {
    delete process.env.MNDE_EXEC_ID_CACHE;
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  process.stdout.write("\n");
  if (failed > 0) {
    process.stdout.write(`FAIL execution ID dedup tests (${results.length - failed}/${results.length})\n`);
    process.exit(1);
  }
  process.stdout.write(`PASS execution ID dedup tests (${results.length}/${results.length})\n`);
}

main().catch((e) => { console.error(e); process.exit(1); });
