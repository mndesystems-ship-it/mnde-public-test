#!/usr/bin/env node
// Hostile-input tests for the @mnde/sidecar packaging CLI (bin/mnde-sidecar.mjs).
//
// Phase 2 packaging requirement: prove the CLI fails closed — clear error,
// nonzero exit, no partial/silent success, no crash bypassing verification —
// under partial initialization, corrupt keys, an occupied port, a malformed
// policy file, and an interrupted startup. Each scenario gets its own throwaway
// MNDE_HOME so scenarios cannot interfere with each other.
//
// Runs against the source CLI directly (not the compiled dist/ copy): the
// build step only type-strips and rewrites import extensions, it does not
// change this file's logic, so testing the source keeps this suite fast and
// independent of whether dist/ has been built yet.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = join(repoRoot, "bin", "mnde-sidecar.mjs");
const nodeCmd = process.execPath;

function freshHome(label) {
  return mkdtempSync(join(tmpdir(), `mnde-hostile-${label}-`));
}

function runCli(args, home, extraEnv = {}) {
  const result = spawnSync(nodeCmd, [cliPath, ...args], {
    encoding: "utf8",
    timeout: 15000,
    env: { ...process.env, MNDE_HOME: home, ...extraEnv }
  });
  if (result.error?.code === "ETIMEDOUT" || result.signal === "SIGTERM") {
    throw new Error(`CLI '${args.join(" ")}' timed out after 15s (stdout so far: ${result.stdout ?? ""})`);
  }
  return result;
}

function killTree(child) {
  if (!child || child.pid == null) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/F", "/T", "/PID", String(child.pid)], { stdio: "ignore" });
  } else {
    try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
  }
}

function freePort() {
  // Port 0 asks the OS for any free port; read it back, then release it
  // immediately so the scenario under test can bind it itself.
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close((err) => (err ? reject(err) : resolvePort(port)));
    });
    srv.on("error", reject);
  });
}

const results = [];
async function scenario(name, fn) {
  process.stdout.write(`running: ${name} ...\n`);
  try {
    await fn();
    results.push({ name, ok: true });
    process.stdout.write(`  ok - ${name}\n`);
  } catch (error) {
    results.push({ name, ok: false, error });
    process.stdout.write(`FAIL - ${name}: ${error.message}\n`);
  }
}

// ---------------------------------------------------------------------------
// 1. Partial initialization: init succeeds, then a piece of required state
//    (the authority manifest) is removed out from under it.
//
//    The manifest is a deterministic re-signing of the existing local keys
//    (bootstrap_dev_receipt_keys.mjs always rewrites it, unconditionally —
//    it is not "new trust", just a recomputed statement about keys that
//    already exist), so `doctor` — which only inspects current state and
//    never repairs it — must catch and report the gap precisely, while
//    `smoke`/`start` — which call the same bootstrap step `init` does before
//    running — must self-heal it and still produce a real verified receipt.
//    Both properties matter: doctor must not paper over a broken state, and
//    the CLI must not get stuck in it either.
// ---------------------------------------------------------------------------
async function testPartialInit() {
  const home = freshHome("partial-init");
  try {
    assert.equal(runCli(["init"], home).status, 0, "baseline init must succeed");
    const manifestPath = join(home, ".mnde-test", "authority", "authority-manifest.json");
    assert.ok(existsSync(manifestPath), "precondition: manifest must exist after init");
    rmSync(manifestPath, { force: true });

    const doctor = runCli(["doctor"], home);
    assert.notEqual(doctor.status, 0, "doctor must fail closed when the authority manifest is missing");
    assert.match(doctor.stdout, /Authority manifest present/);

    const smoke = runCli(["smoke"], home);
    assert.equal(smoke.status, 0, `smoke must self-heal a missing (re-derivable) manifest and still succeed:\n${smoke.stdout}\n${smoke.stderr}`);
    assert.match(smoke.stdout, /VERIFIED ✓/, "smoke must produce a genuinely verified receipt after self-healing");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 2. Corrupt keys: init succeeds, then the private key file is overwritten
//    with garbage. doctor's key-validity check (not just existence) must
//    catch this, and no receipt-signing path may treat it as usable.
// ---------------------------------------------------------------------------
async function testCorruptKeys() {
  const home = freshHome("corrupt-keys");
  try {
    assert.equal(runCli(["init"], home).status, 0, "baseline init must succeed");
    const keyPath = join(home, "shared", "receipt_keys", "receipt_signing_private.pem");
    assert.ok(existsSync(keyPath), "precondition: private key must exist after init");
    writeFileSync(keyPath, "-----BEGIN NOT A KEY-----\nnot actually pem data\n-----END NOT A KEY-----\n", "utf8");

    const doctor = runCli(["doctor"], home);
    assert.notEqual(doctor.status, 0, "doctor must fail closed on a corrupt signing key");
    assert.match(doctor.stdout, /Receipt signing key present \+ valid/);

    const smoke = runCli(["smoke"], home);
    assert.notEqual(smoke.status, 0, "smoke must not succeed with a corrupt signing key");
    assert.doesNotMatch(smoke.stdout, /VERIFIED ✓/, "smoke must never report VERIFIED with a corrupt key");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 3. Occupied port: something else is already bound to the sidecar's port.
//    `start` must fail closed (nonzero exit, no hang) rather than silently
//    reporting success or leaving an orphaned process.
// ---------------------------------------------------------------------------
async function testOccupiedPort() {
  const home = freshHome("occupied-port");
  const port = await freePort();
  const occupier = createServer();
  await new Promise((res, rej) => {
    occupier.listen(port, "127.0.0.1", res);
    occupier.on("error", rej);
  });
  try {
    assert.equal(runCli(["init"], home).status, 0, "baseline init must succeed");
    const start = runCli(["start"], home, { MNDE_BIND_PORT: String(port) });
    assert.notEqual(start.status, 0, "start must fail closed when its port is already bound by something else");
  } finally {
    await new Promise((res) => occupier.close(res));
    rmSync(home, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 4. Malformed policy: init succeeds, then starter-policy.json is overwritten
//    with invalid JSON. doctor must catch this precisely, not crash uncaught.
// ---------------------------------------------------------------------------
async function testMalformedPolicy() {
  const home = freshHome("malformed-policy");
  try {
    assert.equal(runCli(["init"], home).status, 0, "baseline init must succeed");
    const policyPath = join(home, "starter-policy.json");
    assert.ok(existsSync(policyPath), "precondition: starter policy must exist after init");
    writeFileSync(policyPath, "{ this is not valid json ", "utf8");

    const doctor = runCli(["doctor"], home);
    assert.notEqual(doctor.status, 0, "doctor must fail closed on a malformed policy file");
    assert.match(doctor.stdout, /Starter policy present \+ valid/);

    const smoke = runCli(["smoke"], home);
    assert.notEqual(smoke.status, 0, "smoke must not succeed against a malformed policy file");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 5. Interrupted startup: `start` is killed (whole process tree) almost
//    immediately after spawning, before the sidecar becomes ready. A later,
//    ordinary run against the SAME MNDE_HOME must still succeed cleanly —
//    the interruption must not leave corrupt or locked state behind.
// ---------------------------------------------------------------------------
async function testInterruptedStartup() {
  const home = freshHome("interrupted-startup");
  const port = await freePort();
  try {
    assert.equal(runCli(["init"], home).status, 0, "baseline init must succeed");

    const child = spawn(nodeCmd, [cliPath, "start"], {
      cwd: repoRoot,
      env: { ...process.env, MNDE_HOME: home, MNDE_BIND_PORT: String(port) },
      stdio: "ignore"
    });
    await new Promise((r) => setTimeout(r, 50)); // kill well before boot can complete
    killTree(child);
    await new Promise((r) => setTimeout(r, 300)); // let the OS release the port/handles

    const doctor = runCli(["doctor"], home, { MNDE_BIND_PORT: String(port) });
    assert.equal(doctor.status, 0, `doctor must still pass after an interrupted start:\n${doctor.stdout}\n${doctor.stderr}`);

    const smoke = runCli(["smoke"], home);
    assert.equal(smoke.status, 0, `smoke must still succeed after an interrupted start:\n${smoke.stdout}\n${smoke.stderr}`);
    assert.match(smoke.stdout, /VERIFIED ✓/, "smoke must fully recover after an interrupted prior start");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

await scenario("partial initialization", testPartialInit);
await scenario("corrupt signing keys", testCorruptKeys);
await scenario("occupied port", testOccupiedPort);
await scenario("malformed policy", testMalformedPolicy);
await scenario("interrupted startup", testInterruptedStartup);

const failed = results.filter((r) => !r.ok);
for (const r of results) {
  console.log(`${r.ok ? "  ok" : "FAIL"} - ${r.name}`);
  if (!r.ok) console.error(`       ${r.error.message}`);
}

if (failed.length > 0) {
  console.error(`\nFAIL sidecar CLI hostile tests (${results.length - failed.length}/${results.length} passed)`);
  process.exit(1);
}
console.log(`\nPASS sidecar CLI hostile tests (${results.length}/${results.length})`);
